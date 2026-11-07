// Package sfu is the selective forwarding unit: one Pion PeerConnection per
// participant who joined audio, RTP forwarded between them without decoding.
//
// Concurrency: every room has one worker goroutine that runs all Pion calls
// for that room in order (negotiation, track add/remove, teardown). The
// MediaHandler methods and Pion callbacks only enqueue work, so the signaling
// goroutine never blocks on Pion. Events carry the PeerConnection they belong
// to; events from a connection that has since been replaced are ignored.
//
// Negotiation: only the server offers. Per participant one offer is
// outstanding at a time; changes made meanwhile set a pending flag and the
// next offer goes out when the answer arrives.
package sfu

import (
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"sync"
	"time"

	"github.com/pion/ice/v4"
	"github.com/pion/interceptor"
	"github.com/pion/webrtc/v4"

	"github.com/PVKonovalov/tin-can-phone/internal/protocol"
	"github.com/PVKonovalov/tin-can-phone/internal/room"
)

// DefaultDisconnectedTimeout is how long a connection may stay
// "disconnected" before it is closed with media-failed.
const DefaultDisconnectedTimeout = 15 * time.Second

// Opus is the only codec.
var opus = webrtc.RTPCodecCapability{
	MimeType:    webrtc.MimeTypeOpus,
	ClockRate:   48000,
	Channels:    2,
	SDPFmtpLine: "minptime=10;useinbandfec=1",
}

// Options configures the SFU.
type Options struct {
	// UDPAddr is the media listen address, e.g. ":50000".
	UDPAddr string
	// AdvertiseIPs are announced as ICE host candidates (required).
	AdvertiseIPs []net.IP
	Log          *slog.Logger
	// DisconnectedTimeout defaults to DefaultDisconnectedTimeout.
	DisconnectedTimeout time.Duration
}

// SFU implements room.MediaHandler.
type SFU struct {
	opts Options
	log  *slog.Logger
	api  *webrtc.API
	udp  net.PacketConn
	mux  ice.UDPMux

	mu     sync.Mutex
	rooms  map[string]*mediaRoom
	closed bool
	wg     sync.WaitGroup // workers, forwarders, RTCP readers, async closes
}

var _ room.MediaHandler = (*SFU)(nil)

// New opens the UDP media socket and prepares the WebRTC API.
func New(opts Options) (*SFU, error) {
	if len(opts.AdvertiseIPs) == 0 {
		return nil, errors.New("sfu: no IPs to advertise")
	}
	if opts.Log == nil {
		opts.Log = slog.New(slog.DiscardHandler)
	}
	if opts.DisconnectedTimeout <= 0 {
		opts.DisconnectedTimeout = DefaultDisconnectedTimeout
	}

	me := &webrtc.MediaEngine{}
	if err := me.RegisterCodec(webrtc.RTPCodecParameters{RTPCodecCapability: opus, PayloadType: 111}, webrtc.RTPCodecTypeAudio); err != nil {
		return nil, fmt.Errorf("sfu: register opus: %w", err)
	}
	ir := &interceptor.Registry{}
	if err := webrtc.RegisterDefaultInterceptors(me, ir); err != nil {
		return nil, fmt.Errorf("sfu: interceptors: %w", err)
	}

	external := make([]string, 0, len(opts.AdvertiseIPs))
	var v4, v6 bool
	for _, ip := range opts.AdvertiseIPs {
		external = append(external, ip.String())
		if ip.To4() != nil {
			v4 = true
		} else {
			v6 = true
		}
	}
	// The UDP mux publishes a candidate for every address its socket listens
	// on, regardless of SetNetworkTypes. A local address whose family has no
	// advertised IP would not match the rewrite rule and leak unchanged, so
	// the socket only covers the advertised families.
	network := "udp" // both families: dual-stack socket
	switch {
	case v4 && !v6:
		network = "udp4"
	case v6 && !v4:
		network = "udp6"
	}
	udpAddr, err := net.ResolveUDPAddr(network, opts.UDPAddr)
	if err != nil {
		return nil, fmt.Errorf("sfu: media address: %w", err)
	}
	udp, err := net.ListenUDP(network, udpAddr)
	if err != nil {
		return nil, fmt.Errorf("sfu: listen media port: %w", err)
	}

	se := webrtc.SettingEngine{}
	mux := webrtc.NewICEUDPMux(nil, udp)
	se.SetICEUDPMux(mux)
	// Every local address is replaced by the advertised ones of its family.
	if err := se.SetICEAddressRewriteRules(webrtc.ICEAddressRewriteRule{
		External:        external,
		AsCandidateType: webrtc.ICECandidateTypeHost,
		Mode:            webrtc.ICEAddressRewriteReplace,
	}); err != nil {
		_ = udp.Close()
		return nil, fmt.Errorf("sfu: address rewrite: %w", err)
	}
	var nets []webrtc.NetworkType
	if v4 {
		nets = append(nets, webrtc.NetworkTypeUDP4)
	}
	if v6 {
		nets = append(nets, webrtc.NetworkTypeUDP6)
	}
	se.SetNetworkTypes(nets)
	se.SetICEMulticastDNSMode(ice.MulticastDNSModeDisabled)
	se.SetIncludeLoopbackCandidate(true) // loopback locals are rewritten like any other

	s := &SFU{
		opts:  opts,
		log:   opts.Log,
		api:   webrtc.NewAPI(webrtc.WithMediaEngine(me), webrtc.WithInterceptorRegistry(ir), webrtc.WithSettingEngine(se)),
		udp:   udp,
		mux:   mux,
		rooms: map[string]*mediaRoom{},
	}
	s.log.Info("sfu: media listening", "udp", udp.LocalAddr().String(), "advertise", external)
	return s, nil
}

// LocalAddr returns the media socket address.
func (s *SFU) LocalAddr() net.Addr { return s.udp.LocalAddr() }

// Close tears down every connection and closes the media socket.
func (s *SFU) Close() error {
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return nil
	}
	s.closed = true
	rooms := make([]*mediaRoom, 0, len(s.rooms))
	for _, r := range s.rooms {
		rooms = append(rooms, r)
	}
	s.mu.Unlock()
	for _, r := range rooms {
		r.push(func() {
			for id, p := range r.peers {
				r.teardown(p)
				delete(r.peers, id)
			}
		})
	}
	s.wg.Wait()
	err := s.mux.Close() // also closes the UDP socket
	if cerr := s.udp.Close(); cerr != nil && !errors.Is(cerr, net.ErrClosed) {
		err = errors.Join(err, cerr)
	}
	return err
}

// PeerJoined implements room.MediaHandler.
func (s *SFU) PeerJoined(roomID, peerID string, send func(protocol.Envelope) error) {
	s.enqueue(roomID, func(r *mediaRoom) {
		r.peers[peerID] = &participant{id: peerID, send: send}
	})
}

// PeerLeft implements room.MediaHandler.
func (s *SFU) PeerLeft(roomID, peerID string) {
	s.enqueue(roomID, func(r *mediaRoom) {
		if p := r.peers[peerID]; p != nil {
			r.teardown(p)
			delete(r.peers, peerID)
		}
	})
}

// Signal implements room.MediaHandler.
func (s *SFU) Signal(roomID, peerID string, msg protocol.Envelope) {
	s.enqueue(roomID, func(r *mediaRoom) {
		p := r.peers[peerID]
		if p == nil {
			return
		}
		switch msg.Type {
		case protocol.TypeMediaJoin:
			r.mediaJoin(p)
		case protocol.TypeAnswer:
			r.answer(p, msg.Payload)
		case protocol.TypeICECandidate:
			r.candidate(p, msg.Payload)
		case protocol.TypeOffer:
			p.error(protocol.ErrUnexpectedOffer, "the server makes all offers; answer them instead")
		}
	})
}

// enqueue runs fn on the room's worker, starting one if needed. Work for a
// closed SFU is dropped.
func (s *SFU) enqueue(roomID string, fn func(*mediaRoom)) {
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return
	}
	r := s.rooms[roomID]
	if r == nil {
		r = &mediaRoom{s: s, id: roomID, peers: map[string]*participant{}, notify: make(chan struct{}, 1)}
		s.rooms[roomID] = r
		s.wg.Go(r.run)
	}
	r.queue = append(r.queue, func() { fn(r) })
	s.mu.Unlock()
	r.wake()
}

type mediaRoom struct {
	s      *SFU
	id     string
	notify chan struct{}
	queue  []func() // guarded by s.mu

	peers map[string]*participant // worker only
}

func (r *mediaRoom) wake() {
	select {
	case r.notify <- struct{}{}:
	default:
	}
}

// push queues fn even after Close (used by Close itself).
func (r *mediaRoom) push(fn func()) {
	r.s.mu.Lock()
	r.queue = append(r.queue, fn)
	r.s.mu.Unlock()
	r.wake()
}

// run processes the queue. It exits once the room has no participants and
// nothing is queued (or the SFU is closed and the queue is drained).
func (r *mediaRoom) run() {
	for {
		r.s.mu.Lock()
		if len(r.queue) == 0 {
			if len(r.peers) == 0 || r.s.closed {
				if r.s.rooms[r.id] == r {
					delete(r.s.rooms, r.id)
				}
				r.s.mu.Unlock()
				return
			}
			r.s.mu.Unlock()
			<-r.notify
			continue
		}
		fn := r.queue[0]
		r.queue[0] = nil
		r.queue = r.queue[1:]
		r.s.mu.Unlock()
		fn()
	}
}

type participant struct {
	id   string
	send func(protocol.Envelope) error

	pc      *webrtc.PeerConnection
	local   *webrtc.TrackLocalStaticRTP  // this participant's audio, forwarded to others
	senders map[string]*webrtc.RTPSender // publisher peerID → sender on pc
	cands   []webrtc.ICECandidateInit    // client candidates before the first answer
	disc    *time.Timer                  // disconnected timeout

	negotiating bool // offer sent, answer outstanding
	pending     bool // another offer needed after the answer
}

func (p *participant) log(r *mediaRoom) *slog.Logger {
	return r.s.log.With("room", r.id, "peer", p.id)
}

func (p *participant) error(code, message string) {
	_ = p.send(protocol.NewError(p.id, code, message))
}

func (r *mediaRoom) mediaJoin(p *participant) {
	if p.pc != nil {
		p.log(r).Debug("sfu: media-join replaces existing connection")
		r.teardown(p)
	}
	pc, err := r.s.api.NewPeerConnection(webrtc.Configuration{}) // no ICE servers
	if err != nil {
		r.fail(p, "could not create connection")
		return
	}
	local, err := webrtc.NewTrackLocalStaticRTP(opus, p.id+"-audio", p.id)
	if err != nil {
		_ = pc.Close()
		r.fail(p, "could not create track")
		return
	}
	// First transceiver: the client's microphone. It starts recvonly; AddTrack
	// may later reuse it to send another publisher, making it sendrecv.
	if _, err := pc.AddTransceiverFromKind(webrtc.RTPCodecTypeAudio,
		webrtc.RTPTransceiverInit{Direction: webrtc.RTPTransceiverDirectionRecvonly}); err != nil {
		_ = pc.Close()
		r.fail(p, "could not create transceiver")
		return
	}
	p.pc, p.local, p.senders = pc, local, map[string]*webrtc.RTPSender{}
	r.watch(p, pc, local)

	for _, q := range r.peers {
		if q == p {
			continue
		}
		if q.local != nil {
			r.addTrack(p, q)
		}
		if q.pc != nil {
			r.addTrack(q, p)
			r.negotiate(q)
		}
	}
	r.negotiate(p)
}

// watch installs Pion callbacks; they only enqueue work tagged with pc.
func (r *mediaRoom) watch(p *participant, pc *webrtc.PeerConnection, local *webrtc.TrackLocalStaticRTP) {
	id, s := p.id, r.s
	log := p.log(r)
	onPC := func(fn func(p *participant)) {
		s.enqueue(r.id, func(r *mediaRoom) {
			if p := r.peers[id]; p != nil && p.pc == pc {
				fn(p)
			}
		})
	}

	var once sync.Once
	pc.OnTrack(func(remote *webrtc.TrackRemote, _ *webrtc.RTPReceiver) {
		if remote.Kind() != webrtc.RTPCodecTypeAudio {
			return
		}
		once.Do(func() {
			log.Debug("sfu: receiving audio", "ssrc", remote.SSRC())
			s.wg.Go(func() { forward(remote, local) })
		})
	})
	// Candidates go through the worker so they are always sent after the
	// offer whose SetLocalDescription started gathering.
	pc.OnICECandidate(func(c *webrtc.ICECandidate) {
		onPC(func(p *participant) {
			payload := json.RawMessage("null") // end of candidates
			if c != nil {
				payload, _ = json.Marshal(c.ToJSON())
			}
			_ = p.send(protocol.Envelope{Type: protocol.TypeICECandidate, From: protocol.ToSFU, To: p.id, Payload: payload})
		})
	})
	pc.OnICEConnectionStateChange(func(st webrtc.ICEConnectionState) {
		log.Debug("sfu: ice state", "state", st.String())
	})
	pc.OnConnectionStateChange(func(st webrtc.PeerConnectionState) {
		log.Debug("sfu: connection state", "state", st.String())
		onPC(func(p *participant) { r.connectionState(p, st) })
	})
}

func (r *mediaRoom) connectionState(p *participant, st webrtc.PeerConnectionState) {
	switch st {
	case webrtc.PeerConnectionStateFailed:
		r.fail(p, "connection failed")
	case webrtc.PeerConnectionStateDisconnected:
		if p.disc != nil {
			return
		}
		pc, id := p.pc, p.id
		p.disc = time.AfterFunc(r.s.opts.DisconnectedTimeout, func() {
			r.s.enqueue(r.id, func(r *mediaRoom) {
				if p := r.peers[id]; p != nil && p.pc == pc && pc.ConnectionState() == webrtc.PeerConnectionStateDisconnected {
					r.fail(p, "connection lost")
				}
			})
		})
	case webrtc.PeerConnectionStateConnected:
		if p.disc != nil {
			p.disc.Stop()
			p.disc = nil
		}
	}
}

// addTrack sends pub's audio on dst's connection.
func (r *mediaRoom) addTrack(dst, pub *participant) {
	sender, err := dst.pc.AddTrack(pub.local)
	if err != nil {
		dst.log(r).Warn("sfu: add track", "publisher", pub.id, "err", err)
		return
	}
	dst.senders[pub.id] = sender
	// Reading RTCP drives the interceptors (NACK, reports); ends when the
	// sender is stopped or the connection closes.
	r.s.wg.Go(func() {
		buf := make([]byte, 1500)
		for {
			if _, _, err := sender.Read(buf); err != nil {
				return
			}
		}
	})
}

// negotiate sends a new offer, or marks one pending if an answer is outstanding.
func (r *mediaRoom) negotiate(p *participant) {
	if p.pc == nil {
		return
	}
	if p.negotiating {
		p.pending = true
		return
	}
	offer, err := p.pc.CreateOffer(nil)
	if err == nil {
		err = p.pc.SetLocalDescription(offer)
	}
	if err != nil {
		p.log(r).Warn("sfu: create offer", "err", err)
		r.fail(p, "could not create offer")
		return
	}
	p.negotiating, p.pending = true, false
	payload, _ := json.Marshal(offer)
	_ = p.send(protocol.Envelope{Type: protocol.TypeOffer, From: protocol.ToSFU, To: p.id, Payload: payload})
}

func (r *mediaRoom) answer(p *participant, payload json.RawMessage) {
	if p.pc == nil || !p.negotiating {
		p.error(protocol.ErrUnexpectedAnswer, "no offer is outstanding")
		return
	}
	var sd webrtc.SessionDescription
	if err := json.Unmarshal(payload, &sd); err != nil || sd.Type != webrtc.SDPTypeAnswer {
		r.fail(p, "invalid answer")
		return
	}
	if err := p.pc.SetRemoteDescription(sd); err != nil {
		p.log(r).Warn("sfu: set answer", "err", err)
		r.fail(p, "invalid answer")
		return
	}
	p.negotiating = false
	for _, c := range p.cands {
		if err := p.pc.AddICECandidate(c); err != nil {
			p.log(r).Debug("sfu: add candidate", "err", err)
		}
	}
	p.cands = nil
	if p.pending {
		r.negotiate(p)
	}
}

func (r *mediaRoom) candidate(p *participant, payload json.RawMessage) {
	if p.pc == nil {
		return // late candidate for a closed connection
	}
	if len(payload) == 0 || string(payload) == "null" {
		return // end of candidates
	}
	var c webrtc.ICECandidateInit
	if err := json.Unmarshal(payload, &c); err != nil || c.Candidate == "" {
		return
	}
	if p.pc.RemoteDescription() == nil {
		p.cands = append(p.cands, c)
		return
	}
	if err := p.pc.AddICECandidate(c); err != nil {
		p.log(r).Debug("sfu: add candidate", "err", err)
	}
}

// fail tears the connection down and tells the client it may media-join again.
func (r *mediaRoom) fail(p *participant, reason string) {
	p.log(r).Info("sfu: media failed", "reason", reason)
	r.teardown(p)
	p.error(protocol.ErrMediaFailed, reason)
}

// teardown closes p's connection and removes p's track from everyone else.
func (r *mediaRoom) teardown(p *participant) {
	if p.pc == nil {
		return
	}
	pc := p.pc
	if p.disc != nil {
		p.disc.Stop()
	}
	p.pc, p.local, p.senders, p.cands, p.disc = nil, nil, nil, nil, nil
	p.negotiating, p.pending = false, false
	for _, q := range r.peers {
		if q == p || q.pc == nil {
			continue
		}
		if sender := q.senders[p.id]; sender != nil {
			delete(q.senders, p.id)
			if err := q.pc.RemoveTrack(sender); err != nil {
				q.log(r).Debug("sfu: remove track", "err", err)
			}
			r.negotiate(q)
		}
	}
	// GracefulClose waits for Pion's goroutines; keep it off the worker.
	r.s.wg.Go(func() { _ = pc.GracefulClose() })
}

// forward copies RTP from a publisher into its local track until the
// publisher's connection closes. Header extensions are dropped: their IDs are
// negotiated per connection and would be wrong on the other side.
func forward(remote *webrtc.TrackRemote, local *webrtc.TrackLocalStaticRTP) {
	for {
		pkt, _, err := remote.ReadRTP()
		if err != nil {
			return
		}
		pkt.Header.Extension = false
		pkt.Header.ExtensionProfile = 0
		pkt.Header.Extensions = nil
		_ = local.WriteRTP(pkt) // errors are per receiver; keep forwarding
	}
}

// DetectIPs returns the host's non-loopback, non-link-local unicast
// addresses (used when ADVERTISE_IPS is not set).
func DetectIPs() ([]net.IP, error) {
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil, err
	}
	var out []net.IP
	for _, ifc := range ifaces {
		if ifc.Flags&net.FlagUp == 0 || ifc.Flags&net.FlagLoopback != 0 {
			continue
		}
		addrs, err := ifc.Addrs()
		if err != nil {
			continue
		}
		for _, a := range addrs {
			n, ok := a.(*net.IPNet)
			if !ok {
				continue
			}
			ip := n.IP
			if ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsMulticast() || ip.IsUnspecified() {
				continue
			}
			out = append(out, ip)
		}
	}
	if len(out) == 0 {
		return nil, errors.New("no usable network addresses found")
	}
	return out, nil
}
