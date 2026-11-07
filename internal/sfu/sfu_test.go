package sfu

import (
	"context"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/coder/websocket"
	"github.com/pion/ice/v4"
	"github.com/pion/rtp"
	"github.com/pion/webrtc/v4"
	"go.uber.org/goleak"

	"github.com/PVKonovalov/tin-can-phone/internal/protocol"
	"github.com/PVKonovalov/tin-can-phone/internal/room"
	"github.com/PVKonovalov/tin-can-phone/internal/signal"
)

func TestMain(m *testing.M) {
	goleak.VerifyTestMain(m)
}

// harness runs signaling + SFU in-process on 127.0.0.1.
type harness struct {
	t     *testing.T
	sfu   *SFU
	rooms *room.Manager
	sig   *signal.Server
	srv   *httptest.Server
}

func newHarness(t *testing.T) *harness {
	return newHarnessAt(t, "127.0.0.1:0")
}

func newHarnessAt(t *testing.T, udpAddr string) *harness {
	t.Helper()
	s, err := New(Options{UDPAddr: udpAddr, AdvertiseIPs: []net.IP{net.ParseIP("127.0.0.1")}})
	if err != nil {
		t.Fatal(err)
	}
	rooms := room.NewManager(room.Options{MaxPeers: 8, MaxRooms: 10, TTL: time.Hour})
	sig := signal.New(signal.Options{Rooms: rooms, Media: s})
	srv := httptest.NewServer(sig)
	h := &harness{t: t, sfu: s, rooms: rooms, sig: sig, srv: srv}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		_ = sig.Shutdown(ctx)
		srv.Close()
		if err := s.Close(); err != nil {
			t.Errorf("sfu close: %v", err)
		}
	})
	return h
}

func (h *harness) newRoom() string {
	info, err := h.rooms.Create()
	if err != nil {
		h.t.Fatal(err)
	}
	return info.ID
}

// roomPeers returns the number of SFU participants in a room (0 if the room
// worker has exited).
func (h *harness) mediaRooms() int {
	h.sfu.mu.Lock()
	defer h.sfu.mu.Unlock()
	return len(h.sfu.rooms)
}

// client is a Pion-based participant speaking the real signaling protocol.
type client struct {
	t      *testing.T
	name   string
	ws     *websocket.Conn
	peerID string
	pc     *webrtc.PeerConnection
	mic    *webrtc.TrackLocalStaticRTP

	events      chan protocol.Envelope // everything except offer/ice-candidate
	serverCands []string               // candidate lines received from the server
	offers      atomic.Int32
	sdp         atomic.Value // last offer SDP

	mu       sync.Mutex
	received map[string]*atomic.Int64 // stream ID → packets

	stop chan struct{}
	wg   sync.WaitGroup
}

func clientAPI() *webrtc.API {
	me := &webrtc.MediaEngine{}
	if err := me.RegisterCodec(webrtc.RTPCodecParameters{RTPCodecCapability: opus, PayloadType: 111}, webrtc.RTPCodecTypeAudio); err != nil {
		panic(err)
	}
	se := webrtc.SettingEngine{}
	se.SetNetworkTypes([]webrtc.NetworkType{webrtc.NetworkTypeUDP4})
	se.SetIncludeLoopbackCandidate(true)
	se.SetIPFilter(func(ip net.IP) bool { return ip.IsLoopback() })
	se.SetICEMulticastDNSMode(ice.MulticastDNSModeDisabled)
	return webrtc.NewAPI(webrtc.WithMediaEngine(me), webrtc.WithSettingEngine(se))
}

// join connects, says hello and waits for welcome. It does not join media.
func (h *harness) join(roomID, name string) *client {
	h.t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	ws, _, err := websocket.Dial(ctx, strings.Replace(h.srv.URL, "http", "ws", 1)+"/ws?room="+roomID,
		&websocket.DialOptions{HTTPHeader: http.Header{"Origin": {"https://" + strings.TrimPrefix(h.srv.URL, "http://")}}})
	if err != nil {
		h.t.Fatal(err)
	}
	c := &client{t: h.t, name: name, ws: ws, events: make(chan protocol.Envelope, 64),
		received: map[string]*atomic.Int64{}, stop: make(chan struct{})}
	c.sendMsg(protocol.TypeHello, protocol.Hello{DisplayName: name})
	_, data, err := ws.Read(ctx)
	if err != nil {
		h.t.Fatal(err)
	}
	var env protocol.Envelope
	json.Unmarshal(data, &env)
	var w protocol.Welcome
	json.Unmarshal(env.Payload, &w)
	if env.Type != protocol.TypeWelcome || w.PeerID == "" {
		h.t.Fatalf("expected welcome, got %s", data)
	}
	c.peerID = w.PeerID
	c.wg.Go(c.readLoop)
	h.t.Cleanup(c.close)
	return c
}

func (c *client) sendMsg(typ string, payload any) {
	c.sendEnv(protocol.New(typ, "", protocol.ToSFU, payload))
}

func (c *client) sendEnv(env protocol.Envelope) {
	b, _ := json.Marshal(env)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_ = c.ws.Write(ctx, websocket.MessageText, b)
}

// mediaJoin creates the client PeerConnection (mic track added up front) and
// sends media-join.
func (c *client) mediaJoin() {
	c.t.Helper()
	pc, err := clientAPI().NewPeerConnection(webrtc.Configuration{})
	if err != nil {
		c.t.Fatal(err)
	}
	mic, err := webrtc.NewTrackLocalStaticRTP(opus, "mic", c.name)
	if err != nil {
		c.t.Fatal(err)
	}
	if _, err := pc.AddTrack(mic); err != nil {
		c.t.Fatal(err)
	}
	pc.OnICECandidate(func(cand *webrtc.ICECandidate) {
		if cand == nil {
			c.sendEnv(protocol.Envelope{Type: protocol.TypeICECandidate, To: protocol.ToSFU, Payload: json.RawMessage("null")})
			return
		}
		c.sendMsg(protocol.TypeICECandidate, cand.ToJSON())
	})
	pc.OnTrack(func(tr *webrtc.TrackRemote, _ *webrtc.RTPReceiver) {
		c.mu.Lock()
		n := c.received[tr.StreamID()]
		if n == nil {
			n = &atomic.Int64{}
			c.received[tr.StreamID()] = n
		}
		c.mu.Unlock()
		for {
			if _, _, err := tr.ReadRTP(); err != nil {
				return
			}
			n.Add(1)
		}
	})
	c.mu.Lock()
	c.pc, c.mic = pc, mic
	c.mu.Unlock()
	c.wg.Go(func() { c.speak(mic) })
	c.sendMsg(protocol.TypeMediaJoin, nil)
}

// speak sends a synthetic Opus packet every 20 ms.
func (c *client) speak(mic *webrtc.TrackLocalStaticRTP) {
	t := time.NewTicker(20 * time.Millisecond)
	defer t.Stop()
	pkt := &rtp.Packet{Header: rtp.Header{Version: 2, PayloadType: 111, SSRC: 1234}, Payload: []byte{0xf8, 0xff, 0xfe}}
	for {
		select {
		case <-c.stop:
			return
		case <-t.C:
			pkt.SequenceNumber++
			pkt.Timestamp += 960
			_ = mic.WriteRTP(pkt)
		}
	}
}

func (c *client) readLoop() {
	for {
		_, data, err := c.ws.Read(context.Background())
		if err != nil {
			close(c.events)
			return
		}
		var env protocol.Envelope
		if err := json.Unmarshal(data, &env); err != nil {
			continue
		}
		switch env.Type {
		case protocol.TypeOffer:
			c.onOffer(env.Payload)
		case protocol.TypeICECandidate:
			if string(env.Payload) == "null" {
				continue
			}
			var cand webrtc.ICECandidateInit
			json.Unmarshal(env.Payload, &cand)
			c.mu.Lock()
			pc := c.pc
			c.serverCands = append(c.serverCands, cand.Candidate)
			c.mu.Unlock()
			if pc == nil {
				continue
			}
			if err := pc.AddICECandidate(cand); err != nil {
				c.t.Errorf("%s: add candidate: %v", c.name, err)
			}
		default:
			c.events <- env
		}
	}
}

func (c *client) onOffer(payload json.RawMessage) {
	var offer webrtc.SessionDescription
	if err := json.Unmarshal(payload, &offer); err != nil {
		c.t.Errorf("bad offer: %v", err)
		return
	}
	c.mu.Lock()
	pc := c.pc
	c.mu.Unlock()
	c.offers.Add(1)
	if pc == nil {
		return // raw-protocol tests drive answers themselves
	}
	if err := pc.SetRemoteDescription(offer); err != nil {
		c.t.Errorf("%s: set offer: %v", c.name, err)
		return
	}
	answer, err := pc.CreateAnswer(nil)
	if err == nil {
		err = pc.SetLocalDescription(answer)
	}
	if err != nil {
		c.t.Errorf("%s: answer: %v", c.name, err)
		return
	}
	c.sdp.Store(offer.SDP)
	c.sendMsg(protocol.TypeAnswer, answer)
}

func (c *client) packetsFrom(stream string) int64 {
	c.mu.Lock()
	defer c.mu.Unlock()
	if n := c.received[stream]; n != nil {
		return n.Load()
	}
	return 0
}

func (c *client) expectEvent(typ string) protocol.Envelope {
	c.t.Helper()
	timeout := time.After(10 * time.Second)
	for {
		select {
		case e, ok := <-c.events:
			if !ok {
				c.t.Fatalf("%s: socket closed waiting for %s", c.name, typ)
			}
			if e.Type == typ {
				return e
			}
		case <-timeout:
			c.t.Fatalf("%s: no %s", c.name, typ)
		}
	}
}

func (c *client) close() {
	select {
	case <-c.stop:
		return
	default:
	}
	close(c.stop)
	_ = c.ws.CloseNow()
	c.mu.Lock()
	pc := c.pc
	c.mu.Unlock()
	if pc != nil {
		_ = pc.GracefulClose()
	}
	c.wg.Wait()
}

func eventually(t *testing.T, what string, timeout time.Duration, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out: %s", what)
		}
		time.Sleep(20 * time.Millisecond)
	}
}

// receivesFrom waits until c gets a growing packet count on stream.
func receivesFrom(t *testing.T, c *client, stream string) {
	t.Helper()
	eventually(t, c.name+" receives audio from "+stream, 15*time.Second, func() bool { return c.packetsFrom(stream) > 5 })
	before := c.packetsFrom(stream)
	eventually(t, c.name+" audio from "+stream+" keeps flowing", 5*time.Second, func() bool { return c.packetsFrom(stream) > before+5 })
}

func TestTwoPeersExchangeAudioAndRenegotiate(t *testing.T) {
	h := newHarness(t)
	rid := h.newRoom()

	a := h.join(rid, "alice")
	a.mediaJoin()
	eventually(t, "alice connected", 10*time.Second, func() bool {
		return a.pc.ConnectionState() == webrtc.PeerConnectionStateConnected
	})

	// B joins after A is already publishing → both receive each other.
	b := h.join(rid, "bob")
	a.expectEvent(protocol.TypePeerJoined)
	b.mediaJoin()
	receivesFrom(t, b, a.peerID)
	receivesFrom(t, a, b.peerID)
	if a.offers.Load() < 2 {
		t.Errorf("alice got %d offers, want a renegotiation when bob joined", a.offers.Load())
	}
	if n := a.packetsFrom(a.peerID); n != 0 {
		t.Errorf("alice received her own audio (%d packets)", n)
	}
	if !strings.Contains(a.sdp.Load().(string), "msid:"+b.peerID+" "+b.peerID+"-audio") {
		t.Errorf("alice's offer lacks bob's track:\n%s", a.sdp.Load())
	}

	// B leaves → A is renegotiated without B's track and stays connected.
	offersBefore := a.offers.Load()
	b.close()
	a.expectEvent(protocol.TypePeerLeft)
	eventually(t, "renegotiation after bob left", 10*time.Second, func() bool { return a.offers.Load() > offersBefore })
	if sdp := a.sdp.Load().(string); strings.Contains(sdp, "msid:"+b.peerID) {
		t.Errorf("offer after leave still sends bob's track:\n%s", sdp)
	}
	time.Sleep(500 * time.Millisecond)
	if st := a.pc.ConnectionState(); st != webrtc.PeerConnectionStateConnected {
		t.Errorf("alice state %s after bob left", st)
	}

	// A third peer reuses the freed transceiver instead of growing the SDP.
	mlines := strings.Count(a.sdp.Load().(string), "m=audio")
	c := h.join(rid, "carol")
	c.mediaJoin()
	receivesFrom(t, a, c.peerID)
	receivesFrom(t, c, a.peerID)
	if got := strings.Count(a.sdp.Load().(string), "m=audio"); got != mlines {
		t.Errorf("m-lines grew from %d to %d", mlines, got)
	}
}

func TestUnexpectedOfferAndAnswer(t *testing.T) {
	h := newHarness(t)
	rid := h.newRoom()
	a := h.join(rid, "alice")

	a.sendMsg(protocol.TypeOffer, map[string]string{"type": "offer", "sdp": "v=0"})
	var e protocol.Error
	json.Unmarshal(a.expectEvent(protocol.TypeError).Payload, &e)
	if e.Code != protocol.ErrUnexpectedOffer {
		t.Errorf("code %q", e.Code)
	}
	a.sendMsg(protocol.TypeAnswer, map[string]string{"type": "answer", "sdp": "v=0"})
	json.Unmarshal(a.expectEvent(protocol.TypeError).Payload, &e)
	if e.Code != protocol.ErrUnexpectedAnswer {
		t.Errorf("code %q", e.Code)
	}
}

func TestInvalidAnswerFailsMedia(t *testing.T) {
	h := newHarness(t)
	rid := h.newRoom()
	a := h.join(rid, "alice")
	// Join media without a real client: answer the offer with garbage.
	a.sendMsg(protocol.TypeMediaJoin, nil)
	eventually(t, "offer sent", 5*time.Second, func() bool {
		var n int
		h.sfu.mu.Lock()
		r := h.sfu.rooms[rid]
		h.sfu.mu.Unlock()
		if r != nil {
			done := make(chan struct{})
			r.push(func() {
				if p := r.peers[a.peerID]; p != nil && p.negotiating {
					n = 1
				}
				close(done)
			})
			<-done
		}
		return n == 1
	})
	a.sendMsg(protocol.TypeAnswer, map[string]string{"type": "answer", "sdp": "garbage"})
	var e protocol.Error
	json.Unmarshal(a.expectEvent(protocol.TypeError).Payload, &e)
	if e.Code != protocol.ErrMediaFailed {
		t.Errorf("code %q", e.Code)
	}
}

func TestSocketCloseClosesServerConnection(t *testing.T) {
	h := newHarness(t)
	rid := h.newRoom()
	a := h.join(rid, "alice")
	a.mediaJoin()
	eventually(t, "alice connected", 10*time.Second, func() bool {
		return a.pc.ConnectionState() == webrtc.PeerConnectionStateConnected
	})
	if h.mediaRooms() != 1 {
		t.Fatalf("media rooms %d", h.mediaRooms())
	}
	// Close only the WebSocket; the client's PeerConnection stays open.
	_ = a.ws.Close(websocket.StatusNormalClosure, "")
	eventually(t, "server dropped the room", 5*time.Second, func() bool { return h.mediaRooms() == 0 })
	// The server closed its side, so the client sees the connection go away.
	eventually(t, "client connection ends", 15*time.Second, func() bool {
		st := a.pc.ConnectionState()
		return st == webrtc.PeerConnectionStateClosed || st == webrtc.PeerConnectionStateFailed ||
			st == webrtc.PeerConnectionStateDisconnected
	})
}

func TestSecondMediaJoinReplaces(t *testing.T) {
	h := newHarness(t)
	rid := h.newRoom()
	a := h.join(rid, "alice")
	b := h.join(rid, "bob")
	a.mediaJoin()
	b.mediaJoin()
	receivesFrom(t, b, a.peerID)

	// Alice rejoins with a brand-new client connection.
	old := a.pc
	a.mediaJoin()
	_ = old.Close()
	receivesFrom(t, b, a.peerID)
	receivesFrom(t, a, b.peerID)
}

func TestDetectIPs(t *testing.T) {
	ips, err := DetectIPs()
	if err != nil {
		t.Skip("no network interfaces:", err)
	}
	for _, ip := range ips {
		if ip.IsLoopback() || ip.IsLinkLocalUnicast() {
			t.Errorf("unexpected %s", ip)
		}
	}
}

// The media socket listens on every interface, but only ADVERTISE_IPS may
// appear in candidates (no other local address, of either IP family).
func TestOnlyAdvertisedAddressesInCandidates(t *testing.T) {
	h := newHarnessAt(t, ":0")
	rid := h.newRoom()
	a := h.join(rid, "alice")
	a.mediaJoin()
	eventually(t, "alice connected", 10*time.Second, func() bool {
		return a.pc.ConnectionState() == webrtc.PeerConnectionStateConnected
	})
	a.mu.Lock()
	cands := append([]string(nil), a.serverCands...)
	a.mu.Unlock()
	if len(cands) == 0 {
		t.Fatal("no server candidates")
	}
	port := h.sfu.LocalAddr().(*net.UDPAddr).Port
	for _, c := range cands {
		f := strings.Fields(c) // candidate:<f> <comp> <proto> <prio> <addr> <port> typ <type>
		if len(f) < 8 || f[4] != "127.0.0.1" || f[5] != strconv.Itoa(port) || f[7] != "host" {
			t.Errorf("unexpected server candidate %q", c)
		}
	}
}
