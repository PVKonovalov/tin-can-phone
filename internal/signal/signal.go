// Package signal implements the WebSocket signaling endpoint /ws?room={id}.
//
// Each connection has three goroutines: the reader (the HTTP handler
// goroutine), a writer draining a bounded outbound queue, and a pinger.
// Everything that wants to talk to a peer goes through conn.enqueue, which
// never blocks: if the queue is full the peer is too slow and is closed.
package signal

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"slices"
	"strings"
	"sync"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/coder/websocket"

	"github.com/PVKonovalov/tin-can-phone/internal/api"
	"github.com/PVKonovalov/tin-can-phone/internal/config"
	"github.com/PVKonovalov/tin-can-phone/internal/protocol"
	"github.com/PVKonovalov/tin-can-phone/internal/ratelimit"
	"github.com/PVKonovalov/tin-can-phone/internal/room"
)

// Defaults for Options.
const (
	DefaultHelloTimeout = 5 * time.Second
	DefaultPingInterval = 15 * time.Second
	DefaultPongTimeout  = 10 * time.Second
	DefaultWriteTimeout = 5 * time.Second
	DefaultQueueSize    = 64
	DefaultMsgRate      = 50 // messages per second
	DefaultMsgBurst     = 100
	MaxDisplayNameRunes = 40
)

// Options configures the signaling server. Zero values select the defaults.
type Options struct {
	Rooms *room.Manager
	Media room.MediaHandler
	// AllowedOrigins (normalized, see config.NormalizeOrigin). Empty: the
	// Origin must be https:// on the same host as the request.
	AllowedOrigins []string
	Log            *slog.Logger

	HelloTimeout time.Duration
	PingInterval time.Duration
	PongTimeout  time.Duration
	WriteTimeout time.Duration
	QueueSize    int
	MsgRate      float64
	MsgBurst     int
}

// Server is the /ws handler.
type Server struct {
	opts Options

	mu           sync.Mutex
	conns        map[*conn]struct{}
	shuttingDown bool
	wg           sync.WaitGroup // one per active handler
}

// New returns a signaling server.
func New(opts Options) *Server {
	def := func(v *time.Duration, d time.Duration) {
		if *v <= 0 {
			*v = d
		}
	}
	def(&opts.HelloTimeout, DefaultHelloTimeout)
	def(&opts.PingInterval, DefaultPingInterval)
	def(&opts.PongTimeout, DefaultPongTimeout)
	def(&opts.WriteTimeout, DefaultWriteTimeout)
	if opts.QueueSize <= 0 {
		opts.QueueSize = DefaultQueueSize
	}
	if opts.MsgRate <= 0 {
		opts.MsgRate = DefaultMsgRate
	}
	if opts.MsgBurst <= 0 {
		opts.MsgBurst = DefaultMsgBurst
	}
	if opts.Media == nil {
		opts.Media = room.NewUnavailableMedia()
	}
	if opts.Log == nil {
		opts.Log = slog.New(slog.DiscardHandler)
	}
	return &Server{opts: opts, conns: map[*conn]struct{}{}}
}

// ServeHTTP upgrades the request and runs the connection until it closes.
func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if !s.originAllowed(r) {
		api.WriteError(w, http.StatusForbidden, "origin-not-allowed", "WebSocket Origin not allowed")
		return
	}
	s.mu.Lock()
	if s.shuttingDown {
		s.mu.Unlock()
		api.WriteError(w, http.StatusServiceUnavailable, "shutting-down", "server is shutting down")
		return
	}
	s.wg.Add(1)
	s.mu.Unlock()
	defer s.wg.Done()

	// http.Hijacker documents that the hijacked conn may keep the server's
	// Read/WriteTimeout deadlines. Current Go clears them, but the contract
	// does not promise it, so clear them explicitly: liveness is handled by
	// ping/pong and per-write timeouts. (WebSocket runs over HTTP/1.1: Go's
	// HTTP/2 server does not offer extended CONNECT unless GODEBUG=http2xconnect=1.)
	rc := http.NewResponseController(w)
	_ = rc.SetReadDeadline(time.Time{})
	_ = rc.SetWriteDeadline(time.Time{})

	// Origin was checked above against our own policy.
	ws, err := websocket.Accept(w, r, &websocket.AcceptOptions{InsecureSkipVerify: true})
	if err != nil {
		return // Accept has written the HTTP error
	}
	ws.SetReadLimit(-1) // enforced in readLoop so we can close with 4400 instead of 1009

	c := &conn{
		s:         s,
		ws:        ws,
		roomID:    r.URL.Query().Get("room"),
		ip:        api.ClientIP(r),
		out:       make(chan []byte, s.opts.QueueSize),
		done:      make(chan struct{}),
		closeDone: make(chan struct{}),
		limiter:   ratelimit.NewBucket(s.opts.MsgRate, s.opts.MsgBurst, time.Now()),
	}
	s.track(c)
	defer s.untrack(c)
	c.serve()
}

// Shutdown closes every connection with 1001 and waits for them to finish
// (or for ctx). Call it before http.Server.Shutdown, which does not track
// hijacked connections.
func (s *Server) Shutdown(ctx context.Context) error {
	s.mu.Lock()
	s.shuttingDown = true
	conns := make([]*conn, 0, len(s.conns))
	for c := range s.conns {
		conns = append(conns, c)
	}
	s.mu.Unlock()
	for _, c := range conns {
		c.fail(protocol.CloseGoingAway, "server shutting down")
	}
	done := make(chan struct{})
	go func() { s.wg.Wait(); close(done) }()
	select {
	case <-done:
		return nil
	case <-ctx.Done():
		for _, c := range conns {
			_ = c.ws.CloseNow()
		}
		return ctx.Err()
	}
}

func (s *Server) track(c *conn) {
	s.mu.Lock()
	s.conns[c] = struct{}{}
	closing := s.shuttingDown
	s.mu.Unlock()
	if closing { // raced with Shutdown's snapshot
		c.fail(protocol.CloseGoingAway, "server shutting down")
	}
}

func (s *Server) untrack(c *conn) {
	s.mu.Lock()
	delete(s.conns, c)
	s.mu.Unlock()
}

func (s *Server) originAllowed(r *http.Request) bool {
	o := r.Header.Get("Origin")
	if o == "" {
		return false // browsers always send Origin on WebSocket requests
	}
	origin, err := config.NormalizeOrigin(o)
	if err != nil {
		return false
	}
	if len(s.opts.AllowedOrigins) > 0 {
		return slices.Contains(s.opts.AllowedOrigins, origin)
	}
	self, err := config.NormalizeOrigin("https://" + r.Host)
	return err == nil && origin == self
}

var errClosed = errors.New("connection closed")

type conn struct {
	s       *Server
	ws      *websocket.Conn
	roomID  string
	ip      string
	out     chan []byte
	limiter *ratelimit.Bucket // reader goroutine only

	failOnce  sync.Once
	done      chan struct{} // closed by fail: stops writer and pinger
	closeDone chan struct{} // closed when the close handshake has finished

	mu     sync.Mutex // guards peerID, joined, left
	peerID string
	joined bool
	left   bool

	workers sync.WaitGroup
}

func (c *conn) log() *slog.Logger {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.s.opts.Log.With("room", c.roomID, "peer", c.peerID, "ip", c.ip)
}

func (c *conn) serve() {
	c.workers.Go(c.writer)
	c.workers.Go(c.pinger)
	hello := time.AfterFunc(c.s.opts.HelloTimeout, func() {
		c.mu.Lock()
		joined := c.joined
		c.mu.Unlock()
		if !joined {
			c.fail(protocol.CloseBadMessage, "no hello in time")
		}
	})

	if _, ok := c.s.opts.Rooms.Get(c.roomID); !room.ValidID(c.roomID) || !ok {
		c.fail(protocol.CloseRoomNotFound, "room not found")
	} else {
		c.readLoop()
	}
	hello.Stop()
	c.fail(websocket.StatusNormalClosure, "") // no-op if already failing
	<-c.closeDone
	c.workers.Wait()
}

// fail starts closing the connection with code. It never blocks, so it is
// safe to call from Senders (under a room lock) and timers. The first call wins.
func (c *conn) fail(code websocket.StatusCode, reason string) {
	c.failOnce.Do(func() {
		close(c.done)
		go func() {
			c.leave()
			if code != websocket.StatusNormalClosure {
				c.log().Debug("closing connection", "code", int(code), "reason", reason)
			}
			_ = c.ws.Close(code, reason)
			close(c.closeDone)
		}()
	})
}

// leave removes the peer from its room (once) and notifies the media side.
func (c *conn) leave() {
	c.mu.Lock()
	if c.left {
		c.mu.Unlock()
		return
	}
	c.left = true
	joined, peerID := c.joined, c.peerID
	c.mu.Unlock()
	if joined {
		c.s.opts.Rooms.Leave(c.roomID, peerID)
		c.s.opts.Media.PeerLeft(c.roomID, peerID)
		c.s.opts.Log.Info("peer left", "room", c.roomID, "peer", peerID)
	}
}

// enqueue queues env for this peer without blocking. A full queue closes
// the connection.
func (c *conn) enqueue(env protocol.Envelope) error {
	b, err := json.Marshal(env)
	if err != nil {
		return err
	}
	select {
	case <-c.done:
		return errClosed
	default:
	}
	select {
	case c.out <- b:
		return nil
	default:
		c.fail(protocol.ClosePolicy, "send queue overflow")
		return errClosed
	}
}

func (c *conn) writer() {
	for {
		select {
		case <-c.done:
			return
		case b := <-c.out:
			ctx, cancel := context.WithTimeout(context.Background(), c.s.opts.WriteTimeout)
			err := c.ws.Write(ctx, websocket.MessageText, b)
			cancel()
			if err != nil {
				c.fail(protocol.ClosePolicy, "write failed")
				return
			}
		}
	}
}

func (c *conn) pinger() {
	t := time.NewTicker(c.s.opts.PingInterval)
	defer t.Stop()
	for {
		select {
		case <-c.done:
			return
		case <-t.C:
			ctx, cancel := context.WithTimeout(context.Background(), c.s.opts.PongTimeout)
			err := c.ws.Ping(ctx)
			cancel()
			if err != nil {
				c.fail(protocol.ClosePolicy, "pong timeout")
				return
			}
		}
	}
}

// readLoop reads messages until the connection fails or closes.
func (c *conn) readLoop() {
	for {
		// Never pass a cancellable ctx here: cancelling it would drop the
		// connection without our close code. fail() unblocks the read via Close.
		typ, rd, err := c.ws.Reader(context.Background())
		if err != nil {
			return
		}
		data, err := io.ReadAll(io.LimitReader(rd, protocol.MaxMessageBytes+1))
		if err != nil {
			return
		}
		if len(data) > protocol.MaxMessageBytes {
			c.fail(protocol.CloseBadMessage, "message too large")
			return
		}
		if ok, _ := c.limiter.Allow(time.Now()); !ok {
			c.fail(protocol.CloseRateLimited, "message rate exceeded")
			return
		}
		if typ != websocket.MessageText {
			c.fail(protocol.CloseBadMessage, "binary messages are not supported")
			return
		}
		var env protocol.Envelope
		if err := json.Unmarshal(data, &env); err != nil || env.Type == "" {
			c.fail(protocol.CloseBadMessage, "malformed message")
			return
		}
		if code, reason := c.handle(env); code != 0 {
			c.fail(code, reason)
			return
		}
	}
}

// handle processes one message; a non-zero code closes the connection.
func (c *conn) handle(env protocol.Envelope) (websocket.StatusCode, string) {
	c.mu.Lock()
	joined, peerID := c.joined, c.peerID
	c.mu.Unlock()

	if !joined {
		if env.Type != protocol.TypeHello {
			return protocol.CloseBadMessage, "expected hello"
		}
		return c.join(env)
	}

	env.From = peerID // never trust the client's From
	switch env.Type {
	case protocol.TypePeerState:
		var st protocol.PeerState
		if err := json.Unmarshal(env.Payload, &st); err != nil || st.Muted == nil {
			return protocol.CloseBadMessage, "invalid peer-state"
		}
		if err := c.s.opts.Rooms.SetMuted(c.roomID, peerID, *st.Muted); err != nil {
			return protocol.CloseBadMessage, "not in room"
		}
	case protocol.TypeMediaJoin, protocol.TypeOffer, protocol.TypeAnswer, protocol.TypeICECandidate:
		if env.To != "" && env.To != protocol.ToSFU {
			return protocol.CloseBadMessage, `media messages must be addressed to "sfu"`
		}
		env.To = protocol.ToSFU
		c.s.opts.Media.Signal(c.roomID, peerID, env)
	case protocol.TypeHello:
		return protocol.CloseBadMessage, "duplicate hello"
	default:
		return protocol.CloseBadMessage, "unknown message type"
	}
	return 0, ""
}

func (c *conn) join(env protocol.Envelope) (websocket.StatusCode, string) {
	var h protocol.Hello
	if err := json.Unmarshal(env.Payload, &h); err != nil {
		return protocol.CloseBadMessage, "invalid hello"
	}
	name, ok := SanitizeDisplayName(h.DisplayName)
	if !ok {
		return protocol.CloseBadMessage, "displayName must be 1-40 characters"
	}

	// Under c.mu so that leave() either sees the completed join or prevents it.
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.left {
		return 0, ""
	}
	peerID, err := c.s.opts.Rooms.Join(c.roomID, name, c.enqueue)
	switch {
	case errors.Is(err, room.ErrNotFound):
		return protocol.CloseRoomNotFound, "room not found"
	case errors.Is(err, room.ErrFull):
		return protocol.CloseRoomFull, "room is full"
	case err != nil:
		return protocol.ClosePolicy, "send queue overflow"
	}
	c.peerID, c.joined = peerID, true
	c.s.opts.Media.PeerJoined(c.roomID, peerID, c.enqueue)
	c.s.opts.Log.Info("peer joined", "room", c.roomID, "peer", peerID, "ip", c.ip)
	return 0, ""
}

// SanitizeDisplayName strips control and bidi-override characters, trims
// spaces and checks the length (1..40 runes).
func SanitizeDisplayName(s string) (string, bool) {
	s = strings.Map(func(r rune) rune {
		if unicode.IsControl(r) || (r >= 0x202A && r <= 0x202E) || (r >= 0x2066 && r <= 0x2069) {
			return -1
		}
		return r
	}, strings.ToValidUTF8(s, "�"))
	s = strings.TrimSpace(s)
	n := utf8.RuneCountInString(s)
	return s, n >= 1 && n <= MaxDisplayNameRunes
}
