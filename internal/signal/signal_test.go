package signal

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/coder/websocket"

	"github.com/PVKonovalov/tin-can-phone/internal/protocol"
	"github.com/PVKonovalov/tin-can-phone/internal/room"
)

type env struct {
	t     *testing.T
	srv   *httptest.Server
	sig   *Server
	rooms *room.Manager
}

func newEnv(t *testing.T, maxPeers int, tweak func(*Options)) *env {
	t.Helper()
	rooms := room.NewManager(room.Options{MaxPeers: maxPeers, MaxRooms: 100, TTL: time.Hour})
	opts := Options{Rooms: rooms}
	if tweak != nil {
		tweak(&opts)
	}
	sig := New(opts)
	srv := httptest.NewServer(sig)
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		_ = sig.Shutdown(ctx)
		srv.Close()
	})
	return &env{t: t, srv: srv, sig: sig, rooms: rooms}
}

func (e *env) newRoom() string {
	info, err := e.rooms.Create()
	if err != nil {
		e.t.Fatal(err)
	}
	return info.ID
}

func (e *env) origin() string { return "https://" + strings.TrimPrefix(e.srv.URL, "http://") }

type client struct {
	t      *testing.T
	ws     *websocket.Conn
	peerID string
	msgs   chan protocol.Envelope
	closed chan websocket.StatusCode // close code seen by the reader (-1: no close frame)
}

func (e *env) dialRaw(roomID string, opts *websocket.DialOptions) (*websocket.Conn, *http.Response, error) {
	if opts == nil {
		opts = &websocket.DialOptions{}
	}
	if opts.HTTPHeader == nil {
		opts.HTTPHeader = http.Header{"Origin": {e.origin()}}
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	return websocket.Dial(ctx, strings.Replace(e.srv.URL, "http", "ws", 1)+"/ws?room="+roomID, opts)
}

// dial connects and starts a background reader collecting messages.
func (e *env) dial(roomID string) *client {
	e.t.Helper()
	ws, _, err := e.dialRaw(roomID, nil)
	if err != nil {
		e.t.Fatalf("dial: %v", err)
	}
	ws.SetReadLimit(1 << 20)
	c := &client{t: e.t, ws: ws, msgs: make(chan protocol.Envelope, 1024), closed: make(chan websocket.StatusCode, 1)}
	go func() {
		for {
			_, data, err := ws.Read(context.Background())
			if err != nil {
				c.closed <- websocket.CloseStatus(err)
				close(c.msgs)
				return
			}
			var m protocol.Envelope
			if err := json.Unmarshal(data, &m); err != nil {
				e.t.Errorf("bad server message %q", data)
			}
			c.msgs <- m
		}
	}()
	e.t.Cleanup(func() { _ = ws.CloseNow() })
	return c
}

// join dials and completes hello/welcome.
func (e *env) join(roomID, name string) (*client, protocol.Welcome) {
	e.t.Helper()
	c := e.dial(roomID)
	c.send(map[string]any{"type": "hello", "payload": map[string]any{"displayName": name}})
	m := c.expect("welcome")
	var w protocol.Welcome
	if err := json.Unmarshal(m.Payload, &w); err != nil {
		e.t.Fatal(err)
	}
	c.peerID = w.PeerID
	return c, w
}

func (c *client) send(v any) {
	c.t.Helper()
	b, _ := json.Marshal(v)
	c.sendRaw(websocket.MessageText, b)
}

func (c *client) sendRaw(typ websocket.MessageType, b []byte) {
	c.t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := c.ws.Write(ctx, typ, b); err != nil {
		c.t.Fatalf("write: %v", err)
	}
}

func (c *client) next(timeout time.Duration) (protocol.Envelope, bool) {
	select {
	case m, ok := <-c.msgs:
		return m, ok
	case <-time.After(timeout):
		return protocol.Envelope{}, false
	}
}

func (c *client) expect(typ string) protocol.Envelope {
	c.t.Helper()
	m, ok := c.next(3 * time.Second)
	if !ok {
		c.t.Fatalf("expected %s, got nothing", typ)
	}
	if m.Type != typ {
		c.t.Fatalf("expected %s, got %s %s", typ, m.Type, m.Payload)
	}
	return m
}

func (c *client) expectNothing(d time.Duration) {
	c.t.Helper()
	if m, ok := c.next(d); ok {
		c.t.Fatalf("unexpected message %s %s", m.Type, m.Payload)
	}
}

func (c *client) expectClose(code websocket.StatusCode) {
	c.t.Helper()
	deadline := time.After(8 * time.Second)
	for {
		select {
		case <-c.msgs:
		case got := <-c.closed:
			if got != code {
				c.t.Fatalf("close code %d, want %d", got, code)
			}
			return
		case <-deadline:
			c.t.Fatalf("connection not closed (want %d)", code)
		}
	}
}

func TestWelcomeJoinedLeft(t *testing.T) {
	e := newEnv(t, 8, nil)
	rid := e.newRoom()
	a, wa := e.join(rid, "Alice")
	if len(wa.Peers) != 0 || wa.MaxPeers != 8 || wa.PeerID == "" {
		t.Errorf("first welcome %+v", wa)
	}
	b, wb := e.join(rid, "  Bob\u0007‮ ")
	if len(wb.Peers) != 1 || wb.Peers[0].PeerID != a.peerID || wb.Peers[0].DisplayName != "Alice" {
		t.Errorf("second welcome %+v", wb)
	}
	m := a.expect("peer-joined")
	var pj protocol.PeerInfo
	json.Unmarshal(m.Payload, &pj)
	if pj.PeerID != b.peerID || pj.DisplayName != "Bob" || m.From != "server" {
		t.Errorf("peer-joined %+v from %q", pj, m.From)
	}
	c, wc := e.join(rid, "Carol")
	if len(wc.Peers) != 2 {
		t.Errorf("third welcome %+v", wc)
	}
	a.expect("peer-joined")
	b.expect("peer-joined")

	// Clean close.
	b.ws.Close(websocket.StatusNormalClosure, "bye")
	for _, x := range []*client{a, c} {
		m := x.expect("peer-left")
		if string(m.Payload) != `{"peerId":"`+b.peerID+`"}` {
			t.Errorf("peer-left %s", m.Payload)
		}
	}
	// Abrupt drop (no close frame).
	c.ws.CloseNow()
	m = a.expect("peer-left")
	if !strings.Contains(string(m.Payload), c.peerID) {
		t.Errorf("peer-left %s", m.Payload)
	}
	waitFor(t, func() bool { info, _ := e.rooms.Get(rid); return info.Peers == 1 })
}

func TestPeerStateAndSpoofedFrom(t *testing.T) {
	e := newEnv(t, 8, nil)
	rid := e.newRoom()
	a, _ := e.join(rid, "A")
	b, _ := e.join(rid, "B")
	a.expect("peer-joined")

	a.send(map[string]any{"type": "peer-state", "from": b.peerID, "to": "x", "payload": map[string]any{"muted": true}})
	m := b.expect("peer-state")
	if m.From != a.peerID || string(m.Payload) != `{"muted":true}` {
		t.Errorf("peer-state %+v %s", m, m.Payload)
	}
	a.expectNothing(200 * time.Millisecond) // not echoed to the sender

	// Newcomer sees the muted flag.
	_, wc := e.join(rid, "C")
	if !wc.Peers[0].Muted || wc.Peers[1].Muted {
		t.Errorf("welcome peers %+v", wc.Peers)
	}
}

func TestMediaStub(t *testing.T) {
	e := newEnv(t, 8, nil)
	rid := e.newRoom()
	a, _ := e.join(rid, "A")
	for _, typ := range []string{"offer", "answer", "ice-candidate"} {
		a.send(map[string]any{"type": typ, "to": "sfu", "payload": map[string]any{"sdp": "x"}})
		m := a.expect("error")
		var pe protocol.Error
		json.Unmarshal(m.Payload, &pe)
		if pe.Code != "media-unavailable" || m.From != "server" {
			t.Errorf("%s: %+v", typ, pe)
		}
	}
}

type recordingMedia struct {
	mu     sync.Mutex
	events []string
}

func (r *recordingMedia) add(s string) { r.mu.Lock(); r.events = append(r.events, s); r.mu.Unlock() }
func (r *recordingMedia) PeerJoined(roomID, peerID string, send func(protocol.Envelope) error) {
	r.add("joined " + peerID)
}
func (r *recordingMedia) PeerLeft(roomID, peerID string) { r.add("left " + peerID) }
func (r *recordingMedia) Signal(roomID, peerID string, msg protocol.Envelope) {
	r.add(fmt.Sprintf("signal %s %s from=%s to=%s", peerID, msg.Type, msg.From, msg.To))
}
func (r *recordingMedia) list() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]string(nil), r.events...)
}

func TestMediaHandlerContract(t *testing.T) {
	media := &recordingMedia{}
	e := newEnv(t, 8, func(o *Options) { o.Media = media })
	rid := e.newRoom()
	a, _ := e.join(rid, "A")
	a.send(map[string]any{"type": "offer", "from": "spoof", "payload": map[string]any{"sdp": "x"}})
	a.ws.Close(websocket.StatusNormalClosure, "")
	want := []string{"joined " + a.peerID, "signal " + a.peerID + " offer from=" + a.peerID + " to=sfu", "left " + a.peerID}
	waitFor(t, func() bool { return len(media.list()) == 3 })
	if got := media.list(); fmt.Sprint(got) != fmt.Sprint(want) {
		t.Errorf("events %v, want %v", got, want)
	}
}

func TestCloseCodes(t *testing.T) {
	e := newEnv(t, 2, func(o *Options) { o.HelloTimeout = 300 * time.Millisecond })
	rid := e.newRoom()

	t.Run("unknown room", func(t *testing.T) {
		e.dial("aaaaaaaaaaaaaaaaaaaaaaaaaa").expectClose(protocol.CloseRoomNotFound)
		e.dial("not-an-id").expectClose(protocol.CloseRoomNotFound)
	})
	t.Run("full room", func(t *testing.T) {
		e.join(rid, "1")
		e.join(rid, "2")
		c := e.dial(rid)
		c.send(map[string]any{"type": "hello", "payload": map[string]any{"displayName": "3"}})
		c.expectClose(protocol.CloseRoomFull)
	})
	other := e.newRoom()
	cases := []struct {
		name string
		msgs [][]byte
		typ  websocket.MessageType
	}{
		{"no hello", nil, websocket.MessageText},
		{"garbage", [][]byte{[]byte("{not json")}, websocket.MessageText},
		{"no type", [][]byte{[]byte(`{"payload":{}}`)}, websocket.MessageText},
		{"binary", [][]byte{[]byte(`{"type":"hello"}`)}, websocket.MessageBinary},
		{"oversized", [][]byte{[]byte(`{"type":"hello","payload":{"displayName":"` + strings.Repeat("x", protocol.MaxMessageBytes) + `"}}`)}, websocket.MessageText},
		{"message before hello", [][]byte{[]byte(`{"type":"peer-state","payload":{"muted":true}}`)}, websocket.MessageText},
		{"empty name", [][]byte{[]byte(`{"type":"hello","payload":{"displayName":" \u0000 "}}`)}, websocket.MessageText},
		{"long name", [][]byte{[]byte(`{"type":"hello","payload":{"displayName":"` + strings.Repeat("é", 41) + `"}}`)}, websocket.MessageText},
		{"unknown type after hello", [][]byte{[]byte(`{"type":"hello","payload":{"displayName":"x"}}`), []byte(`{"type":"dance"}`)}, websocket.MessageText},
		{"bad peer-state", [][]byte{[]byte(`{"type":"hello","payload":{"displayName":"x"}}`), []byte(`{"type":"peer-state","payload":{}}`)}, websocket.MessageText},
		{"duplicate hello", [][]byte{[]byte(`{"type":"hello","payload":{"displayName":"x"}}`), []byte(`{"type":"hello","payload":{"displayName":"x"}}`)}, websocket.MessageText},
		{"media to a peer", [][]byte{[]byte(`{"type":"hello","payload":{"displayName":"x"}}`), []byte(`{"type":"offer","to":"someone"}`)}, websocket.MessageText},
	}
	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			c := e.dial(other)
			for _, m := range tt.msgs {
				c.sendRaw(tt.typ, m)
			}
			c.expectClose(protocol.CloseBadMessage)
		})
	}
	waitFor(t, func() bool { info, _ := e.rooms.Get(other); return info.Peers == 0 })
}

func TestFloodRateLimited(t *testing.T) {
	e := newEnv(t, 8, nil)
	rid := e.newRoom()
	a, _ := e.join(rid, "A")
	b, _ := e.join(rid, "B")
	for i := range DefaultMsgBurst + 50 {
		if err := a.ws.Write(context.Background(), websocket.MessageText, []byte(fmt.Sprintf(`{"type":"peer-state","payload":{"muted":%v}}`, i%2 == 0))); err != nil {
			break // server may already have closed
		}
	}
	a.expectClose(protocol.CloseRateLimited)
	deadline := time.After(5 * time.Second)
	for {
		select {
		case m := <-b.msgs:
			if m.Type == "peer-left" {
				return
			}
		case <-deadline:
			t.Fatal("no peer-left after flood")
		}
	}
}

func TestBadOrigin(t *testing.T) {
	e := newEnv(t, 8, nil)
	rid := e.newRoom()
	for _, origin := range []string{"https://evil.example.com", "", "http://" + strings.TrimPrefix(e.srv.URL, "http://"), "null"} {
		h := http.Header{}
		if origin != "" {
			h.Set("Origin", origin)
		}
		_, resp, err := e.dialRaw(rid, &websocket.DialOptions{HTTPHeader: h})
		if err == nil || resp == nil || resp.StatusCode != http.StatusForbidden {
			t.Errorf("origin %q: err=%v resp=%v", origin, err, resp)
		}
	}

	// Explicit allow-list.
	e2 := newEnv(t, 8, func(o *Options) { o.AllowedOrigins = []string{"https://call.example.com"} })
	rid2 := e2.newRoom()
	if _, resp, err := e2.dialRaw(rid2, nil); err == nil || resp.StatusCode != 403 {
		t.Error("same-host origin accepted although not in allow-list")
	}
	ws, _, err := e2.dialRaw(rid2, &websocket.DialOptions{HTTPHeader: http.Header{"Origin": {"https://CALL.example.com:443"}}})
	if err != nil {
		t.Fatalf("allowed origin rejected: %v", err)
	}
	ws.CloseNow()
}

// stalledDialer gives the client a tiny receive buffer so the server's
// writes back up quickly when the client stops reading.
func stalledDialer() *http.Client {
	d := &net.Dialer{}
	return &http.Client{Transport: &http.Transport{DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
		c, err := d.DialContext(ctx, network, addr)
		if err == nil {
			c.(*net.TCPConn).SetReadBuffer(1024)
		}
		return c, err
	}}}
}

func TestSlowConsumerDoesNotStallRoom(t *testing.T) {
	e := newEnv(t, 8, func(o *Options) {
		o.MsgRate, o.MsgBurst = 1e6, 1e6
		o.WriteTimeout = time.Second
		o.QueueSize = 16
	})
	rid := e.newRoom()
	a, _ := e.join(rid, "A")
	b, _ := e.join(rid, "B")
	a.expect("peer-joined")

	// The stalled peer completes hello, then never reads again.
	ws, _, err := e.dialRaw(rid, &websocket.DialOptions{HTTPClient: stalledDialer(), HTTPHeader: http.Header{"Origin": {e.origin()}}})
	if err != nil {
		t.Fatal(err)
	}
	defer ws.CloseNow()
	ws.Write(context.Background(), websocket.MessageText, []byte(`{"type":"hello","payload":{"displayName":"slow"}}`))
	slowID := ""
	for _, x := range []*client{a, b} {
		var pj protocol.PeerInfo
		json.Unmarshal(x.expect("peer-joined").Payload, &pj)
		slowID = pj.PeerID
	}

	// It floods media messages; every one triggers an error reply it never reads.
	go func() {
		msg := []byte(`{"type":"offer","to":"sfu","payload":{}}`)
		for range 50000 {
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			err := ws.Write(ctx, websocket.MessageText, msg)
			cancel()
			if err != nil {
				return
			}
		}
	}()

	// Meanwhile A and B keep talking without delay, and eventually see the slow peer leave.
	deadline := time.After(10 * time.Second)
	muted := false
	for {
		muted = !muted
		start := time.Now()
		a.send(map[string]any{"type": "peer-state", "payload": map[string]any{"muted": muted}})
	wait:
		for {
			select {
			case m, ok := <-b.msgs:
				if !ok {
					t.Fatal("B disconnected")
				}
				if m.Type == "peer-left" && strings.Contains(string(m.Payload), slowID) {
					return // success
				}
				if m.Type == "peer-state" {
					if d := time.Since(start); d > time.Second {
						t.Fatalf("peer-state took %v: room stalled", d)
					}
					break wait
				}
			case <-deadline:
				t.Fatal("slow peer was never removed")
			}
		}
		time.Sleep(20 * time.Millisecond)
	}
}

func TestShutdownClosesWith1001(t *testing.T) {
	e := newEnv(t, 8, nil)
	rid := e.newRoom()
	a, _ := e.join(rid, "A")
	pre := e.dial(rid) // connected, no hello yet
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := e.sig.Shutdown(ctx); err != nil {
		t.Fatalf("Shutdown: %v", err)
	}
	a.expectClose(websocket.StatusGoingAway)
	pre.expectClose(websocket.StatusGoingAway)
	if _, resp, err := e.dialRaw(rid, nil); err == nil || resp.StatusCode != http.StatusServiceUnavailable {
		t.Errorf("new connection during shutdown: %v %v", err, resp)
	}
}

func TestPingTimeoutClosesDeadPeer(t *testing.T) {
	e := newEnv(t, 8, func(o *Options) { o.PingInterval, o.PongTimeout = 100*time.Millisecond, 200*time.Millisecond })
	rid := e.newRoom()
	a, _ := e.join(rid, "A")
	// A client that never reads cannot answer pings.
	ws, _, err := e.dialRaw(rid, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer ws.CloseNow()
	ws.Write(context.Background(), websocket.MessageText, []byte(`{"type":"hello","payload":{"displayName":"mute"}}`))
	a.expect("peer-joined")
	// A keeps reading (its reader answers pings) and must stay connected.
	m := a.expect("peer-left")
	if m.Type != "peer-left" {
		t.Fatal(m)
	}
	a.send(map[string]any{"type": "peer-state", "payload": map[string]any{"muted": true}})
	a.expectNothing(400 * time.Millisecond)
	if info, _ := e.rooms.Get(rid); info.Peers != 1 {
		t.Errorf("peers %d", info.Peers)
	}
}

func TestSanitizeDisplayName(t *testing.T) {
	for in, want := range map[string]string{
		"  Ann  ":               "Ann",
		"A\u0000B\tC\nD":        "ABCD",
		"‮evil‬":                "evil",
		"Ünïcødé 名前":            "Ünïcødé 名前",
		"\xff\xfe":              "�",
		strings.Repeat("я", 40): strings.Repeat("я", 40),
	} {
		got, ok := SanitizeDisplayName(in)
		if !ok || got != want {
			t.Errorf("%q → %q %v, want %q", in, got, ok, want)
		}
	}
	for _, bad := range []string{"", "   ", "\u0001\u0002", strings.Repeat("я", 41)} {
		if _, ok := SanitizeDisplayName(bad); ok {
			t.Errorf("%q accepted", bad)
		}
	}
}

func waitFor(t *testing.T, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatal("condition not met")
		}
		time.Sleep(10 * time.Millisecond)
	}
}
