package httpserver_test

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/coder/websocket"

	"github.com/PVKonovalov/tin-can-phone/internal/protocol"
)

func (r *running) createRoom(t *testing.T) (id, url string) {
	t.Helper()
	resp, err := r.client.Post(r.httpsURL+"/api/rooms", "", nil)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("create: %d", resp.StatusCode)
	}
	var body struct{ RoomID, URL string }
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		t.Fatal(err)
	}
	return body.RoomID, body.URL
}

func (r *running) dialWS(t *testing.T, roomID string) *websocket.Conn {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	ws, _, err := websocket.Dial(ctx, strings.Replace(r.httpsURL, "https", "wss", 1)+"/ws?room="+roomID, &websocket.DialOptions{
		HTTPClient: &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: r.roots}}},
		HTTPHeader: http.Header{"Origin": {r.httpsURL}},
	})
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	t.Cleanup(func() { ws.CloseNow() })
	return ws
}

func readEnv(t *testing.T, ws *websocket.Conn) protocol.Envelope {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_, data, err := ws.Read(ctx)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	var e protocol.Envelope
	if err := json.Unmarshal(data, &e); err != nil {
		t.Fatal(err)
	}
	return e
}

func write(t *testing.T, ws *websocket.Conn, s string) {
	t.Helper()
	if err := ws.Write(context.Background(), websocket.MessageText, []byte(s)); err != nil {
		t.Fatal(err)
	}
}

func TestRoomPagesAndAPI(t *testing.T) {
	s := start(t, selfCAConfig(t), nil)
	id, url := s.createRoom(t)
	if url != s.httpsURL+"/room/"+id {
		t.Errorf("url %q", url)
	}
	resp, body := s.get(t, s.httpsURL+"/api/rooms/"+id)
	if resp.StatusCode != 200 || !strings.Contains(body, `"peers":0`) {
		t.Errorf("lookup: %d %s", resp.StatusCode, body)
	}
	if resp.Header.Get("Content-Security-Policy") == "" {
		t.Error("API responses lack security headers")
	}
	resp, body = s.get(t, s.httpsURL+"/room/"+id)
	if resp.StatusCode != 200 || !strings.Contains(body, "tin-can-phone") {
		t.Errorf("/room/{id}: %d", resp.StatusCode)
	}
	for _, bad := range []string{"/room/short", "/room/" + strings.ToUpper(id), "/room/"} {
		if resp, _ := s.get(t, s.httpsURL+bad); resp.StatusCode != 404 {
			t.Errorf("%s: %d", bad, resp.StatusCode)
		}
	}
}

func TestPublicURLInRoomLink(t *testing.T) {
	cfg := selfCAConfig(t)
	cfg.PublicURL = "https://call.example.com"
	s := start(t, cfg, nil)
	id, url := s.createRoom(t)
	if url != "https://call.example.com/room/"+id {
		t.Errorf("url %q", url)
	}
}

// The http.Server Read/WriteTimeout deadlines must not kill WebSockets.
func TestWebSocketOutlivesServerTimeouts(t *testing.T) {
	s := start(t, selfCAConfig(t), nil, func(srv *http.Server) {
		srv.ReadTimeout, srv.WriteTimeout = 300*time.Millisecond, 300*time.Millisecond
	})
	id, _ := s.createRoom(t)
	a := s.dialWS(t, id)
	write(t, a, `{"type":"hello","payload":{"displayName":"A"}}`)
	if e := readEnv(t, a); e.Type != "welcome" {
		t.Fatalf("got %s", e.Type)
	}
	time.Sleep(time.Second)
	b := s.dialWS(t, id)
	write(t, b, `{"type":"hello","payload":{"displayName":"B"}}`)
	readEnv(t, b)
	if e := readEnv(t, a); e.Type != "peer-joined" {
		t.Fatalf("A got %s after idle period", e.Type)
	}
	write(t, a, `{"type":"peer-state","payload":{"muted":true}}`)
	if e := readEnv(t, b); e.Type != "peer-state" {
		t.Fatalf("B got %s", e.Type)
	}
}

func TestShutdownClosesWebSockets(t *testing.T) {
	s := start(t, selfCAConfig(t), nil)
	id, _ := s.createRoom(t)
	a := s.dialWS(t, id)
	write(t, a, `{"type":"hello","payload":{"displayName":"A"}}`)
	readEnv(t, a)
	s.cancel() // triggers graceful shutdown; cleanup waits for Run to return
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_, _, err := a.Read(ctx)
	if websocket.CloseStatus(err) != websocket.StatusGoingAway {
		t.Fatalf("got %v, want close 1001", err)
	}
}
