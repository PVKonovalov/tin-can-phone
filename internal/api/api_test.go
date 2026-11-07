package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/PVKonovalov/tin-can-phone/internal/ratelimit"
	"github.com/PVKonovalov/tin-can-phone/internal/room"
)

func newAPI(publicURL string, maxRooms int) (http.Handler, *room.Manager) {
	m := room.NewManager(room.Options{MaxPeers: 8, MaxRooms: maxRooms, TTL: time.Minute})
	return New(Options{Rooms: m, PublicURL: publicURL}), m
}

func do(h http.Handler, method, url, remote string) (*httptest.ResponseRecorder, map[string]any) {
	req := httptest.NewRequest(method, url, nil)
	if remote != "" {
		req.RemoteAddr = remote
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	var body map[string]any
	_ = json.Unmarshal(rec.Body.Bytes(), &body)
	return rec, body
}

func TestCreateAndGet(t *testing.T) {
	for _, tt := range []struct{ public, reqURL, wantPrefix string }{
		{"", "https://192.168.1.10:8443/api/rooms", "https://192.168.1.10:8443/room/"},
		{"https://call.example.com", "https://10.0.0.5:8443/api/rooms", "https://call.example.com/room/"},
	} {
		h, _ := newAPI(tt.public, 10)
		rec, body := do(h, "POST", tt.reqURL, "")
		if rec.Code != http.StatusCreated {
			t.Fatalf("status %d %v", rec.Code, body)
		}
		if ct := rec.Header().Get("Content-Type"); ct != "application/json" {
			t.Errorf("content type %q", ct)
		}
		id, _ := body["roomId"].(string)
		if !room.ValidID(id) {
			t.Errorf("roomId %q", id)
		}
		if body["url"] != tt.wantPrefix+id {
			t.Errorf("url %v, want %s%s", body["url"], tt.wantPrefix, id)
		}

		rec, body = do(h, "GET", "/api/rooms/"+id, "")
		if rec.Code != 200 || body["roomId"] != id || body["peers"] != 0.0 || body["maxPeers"] != 8.0 {
			t.Errorf("get: %d %v", rec.Code, body)
		}
	}
}

func TestGetErrors(t *testing.T) {
	h, _ := newAPI("", 10)
	for _, url := range []string{"/api/rooms/aaaaaaaaaaaaaaaaaaaaaaaaaa", "/api/rooms/NOT-VALID", "/api/rooms/x%2F..", "/api/other"} {
		rec, body := do(h, "GET", url, "")
		if rec.Code != 404 {
			t.Errorf("%s: %d", url, rec.Code)
		}
		if body["error"] == "" || body["message"] == "" {
			t.Errorf("%s: error body %v", url, body)
		}
	}
	rec, body := do(h, "DELETE", "/api/rooms", "")
	if rec.Code != http.StatusNotFound || body["error"] != "not-found" {
		t.Errorf("DELETE: %d %v", rec.Code, body)
	}
}

func TestCreateRateLimit(t *testing.T) {
	h, _ := newAPI("", 100)
	for i := range CreateBurst {
		if rec, _ := do(h, "POST", "/api/rooms", "10.0.0.1:1234"); rec.Code != 201 {
			t.Fatalf("request %d: %d", i, rec.Code)
		}
	}
	rec, body := do(h, "POST", "/api/rooms", "10.0.0.1:5555")
	if rec.Code != http.StatusTooManyRequests || body["error"] != "rate-limited" {
		t.Fatalf("got %d %v", rec.Code, body)
	}
	if ra := rec.Header().Get("Retry-After"); ra == "" || ra == "0" {
		t.Errorf("Retry-After %q", ra)
	}
	// Another IP is unaffected.
	if rec, _ := do(h, "POST", "/api/rooms", "10.0.0.2:1"); rec.Code != 201 {
		t.Errorf("other IP: %d", rec.Code)
	}
}

func TestMaxRooms(t *testing.T) {
	m := room.NewManager(room.Options{MaxPeers: 8, MaxRooms: 2, TTL: time.Minute})
	h := New(Options{Rooms: m, Limiter: ratelimit.NewPerKey(1000, 1000, nil)})
	do(h, "POST", "/api/rooms", "")
	do(h, "POST", "/api/rooms", "")
	rec, body := do(h, "POST", "/api/rooms", "")
	if rec.Code != http.StatusServiceUnavailable || !strings.Contains(body["error"].(string), "too-many") {
		t.Errorf("got %d %v", rec.Code, body)
	}
}
