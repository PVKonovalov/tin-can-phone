// Package api implements the REST endpoints under /api/.
package api

import (
	"encoding/json"
	"errors"
	"log/slog"
	"math"
	"net"
	"net/http"
	"strconv"

	"github.com/PVKonovalov/tin-can-phone/internal/ratelimit"
	"github.com/PVKonovalov/tin-can-phone/internal/room"
)

// Room creation limit per client IP.
const (
	CreateRatePerMinute = 10
	CreateBurst         = 5
)

// Options configures the API handler.
type Options struct {
	Rooms     *room.Manager
	PublicURL string            // base for room URLs; request Host is used when empty
	Limiter   *ratelimit.PerKey // room creation limiter; defaults to 10/min, burst 5 per IP
	Log       *slog.Logger
}

type handler struct{ Options }

// New returns the /api/ handler.
func New(opts Options) http.Handler {
	if opts.Limiter == nil {
		opts.Limiter = ratelimit.NewPerKey(CreateRatePerMinute/60.0, CreateBurst, nil)
	}
	if opts.Log == nil {
		opts.Log = slog.New(slog.DiscardHandler)
	}
	h := &handler{opts}
	mux := http.NewServeMux()
	mux.HandleFunc("POST /api/rooms", h.create)
	mux.HandleFunc("GET /api/rooms/{id}", h.get)
	mux.HandleFunc("/api/", func(w http.ResponseWriter, r *http.Request) {
		WriteError(w, http.StatusNotFound, "not-found", "no such endpoint")
	})
	return mux
}

type createResponse struct {
	RoomID string `json:"roomId"`
	URL    string `json:"url"`
}

type roomResponse struct {
	RoomID   string `json:"roomId"`
	Peers    int    `json:"peers"`
	MaxPeers int    `json:"maxPeers"`
}

func (h *handler) create(w http.ResponseWriter, r *http.Request) {
	if ok, wait := h.Limiter.Allow(ClientIP(r)); !ok {
		w.Header().Set("Retry-After", strconv.Itoa(int(math.Ceil(wait.Seconds()))))
		WriteError(w, http.StatusTooManyRequests, "rate-limited", "too many rooms created, try again later")
		return
	}
	info, err := h.Rooms.Create()
	if errors.Is(err, room.ErrTooManyRooms) {
		WriteError(w, http.StatusServiceUnavailable, "too-many-rooms", "the server has reached its room limit")
		return
	}
	if err != nil {
		WriteError(w, http.StatusInternalServerError, "internal", "could not create room")
		return
	}
	base := h.PublicURL
	if base == "" {
		base = "https://" + r.Host
	}
	h.Log.Info("room created", "room", info.ID, "ip", ClientIP(r))
	writeJSON(w, http.StatusCreated, createResponse{RoomID: info.ID, URL: base + "/room/" + info.ID})
}

func (h *handler) get(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	info, ok := h.Rooms.Get(id)
	if !room.ValidID(id) || !ok {
		WriteError(w, http.StatusNotFound, "room-not-found", "room does not exist or has expired")
		return
	}
	writeJSON(w, http.StatusOK, roomResponse{RoomID: info.ID, Peers: info.Peers, MaxPeers: info.MaxPeers})
}

// ClientIP returns the remote IP of the connection. Proxy headers are not
// trusted: the server is meant to face clients directly.
func ClientIP(r *http.Request) string {
	if h, _, err := net.SplitHostPort(r.RemoteAddr); err == nil {
		return h
	}
	return r.RemoteAddr
}

// WriteError writes {"error": code, "message": message}.
func WriteError(w http.ResponseWriter, status int, code, message string) {
	writeJSON(w, status, map[string]string{"error": code, "message": message})
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}
