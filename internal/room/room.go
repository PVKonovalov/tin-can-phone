// Package room is the in-memory room manager.
//
// Locking: the Manager lock guards the room map only; each room has its own
// lock. Outgoing messages are handed to Sender functions while the room lock
// is held, which keeps the per-room message order consistent for every peer
// (e.g. a newcomer always sees welcome before any later peer-state). Senders
// therefore must not block and must not call back into the Manager; the
// WebSocket layer implements them as a non-blocking push to a bounded queue.
// No lock is ever held while writing to a socket.
package room

import (
	"context"
	"crypto/rand"
	"encoding/base32"
	"errors"
	"strings"
	"sync"
	"time"

	"github.com/PVKonovalov/tin-can-phone/internal/protocol"
)

var (
	ErrNotFound     = errors.New("room not found")
	ErrFull         = errors.New("room is full")
	ErrTooManyRooms = errors.New("too many rooms")
	ErrNotInRoom    = errors.New("peer not in room")
)

// Sender delivers a message to one peer. It must not block and must not call
// back into the Manager.
type Sender func(protocol.Envelope) error

// MediaHandler receives media signaling for a peer and peer lifecycle events.
type MediaHandler interface {
	PeerJoined(roomID, peerID string, send func(protocol.Envelope) error)
	PeerLeft(roomID, peerID string)
	Signal(roomID, peerID string, msg protocol.Envelope) // offer / answer / ice-candidate
}

// Options configures a Manager.
type Options struct {
	MaxPeers int
	MaxRooms int
	TTL      time.Duration    // an empty room is removed after this
	Now      func() time.Time // defaults to time.Now
}

// Info is a snapshot of a room.
type Info struct {
	ID        string
	Peers     int
	MaxPeers  int
	CreatedAt time.Time
}

// PeerDetails is a snapshot of a peer.
type PeerDetails struct {
	protocol.PeerInfo
	ConnectedAt time.Time
}

type peer struct {
	info        protocol.PeerInfo
	connectedAt time.Time
	send        Sender
}

type room struct {
	id        string
	createdAt time.Time

	mu         sync.Mutex
	emptySince time.Time
	peers      map[string]*peer
	order      []string // join order
	closed     bool     // removed by the janitor
}

// Manager owns all rooms. Safe for concurrent use.
type Manager struct {
	opts Options

	mu    sync.RWMutex
	rooms map[string]*room
}

// NewManager returns a Manager.
func NewManager(opts Options) *Manager {
	if opts.Now == nil {
		opts.Now = time.Now
	}
	return &Manager{opts: opts, rooms: map[string]*room{}}
}

// MaxPeers returns the per-room participant limit.
func (m *Manager) MaxPeers() int { return m.opts.MaxPeers }

// Create makes a new, empty room.
func (m *Manager) Create() (Info, error) {
	now := m.opts.Now()
	m.mu.Lock()
	defer m.mu.Unlock()
	if len(m.rooms) >= m.opts.MaxRooms {
		return Info{}, ErrTooManyRooms
	}
	id := NewRoomID()
	for m.rooms[id] != nil { // 128 random bits: never in practice
		id = NewRoomID()
	}
	r := &room{id: id, createdAt: now, emptySince: now, peers: map[string]*peer{}}
	m.rooms[id] = r
	return Info{ID: id, MaxPeers: m.opts.MaxPeers, CreatedAt: now}, nil
}

// Get returns a snapshot of the room.
func (m *Manager) Get(id string) (Info, bool) {
	r := m.get(id)
	if r == nil {
		return Info{}, false
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed {
		return Info{}, false
	}
	return Info{ID: r.id, Peers: len(r.peers), MaxPeers: m.opts.MaxPeers, CreatedAt: r.createdAt}, true
}

// Peers returns the room's peers in join order.
func (m *Manager) Peers(id string) ([]PeerDetails, bool) {
	r := m.get(id)
	if r == nil {
		return nil, false
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]PeerDetails, 0, len(r.order))
	for _, pid := range r.order {
		p := r.peers[pid]
		out = append(out, PeerDetails{PeerInfo: p.info, ConnectedAt: p.connectedAt})
	}
	return out, !r.closed
}

// Len returns the number of rooms.
func (m *Manager) Len() int {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return len(m.rooms)
}

func (m *Manager) get(id string) *room {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.rooms[id]
}

// Join adds a peer with a server-assigned ID. It sends welcome to the new peer
// and peer-joined to everyone else before returning.
func (m *Manager) Join(roomID, displayName string, send Sender) (string, error) {
	r := m.get(roomID)
	if r == nil {
		return "", ErrNotFound
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed {
		return "", ErrNotFound
	}
	if len(r.peers) >= m.opts.MaxPeers {
		return "", ErrFull
	}
	id := NewPeerID()
	for r.peers[id] != nil || id == protocol.FromServer || id == protocol.ToSFU {
		id = NewPeerID()
	}
	others := make([]protocol.PeerInfo, 0, len(r.order))
	for _, pid := range r.order {
		others = append(others, r.peers[pid].info)
	}
	if err := send(protocol.New(protocol.TypeWelcome, protocol.FromServer, id, protocol.Welcome{
		PeerID: id, Peers: others, MaxPeers: m.opts.MaxPeers,
	})); err != nil {
		return "", err
	}
	p := &peer{
		info:        protocol.PeerInfo{PeerID: id, DisplayName: displayName},
		connectedAt: m.opts.Now(),
		send:        send,
	}
	r.broadcastLocked(id, protocol.New(protocol.TypePeerJoined, protocol.FromServer, "", p.info))
	r.peers[id] = p
	r.order = append(r.order, id)
	return id, nil
}

// Leave removes a peer and notifies the others. It reports whether the peer
// was in the room.
func (m *Manager) Leave(roomID, peerID string) bool {
	r := m.get(roomID)
	if r == nil {
		return false
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, ok := r.peers[peerID]; !ok {
		return false
	}
	delete(r.peers, peerID)
	for i, pid := range r.order {
		if pid == peerID {
			r.order = append(r.order[:i], r.order[i+1:]...)
			break
		}
	}
	if len(r.peers) == 0 {
		r.emptySince = m.opts.Now()
	}
	r.broadcastLocked(peerID, protocol.New(protocol.TypePeerLeft, protocol.FromServer, "", protocol.PeerLeft{PeerID: peerID}))
	return true
}

// SetMuted updates a peer's state and rebroadcasts it (From = peerID).
func (m *Manager) SetMuted(roomID, peerID string, muted bool) error {
	r := m.get(roomID)
	if r == nil {
		return ErrNotFound
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	p, ok := r.peers[peerID]
	if !ok {
		return ErrNotInRoom
	}
	p.info.Muted = muted
	r.broadcastLocked(peerID, protocol.New(protocol.TypePeerState, peerID, "", protocol.PeerState{Muted: &muted}))
	return nil
}

// broadcastLocked sends env to every peer except skip. Send errors are the
// sender's business (it closes its own connection).
func (r *room) broadcastLocked(skip string, env protocol.Envelope) {
	for _, pid := range r.order {
		if pid != skip {
			_ = r.peers[pid].send(env)
		}
	}
}

// Sweep removes rooms that have been empty for at least TTL and returns how
// many were removed.
func (m *Manager) Sweep() int {
	now := m.opts.Now()
	m.mu.Lock()
	defer m.mu.Unlock()
	n := 0
	for id, r := range m.rooms {
		r.mu.Lock()
		if len(r.peers) == 0 && now.Sub(r.emptySince) >= m.opts.TTL {
			r.closed = true
			delete(m.rooms, id)
			n++
		}
		r.mu.Unlock()
	}
	return n
}

// Run sweeps expired rooms until ctx is done.
func (m *Manager) Run(ctx context.Context) {
	every := min(max(m.opts.TTL/4, time.Second), time.Minute)
	t := time.NewTicker(every)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			m.Sweep()
		}
	}
}

var b32 = base32.StdEncoding.WithPadding(base32.NoPadding)

func randomID(nbytes int) string {
	b := make([]byte, nbytes)
	_, _ = rand.Read(b) // never fails
	return strings.ToLower(b32.EncodeToString(b))
}

// RoomIDLen is the length of a room ID: 128 bits in base32 without padding.
const RoomIDLen = 26

// NewRoomID returns 128 random bits as lowercase base32 without padding.
func NewRoomID() string { return randomID(16) }

// NewPeerID returns 64 random bits as lowercase base32 without padding.
func NewPeerID() string { return randomID(8) }

// ValidID reports whether id has the room ID format.
func ValidID(id string) bool {
	if len(id) != RoomIDLen {
		return false
	}
	for i := 0; i < len(id); i++ {
		c := id[i]
		if !(c >= 'a' && c <= 'z' || c >= '2' && c <= '7') {
			return false
		}
	}
	return true
}
