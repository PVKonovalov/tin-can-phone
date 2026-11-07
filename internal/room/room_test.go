package room

import (
	"encoding/json"
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/PVKonovalov/tin-can-phone/internal/protocol"
)

type clock struct {
	mu  sync.Mutex
	now time.Time
}

func (c *clock) Now() time.Time      { c.mu.Lock(); defer c.mu.Unlock(); return c.now }
func (c *clock) Add(d time.Duration) { c.mu.Lock(); c.now = c.now.Add(d); c.mu.Unlock() }

type inbox struct {
	mu   sync.Mutex
	msgs []protocol.Envelope
}

func (b *inbox) send(e protocol.Envelope) error {
	b.mu.Lock()
	b.msgs = append(b.msgs, e)
	b.mu.Unlock()
	return nil
}

func (b *inbox) types() []string {
	b.mu.Lock()
	defer b.mu.Unlock()
	var out []string
	for _, m := range b.msgs {
		out = append(out, m.Type)
	}
	return out
}

func newTestManager(c *clock) *Manager {
	return NewManager(Options{MaxPeers: 3, MaxRooms: 2, TTL: 10 * time.Minute, Now: c.Now})
}

func TestCreateLookupAndIDs(t *testing.T) {
	m := newTestManager(&clock{now: time.Unix(1000, 0)})
	a, err := m.Create()
	if err != nil {
		t.Fatal(err)
	}
	if !ValidID(a.ID) {
		t.Errorf("invalid id %q", a.ID)
	}
	info, ok := m.Get(a.ID)
	if !ok || info.Peers != 0 || info.MaxPeers != 3 {
		t.Errorf("Get: %+v %v", info, ok)
	}
	if _, ok := m.Get("nope"); ok {
		t.Error("found unknown room")
	}
	if _, err := m.Create(); err != nil {
		t.Fatal(err)
	}
	if _, err := m.Create(); !errors.Is(err, ErrTooManyRooms) {
		t.Errorf("MAX_ROOMS not enforced: %v", err)
	}

	for _, bad := range []string{"", "ABCDEFGHIJKLMNOPQRSTUVWXYZ", "abcdefghijklmnopqrstuvwxy1", "abcdefghijklmnopqrstuvwxy", a.ID + "a"} {
		if ValidID(bad) {
			t.Errorf("ValidID(%q)", bad)
		}
	}
	seen := map[string]bool{}
	for range 1000 {
		id := NewPeerID()
		if len(id) != 13 || seen[id] {
			t.Fatalf("peer id %q", id)
		}
		seen[id] = true
	}
}

func TestJoinLeaveNotifications(t *testing.T) {
	m := newTestManager(&clock{now: time.Unix(1000, 0)})
	r, _ := m.Create()
	var a, b, c, d inbox
	idA, err := m.Join(r.ID, "Alice", a.send)
	if err != nil {
		t.Fatal(err)
	}
	idB, _ := m.Join(r.ID, "Bob", b.send)
	if _, err := m.Join(r.ID, "Carol", c.send); err != nil {
		t.Fatal(err)
	}
	if _, err := m.Join(r.ID, "Dave", d.send); !errors.Is(err, ErrFull) {
		t.Errorf("MAX_PEERS not enforced: %v", err)
	}
	if len(d.msgs) != 0 {
		t.Error("rejected peer got messages")
	}

	// Bob's welcome lists Alice only.
	var w protocol.Welcome
	if err := json.Unmarshal(b.msgs[0].Payload, &w); err != nil {
		t.Fatal(err)
	}
	if b.msgs[0].Type != "welcome" || w.PeerID != idB || len(w.Peers) != 1 || w.Peers[0].DisplayName != "Alice" || w.MaxPeers != 3 {
		t.Errorf("welcome %+v", w)
	}
	if got := fmt.Sprint(a.types()); got != "[welcome peer-joined peer-joined]" {
		t.Errorf("alice got %s", got)
	}

	if err := m.SetMuted(r.ID, idA, true); err != nil {
		t.Fatal(err)
	}
	last := b.msgs[len(b.msgs)-1]
	if last.Type != "peer-state" || last.From != idA {
		t.Errorf("peer-state %+v", last)
	}
	if got := a.types(); got[len(got)-1] == "peer-state" {
		t.Error("sender got its own peer-state")
	}

	if !m.Leave(r.ID, idA) || m.Leave(r.ID, idA) {
		t.Error("Leave result")
	}
	last = b.msgs[len(b.msgs)-1]
	if last.Type != "peer-left" || string(last.Payload) != `{"peerId":"`+idA+`"}` {
		t.Errorf("peer-left %+v %s", last, last.Payload)
	}
	if err := m.SetMuted(r.ID, idA, false); !errors.Is(err, ErrNotInRoom) {
		t.Errorf("SetMuted after leave: %v", err)
	}

	// Late joiner sees muted state of existing peers.
	var e inbox
	m.SetMuted(r.ID, idB, true)
	m.Join(r.ID, "Eve", e.send)
	json.Unmarshal(e.msgs[0].Payload, &w)
	if len(w.Peers) != 2 || !w.Peers[0].Muted || w.Peers[0].PeerID != idB {
		t.Errorf("welcome peers %+v", w.Peers)
	}
}

func TestJoinUnknownRoom(t *testing.T) {
	m := newTestManager(&clock{now: time.Unix(1000, 0)})
	var a inbox
	if _, err := m.Join("aaaaaaaaaaaaaaaaaaaaaaaaaa", "x", a.send); !errors.Is(err, ErrNotFound) {
		t.Errorf("got %v", err)
	}
}

func TestTTL(t *testing.T) {
	c := &clock{now: time.Unix(1000, 0)}
	m := newTestManager(c)
	never, _ := m.Create() // never joined
	used, _ := m.Create()
	var a inbox
	id, _ := m.Join(used.ID, "A", a.send)

	c.Add(9 * time.Minute)
	if n := m.Sweep(); n != 0 {
		t.Fatalf("swept %d early", n)
	}
	m.Leave(used.ID, id) // empty since t+9m
	c.Add(time.Minute)
	if n := m.Sweep(); n != 1 {
		t.Fatalf("swept %d, want 1 (never-joined room)", n)
	}
	if _, ok := m.Get(never.ID); ok {
		t.Error("never-joined room kept")
	}
	if _, ok := m.Get(used.ID); !ok {
		t.Error("recently emptied room removed")
	}
	// Occupied rooms are never swept.
	m.Join(used.ID, "B", a.send)
	c.Add(time.Hour)
	if n := m.Sweep(); n != 0 {
		t.Error("occupied room swept")
	}
	if _, err := m.Join("x", "y", a.send); !errors.Is(err, ErrNotFound) {
		t.Error(err)
	}
	// Joining a swept room fails even with a stale pointer.
	r := m.get(used.ID)
	pid := ""
	for k := range r.peers {
		pid = k
	}
	m.Leave(used.ID, pid)
	c.Add(time.Hour)
	m.Sweep()
	if _, err := m.Join(used.ID, "late", a.send); !errors.Is(err, ErrNotFound) {
		t.Errorf("joined swept room: %v", err)
	}
	if !r.closed {
		t.Error("swept room not marked closed")
	}
}

func TestConcurrentJoinLeave(t *testing.T) {
	m := NewManager(Options{MaxPeers: 32, MaxRooms: 100, TTL: time.Minute})
	var rooms []string
	for range 4 {
		r, _ := m.Create()
		rooms = append(rooms, r.ID)
	}
	var wg sync.WaitGroup
	for i := range 64 {
		wg.Go(func() {
			rid := rooms[i%len(rooms)]
			for j := range 50 {
				var b inbox
				id, err := m.Join(rid, "p", b.send)
				if errors.Is(err, ErrFull) {
					continue
				}
				if err != nil {
					t.Error(err)
					return
				}
				_ = m.SetMuted(rid, id, j%2 == 0)
				m.Get(rid)
				m.Peers(rid)
				m.Leave(rid, id)
			}
		})
	}
	wg.Go(func() {
		for range 100 {
			m.Sweep()
		}
	})
	wg.Wait()
	for _, rid := range rooms {
		if info, ok := m.Get(rid); !ok || info.Peers != 0 {
			t.Errorf("room %s: %+v %v", rid, info, ok)
		}
	}
}

func TestUnavailableMedia(t *testing.T) {
	u := NewUnavailableMedia()
	var b inbox
	u.PeerJoined("r", "p", b.send)
	u.Signal("r", "p", protocol.Envelope{Type: "offer"})
	if len(b.msgs) != 1 || b.msgs[0].Type != "error" {
		t.Fatalf("got %+v", b.msgs)
	}
	var e protocol.Error
	json.Unmarshal(b.msgs[0].Payload, &e)
	if e.Code != "media-unavailable" {
		t.Errorf("code %q", e.Code)
	}
	u.PeerLeft("r", "p")
	u.Signal("r", "p", protocol.Envelope{Type: "offer"})
	if len(b.msgs) != 1 {
		t.Error("message after PeerLeft")
	}
}
