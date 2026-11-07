package ratelimit

import (
	"testing"
	"time"
)

func TestBucket(t *testing.T) {
	now := time.Unix(1000, 0)
	b := NewBucket(1, 3, now) // 1/s, burst 3
	for i := range 3 {
		if ok, _ := b.Allow(now); !ok {
			t.Fatalf("token %d denied", i)
		}
	}
	ok, wait := b.Allow(now)
	if ok || wait != time.Second {
		t.Fatalf("got %v %v", ok, wait)
	}
	if ok, _ := b.Allow(now.Add(500 * time.Millisecond)); ok {
		t.Fatal("allowed after half a token")
	}
	if ok, _ := b.Allow(now.Add(1100 * time.Millisecond)); !ok {
		t.Fatal("denied after refill")
	}
	// Refill never exceeds burst.
	later := now.Add(time.Hour)
	for range 3 {
		b.Allow(later)
	}
	if ok, _ := b.Allow(later); ok {
		t.Fatal("burst exceeded")
	}
}

func TestPerKey(t *testing.T) {
	now := time.Unix(1000, 0)
	p := NewPerKey(10.0/60, 2, func() time.Time { return now })
	p.Allow("a")
	p.Allow("a")
	if ok, wait := p.Allow("a"); ok || wait <= 0 || wait > 6*time.Second {
		t.Fatalf("a: %v %v", ok, wait)
	}
	if ok, _ := p.Allow("b"); !ok {
		t.Fatal("keys not independent")
	}
	now = now.Add(2 * time.Minute) // everything refilled → swept
	p.Allow("c")
	if p.Len() != 1 {
		t.Errorf("stale keys kept: %d", p.Len())
	}
}
