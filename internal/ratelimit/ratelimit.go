// Package ratelimit provides token-bucket rate limiters.
package ratelimit

import (
	"math"
	"sync"
	"time"
)

// Bucket is a token bucket. It is not safe for concurrent use.
type Bucket struct {
	rate   float64 // tokens per second
	burst  float64
	tokens float64
	last   time.Time
}

// NewBucket returns a full bucket refilling at rate tokens per second.
func NewBucket(rate float64, burst int, now time.Time) *Bucket {
	return &Bucket{rate: rate, burst: float64(burst), tokens: float64(burst), last: now}
}

// Allow takes one token if available. Otherwise it returns false and how long
// until a token becomes available.
func (b *Bucket) Allow(now time.Time) (bool, time.Duration) {
	if el := now.Sub(b.last).Seconds(); el > 0 {
		b.tokens = math.Min(b.burst, b.tokens+el*b.rate)
		b.last = now
	}
	if b.tokens >= 1 {
		b.tokens--
		return true, 0
	}
	wait := time.Duration((1 - b.tokens) / b.rate * float64(time.Second))
	return false, wait
}

func (b *Bucket) full(now time.Time) bool {
	return b.tokens+now.Sub(b.last).Seconds()*b.rate >= b.burst
}

// PerKey keeps one bucket per key (e.g. client IP). Safe for concurrent use.
// Buckets that have refilled completely are dropped periodically, so memory
// stays proportional to recently active keys.
type PerKey struct {
	rate  float64
	burst int
	now   func() time.Time

	mu        sync.Mutex
	buckets   map[string]*Bucket
	lastSweep time.Time
}

// NewPerKey returns a keyed limiter. now defaults to time.Now.
func NewPerKey(rate float64, burst int, now func() time.Time) *PerKey {
	if now == nil {
		now = time.Now
	}
	return &PerKey{rate: rate, burst: burst, now: now, buckets: map[string]*Bucket{}, lastSweep: now()}
}

// Allow takes a token from key's bucket.
func (p *PerKey) Allow(key string) (bool, time.Duration) {
	now := p.now()
	p.mu.Lock()
	defer p.mu.Unlock()
	if now.Sub(p.lastSweep) > time.Minute {
		for k, b := range p.buckets {
			if b.full(now) {
				delete(p.buckets, k)
			}
		}
		p.lastSweep = now
	}
	b, ok := p.buckets[key]
	if !ok {
		b = NewBucket(p.rate, p.burst, now)
		p.buckets[key] = b
	}
	return b.Allow(now)
}

// Len returns the number of tracked keys.
func (p *PerKey) Len() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return len(p.buckets)
}
