package server

import (
	"sync"
	"time"
)

// RatePolicy is a fixed-window policy. Buckets expire naturally and cleanup
// prevents unauthenticated traffic from consuming unbounded memory.
type RatePolicy struct {
	Limit  int
	Window time.Duration
}

type rateBucket struct {
	Count       int
	WindowStart time.Time
	LastSeen    time.Time
}

type rateLimiter struct {
	mu      sync.Mutex
	buckets map[string]rateBucket
	now     func() time.Time
}

const maxRateLimitBuckets = 10000

func newRateLimiter(now func() time.Time) *rateLimiter {
	if now == nil {
		now = time.Now
	}
	return &rateLimiter{buckets: make(map[string]rateBucket), now: now}
}

// Allow consumes one attempt and reports the remaining wait when limited.
func (l *rateLimiter) Allow(key string, policy RatePolicy) (bool, time.Duration) {
	if policy.Limit <= 0 || policy.Window <= 0 {
		return true, 0
	}
	now := l.now().UTC()
	l.mu.Lock()
	defer l.mu.Unlock()
	bucket := l.buckets[key]
	if bucket.WindowStart.IsZero() && len(l.buckets) >= maxRateLimitBuckets {
		// An attacker can vary IP/account keys faster than age cleanup runs.
		// Evict the least recently seen bucket to keep memory strictly bounded.
		var oldestKey string
		var oldest time.Time
		for candidate, existing := range l.buckets {
			if oldestKey == "" || existing.LastSeen.Before(oldest) {
				oldestKey, oldest = candidate, existing.LastSeen
			}
		}
		if oldestKey != "" {
			delete(l.buckets, oldestKey)
		}
	}
	if bucket.WindowStart.IsZero() || !now.Before(bucket.WindowStart.Add(policy.Window)) {
		bucket = rateBucket{WindowStart: now}
	}
	bucket.LastSeen = now
	if bucket.Count >= policy.Limit {
		l.buckets[key] = bucket
		return false, bucket.WindowStart.Add(policy.Window).Sub(now)
	}
	bucket.Count++
	l.buckets[key] = bucket
	return true, 0
}

func (l *rateLimiter) Cleanup(maxAge time.Duration) {
	now := l.now().UTC()
	l.mu.Lock()
	defer l.mu.Unlock()
	for key, bucket := range l.buckets {
		if now.Sub(bucket.LastSeen) > maxAge {
			delete(l.buckets, key)
		}
	}
}
