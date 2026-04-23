package proxy

import (
	"crypto/sha256"
	"sync"
	"sync/atomic"
	"time"
)

// passwordCache stores recent successful Basic-auth outcomes so the bcrypt
// cost is paid once per (credential, hash) pair within the TTL window. Only
// successful authentications are cached — failures always run bcrypt, so a
// cache cannot accelerate brute-force attacks.
//
// Keys are fixed-size SHA-256 hashes of (stored_hash || 0x00 || password),
// which binds each cache entry to the exact stored bcrypt hash. Rotating a
// password produces a new stored hash and therefore a new key, automatically
// invalidating the prior cache entry.
type passwordCache struct {
	mu      sync.RWMutex
	entries map[[sha256.Size]byte]int64 // key → expiry in unix-nano
	ttl     time.Duration
	maxSize int

	hits   atomic.Int64
	misses atomic.Int64
}

func newPasswordCache(ttl time.Duration, maxSize int) *passwordCache {
	initial := max(maxSize/4, 16)
	return &passwordCache{
		entries: make(map[[sha256.Size]byte]int64, initial),
		ttl:     ttl,
		maxSize: maxSize,
	}
}

// cacheKey derives a fixed-size key from the stored hash and the password.
// A stack buffer holds the concatenation for typical inputs; oversized
// inputs fall back to the streaming Hash interface.
func cacheKey(hash, password []byte) [sha256.Size]byte {
	var buf [256]byte
	need := len(hash) + 1 + len(password)
	if need <= len(buf) {
		n := copy(buf[:], hash)
		buf[n] = 0
		n++
		n += copy(buf[n:], password)
		return sha256.Sum256(buf[:n])
	}
	h := sha256.New()
	_, _ = h.Write(hash)
	_, _ = h.Write([]byte{0})
	_, _ = h.Write(password)
	var out [sha256.Size]byte
	_ = h.Sum(out[:0])
	return out
}

// check reports whether (hash, password) is currently cached as a successful
// authentication. Hot path: RLock only.
func (c *passwordCache) check(key [sha256.Size]byte, now time.Time) bool {
	c.mu.RLock()
	exp, ok := c.entries[key]
	c.mu.RUnlock()
	if ok && now.UnixNano() < exp {
		c.hits.Add(1)
		return true
	}
	c.misses.Add(1)
	return false
}

// set records a successful authentication. Evicts expired entries on a full
// map; if the map is still full (all entries valid), bulk-drops half to
// bound memory under sustained churn.
func (c *passwordCache) set(key [sha256.Size]byte, now time.Time) {
	expiry := now.Add(c.ttl).UnixNano()
	c.mu.Lock()
	defer c.mu.Unlock()
	if len(c.entries) >= c.maxSize {
		c.evictLocked(now.UnixNano())
	}
	c.entries[key] = expiry
}

// evictLocked drops expired entries first, then — if still at capacity —
// bulk-removes half the map (map iteration order acts as pseudo-random
// eviction). Simpler than a full LRU and good enough for a bounded cache.
func (c *passwordCache) evictLocked(nowNano int64) {
	for k, exp := range c.entries {
		if nowNano >= exp {
			delete(c.entries, k)
		}
	}
	target := c.maxSize / 2
	for k := range c.entries {
		if len(c.entries) <= target {
			break
		}
		delete(c.entries, k)
	}
}

// Stats returns the current hit and miss counters. For tests and metrics.
func (c *passwordCache) Stats() (hits, misses int64) {
	return c.hits.Load(), c.misses.Load()
}

// Len returns the current number of cached entries. For tests and metrics.
func (c *passwordCache) Len() int {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return len(c.entries)
}
