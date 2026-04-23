package proxy

import (
	"crypto/rand"
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
// Cache keys are HMAC-SHA-256(secret, stored_hash || 0x00 || password) where
// secret is 32 bytes from crypto/rand, regenerated per-process on every
// newPasswordCache. The HMAC secret makes a memory-dump attack useless for
// offline password cracking: without the secret, the key is an unpredictable
// 32-byte blob that cannot be recomputed from (hash, candidate_password).
//
// Binding to the stored bcrypt hash means rotating a password produces a new
// stored hash and therefore a new key, automatically orphaning prior entries.
type passwordCache struct {
	mu      sync.RWMutex
	entries map[[sha256.Size]byte]int64 // key → expiry in unix-nano
	ttl     time.Duration
	maxSize int

	// Pre-computed HMAC pads. Storing these instead of the raw secret lets
	// the hot path run two stack-buffered SHA-256 computations with zero
	// heap allocations.
	hmacInnerPad [sha256.BlockSize]byte
	hmacOuterPad [sha256.BlockSize]byte

	hits   atomic.Uint64
	misses atomic.Uint64
}

func newPasswordCache(ttl time.Duration, maxSize int) *passwordCache {
	// Cap the initial map hint so that a permissive `max_entries` (e.g. 1M)
	// does not balloon idle memory with buckets that will never be used.
	// Operators commonly set a high ceiling for headroom while only touching
	// a small active working set. The map will grow naturally as entries are
	// inserted — amortized cost is O(n) for n inserts.
	initial := min(maxSize, 1024)
	if initial < 16 {
		initial = 16
	}
	c := &passwordCache{
		entries: make(map[[sha256.Size]byte]int64, initial),
		ttl:     ttl,
		maxSize: maxSize,
	}
	var secret [32]byte
	if _, err := rand.Read(secret[:]); err != nil {
		// crypto/rand only fails on catastrophic OS-level errors; panic is
		// the right outcome — an unseeded cache is a silent security bug.
		panic("fcgi-proxy: crypto/rand failure: " + err.Error())
	}
	// HMAC key prep per RFC 2104: pad the secret to SHA-256's block size
	// with zero bytes (our secret is 32 bytes < 64 = blockSize), then XOR
	// with ipad/opad to derive the inner and outer pads. We store only the
	// pads; the raw secret is discarded so a memory dump cannot recover it
	// in its original form.
	var key [sha256.BlockSize]byte
	copy(key[:], secret[:])
	for i := range key {
		c.hmacInnerPad[i] = key[i] ^ 0x36
		c.hmacOuterPad[i] = key[i] ^ 0x5c
	}
	return c
}

// key returns the HMAC-SHA-256 cache key for (hash, password). Zero-alloc
// when the concatenation fits in the stack buffer (true for any realistic
// bcrypt hash + password combination).
func (c *passwordCache) key(hash, password []byte) [sha256.Size]byte {
	// Inner hash: SHA-256(innerPad || hash || 0x00 || password)
	var inner [sha256.Size]byte
	need := sha256.BlockSize + len(hash) + 1 + len(password)
	if need <= 256 {
		var buf [256]byte
		n := copy(buf[:], c.hmacInnerPad[:])
		n += copy(buf[n:], hash)
		buf[n] = 0
		n++
		n += copy(buf[n:], password)
		inner = sha256.Sum256(buf[:n])
	} else {
		h := sha256.New()
		_, _ = h.Write(c.hmacInnerPad[:])
		_, _ = h.Write(hash)
		_, _ = h.Write([]byte{0})
		_, _ = h.Write(password)
		// Sum(out[:0]) appends the digest into the backing array of `out`,
		// which has cap sha256.Size. No allocation — the returned slice is
		// discarded because `out` already holds the result.
		_ = h.Sum(inner[:0])
	}
	// Outer hash: SHA-256(outerPad || inner). Fits trivially on the stack.
	var outerBuf [sha256.BlockSize + sha256.Size]byte
	copy(outerBuf[:sha256.BlockSize], c.hmacOuterPad[:])
	copy(outerBuf[sha256.BlockSize:], inner[:])
	return sha256.Sum256(outerBuf[:])
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

// set records a successful authentication. Eviction runs only when inserting
// a NEW key into an at-capacity cache — re-authenticating an existing user at
// a full cache does not trigger an O(n) map scan.
func (c *passwordCache) set(key [sha256.Size]byte, now time.Time) {
	expiry := now.Add(c.ttl).UnixNano()
	c.mu.Lock()
	defer c.mu.Unlock()
	if _, exists := c.entries[key]; !exists && len(c.entries) >= c.maxSize {
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

// stats returns the current hit and miss counters. For tests and metrics.
func (c *passwordCache) stats() (hits, misses uint64) {
	return c.hits.Load(), c.misses.Load()
}

// length returns the current number of cached entries. For tests and metrics.
func (c *passwordCache) length() int {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return len(c.entries)
}
