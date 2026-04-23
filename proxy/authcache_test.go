package proxy

import (
	"sync"
	"testing"
	"time"
)

func TestPasswordCache_MissOnEmpty(t *testing.T) {
	c := newPasswordCache(time.Minute, 100)
	key := c.key([]byte("hash"), []byte("pw"))
	if c.check(key, time.Now()) {
		t.Fatal("empty cache should miss")
	}
	if _, m := c.stats(); m != 1 {
		t.Errorf("misses = %d, want 1", m)
	}
}

func TestPasswordCache_HitAfterSet(t *testing.T) {
	c := newPasswordCache(time.Minute, 100)
	key := c.key([]byte("hash"), []byte("pw"))
	now := time.Now()
	c.set(key, now)
	if !c.check(key, now) {
		t.Fatal("cache should hit after set")
	}
	h, _ := c.stats()
	if h != 1 {
		t.Errorf("hits = %d, want 1", h)
	}
}

func TestPasswordCache_ExpiredEntry(t *testing.T) {
	c := newPasswordCache(10*time.Millisecond, 100)
	key := c.key([]byte("hash"), []byte("pw"))
	c.set(key, time.Now())
	if c.check(key, time.Now().Add(20*time.Millisecond)) {
		t.Fatal("expired entry should miss")
	}
}

func TestPasswordCache_DifferentPasswordDifferentKey(t *testing.T) {
	c := newPasswordCache(time.Minute, 100)
	k1 := c.key([]byte("hash"), []byte("pw1"))
	k2 := c.key([]byte("hash"), []byte("pw2"))
	if k1 == k2 {
		t.Fatal("different passwords must produce different keys")
	}
	c.set(k1, time.Now())
	if c.check(k2, time.Now()) {
		t.Fatal("pw2 should not hit a pw1 cache entry")
	}
}

func TestPasswordCache_DifferentHashDifferentKey(t *testing.T) {
	// Rotating the password produces a new bcrypt hash. The cache must treat
	// that as a new key, automatically invalidating any prior entry.
	c := newPasswordCache(time.Minute, 100)
	k1 := c.key([]byte("hash-v1"), []byte("pw"))
	k2 := c.key([]byte("hash-v2"), []byte("pw"))
	if k1 == k2 {
		t.Fatal("different stored hashes must produce different keys")
	}
}

func TestPasswordCache_DifferentInstancesDifferentKeys(t *testing.T) {
	// HMAC secrets are per-instance, so two caches that see the same (hash,
	// password) must produce different keys. Prevents a memory dump of one
	// process from being replayable against another.
	c1 := newPasswordCache(time.Minute, 100)
	c2 := newPasswordCache(time.Minute, 100)
	k1 := c1.key([]byte("hash"), []byte("pw"))
	k2 := c2.key([]byte("hash"), []byte("pw"))
	if k1 == k2 {
		t.Fatal("two independent caches must derive different HMAC keys")
	}
}

func TestPasswordCache_EvictsExpiredOnFull(t *testing.T) {
	c := newPasswordCache(10*time.Millisecond, 4)
	now := time.Now()
	for i := 0; i < 4; i++ {
		c.set(c.key([]byte("hash"), []byte{'p', byte('a' + i)}), now)
	}
	if c.length() != 4 {
		t.Fatalf("length = %d, want 4", c.length())
	}
	// Advance time past TTL, then insert a 5th entry. The eviction pass
	// should drop the expired four first.
	c.set(c.key([]byte("hash"), []byte("new")), now.Add(20*time.Millisecond))
	if c.length() != 1 {
		t.Errorf("after eviction length = %d, want 1", c.length())
	}
}

func TestPasswordCache_BulkEvictsWhenAllValid(t *testing.T) {
	c := newPasswordCache(time.Minute, 4)
	now := time.Now()
	for i := 0; i < 4; i++ {
		c.set(c.key([]byte("hash"), []byte{'p', byte('a' + i)}), now)
	}
	// All four are still valid. Inserting a 5th must drop half.
	c.set(c.key([]byte("hash"), []byte("new")), now)
	if l := c.length(); l > 3 {
		t.Errorf("after bulk eviction length = %d, want ≤3", l)
	}
}

// Re-authenticating an existing user at a full cache must NOT trigger
// eviction — the map is not growing, so the O(n) scan is wasteful.
func TestPasswordCache_SetExistingKeyAtCapacityDoesNotEvict(t *testing.T) {
	c := newPasswordCache(time.Minute, 4)
	now := time.Now()
	// Fill to capacity with four distinct entries.
	keys := make([][32]byte, 4)
	for i := 0; i < 4; i++ {
		keys[i] = c.key([]byte("hash"), []byte{'p', byte('a' + i)})
		c.set(keys[i], now)
	}
	if c.length() != 4 {
		t.Fatalf("pre length = %d, want 4", c.length())
	}
	// Re-set one of the existing keys with a later expiry. The map should
	// stay at 4 entries (no entry dropped) and the TTL should refresh.
	c.set(keys[0], now.Add(5*time.Second))
	if c.length() != 4 {
		t.Errorf("re-auth at capacity changed length: %d (want 4)", c.length())
	}
	// Verify all four original entries are still present.
	for i, k := range keys {
		if !c.check(k, now) {
			t.Errorf("entry %d was evicted by a re-auth", i)
		}
	}
}

func TestPasswordCache_ConcurrentAccess(t *testing.T) {
	c := newPasswordCache(time.Minute, 1000)
	const workers = 8
	const ops = 500
	var wg sync.WaitGroup
	for w := range workers {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			for i := range ops {
				key := c.key([]byte("hash"), []byte{byte(id), byte(i)})
				c.set(key, time.Now())
				_ = c.check(key, time.Now())
			}
		}(w)
	}
	wg.Wait()
	if c.length() > 1000 {
		t.Errorf("length = %d exceeded maxSize", c.length())
	}
}

func TestCacheKey_ZeroAllocTypicalSize(t *testing.T) {
	c := newPasswordCache(time.Minute, 100)
	hash := []byte("$2b$10$abcdefghijklmnopqrstuuVeryTypicalBcryptHashBytesHere1234567")
	pw := []byte("s3cretpassword")
	// Warm any one-time runtime initialization.
	_ = c.key(hash, pw)
	allocs := testing.AllocsPerRun(100, func() {
		_ = c.key(hash, pw)
	})
	if allocs != 0 {
		t.Errorf("cache.key allocated %.1f times per run, want 0", allocs)
	}
}

func TestCacheKey_OversizedInputFallback(t *testing.T) {
	// Combined length > 256 — must take the streaming path and still produce
	// a stable, deterministic key.
	c := newPasswordCache(time.Minute, 100)
	big := make([]byte, 512)
	for i := range big {
		big[i] = byte(i)
	}
	k1 := c.key(big[:200], big[:200])
	k2 := c.key(big[:200], big[:200])
	if k1 != k2 {
		t.Error("oversized-input path must be deterministic")
	}
}

// TestCacheKey_BoundaryCrossover exercises inputs around the stack-vs-stream
// decision boundary (256 bytes). Growing the combined length by a single byte
// must produce a different key, independent of which path computes it.
func TestCacheKey_BoundaryCrossover(t *testing.T) {
	c := newPasswordCache(time.Minute, 100)
	// Fixed hash so only password length varies. Inner pad is 64 bytes, so
	// need = 64 + len(hash) + 1 + len(password). Pick inputs landing on 256
	// (stack) and 257 (stream).
	hash := make([]byte, 32)
	// At password length 159: 64 + 32 + 1 + 159 = 256 → stack path
	// At password length 160: 64 + 32 + 1 + 160 = 257 → stream path
	pw256 := make([]byte, 159)
	pw257 := make([]byte, 160)
	for i := range pw257 {
		pw257[i] = byte(i)
	}
	copy(pw256, pw257)

	k256 := c.key(hash, pw256)
	k257 := c.key(hash, pw257)
	if k256 == k257 {
		t.Fatal("a single extra input byte must change the key")
	}
	// Repeat to confirm determinism of each path independently.
	if k256 != c.key(hash, pw256) {
		t.Error("stack path not deterministic")
	}
	if k257 != c.key(hash, pw257) {
		t.Error("stream path not deterministic")
	}
}

func TestPasswordCacheCheck_ZeroAlloc(t *testing.T) {
	c := newPasswordCache(time.Minute, 100)
	key := c.key([]byte("hash"), []byte("pw"))
	c.set(key, time.Now())
	now := time.Now()
	allocs := testing.AllocsPerRun(100, func() {
		_ = c.check(key, now)
	})
	if allocs != 0 {
		t.Errorf("passwordCache.check allocated %.1f times per run, want 0", allocs)
	}
}

func BenchmarkPasswordCache_Hit(b *testing.B) {
	c := newPasswordCache(time.Minute, 10000)
	key := c.key([]byte("hash"), []byte("pw"))
	c.set(key, time.Now())
	now := time.Now()
	b.ReportAllocs()
	for b.Loop() {
		_ = c.check(key, now)
	}
}

func BenchmarkPasswordCache_Key(b *testing.B) {
	c := newPasswordCache(time.Minute, 10000)
	hash := []byte("$2b$10$abcdefghijklmnopqrstuuVeryTypicalBcryptHashBytesHere1234567")
	pw := []byte("s3cretpassword")
	b.ReportAllocs()
	for b.Loop() {
		_ = c.key(hash, pw)
	}
}
