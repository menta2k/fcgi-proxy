package proxy

import (
	"sync"
	"testing"
	"time"
)

func TestPasswordCache_MissOnEmpty(t *testing.T) {
	c := newPasswordCache(time.Minute, 100)
	key := cacheKey([]byte("hash"), []byte("pw"))
	if c.check(key, time.Now()) {
		t.Fatal("empty cache should miss")
	}
	if _, m := c.Stats(); m != 1 {
		t.Errorf("misses = %d, want 1", m)
	}
}

func TestPasswordCache_HitAfterSet(t *testing.T) {
	c := newPasswordCache(time.Minute, 100)
	key := cacheKey([]byte("hash"), []byte("pw"))
	now := time.Now()
	c.set(key, now)
	if !c.check(key, now) {
		t.Fatal("cache should hit after set")
	}
	h, _ := c.Stats()
	if h != 1 {
		t.Errorf("hits = %d, want 1", h)
	}
}

func TestPasswordCache_ExpiredEntry(t *testing.T) {
	c := newPasswordCache(10*time.Millisecond, 100)
	key := cacheKey([]byte("hash"), []byte("pw"))
	c.set(key, time.Now())
	if c.check(key, time.Now().Add(20*time.Millisecond)) {
		t.Fatal("expired entry should miss")
	}
}

func TestPasswordCache_DifferentPasswordDifferentKey(t *testing.T) {
	c := newPasswordCache(time.Minute, 100)
	k1 := cacheKey([]byte("hash"), []byte("pw1"))
	k2 := cacheKey([]byte("hash"), []byte("pw2"))
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
	k1 := cacheKey([]byte("hash-v1"), []byte("pw"))
	k2 := cacheKey([]byte("hash-v2"), []byte("pw"))
	if k1 == k2 {
		t.Fatal("different stored hashes must produce different keys")
	}
}

func TestPasswordCache_EvictsExpiredOnFull(t *testing.T) {
	c := newPasswordCache(10*time.Millisecond, 4)
	now := time.Now()
	for i := 0; i < 4; i++ {
		c.set(cacheKey([]byte("hash"), []byte{'p', byte('a' + i)}), now)
	}
	if c.Len() != 4 {
		t.Fatalf("Len = %d, want 4", c.Len())
	}
	// Advance time past TTL, then insert a 5th entry. The eviction pass
	// should drop the expired four first.
	c.set(cacheKey([]byte("hash"), []byte("new")), now.Add(20*time.Millisecond))
	if c.Len() != 1 {
		t.Errorf("after eviction Len = %d, want 1", c.Len())
	}
}

func TestPasswordCache_BulkEvictsWhenAllValid(t *testing.T) {
	c := newPasswordCache(time.Minute, 4)
	now := time.Now()
	for i := 0; i < 4; i++ {
		c.set(cacheKey([]byte("hash"), []byte{'p', byte('a' + i)}), now)
	}
	// All four are still valid. Inserting a 5th must drop half.
	c.set(cacheKey([]byte("hash"), []byte("new")), now)
	if l := c.Len(); l > 3 {
		t.Errorf("after bulk eviction Len = %d, want ≤3", l)
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
				key := cacheKey([]byte("hash"), []byte{byte(id), byte(i)})
				c.set(key, time.Now())
				_ = c.check(key, time.Now())
			}
		}(w)
	}
	wg.Wait()
	if c.Len() > 1000 {
		t.Errorf("Len = %d exceeded maxSize", c.Len())
	}
}

func TestCacheKey_ZeroAllocTypicalSize(t *testing.T) {
	hash := []byte("$2b$10$abcdefghijklmnopqrstuuVeryTypicalBcryptHashBytesHere1234567")
	pw := []byte("s3cretpassword")
	allocs := testing.AllocsPerRun(100, func() {
		_ = cacheKey(hash, pw)
	})
	if allocs != 0 {
		t.Errorf("cacheKey allocated %.1f times per run, want 0", allocs)
	}
}

func TestCacheKey_OversizedInputFallback(t *testing.T) {
	// Combined length > 256 — must take the streaming path and still produce
	// a stable, deterministic key.
	big := make([]byte, 512)
	for i := range big {
		big[i] = byte(i)
	}
	k1 := cacheKey(big[:200], big[:200])
	k2 := cacheKey(big[:200], big[:200])
	if k1 != k2 {
		t.Error("oversized-input path must be deterministic")
	}
}

func TestPasswordCacheCheck_ZeroAlloc(t *testing.T) {
	c := newPasswordCache(time.Minute, 100)
	key := cacheKey([]byte("hash"), []byte("pw"))
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
	key := cacheKey([]byte("hash"), []byte("pw"))
	c.set(key, time.Now())
	now := time.Now()
	b.ReportAllocs()
	for b.Loop() {
		_ = c.check(key, now)
	}
}
