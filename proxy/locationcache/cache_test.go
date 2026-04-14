package locationcache

import (
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// newPublicServer creates a test server on a non-loopback address.
// Since the SSRF guard blocks loopback, we need to test differently.
// For unit tests, we'll test the cache logic with a custom client that bypasses the guard.
func newTestCache(locations []Location) *Cache {
	locMap := make(map[string]Location, len(locations))
	for _, loc := range locations {
		locMap[loc.Path] = loc
	}
	return &Cache{
		locations: locMap,
		entries:   make(map[string]Entry),
		client:    &http.Client{Timeout: 5 * time.Second},
	}
}

func TestCache_FetchAndServe(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(200)
		w.Write([]byte(`{"appID":"ABCDE12345.com.example.app"}`))
	}))
	defer server.Close()

	loc := Location{
		Path:     "/apple-app-site-association",
		Upstream: server.URL,
		TTL:      time.Minute,
	}

	cache := newTestCache([]Location{loc})

	entry, err := cache.Get(loc)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if entry.StatusCode != 200 {
		t.Errorf("status = %d, want 200", entry.StatusCode)
	}
	if entry.ContentType != "application/json" {
		t.Errorf("content-type = %q", entry.ContentType)
	}
	if string(entry.Body) != `{"appID":"ABCDE12345.com.example.app"}` {
		t.Errorf("body = %q", entry.Body)
	}
	if entry.FromCache {
		t.Error("first fetch should not be from cache")
	}
}

func TestCache_ServesFromCache(t *testing.T) {
	callCount := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		callCount++
		w.WriteHeader(200)
		w.Write([]byte("response"))
	}))
	defer server.Close()

	loc := Location{Path: "/cached", Upstream: server.URL, TTL: time.Minute}
	cache := newTestCache([]Location{loc})

	_, _ = cache.Get(loc)
	if callCount != 1 {
		t.Fatalf("expected 1 upstream call, got %d", callCount)
	}

	entry, _ := cache.Get(loc)
	if callCount != 1 {
		t.Errorf("expected cache hit (1 call), got %d", callCount)
	}
	if !entry.FromCache {
		t.Error("second call should be from cache")
	}
}

func TestCache_ExpiredTTL_Refetches(t *testing.T) {
	callCount := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		callCount++
		w.WriteHeader(200)
		w.Write([]byte("response"))
	}))
	defer server.Close()

	loc := Location{Path: "/short-ttl", Upstream: server.URL, TTL: 1 * time.Millisecond}
	cache := newTestCache([]Location{loc})

	_, _ = cache.Get(loc)
	time.Sleep(5 * time.Millisecond)
	_, _ = cache.Get(loc)

	if callCount < 2 {
		t.Errorf("expected at least 2 upstream calls after TTL expiry, got %d", callCount)
	}
}

func TestCache_UpstreamDown_ServesStale(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
		w.Write([]byte("original"))
	}))

	loc := Location{Path: "/stale", Upstream: server.URL, TTL: 1 * time.Millisecond}
	cache := newTestCache([]Location{loc})

	_, err := cache.Get(loc)
	if err != nil {
		t.Fatal(err)
	}

	server.Close()
	time.Sleep(5 * time.Millisecond)

	entry, err := cache.Get(loc)
	if err != nil {
		t.Fatalf("expected stale entry, got error: %v", err)
	}
	if string(entry.Body) != "original" {
		t.Errorf("body = %q, want %q", entry.Body, "original")
	}
	if !entry.FromCache {
		t.Error("stale fallback should be marked as from cache")
	}
}

func TestCache_UpstreamDown_NoCacheEntry_ReturnsError(t *testing.T) {
	loc := Location{Path: "/never-fetched", Upstream: "http://192.0.2.1:1", TTL: time.Minute}
	cache := newTestCache([]Location{loc})

	_, err := cache.Get(loc)
	if err == nil {
		t.Fatal("expected error when upstream is down and no cache entry exists")
	}
}

func TestCache_Match(t *testing.T) {
	locs := []Location{
		{Path: "/foo", Upstream: "http://example.com/foo", TTL: time.Minute},
		{Path: "/bar", Upstream: "http://example.com/bar", TTL: time.Minute},
	}
	cache := newTestCache(locs)

	if _, ok := cache.Match("/foo"); !ok {
		t.Error("/foo should match")
	}
	if _, ok := cache.Match("/bar"); !ok {
		t.Error("/bar should match")
	}
	if _, ok := cache.Match("/baz"); ok {
		t.Error("/baz should not match")
	}
}

func TestCache_ZeroTTL_AlwaysFetches(t *testing.T) {
	callCount := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		callCount++
		w.WriteHeader(200)
		w.Write([]byte("fresh"))
	}))
	defer server.Close()

	loc := Location{Path: "/no-cache", Upstream: server.URL, TTL: 0}
	cache := newTestCache([]Location{loc})

	_, _ = cache.Get(loc)
	_, _ = cache.Get(loc)
	_, _ = cache.Get(loc)

	if callCount != 3 {
		t.Errorf("expected 3 upstream calls with TTL=0, got %d", callCount)
	}
}

func TestCache_Non200_NotCached(t *testing.T) {
	callCount := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		callCount++
		w.WriteHeader(404)
		w.Write([]byte("not found"))
	}))
	defer server.Close()

	loc := Location{Path: "/missing", Upstream: server.URL, TTL: time.Minute}
	cache := newTestCache([]Location{loc})

	entry, err := cache.Get(loc)
	if err != nil {
		t.Fatal(err)
	}
	if entry.StatusCode != 404 {
		t.Errorf("status = %d, want 404", entry.StatusCode)
	}

	_, _ = cache.Get(loc)
	if callCount != 2 {
		t.Errorf("expected 2 upstream calls (non-200 not cached), got %d", callCount)
	}
}

func TestCache_200_ThenNon200_CachePreserved(t *testing.T) {
	callCount := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		callCount++
		if callCount == 1 {
			w.WriteHeader(200)
			w.Write([]byte("good"))
		} else {
			w.WriteHeader(500)
			w.Write([]byte("error"))
		}
	}))
	defer server.Close()

	loc := Location{Path: "/flaky", Upstream: server.URL, TTL: 1 * time.Millisecond}
	cache := newTestCache([]Location{loc})

	// First call — 200, cached.
	entry, _ := cache.Get(loc)
	if entry.StatusCode != 200 {
		t.Fatalf("first call status = %d, want 200", entry.StatusCode)
	}

	time.Sleep(5 * time.Millisecond)

	// Second call — TTL expired, upstream returns 500 (not cached, returned directly).
	entry, _ = cache.Get(loc)
	if entry.StatusCode != 500 {
		t.Errorf("second call status = %d, want 500", entry.StatusCode)
	}

	time.Sleep(5 * time.Millisecond)

	// Third call — TTL expired, upstream still 500.
	// The original 200 cache entry is still intact (not overwritten by 500).
	entry, _ = cache.Get(loc)
	if entry.StatusCode != 500 {
		t.Errorf("third call status = %d, want 500 (fresh from upstream)", entry.StatusCode)
	}
	if callCount < 3 {
		t.Errorf("expected at least 3 calls, got %d", callCount)
	}
}

func TestCache_Singleflight(t *testing.T) {
	callCount := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		callCount++
		time.Sleep(50 * time.Millisecond) // slow response
		w.WriteHeader(200)
		w.Write([]byte("data"))
	}))
	defer server.Close()

	loc := Location{Path: "/dedup", Upstream: server.URL, TTL: time.Minute}
	cache := newTestCache([]Location{loc})

	// Launch 10 concurrent requests.
	done := make(chan error, 10)
	for range 10 {
		go func() {
			_, err := cache.Get(loc)
			done <- err
		}()
	}

	for range 10 {
		if err := <-done; err != nil {
			t.Fatalf("concurrent Get error: %v", err)
		}
	}

	// Singleflight should have deduped to 1 upstream call.
	if callCount != 1 {
		t.Errorf("expected 1 upstream call (singleflight), got %d", callCount)
	}
}

func TestSanitizeURL(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{"https://example.com/path", "https://example.com/path"},
		{"https://user:pass@example.com/path", "https://example.com/path"},
		{"http://example.com:8080/path?q=1", "http://example.com:8080/path?q=1"},
	}
	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			got := sanitizeURL(tt.input)
			if got != tt.want {
				t.Errorf("sanitizeURL(%q) = %q, want %q", tt.input, got, tt.want)
			}
		})
	}
}

func TestSSRFGuard_BlocksLoopback(t *testing.T) {
	loc := Location{Path: "/ssrf", Upstream: "http://127.0.0.1:9999/secret", TTL: time.Minute}
	// Use the real New() which has the SSRF guard.
	cache := New([]Location{loc}, 2*time.Second)

	_, err := cache.Get(loc)
	if err == nil {
		t.Fatal("expected SSRF guard to block loopback address")
	}
}

func TestSSRFGuard_BlocksMetadata(t *testing.T) {
	loc := Location{Path: "/metadata", Upstream: "http://169.254.169.254/latest/meta-data/", TTL: time.Minute}
	cache := New([]Location{loc}, 2*time.Second)

	_, err := cache.Get(loc)
	if err == nil {
		t.Fatal("expected SSRF guard to block metadata endpoint")
	}
}

func TestIsPrivateIP(t *testing.T) {
	private := []string{"127.0.0.1", "10.0.0.1", "192.168.1.1", "172.16.0.1", "169.254.169.254", "::1", "0.0.0.0"}
	for _, ip := range private {
		if !isPrivateIP(net.ParseIP(ip)) {
			t.Errorf("%s should be private", ip)
		}
	}

	public := []string{"8.8.8.8", "1.1.1.1", "93.123.45.67"}
	for _, ip := range public {
		if isPrivateIP(net.ParseIP(ip)) {
			t.Errorf("%s should not be private", ip)
		}
	}
}
