package locationcache

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"sync"
	"time"

	"golang.org/x/sync/singleflight"
)

const (
	maxResponseSize = 10 * 1024 * 1024 // 10 MB per upstream response
	maxStaleAge     = 24 * time.Hour   // maximum age for stale-on-error fallback
	maxRedirects    = 5
)

// Entry holds a cached response from an external server.
type Entry struct {
	Body        []byte
	ContentType string
	StatusCode  int
	FetchedAt   time.Time
	FromCache   bool
}

// Location defines a path-to-upstream mapping with caching.
type Location struct {
	Path     string
	Upstream string
	TTL      time.Duration
}

// Cache fetches and caches responses from external servers for configured paths.
type Cache struct {
	locations map[string]Location
	mu        sync.RWMutex
	entries   map[string]Entry
	client    *http.Client
	group     singleflight.Group
}

// New creates a Cache from the given locations. The timeout controls the
// HTTP client timeout for upstream fetches.
func New(locations []Location, fetchTimeout time.Duration) *Cache {
	locMap := make(map[string]Location, len(locations))
	for _, loc := range locations {
		locMap[loc.Path] = loc
	}

	transport := &http.Transport{
		DialContext: ssrfGuardDial,
	}

	client := &http.Client{
		Timeout:   fetchTimeout,
		Transport: transport,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			// via contains the chain of previous requests for this single redirect sequence.
			// Using len(via) instead of a shared counter so each request starts fresh.
			if len(via) >= maxRedirects {
				return fmt.Errorf("too many redirects (%d)", len(via))
			}
			return nil
		},
	}

	return &Cache{
		locations: locMap,
		entries:   make(map[string]Entry),
		client:    client,
	}
}

// Match returns the location for the given path, or false if not configured.
func (c *Cache) Match(path string) (Location, bool) {
	loc, ok := c.locations[path]
	return loc, ok
}

// Get returns a cached or freshly-fetched entry for the given location.
// Uses singleflight to prevent concurrent fetches for the same path.
func (c *Cache) Get(loc Location) (Entry, error) {
	c.mu.RLock()
	entry, ok := c.entries[loc.Path]
	c.mu.RUnlock()

	if ok && time.Since(entry.FetchedAt) < loc.TTL {
		cached := entry
		cached.FromCache = true
		return cached, nil
	}

	// Deduplicate concurrent fetches for the same path.
	result, err, _ := c.group.Do(loc.Path, func() (any, error) {
		return c.fetch(loc)
	})
	if err != nil {
		return Entry{}, err
	}

	return result.(Entry), nil
}

func (c *Cache) fetch(loc Location) (Entry, error) {
	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, loc.Upstream, nil)
	if err != nil {
		return c.staleOrError(loc, fmt.Errorf("locationcache: build request for %s: %w", sanitizeURL(loc.Upstream), err))
	}

	resp, err := c.client.Do(req)
	if err != nil {
		return c.staleOrError(loc, fmt.Errorf("locationcache: fetch %s: %w", sanitizeURL(loc.Upstream), err))
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseSize))
	if err != nil {
		return Entry{}, fmt.Errorf("locationcache: read %s: %w", sanitizeURL(loc.Upstream), err)
	}

	entry := Entry{
		Body:        body,
		ContentType: resp.Header.Get("Content-Type"),
		StatusCode:  resp.StatusCode,
		FetchedAt:   time.Now(),
	}

	// Only cache 200 responses. Non-200 responses are returned directly
	// so the next request retries the upstream.
	if resp.StatusCode == http.StatusOK {
		c.mu.Lock()
		c.entries[loc.Path] = entry
		c.mu.Unlock()
	}

	return entry, nil
}

// staleOrError returns a stale cache entry if available and not too old,
// otherwise returns the original error.
func (c *Cache) staleOrError(loc Location, fetchErr error) (Entry, error) {
	c.mu.RLock()
	stale, ok := c.entries[loc.Path]
	c.mu.RUnlock()

	if ok && time.Since(stale.FetchedAt) < maxStaleAge {
		cached := stale
		cached.FromCache = true
		return cached, nil
	}

	// Evict entries beyond maxStaleAge so the body bytes can be GC'd.
	if ok {
		c.mu.Lock()
		delete(c.entries, loc.Path)
		c.mu.Unlock()
	}

	return Entry{}, fetchErr
}

// ssrfGuardDial prevents connections to private/loopback/link-local addresses.
func ssrfGuardDial(ctx context.Context, network, addr string) (net.Conn, error) {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, fmt.Errorf("locationcache: invalid address %q", addr)
	}

	ip := net.ParseIP(host)
	if ip != nil && isPrivateIP(ip) {
		return nil, fmt.Errorf("locationcache: upstream address %s is not allowed (private/loopback)", host)
	}

	// Resolve hostname and check all IPs.
	ips, err := net.DefaultResolver.LookupIPAddr(ctx, host)
	if err != nil {
		return nil, fmt.Errorf("locationcache: resolve %s: %w", host, err)
	}
	for _, resolved := range ips {
		if isPrivateIP(resolved.IP) {
			return nil, fmt.Errorf("locationcache: upstream %s resolves to private address %s", host, resolved.IP)
		}
	}

	return (&net.Dialer{}).DialContext(ctx, network, addr)
}

func isPrivateIP(ip net.IP) bool {
	if ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() || ip.IsUnspecified() {
		return true
	}
	// AWS/GCP/Azure metadata endpoint.
	if ip.Equal(net.ParseIP("169.254.169.254")) {
		return true
	}
	return false
}

// sanitizeURL strips credentials from a URL for safe logging.
func sanitizeURL(rawURL string) string {
	parsed, err := url.Parse(rawURL)
	if err != nil {
		return "[invalid URL]"
	}
	parsed.User = nil
	return parsed.String()
}
