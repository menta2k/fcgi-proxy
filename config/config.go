package config

import (
	"encoding/json"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

// Config holds the application configuration.
type Config struct {
	Listen         string `json:"listen"`
	Network        string `json:"network"`
	Address        string `json:"address"`
	DocumentRoot   string `json:"document_root"`
	Index          string `json:"index"`
	DialTimeout    string `json:"dial_timeout"`
	ReadTimeout    string `json:"read_timeout"`
	WriteTimeout   string `json:"write_timeout"`
	MaxBodySize     int               `json:"max_body_size"`
	MaxConcurrency  int               `json:"max_concurrency"`
	PoolMaxIdle     int               `json:"pool_max_idle"`
	PoolIdleTimeout string            `json:"pool_idle_timeout"`
	ResponseHeaders map[string]string `json:"response_headers"`
	Locations       []LocationConfig  `json:"locations"`
	CORS            CORSConfig        `json:"cors"`
}

// CORSConfig defines Cross-Origin Resource Sharing rules.
// When Enabled is false, no CORS headers are emitted and preflights are not handled.
type CORSConfig struct {
	Enabled          bool     `json:"enabled"`
	AllowedOrigins   []string `json:"allowed_origins"`
	AllowedMethods   []string `json:"allowed_methods"`
	AllowedHeaders   []string `json:"allowed_headers"`
	ExposedHeaders   []string `json:"exposed_headers"`
	AllowCredentials bool     `json:"allow_credentials"`
	MaxAge           string   `json:"max_age"`
}

// LocationConfig defines a location rule. Each entry must set either Upstream
// (cached reverse proxy to an external URL) OR Return (inline static response),
// but not both.
type LocationConfig struct {
	Path     string        `json:"path"`
	Upstream string        `json:"upstream,omitempty"`
	CacheTTL string        `json:"cache_ttl,omitempty"`
	Return   *ReturnConfig `json:"return,omitempty"`
}

// ReturnConfig describes an inline static response served for a location —
// the nginx `return 200 '...';` equivalent.
type ReturnConfig struct {
	Status      int    `json:"status"`       // defaults to 200
	Body        string `json:"body"`         // required (may be empty string for 204/304)
	ContentType string `json:"content_type"` // defaults to "text/plain; charset=utf-8"
}

// ParsedLocation holds a validated location config. Exactly one of
// Upstream and Return is populated.
type ParsedLocation struct {
	Path     string
	Upstream string
	CacheTTL time.Duration
	Return   *ParsedReturn
}

// ParsedReturn is a pre-built static response. Body is materialized once at
// parse time so the request hot path only does SetBody(b), zero allocations.
type ParsedReturn struct {
	Status      int
	Body        []byte
	ContentType string
}

// Parsed holds validated, parsed config values ready for use.
type Parsed struct {
	Listen         string
	Network        string
	Address        string
	DocumentRoot   string
	Index          string
	DialTimeout    time.Duration
	ReadTimeout    time.Duration
	WriteTimeout   time.Duration
	MaxBodySize     int
	MaxConcurrency  int
	PoolMaxIdle     int
	PoolIdleTimeout time.Duration
	ResponseHeaders map[string]string
	Locations       []ParsedLocation
	CORS            ParsedCORS
}

// ParsedCORS holds validated CORS settings with pre-built header values.
// All header values are pre-formatted at parse time so the request hot path
// allocates nothing.
type ParsedCORS struct {
	Enabled          bool
	AllowAllOrigins  bool                // true if "*" is configured (implies !AllowCredentials)
	AllowedOrigins   map[string]struct{} // lowercase allowlist (empty when AllowAllOrigins)
	AllowedMethods   string              // comma-joined, ready for Access-Control-Allow-Methods
	AllowedHeaders   string              // comma-joined, ready for Access-Control-Allow-Headers
	ExposedHeaders   string              // comma-joined, ready for Access-Control-Expose-Headers
	AllowCredentials bool
	// MaxAge is the pre-formatted Access-Control-Max-Age value (seconds as a
	// decimal string). Empty means omit the header.
	MaxAge string
}

const (
	minTimeout            = 100 * time.Millisecond
	maxTimeout            = 5 * time.Minute
	maxAllowedBodySize    = 256 * 1024 * 1024 // 256 MB
	maxAllowedConcurrency = 65535
	maxLocations          = 100
	maxReturnBodySize     = 64 * 1024 // 64 KiB — anything larger belongs on a real upstream
)

var allowedNetworks = map[string]bool{
	"tcp":  true,
	"tcp4": true,
	"tcp6": true,
	"unix": true,
}

// DefaultConfig returns sensible defaults.
func DefaultConfig() Config {
	return Config{
		Listen:         ":8080",
		Network:        "tcp",
		Address:        "127.0.0.1:9000",
		DocumentRoot:   "/var/www/html",
		Index:          "index.php",
		DialTimeout:    "5s",
		ReadTimeout:    "30s",
		WriteTimeout:   "30s",
		MaxBodySize:     10 * 1024 * 1024, // 10 MB
		MaxConcurrency:  1024,
		PoolMaxIdle:     32,
		PoolIdleTimeout: "30s",
	}
}

// Load reads config from a JSON file. If the file doesn't exist, returns defaults.
func Load(path string) (Config, error) {
	cfg := DefaultConfig()

	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return cfg, nil
		}
		return Config{}, fmt.Errorf("config: read %s: %w", path, err)
	}

	if err := json.Unmarshal(data, &cfg); err != nil {
		return Config{}, fmt.Errorf("config: parse %s: %w", path, err)
	}

	return cfg, nil
}

// Parse validates a Config and returns a Parsed config ready for use.
func Parse(cfg Config) (Parsed, error) {
	if _, _, err := net.SplitHostPort(cfg.Listen); err != nil {
		return Parsed{}, fmt.Errorf("config: invalid listen address %q: %w", cfg.Listen, err)
	}

	if !allowedNetworks[cfg.Network] {
		return Parsed{}, fmt.Errorf("config: invalid network %q (allowed: tcp, tcp4, tcp6, unix)", cfg.Network)
	}

	if cfg.Address == "" {
		return Parsed{}, fmt.Errorf("config: address must not be empty")
	}

	if !filepath.IsAbs(cfg.DocumentRoot) {
		return Parsed{}, fmt.Errorf("config: document_root must be an absolute path, got %q", cfg.DocumentRoot)
	}
	docRoot := filepath.Clean(cfg.DocumentRoot)

	if strings.ContainsAny(cfg.Index, "/\\\x00") || cfg.Index == "" {
		return Parsed{}, fmt.Errorf("config: index must be a plain filename without path separators or null bytes, got %q", cfg.Index)
	}

	dialTimeout, err := parseBoundedDuration(cfg.DialTimeout, "dial_timeout")
	if err != nil {
		return Parsed{}, err
	}
	readTimeout, err := parseBoundedDuration(cfg.ReadTimeout, "read_timeout")
	if err != nil {
		return Parsed{}, err
	}
	writeTimeout, err := parseBoundedDuration(cfg.WriteTimeout, "write_timeout")
	if err != nil {
		return Parsed{}, err
	}

	for k, v := range cfg.ResponseHeaders {
		if k == "" || !isValidHeaderName(k) {
			return Parsed{}, fmt.Errorf("config: response_headers key %q is invalid (must be alphanumeric or hyphens)", k)
		}
		if strings.ContainsAny(v, "\r\n\x00") {
			return Parsed{}, fmt.Errorf("config: response_headers value for %q contains invalid characters (CR, LF, or null)", k)
		}
	}

	if len(cfg.Locations) > maxLocations {
		return Parsed{}, fmt.Errorf("config: too many locations (%d), maximum is %d", len(cfg.Locations), maxLocations)
	}

	parsedLocations := make([]ParsedLocation, 0, len(cfg.Locations))
	seenPaths := make(map[string]struct{}, len(cfg.Locations))
	for i, loc := range cfg.Locations {
		if loc.Path == "" || loc.Path[0] != '/' {
			return Parsed{}, fmt.Errorf("config: locations[%d].path must be an absolute path starting with /", i)
		}
		if _, dup := seenPaths[loc.Path]; dup {
			return Parsed{}, fmt.Errorf("config: locations[%d].path %q is duplicated", i, loc.Path)
		}
		seenPaths[loc.Path] = struct{}{}

		hasUpstream := loc.Upstream != ""
		hasReturn := loc.Return != nil
		if hasUpstream && hasReturn {
			return Parsed{}, fmt.Errorf("config: locations[%d] must set either upstream or return, not both", i)
		}
		if !hasUpstream && !hasReturn {
			return Parsed{}, fmt.Errorf("config: locations[%d] must set one of upstream or return", i)
		}

		parsed := ParsedLocation{Path: loc.Path}
		if hasReturn {
			if loc.CacheTTL != "" {
				return Parsed{}, fmt.Errorf("config: locations[%d].cache_ttl is not applicable to static return", i)
			}
			ret, err := parseReturnConfig(loc.Return, i)
			if err != nil {
				return Parsed{}, err
			}
			parsed.Return = ret
		} else {
			if !strings.HasPrefix(loc.Upstream, "http://") && !strings.HasPrefix(loc.Upstream, "https://") {
				return Parsed{}, fmt.Errorf("config: locations[%d].upstream must start with http:// or https://, got %q", i, loc.Upstream)
			}
			if strings.Contains(loc.Upstream, "@") {
				return Parsed{}, fmt.Errorf("config: locations[%d].upstream must not contain credentials (found @)", i)
			}
			ttl := 5 * time.Minute // default
			if loc.CacheTTL != "" {
				var parseErr error
				ttl, parseErr = time.ParseDuration(loc.CacheTTL)
				if parseErr != nil {
					return Parsed{}, fmt.Errorf("config: locations[%d].cache_ttl %q is invalid: %w", i, loc.CacheTTL, parseErr)
				}
				if ttl < 0 {
					return Parsed{}, fmt.Errorf("config: locations[%d].cache_ttl must not be negative", i)
				}
			}
			parsed.Upstream = loc.Upstream
			parsed.CacheTTL = ttl
		}
		parsedLocations = append(parsedLocations, parsed)
	}

	if cfg.MaxBodySize <= 0 || cfg.MaxBodySize > maxAllowedBodySize {
		return Parsed{}, fmt.Errorf("config: max_body_size must be between 1 and %d, got %d", maxAllowedBodySize, cfg.MaxBodySize)
	}
	if cfg.MaxConcurrency <= 0 || cfg.MaxConcurrency > maxAllowedConcurrency {
		return Parsed{}, fmt.Errorf("config: max_concurrency must be between 1 and %d, got %d", maxAllowedConcurrency, cfg.MaxConcurrency)
	}

	if cfg.PoolMaxIdle <= 0 || cfg.PoolMaxIdle > 1024 {
		return Parsed{}, fmt.Errorf("config: pool_max_idle must be between 1 and 1024, got %d", cfg.PoolMaxIdle)
	}
	poolIdleTimeout, err := time.ParseDuration(cfg.PoolIdleTimeout)
	if err != nil {
		return Parsed{}, fmt.Errorf("config: invalid pool_idle_timeout %q: %w", cfg.PoolIdleTimeout, err)
	}
	if poolIdleTimeout < time.Second || poolIdleTimeout > maxTimeout {
		return Parsed{}, fmt.Errorf("config: pool_idle_timeout must be between 1s and %v, got %v", maxTimeout, poolIdleTimeout)
	}

	parsedCORS, err := parseCORS(cfg.CORS)
	if err != nil {
		return Parsed{}, err
	}

	// Prevent silent conflict between the generic response_headers injector and
	// the CORS middleware. When both are configured, the middleware overwrites
	// any overlapping Access-Control-* header from response_headers, which
	// violates operator intent.
	if parsedCORS.Enabled {
		for k := range cfg.ResponseHeaders {
			if hasCORSHeaderPrefix(k) {
				return Parsed{}, fmt.Errorf("config: response_headers must not set %q when cors.enabled is true (CORS middleware is authoritative)", k)
			}
		}
	}

	return Parsed{
		Listen:         cfg.Listen,
		Network:        cfg.Network,
		Address:        cfg.Address,
		DocumentRoot:   docRoot,
		Index:          cfg.Index,
		DialTimeout:    dialTimeout,
		ReadTimeout:    readTimeout,
		WriteTimeout:   writeTimeout,
		MaxBodySize:     cfg.MaxBodySize,
		MaxConcurrency:  cfg.MaxConcurrency,
		PoolMaxIdle:     cfg.PoolMaxIdle,
		PoolIdleTimeout: poolIdleTimeout,
		ResponseHeaders: cfg.ResponseHeaders,
		Locations:       parsedLocations,
		CORS:            parsedCORS,
	}, nil
}

const (
	maxCORSMaxAge   = 24 * time.Hour
	maxCORSListSize = 64
)

// validHTTPMethods is the allow-set for CORS method validation.
// Case-insensitive; normalized to upper-case in ParsedCORS.
var validHTTPMethods = map[string]bool{
	"GET":     true,
	"HEAD":    true,
	"POST":    true,
	"PUT":     true,
	"PATCH":   true,
	"DELETE":  true,
	"OPTIONS": true,
}

// parseCORS validates a CORSConfig and returns a ParsedCORS.
func parseCORS(c CORSConfig) (ParsedCORS, error) {
	if !c.Enabled {
		return ParsedCORS{Enabled: false}, nil
	}

	if len(c.AllowedOrigins) == 0 {
		return ParsedCORS{}, fmt.Errorf("config: cors.allowed_origins must not be empty when cors is enabled")
	}
	if len(c.AllowedOrigins) > maxCORSListSize {
		return ParsedCORS{}, fmt.Errorf("config: cors.allowed_origins has too many entries (max %d)", maxCORSListSize)
	}

	origins := make(map[string]struct{}, len(c.AllowedOrigins))
	allowAll := false
	hasNull := false
	for _, o := range c.AllowedOrigins {
		o = strings.TrimSpace(o)
		if o == "" {
			return ParsedCORS{}, fmt.Errorf("config: cors.allowed_origins contains an empty entry")
		}
		if o == "*" {
			allowAll = true
			continue
		}
		if err := validateOrigin(o); err != nil {
			return ParsedCORS{}, fmt.Errorf("config: cors.allowed_origins entry %q is invalid: %w", o, err)
		}
		if o == "null" {
			hasNull = true
		}
		// Normalize scheme+host to lowercase per RFC 6454 §6.2 so request-time
		// lookups can use a zero-alloc map hit via the Go compiler's
		// m[string(byteSlice)] optimization.
		origins[strings.ToLower(o)] = struct{}{}
	}

	if allowAll && len(origins) > 0 {
		return ParsedCORS{}, fmt.Errorf("config: cors.allowed_origins cannot mix \"*\" with explicit origins")
	}
	if allowAll && c.AllowCredentials {
		return ParsedCORS{}, fmt.Errorf("config: cors.allow_credentials cannot be true when cors.allowed_origins is \"*\"")
	}
	if hasNull && c.AllowCredentials {
		// "null" is sent by sandboxed iframes, file://, data:, and some redirect
		// chains — any attacker-controlled page can produce it. Echoing it back
		// with Allow-Credentials: true is the CORS anti-pattern.
		return ParsedCORS{}, fmt.Errorf("config: cors.allow_credentials cannot be true when \"null\" is in cors.allowed_origins")
	}

	methods, err := parseCORSMethods(c.AllowedMethods)
	if err != nil {
		return ParsedCORS{}, err
	}
	headers, err := parseCORSHeaderList(c.AllowedHeaders, "allowed_headers")
	if err != nil {
		return ParsedCORS{}, err
	}
	exposed, err := parseCORSHeaderList(c.ExposedHeaders, "exposed_headers")
	if err != nil {
		return ParsedCORS{}, err
	}

	maxAge := ""
	if c.MaxAge != "" {
		d, parseErr := time.ParseDuration(c.MaxAge)
		if parseErr != nil {
			return ParsedCORS{}, fmt.Errorf("config: invalid cors.max_age %q: %w", c.MaxAge, parseErr)
		}
		if d < 0 {
			return ParsedCORS{}, fmt.Errorf("config: cors.max_age must not be negative, got %v", d)
		}
		if d > maxCORSMaxAge {
			return ParsedCORS{}, fmt.Errorf("config: cors.max_age must not exceed %v, got %v", maxCORSMaxAge, d)
		}
		if secs := int(d.Seconds()); secs > 0 {
			maxAge = strconv.Itoa(secs)
		}
	}

	return ParsedCORS{
		Enabled:          true,
		AllowAllOrigins:  allowAll,
		AllowedOrigins:   origins,
		AllowedMethods:   methods,
		AllowedHeaders:   headers,
		ExposedHeaders:   exposed,
		AllowCredentials: c.AllowCredentials,
		MaxAge:           maxAge,
	}, nil
}

// parseReturnConfig validates and materializes a static return response.
// Body is copied into a new []byte exactly once so the request hot path can
// serve it with a plain SetBody call and zero allocations.
func parseReturnConfig(r *ReturnConfig, locIndex int) (*ParsedReturn, error) {
	status := r.Status
	if status == 0 {
		status = 200
	}
	if status < 100 || status > 599 {
		return nil, fmt.Errorf("config: locations[%d].return.status %d is out of range 100-599", locIndex, status)
	}
	if len(r.Body) > maxReturnBodySize {
		return nil, fmt.Errorf("config: locations[%d].return.body is %d bytes, exceeds %d", locIndex, len(r.Body), maxReturnBodySize)
	}

	contentType := r.ContentType
	if contentType == "" {
		contentType = "text/plain; charset=utf-8"
	}
	if strings.ContainsAny(contentType, "\r\n\x00") {
		return nil, fmt.Errorf("config: locations[%d].return.content_type contains invalid characters", locIndex)
	}

	body := []byte(r.Body)
	return &ParsedReturn{
		Status:      status,
		Body:        body,
		ContentType: contentType,
	}, nil
}

// hasCORSHeaderPrefix reports whether a header name begins with "Access-Control-",
// case-insensitive, without allocating a lowercased copy.
func hasCORSHeaderPrefix(name string) bool {
	const prefix = "access-control-"
	if len(name) < len(prefix) {
		return false
	}
	for i := range len(prefix) {
		c := name[i]
		if c >= 'A' && c <= 'Z' {
			c += 'a' - 'A'
		}
		if c != prefix[i] {
			return false
		}
	}
	return true
}

// validateOrigin checks that an origin has the form scheme://host[:port] with
// no path, query, or fragment. Scheme is compared case-insensitively per
// RFC 6454 §6.2. In addition to http and https, "app" is accepted so Cordova
// and hybrid mobile apps that send Origin: app://localhost can be allowlisted.
// The host is validated structurally: bare hostname, hostname:port, or
// bracketed IPv6 [addr][:port]. If a port is present it must be decimal and
// in the range 1-65535. Zero allocations in the validation path.
func validateOrigin(origin string) error {
	if origin == "null" {
		// "null" is a valid Origin for sandboxed iframes/file://; allow it.
		return nil
	}
	if strings.ContainsAny(origin, " \t\r\n\x00") {
		return fmt.Errorf("contains whitespace or control characters")
	}
	scheme, rest, ok := strings.Cut(origin, "://")
	if !ok {
		return fmt.Errorf("missing scheme (expected scheme://host)")
	}
	switch strings.ToLower(scheme) {
	case "http", "https", "app":
	default:
		return fmt.Errorf("scheme must be http, https, or app, got %q", scheme)
	}
	if rest == "" {
		return fmt.Errorf("missing host")
	}
	if strings.ContainsAny(rest, "/?#") {
		return fmt.Errorf("must not contain a path, query, or fragment")
	}
	return validateOriginHostPort(rest)
}

// validateOriginHostPort validates the host[:port] portion of an origin.
// Accepts: "example.com", "example.com:443", "[::1]", "[::1]:443".
// Rejects: userinfo (@), empty host, multiple unbracketed colons, empty or
// non-numeric port, port out of 1-65535 range.
func validateOriginHostPort(hp string) error {
	if strings.IndexByte(hp, '@') >= 0 {
		return fmt.Errorf("must not contain userinfo (@)")
	}

	// Bracketed IPv6 literal: "[...]", optionally followed by ":port".
	if hp[0] == '[' {
		rbracket := strings.IndexByte(hp, ']')
		if rbracket < 0 {
			return fmt.Errorf("IPv6 literal missing closing ']'")
		}
		if rbracket == 1 {
			return fmt.Errorf("IPv6 literal is empty")
		}
		tail := hp[rbracket+1:]
		if tail == "" {
			return nil
		}
		if tail[0] != ':' {
			return fmt.Errorf("unexpected character after IPv6 literal")
		}
		return validateOriginPort(tail[1:])
	}

	idx := strings.IndexByte(hp, ':')
	if idx < 0 {
		return nil
	}
	// Unbracketed form: exactly one colon, separating host from port.
	if strings.IndexByte(hp[idx+1:], ':') >= 0 {
		return fmt.Errorf("host contains multiple colons (IPv6 literals must use [brackets])")
	}
	if idx == 0 {
		return fmt.Errorf("host is empty before port")
	}
	return validateOriginPort(hp[idx+1:])
}

// validateOriginPort checks that p is a decimal port in 1..65535. Zero
// allocations — byte-level arithmetic, no strconv.
func validateOriginPort(p string) error {
	if p == "" {
		return fmt.Errorf("port is empty")
	}
	if len(p) > 5 {
		return fmt.Errorf("port %q is too long", p)
	}
	n := 0
	for i := 0; i < len(p); i++ {
		c := p[i]
		if c < '0' || c > '9' {
			return fmt.Errorf("port %q must be numeric", p)
		}
		n = n*10 + int(c-'0')
	}
	if n < 1 || n > 65535 {
		return fmt.Errorf("port %d out of range 1-65535", n)
	}
	return nil
}

func parseCORSMethods(methods []string) (string, error) {
	if len(methods) == 0 {
		return "", nil
	}
	if len(methods) > maxCORSListSize {
		return "", fmt.Errorf("config: cors.allowed_methods has too many entries (max %d)", maxCORSListSize)
	}
	upper := make([]string, 0, len(methods))
	for _, m := range methods {
		m = strings.TrimSpace(strings.ToUpper(m))
		if m == "" {
			return "", fmt.Errorf("config: cors.allowed_methods contains an empty entry")
		}
		if !validHTTPMethods[m] {
			return "", fmt.Errorf("config: cors.allowed_methods entry %q is not a recognized HTTP method", m)
		}
		upper = append(upper, m)
	}
	return strings.Join(upper, ", "), nil
}

func parseCORSHeaderList(headers []string, field string) (string, error) {
	if len(headers) == 0 {
		return "", nil
	}
	if len(headers) > maxCORSListSize {
		return "", fmt.Errorf("config: cors.%s has too many entries (max %d)", field, maxCORSListSize)
	}
	trimmed := make([]string, 0, len(headers))
	for _, h := range headers {
		h = strings.TrimSpace(h)
		if h == "" {
			return "", fmt.Errorf("config: cors.%s contains an empty entry", field)
		}
		if h != "*" && !isValidHeaderName(h) {
			// Wildcard is allowed by the CORS spec but only meaningful without
			// credentials — callers should avoid combining them.
			return "", fmt.Errorf("config: cors.%s entry %q is not a valid header name", field, h)
		}
		trimmed = append(trimmed, h)
	}
	return strings.Join(trimmed, ", "), nil
}

// isValidHeaderName checks that s is a valid HTTP header field name (RFC 7230 token).
func isValidHeaderName(s string) bool {
	for _, c := range s {
		if !((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '-') {
			return false
		}
	}
	return true
}

func parseBoundedDuration(s, name string) (time.Duration, error) {
	d, err := time.ParseDuration(s)
	if err != nil {
		return 0, fmt.Errorf("config: invalid %s %q: %w", name, s, err)
	}
	if d < minTimeout || d > maxTimeout {
		return 0, fmt.Errorf("config: %s must be between %v and %v, got %v", name, minTimeout, maxTimeout, d)
	}
	return d, nil
}
