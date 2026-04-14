package config

import (
	"encoding/json"
	"fmt"
	"net"
	"os"
	"path/filepath"
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
}

// LocationConfig defines an external proxy location with caching.
type LocationConfig struct {
	Path     string `json:"path"`
	Upstream string `json:"upstream"`
	CacheTTL string `json:"cache_ttl"`
}

// ParsedLocation holds a validated location config.
type ParsedLocation struct {
	Path     string
	Upstream string
	CacheTTL time.Duration
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
}

const (
	minTimeout            = 100 * time.Millisecond
	maxTimeout            = 5 * time.Minute
	maxAllowedBodySize    = 256 * 1024 * 1024 // 256 MB
	maxAllowedConcurrency = 65535
	maxLocations          = 100
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
	for i, loc := range cfg.Locations {
		if loc.Path == "" || loc.Path[0] != '/' {
			return Parsed{}, fmt.Errorf("config: locations[%d].path must be an absolute path starting with /", i)
		}
		if loc.Upstream == "" {
			return Parsed{}, fmt.Errorf("config: locations[%d].upstream must not be empty", i)
		}
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
		parsedLocations = append(parsedLocations, ParsedLocation{
			Path:     loc.Path,
			Upstream: loc.Upstream,
			CacheTTL: ttl,
		})
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
	}, nil
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
