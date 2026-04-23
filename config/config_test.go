package config

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestDefaultConfig(t *testing.T) {
	cfg := DefaultConfig()
	if cfg.Listen != ":8080" {
		t.Errorf("Listen = %q, want :8080", cfg.Listen)
	}
	if cfg.Network != "tcp" {
		t.Errorf("Network = %q, want tcp", cfg.Network)
	}
}

func TestLoad_FileNotFound(t *testing.T) {
	cfg, err := Load("/nonexistent/config.json")
	if err != nil {
		t.Fatalf("expected defaults on missing file, got error: %v", err)
	}
	if cfg.Listen != ":8080" {
		t.Errorf("expected default listen, got %q", cfg.Listen)
	}
}

func TestLoad_ValidJSON(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.json")
	data := []byte(`{"listen": ":9090", "network": "unix", "address": "/tmp/php.sock", "document_root": "/srv/www", "index": "app.php"}`)
	if err := os.WriteFile(path, data, 0644); err != nil {
		t.Fatal(err)
	}

	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.Listen != ":9090" {
		t.Errorf("Listen = %q, want :9090", cfg.Listen)
	}
	if cfg.Network != "unix" {
		t.Errorf("Network = %q, want unix", cfg.Network)
	}
	if cfg.Address != "/tmp/php.sock" {
		t.Errorf("Address = %q", cfg.Address)
	}
}

func TestLoad_InvalidJSON(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.json")
	if err := os.WriteFile(path, []byte("{invalid"), 0644); err != nil {
		t.Fatal(err)
	}

	_, err := Load(path)
	if err == nil {
		t.Fatal("expected error for invalid JSON")
	}
}

func TestParse_Valid(t *testing.T) {
	cfg := DefaultConfig()
	parsed, err := Parse(cfg)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if parsed.DialTimeout.Seconds() != 5 {
		t.Errorf("DialTimeout = %v, want 5s", parsed.DialTimeout)
	}
}

func TestParse_InvalidNetwork(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Network = "udp"
	_, err := Parse(cfg)
	if err == nil {
		t.Fatal("expected error for invalid network")
	}
}

func TestParse_RelativeDocRoot(t *testing.T) {
	cfg := DefaultConfig()
	cfg.DocumentRoot = "relative/path"
	_, err := Parse(cfg)
	if err == nil {
		t.Fatal("expected error for relative document root")
	}
}

func TestParse_EmptyAddress(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Address = ""
	_, err := Parse(cfg)
	if err == nil {
		t.Fatal("expected error for empty address")
	}
}

func TestParse_ZeroTimeout(t *testing.T) {
	cfg := DefaultConfig()
	cfg.DialTimeout = "0s"
	_, err := Parse(cfg)
	if err == nil {
		t.Fatal("expected error for zero timeout")
	}
}

func TestParse_ExcessiveTimeout(t *testing.T) {
	cfg := DefaultConfig()
	cfg.ReadTimeout = "1h"
	_, err := Parse(cfg)
	if err == nil {
		t.Fatal("expected error for excessive timeout")
	}
}

func TestParse_ZeroBodySize(t *testing.T) {
	cfg := DefaultConfig()
	cfg.MaxBodySize = 0
	_, err := Parse(cfg)
	if err == nil {
		t.Fatal("expected error for zero body size")
	}
}

func TestParse_ExcessiveBodySize(t *testing.T) {
	cfg := DefaultConfig()
	cfg.MaxBodySize = 1024 * 1024 * 1024 // 1 GB, exceeds 256 MB cap
	_, err := Parse(cfg)
	if err == nil {
		t.Fatal("expected error for excessive body size")
	}
}

func TestParse_ExcessiveConcurrency(t *testing.T) {
	cfg := DefaultConfig()
	cfg.MaxConcurrency = 100000
	_, err := Parse(cfg)
	if err == nil {
		t.Fatal("expected error for excessive concurrency")
	}
}

func TestParse_IndexWithSlash(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Index = "../evil.php"
	_, err := Parse(cfg)
	if err == nil {
		t.Fatal("expected error for index with path separator")
	}
}

func TestParse_IndexWithNullByte(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Index = "index.php\x00"
	_, err := Parse(cfg)
	if err == nil {
		t.Fatal("expected error for index with null byte")
	}
}

func TestParse_EmptyIndex(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Index = ""
	_, err := Parse(cfg)
	if err == nil {
		t.Fatal("expected error for empty index")
	}
}

func TestParse_InvalidListen(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Listen = "invalid"
	_, err := Parse(cfg)
	if err == nil {
		t.Fatal("expected error for invalid listen address")
	}
}

func TestParse_EmptyListen(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Listen = ""
	_, err := Parse(cfg)
	if err == nil {
		t.Fatal("expected error for empty listen address")
	}
}

func TestParse_ValidListen(t *testing.T) {
	tests := []string{":8080", "0.0.0.0:9090", "[::1]:443"}
	for _, listen := range tests {
		t.Run(listen, func(t *testing.T) {
			cfg := DefaultConfig()
			cfg.Listen = listen
			_, err := Parse(cfg)
			if err != nil {
				t.Fatalf("unexpected error for %q: %v", listen, err)
			}
		})
	}
}

func TestParse_ResponseHeaders_Valid(t *testing.T) {
	cfg := DefaultConfig()
	cfg.ResponseHeaders = map[string]string{
		"X-Frame-Options":        "DENY",
		"X-Content-Type-Options": "nosniff",
	}
	parsed, err := Parse(cfg)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if parsed.ResponseHeaders["X-Frame-Options"] != "DENY" {
		t.Errorf("X-Frame-Options = %q, want DENY", parsed.ResponseHeaders["X-Frame-Options"])
	}
}

func TestParse_ResponseHeaders_InvalidKey(t *testing.T) {
	tests := []struct {
		name string
		key  string
	}{
		{"empty key", ""},
		{"colon in key", "X-Foo:Bar"},
		{"space in key", "X Foo"},
		{"newline in key", "X-Foo\nBar"},
		{"null in key", "X-Foo\x00"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := DefaultConfig()
			cfg.ResponseHeaders = map[string]string{tt.key: "value"}
			_, err := Parse(cfg)
			if err == nil {
				t.Fatalf("expected error for key %q", tt.key)
			}
		})
	}
}

func TestParse_ResponseHeaders_InvalidValue(t *testing.T) {
	tests := []struct {
		name  string
		value string
	}{
		{"CRLF in value", "foo\r\nbar"},
		{"LF in value", "foo\nbar"},
		{"CR in value", "foo\rbar"},
		{"null in value", "foo\x00bar"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := DefaultConfig()
			cfg.ResponseHeaders = map[string]string{"X-Test": tt.value}
			_, err := Parse(cfg)
			if err == nil {
				t.Fatalf("expected error for value %q", tt.value)
			}
		})
	}
}

func TestParse_ResponseHeaders_Nil(t *testing.T) {
	cfg := DefaultConfig()
	cfg.ResponseHeaders = nil
	_, err := Parse(cfg)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestParse_Locations_Valid(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Locations = []LocationConfig{
		{Path: "/apple-app-site-association", Upstream: "https://example.com/aasa", CacheTTL: "1h"},
		{Path: "/.well-known/assetlinks.json", Upstream: "http://cdn.example.com/links.json"},
	}
	parsed, err := Parse(cfg)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(parsed.Locations) != 2 {
		t.Fatalf("got %d locations, want 2", len(parsed.Locations))
	}
	if parsed.Locations[0].CacheTTL != time.Hour {
		t.Errorf("TTL = %v, want 1h", parsed.Locations[0].CacheTTL)
	}
	// Default TTL when not specified.
	if parsed.Locations[1].CacheTTL != 5*time.Minute {
		t.Errorf("default TTL = %v, want 5m", parsed.Locations[1].CacheTTL)
	}
}

func TestParse_Locations_InvalidPath(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Locations = []LocationConfig{
		{Path: "no-leading-slash", Upstream: "https://example.com/foo"},
	}
	_, err := Parse(cfg)
	if err == nil {
		t.Fatal("expected error for path without leading /")
	}
}

func TestParse_Locations_EmptyUpstream(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Locations = []LocationConfig{
		{Path: "/foo", Upstream: ""},
	}
	_, err := Parse(cfg)
	if err == nil {
		t.Fatal("expected error for empty upstream")
	}
}

func TestParse_Locations_BadScheme(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Locations = []LocationConfig{
		{Path: "/foo", Upstream: "ftp://example.com/foo"},
	}
	_, err := Parse(cfg)
	if err == nil {
		t.Fatal("expected error for non-http upstream")
	}
}

func TestParse_Locations_InvalidTTL(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Locations = []LocationConfig{
		{Path: "/foo", Upstream: "https://example.com/foo", CacheTTL: "invalid"},
	}
	_, err := Parse(cfg)
	if err == nil {
		t.Fatal("expected error for invalid TTL")
	}
}

func TestParse_Locations_NegativeTTL(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Locations = []LocationConfig{
		{Path: "/foo", Upstream: "https://example.com/foo", CacheTTL: "-5s"},
	}
	_, err := Parse(cfg)
	if err == nil {
		t.Fatal("expected error for negative TTL")
	}
}

func TestParse_Locations_CredentialsInUpstream(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Locations = []LocationConfig{
		{Path: "/foo", Upstream: "https://user:pass@example.com/foo"},
	}
	_, err := Parse(cfg)
	if err == nil {
		t.Fatal("expected error for credentials in upstream URL")
	}
}

func TestParse_Locations_TooMany(t *testing.T) {
	cfg := DefaultConfig()
	for i := range 101 {
		cfg.Locations = append(cfg.Locations, LocationConfig{
			Path:     fmt.Sprintf("/loc-%d", i),
			Upstream: "https://example.com/",
		})
	}
	_, err := Parse(cfg)
	if err == nil {
		t.Fatal("expected error for too many locations")
	}
}

func TestParse_CORS_Disabled(t *testing.T) {
	cfg := DefaultConfig()
	parsed, err := Parse(cfg)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if parsed.CORS.Enabled {
		t.Error("expected CORS disabled by default")
	}
}

func TestParse_CORS_Valid(t *testing.T) {
	cfg := DefaultConfig()
	cfg.CORS = CORSConfig{
		Enabled:          true,
		AllowedOrigins:   []string{"https://app.example.com", "https://admin.example.com"},
		AllowedMethods:   []string{"get", "POST", "options"},
		AllowedHeaders:   []string{"Content-Type", "Authorization"},
		ExposedHeaders:   []string{"X-Request-Id"},
		AllowCredentials: true,
		MaxAge:           "5m",
	}
	parsed, err := Parse(cfg)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !parsed.CORS.Enabled {
		t.Fatal("expected CORS enabled")
	}
	if parsed.CORS.AllowAllOrigins {
		t.Error("AllowAllOrigins should be false for explicit origins")
	}
	if _, ok := parsed.CORS.AllowedOrigins["https://app.example.com"]; !ok {
		t.Error("expected app.example.com in allowlist")
	}
	if parsed.CORS.AllowedMethods != "GET, POST, OPTIONS" {
		t.Errorf("AllowedMethods = %q, want normalized upper-case join", parsed.CORS.AllowedMethods)
	}
	if parsed.CORS.MaxAgeSeconds != 300 {
		t.Errorf("MaxAgeSeconds = %d, want 300", parsed.CORS.MaxAgeSeconds)
	}
	if !parsed.CORS.AllowCredentials {
		t.Error("expected AllowCredentials true")
	}
}

func TestParse_CORS_Wildcard(t *testing.T) {
	cfg := DefaultConfig()
	cfg.CORS = CORSConfig{
		Enabled:        true,
		AllowedOrigins: []string{"*"},
	}
	parsed, err := Parse(cfg)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !parsed.CORS.AllowAllOrigins {
		t.Error("expected AllowAllOrigins true")
	}
}

func TestParse_CORS_WildcardWithCredentials(t *testing.T) {
	cfg := DefaultConfig()
	cfg.CORS = CORSConfig{
		Enabled:          true,
		AllowedOrigins:   []string{"*"},
		AllowCredentials: true,
	}
	_, err := Parse(cfg)
	if err == nil {
		t.Fatal("expected error mixing wildcard with credentials")
	}
}

func TestParse_CORS_WildcardMixedWithOrigin(t *testing.T) {
	cfg := DefaultConfig()
	cfg.CORS = CORSConfig{
		Enabled:        true,
		AllowedOrigins: []string{"*", "https://app.example.com"},
	}
	_, err := Parse(cfg)
	if err == nil {
		t.Fatal("expected error mixing wildcard with explicit origin")
	}
}

func TestParse_CORS_EmptyOrigins(t *testing.T) {
	cfg := DefaultConfig()
	cfg.CORS = CORSConfig{Enabled: true}
	_, err := Parse(cfg)
	if err == nil {
		t.Fatal("expected error when allowed_origins is empty")
	}
}

func TestParse_CORS_InvalidOrigins(t *testing.T) {
	tests := []struct {
		name   string
		origin string
	}{
		{"missing scheme", "example.com"},
		{"bad scheme", "ftp://example.com"},
		{"with path", "https://example.com/foo"},
		{"with query", "https://example.com?x=1"},
		{"whitespace", "https://exa mple.com"},
		{"empty", ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := DefaultConfig()
			cfg.CORS = CORSConfig{
				Enabled:        true,
				AllowedOrigins: []string{tt.origin},
			}
			if _, err := Parse(cfg); err == nil {
				t.Fatalf("expected error for origin %q", tt.origin)
			}
		})
	}
}

func TestParse_CORS_NullOrigin(t *testing.T) {
	cfg := DefaultConfig()
	cfg.CORS = CORSConfig{
		Enabled:        true,
		AllowedOrigins: []string{"null"},
	}
	if _, err := Parse(cfg); err != nil {
		t.Fatalf("expected \"null\" origin to be accepted, got %v", err)
	}
}

func TestParse_CORS_InvalidMethod(t *testing.T) {
	cfg := DefaultConfig()
	cfg.CORS = CORSConfig{
		Enabled:        true,
		AllowedOrigins: []string{"https://app.example.com"},
		AllowedMethods: []string{"GET", "TRACE"},
	}
	if _, err := Parse(cfg); err == nil {
		t.Fatal("expected error for TRACE method")
	}
}

func TestParse_CORS_InvalidHeaderName(t *testing.T) {
	cfg := DefaultConfig()
	cfg.CORS = CORSConfig{
		Enabled:        true,
		AllowedOrigins: []string{"https://app.example.com"},
		AllowedHeaders: []string{"Content Type"}, // space is invalid
	}
	if _, err := Parse(cfg); err == nil {
		t.Fatal("expected error for invalid header name")
	}
}

func TestParse_CORS_InvalidMaxAge(t *testing.T) {
	tests := []struct {
		name   string
		maxAge string
	}{
		{"garbage", "not-a-duration"},
		{"negative", "-5s"},
		{"excessive", "100h"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := DefaultConfig()
			cfg.CORS = CORSConfig{
				Enabled:        true,
				AllowedOrigins: []string{"https://app.example.com"},
				MaxAge:         tt.maxAge,
			}
			if _, err := Parse(cfg); err == nil {
				t.Fatalf("expected error for max_age %q", tt.maxAge)
			}
		})
	}
}

func TestParse_CORS_HeaderWildcard(t *testing.T) {
	cfg := DefaultConfig()
	cfg.CORS = CORSConfig{
		Enabled:        true,
		AllowedOrigins: []string{"https://app.example.com"},
		AllowedHeaders: []string{"*"},
	}
	parsed, err := Parse(cfg)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if parsed.CORS.AllowedHeaders != "*" {
		t.Errorf("AllowedHeaders = %q, want \"*\"", parsed.CORS.AllowedHeaders)
	}
}

func TestParse_CORS_ZeroMaxAgeOmitted(t *testing.T) {
	cfg := DefaultConfig()
	cfg.CORS = CORSConfig{
		Enabled:        true,
		AllowedOrigins: []string{"https://app.example.com"},
	}
	parsed, err := Parse(cfg)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if parsed.CORS.MaxAgeSeconds != 0 {
		t.Errorf("MaxAgeSeconds = %d, want 0 when unset", parsed.CORS.MaxAgeSeconds)
	}
}

func TestParse_CORS_NullOriginWithCredentialsRejected(t *testing.T) {
	cfg := DefaultConfig()
	cfg.CORS = CORSConfig{
		Enabled:          true,
		AllowedOrigins:   []string{"https://app.example.com", "null"},
		AllowCredentials: true,
	}
	_, err := Parse(cfg)
	if err == nil {
		t.Fatal("expected error combining \"null\" origin with allow_credentials")
	}
}

func TestParse_CORS_NullOriginWithoutCredentialsAllowed(t *testing.T) {
	cfg := DefaultConfig()
	cfg.CORS = CORSConfig{
		Enabled:        true,
		AllowedOrigins: []string{"null"},
	}
	if _, err := Parse(cfg); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestParse_CORS_OriginsLowercased(t *testing.T) {
	cfg := DefaultConfig()
	cfg.CORS = CORSConfig{
		Enabled:        true,
		AllowedOrigins: []string{"HTTPS://App.Example.COM"},
	}
	parsed, err := Parse(cfg)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if _, ok := parsed.CORS.AllowedOrigins["https://app.example.com"]; !ok {
		t.Errorf("expected origin to be lowercased in allowlist, got keys: %v", parsed.CORS.AllowedOrigins)
	}
}

func TestParse_CORS_HeaderListTrimmed(t *testing.T) {
	cfg := DefaultConfig()
	cfg.CORS = CORSConfig{
		Enabled:        true,
		AllowedOrigins: []string{"https://app.example.com"},
		AllowedHeaders: []string{"  Authorization  ", " Content-Type "},
	}
	parsed, err := Parse(cfg)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	want := "Authorization, Content-Type"
	if parsed.CORS.AllowedHeaders != want {
		t.Errorf("AllowedHeaders = %q, want %q", parsed.CORS.AllowedHeaders, want)
	}
}

func TestParse_CORS_ConflictWithResponseHeaders(t *testing.T) {
	tests := []string{
		"Access-Control-Allow-Origin",
		"access-control-allow-credentials",
		"ACCESS-CONTROL-EXPOSE-HEADERS",
	}
	for _, name := range tests {
		t.Run(name, func(t *testing.T) {
			cfg := DefaultConfig()
			cfg.ResponseHeaders = map[string]string{name: "*"}
			cfg.CORS = CORSConfig{
				Enabled:        true,
				AllowedOrigins: []string{"https://app.example.com"},
			}
			if _, err := Parse(cfg); err == nil {
				t.Fatalf("expected error for response_headers %q combined with enabled CORS", name)
			}
		})
	}
}

func TestParse_CORS_ResponseHeadersOKWhenCORSDisabled(t *testing.T) {
	cfg := DefaultConfig()
	cfg.ResponseHeaders = map[string]string{"Access-Control-Allow-Origin": "*"}
	if _, err := Parse(cfg); err != nil {
		t.Fatalf("unexpected error with CORS disabled: %v", err)
	}
}

func TestParse_CORS_MaxAgeDurationConversion(t *testing.T) {
	cases := []struct {
		input string
		want  int
	}{
		{"30s", 30},
		{"10m", 600},
		{"1h", 3600},
	}
	for _, tc := range cases {
		t.Run(tc.input, func(t *testing.T) {
			cfg := DefaultConfig()
			cfg.CORS = CORSConfig{
				Enabled:        true,
				AllowedOrigins: []string{"https://app.example.com"},
				MaxAge:         tc.input,
			}
			parsed, err := Parse(cfg)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if parsed.CORS.MaxAgeSeconds != tc.want {
				t.Errorf("MaxAgeSeconds = %d, want %d", parsed.CORS.MaxAgeSeconds, tc.want)
			}
		})
	}
}

