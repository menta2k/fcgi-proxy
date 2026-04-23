package config

import (
	"crypto/md5"
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"testing"
)

func sha256HA1(user, realm, password string) string {
	s := sha256.Sum256([]byte(user + ":" + realm + ":" + password))
	return hex.EncodeToString(s[:])
}

func md5HA1(user, realm, password string) string {
	s := md5.Sum([]byte(user + ":" + realm + ":" + password))
	return hex.EncodeToString(s[:])
}

func TestParse_Auth_Disabled(t *testing.T) {
	cfg := DefaultConfig()
	parsed, err := Parse(cfg)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if parsed.Auth.Enabled {
		t.Error("auth should be disabled by default")
	}
}

func TestParse_Auth_Valid_SHA256(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Auth = AuthConfig{
		Enabled:       true,
		Type:          "digest",
		Realm:         "fcgi-proxy",
		Algorithm:     "SHA-256",
		NonceLifetime: "5m",
		Users: []AuthUser{
			{Username: "alice", HA1: sha256HA1("alice", "fcgi-proxy", "s3cret")},
		},
	}
	parsed, err := Parse(cfg)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !parsed.Auth.Enabled {
		t.Fatal("expected auth enabled")
	}
	if parsed.Auth.AlgorithmName != "SHA-256" {
		t.Errorf("AlgorithmName = %q, want SHA-256", parsed.Auth.AlgorithmName)
	}
	if parsed.Auth.HashHexSize != 64 {
		t.Errorf("HashHexSize = %d, want 64", parsed.Auth.HashHexSize)
	}
	if parsed.Auth.Realm != "fcgi-proxy" {
		t.Errorf("Realm = %q", parsed.Auth.Realm)
	}
	if _, ok := parsed.Auth.Users["alice"]; !ok {
		t.Error("alice should be in user map")
	}
	if len(parsed.Auth.NonceSecret) != 32 {
		t.Errorf("NonceSecret length = %d, want 32", len(parsed.Auth.NonceSecret))
	}
}

func TestParse_Auth_Valid_MD5(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Auth = AuthConfig{
		Enabled:   true,
		Type:      "digest",
		Realm:     "fcgi-proxy",
		Algorithm: "MD5",
		Users: []AuthUser{
			{Username: "alice", HA1: md5HA1("alice", "fcgi-proxy", "s3cret")},
		},
	}
	parsed, err := Parse(cfg)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if parsed.Auth.AlgorithmName != "MD5" {
		t.Errorf("AlgorithmName = %q, want MD5", parsed.Auth.AlgorithmName)
	}
	if parsed.Auth.HashHexSize != 32 {
		t.Errorf("HashHexSize = %d, want 32", parsed.Auth.HashHexSize)
	}
}

func TestParse_Auth_AlgorithmDefault(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Auth = AuthConfig{
		Enabled: true,
		Realm:   "r",
		Users:   []AuthUser{{Username: "a", HA1: sha256HA1("a", "r", "p")}},
	}
	parsed, err := Parse(cfg)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if parsed.Auth.AlgorithmName != "SHA-256" {
		t.Errorf("expected default SHA-256, got %q", parsed.Auth.AlgorithmName)
	}
}

func TestParse_Auth_NonceLifetimeDefault(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Auth = AuthConfig{
		Enabled: true,
		Realm:   "r",
		Users:   []AuthUser{{Username: "a", HA1: sha256HA1("a", "r", "p")}},
	}
	parsed, err := Parse(cfg)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if parsed.Auth.NonceLifetime.Minutes() != 5 {
		t.Errorf("default nonce lifetime = %v, want 5m", parsed.Auth.NonceLifetime)
	}
}

func TestParse_Auth_Invalid(t *testing.T) {
	base := AuthConfig{
		Enabled:   true,
		Type:      "digest",
		Realm:     "r",
		Algorithm: "SHA-256",
		Users:     []AuthUser{{Username: "a", HA1: sha256HA1("a", "r", "p")}},
	}
	tests := []struct {
		name  string
		mutate func(*AuthConfig)
	}{
		{"basic type with digest credentials", func(c *AuthConfig) { c.Type = "basic" }},
		{"bad type", func(c *AuthConfig) { c.Type = "bearer" }},
		{"empty realm", func(c *AuthConfig) { c.Realm = "" }},
		{"realm with quote", func(c *AuthConfig) { c.Realm = `a"b` }},
		{"realm with CRLF", func(c *AuthConfig) { c.Realm = "a\r\nb" }},
		{"bad algorithm", func(c *AuthConfig) { c.Algorithm = "SHA-1" }},
		{"bad nonce lifetime", func(c *AuthConfig) { c.NonceLifetime = "garbage" }},
		{"nonce lifetime too short", func(c *AuthConfig) { c.NonceLifetime = "1s" }},
		{"nonce lifetime too long", func(c *AuthConfig) { c.NonceLifetime = "48h" }},
		{"no users", func(c *AuthConfig) { c.Users = nil }},
		{"empty username", func(c *AuthConfig) { c.Users = []AuthUser{{Username: "", HA1: sha256HA1("", "r", "p")}} }},
		{"colon in username", func(c *AuthConfig) { c.Users = []AuthUser{{Username: "a:b", HA1: sha256HA1("a:b", "r", "p")}} }},
		{"duplicate username", func(c *AuthConfig) {
			c.Users = []AuthUser{
				{Username: "a", HA1: sha256HA1("a", "r", "p1")},
				{Username: "a", HA1: sha256HA1("a", "r", "p2")},
			}
		}},
		{"ha1 wrong length", func(c *AuthConfig) {
			c.Users = []AuthUser{{Username: "a", HA1: "deadbeef"}}
		}},
		{"ha1 wrong length for algorithm", func(c *AuthConfig) {
			c.Algorithm = "MD5"
			c.Users = []AuthUser{{Username: "a", HA1: sha256HA1("a", "r", "p")}} // 64 chars, MD5 wants 32
		}},
		{"ha1 non-hex", func(c *AuthConfig) {
			c.Users = []AuthUser{{Username: "a", HA1: strings.Repeat("z", 64)}}
		}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := DefaultConfig()
			cfg.Auth = base
			tt.mutate(&cfg.Auth)
			if _, err := Parse(cfg); err == nil {
				t.Fatalf("expected error for %q", tt.name)
			}
		})
	}
}
