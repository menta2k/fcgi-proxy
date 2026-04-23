package config

import (
	"crypto/md5"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"hash"
	"strings"
	"time"
)

// AuthConfig is the JSON shape for HTTP authentication configuration.
// Supported schemes: "digest" (RFC 7616) and "basic" (RFC 7617).
type AuthConfig struct {
	Enabled       bool       `json:"enabled"`
	Type          string     `json:"type"`            // "digest" or "basic"
	Realm         string     `json:"realm"`           // appears in the WWW-Authenticate challenge
	Algorithm     string     `json:"algorithm"`       // digest only: "SHA-256" (default) or "MD5"
	NonceLifetime string     `json:"nonce_lifetime"`  // digest only: how long a nonce stays valid
	Users         []AuthUser `json:"users"`           // inline user database
}

// AuthUser is a single credential entry.
//   - For Digest auth, set HA1 = lowercase hex of H(username:realm:password)
//     matching the configured algorithm (32 hex chars for MD5, 64 for SHA-256).
//   - For Basic auth, set PasswordHash to a bcrypt hash (starts with "$2a$",
//     "$2b$", or "$2y$"). Generate with `htpasswd -B -n username`.
type AuthUser struct {
	Username     string `json:"username"`
	HA1          string `json:"ha1,omitempty"`
	PasswordHash string `json:"password_hash,omitempty"`
}

// Auth scheme names stored on ParsedAuth.Type.
const (
	AuthTypeDigest = "digest"
	AuthTypeBasic  = "basic"
)

// ParsedAuth is the validated, runtime-ready auth configuration. User
// credentials are decoded once at parse time; digest-only fields are zero
// for basic auth and vice versa.
type ParsedAuth struct {
	Enabled bool
	Type    string // AuthTypeDigest or AuthTypeBasic
	Realm   string
	// Users maps username → credential bytes. For digest, the value is the
	// raw HA1 (hex-decoded). For basic, it is the raw bcrypt hash bytes.
	// The map is built once at parse time and treated read-only at request time.
	Users map[string][]byte
	// Digest-only fields. Zero-valued when Type == AuthTypeBasic.
	AlgorithmName string           // "SHA-256" or "MD5"
	HashNew       func() hash.Hash // constructor for the digest algorithm
	HashHexSize   int              // 32 (MD5) or 64 (SHA-256)
	NonceLifetime time.Duration
	// NonceSecret is a 32-byte random key used to HMAC-sign stateless nonces.
	// Regenerated on every process start; clients with an outdated nonce
	// receive a stale=true challenge and re-authenticate transparently.
	NonceSecret []byte
}

const (
	minNonceLifetime = 30 * time.Second
	maxNonceLifetime = 24 * time.Hour
	defaultNonceLife = 5 * time.Minute
	maxAuthUsers     = 1000
	nonceSecretSize  = 32
)

// parseAuth validates AuthConfig and returns a ParsedAuth. When auth is
// disabled the returned value is the zero ParsedAuth.
func parseAuth(c AuthConfig) (ParsedAuth, error) {
	if !c.Enabled {
		return ParsedAuth{}, nil
	}

	authType := strings.ToLower(strings.TrimSpace(c.Type))
	if authType == "" {
		authType = AuthTypeDigest
	}
	switch authType {
	case AuthTypeDigest, AuthTypeBasic:
	default:
		return ParsedAuth{}, fmt.Errorf("config: auth.type %q is not supported (expected \"digest\" or \"basic\")", c.Type)
	}

	realm := strings.TrimSpace(c.Realm)
	if realm == "" {
		return ParsedAuth{}, fmt.Errorf("config: auth.realm must not be empty when auth is enabled")
	}
	if strings.ContainsAny(realm, "\r\n\x00\"") {
		return ParsedAuth{}, fmt.Errorf("config: auth.realm must not contain CR, LF, NUL, or double-quote")
	}

	if len(c.Users) == 0 {
		return ParsedAuth{}, fmt.Errorf("config: auth.users must contain at least one entry when auth is enabled")
	}
	if len(c.Users) > maxAuthUsers {
		return ParsedAuth{}, fmt.Errorf("config: auth.users has %d entries, max is %d", len(c.Users), maxAuthUsers)
	}

	if authType == AuthTypeDigest {
		return parseDigestAuth(c, realm)
	}
	return parseBasicAuth(c, realm)
}

func parseDigestAuth(c AuthConfig, realm string) (ParsedAuth, error) {
	algName, hashNew, hashHex, err := parseAuthAlgorithm(c.Algorithm)
	if err != nil {
		return ParsedAuth{}, err
	}

	lifetime := defaultNonceLife
	if c.NonceLifetime != "" {
		d, parseErr := time.ParseDuration(c.NonceLifetime)
		if parseErr != nil {
			return ParsedAuth{}, fmt.Errorf("config: invalid auth.nonce_lifetime %q: %w", c.NonceLifetime, parseErr)
		}
		if d < minNonceLifetime || d > maxNonceLifetime {
			return ParsedAuth{}, fmt.Errorf("config: auth.nonce_lifetime must be between %v and %v, got %v", minNonceLifetime, maxNonceLifetime, d)
		}
		lifetime = d
	}

	users := make(map[string][]byte, len(c.Users))
	for i, u := range c.Users {
		username, err := validateAuthUsername(u.Username, i)
		if err != nil {
			return ParsedAuth{}, err
		}
		if _, dup := users[username]; dup {
			return ParsedAuth{}, fmt.Errorf("config: auth.users[%d].username %q is duplicated", i, username)
		}
		if u.PasswordHash != "" {
			return ParsedAuth{}, fmt.Errorf("config: auth.users[%d].password_hash is for basic auth; use ha1 with digest", i)
		}
		ha1 := strings.TrimSpace(u.HA1)
		if len(ha1) != hashHex {
			return ParsedAuth{}, fmt.Errorf("config: auth.users[%d].ha1 length %d does not match algorithm %s (expected %d hex chars)", i, len(ha1), algName, hashHex)
		}
		raw, hexErr := hex.DecodeString(strings.ToLower(ha1))
		if hexErr != nil {
			return ParsedAuth{}, fmt.Errorf("config: auth.users[%d].ha1 is not valid hex: %w", i, hexErr)
		}
		users[username] = raw
	}

	secret := make([]byte, nonceSecretSize)
	if _, err := rand.Read(secret); err != nil {
		return ParsedAuth{}, fmt.Errorf("config: generate auth nonce secret: %w", err)
	}

	return ParsedAuth{
		Enabled:       true,
		Type:          AuthTypeDigest,
		Realm:         realm,
		AlgorithmName: algName,
		HashNew:       hashNew,
		HashHexSize:   hashHex,
		NonceLifetime: lifetime,
		Users:         users,
		NonceSecret:   secret,
	}, nil
}

func parseBasicAuth(c AuthConfig, realm string) (ParsedAuth, error) {
	if c.Algorithm != "" {
		return ParsedAuth{}, fmt.Errorf("config: auth.algorithm is only valid for digest auth")
	}
	if c.NonceLifetime != "" {
		return ParsedAuth{}, fmt.Errorf("config: auth.nonce_lifetime is only valid for digest auth")
	}

	users := make(map[string][]byte, len(c.Users))
	for i, u := range c.Users {
		username, err := validateAuthUsername(u.Username, i)
		if err != nil {
			return ParsedAuth{}, err
		}
		if _, dup := users[username]; dup {
			return ParsedAuth{}, fmt.Errorf("config: auth.users[%d].username %q is duplicated", i, username)
		}
		if u.HA1 != "" {
			return ParsedAuth{}, fmt.Errorf("config: auth.users[%d].ha1 is for digest auth; use password_hash with basic", i)
		}
		hash := strings.TrimSpace(u.PasswordHash)
		if hash == "" {
			return ParsedAuth{}, fmt.Errorf("config: auth.users[%d].password_hash must not be empty", i)
		}
		if !isBcryptHash(hash) {
			return ParsedAuth{}, fmt.Errorf("config: auth.users[%d].password_hash must be a bcrypt hash (starts with $2a$, $2b$, or $2y$) — generate with `htpasswd -B -n %s`", i, username)
		}
		users[username] = []byte(hash)
	}

	return ParsedAuth{
		Enabled: true,
		Type:    AuthTypeBasic,
		Realm:   realm,
		Users:   users,
	}, nil
}

// validateAuthUsername trims, checks for forbidden characters, and returns
// the canonical form.
func validateAuthUsername(raw string, index int) (string, error) {
	username := strings.TrimSpace(raw)
	if username == "" {
		return "", fmt.Errorf("config: auth.users[%d].username must not be empty", index)
	}
	// ':' breaks the HA1 formula (digest) and the userpass split (basic);
	// CR/LF/NUL/quote break header emission.
	if strings.ContainsAny(username, ":\r\n\x00\"") {
		return "", fmt.Errorf("config: auth.users[%d].username must not contain ':', CR, LF, NUL, or double-quote", index)
	}
	return username, nil
}

// isBcryptHash reports whether s has a supported bcrypt prefix. It does NOT
// verify the hash cryptographically — that happens at request time.
func isBcryptHash(s string) bool {
	return len(s) >= 4 && s[0] == '$' && s[1] == '2' &&
		(s[2] == 'a' || s[2] == 'b' || s[2] == 'y') && s[3] == '$'
}

// parseAuthAlgorithm canonicalizes the algorithm name and returns the matching
// constructor and hex-encoded size.
func parseAuthAlgorithm(raw string) (name string, hashNew func() hash.Hash, hexSize int, err error) {
	switch strings.ToUpper(strings.TrimSpace(raw)) {
	case "", "SHA-256", "SHA256":
		return "SHA-256", sha256.New, 64, nil
	case "MD5":
		return "MD5", md5.New, 32, nil
	}
	return "", nil, 0, fmt.Errorf("config: auth.algorithm %q is not supported (expected \"SHA-256\" or \"MD5\")", raw)
}
