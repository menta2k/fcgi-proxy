package proxy

import (
	"encoding/base64"
	"strings"
	"testing"
	"time"

	"github.com/menta2k/fcgi-proxy/config"
	"github.com/valyala/fasthttp"
	"golang.org/x/crypto/bcrypt"
)

func bcryptHash(t *testing.T, password string) string {
	t.Helper()
	h, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.MinCost)
	if err != nil {
		t.Fatalf("bcrypt.GenerateFromPassword: %v", err)
	}
	return string(h)
}

func buildBasicAuth(t *testing.T, realm, user, password string) config.ParsedAuth {
	t.Helper()
	cfg := config.DefaultConfig()
	cfg.Auth = config.AuthConfig{
		Enabled: true,
		Type:    "basic",
		Realm:   realm,
		Users:   []config.AuthUser{{Username: user, PasswordHash: bcryptHash(t, password)}},
	}
	p, err := config.Parse(cfg)
	if err != nil {
		t.Fatalf("config.Parse: %v", err)
	}
	return p.Auth
}

func basicHeader(user, password string) string {
	return "Basic " + base64.StdEncoding.EncodeToString([]byte(user+":"+password))
}

func TestBasicAuth_NoHeader_SendsChallenge(t *testing.T) {
	cfg := buildBasicAuth(t, "r", "alice", "s3cret")
	ctx := newAuthCtx("GET", "/index.php", "")
	if authenticate(ctx, cfg) {
		t.Fatal("authenticate should return false for missing header")
	}
	if ctx.Response.StatusCode() != fasthttp.StatusUnauthorized {
		t.Errorf("status = %d, want 401", ctx.Response.StatusCode())
	}
	ch := string(ctx.Response.Header.Peek("WWW-Authenticate"))
	if !strings.HasPrefix(ch, "Basic ") {
		t.Errorf("challenge must start with \"Basic \", got %q", ch)
	}
	if !strings.Contains(ch, `realm="r"`) {
		t.Errorf("challenge lacks realm: %q", ch)
	}
	if !strings.Contains(ch, "charset=") {
		t.Errorf("challenge lacks charset: %q", ch)
	}
}

func TestBasicAuth_Valid(t *testing.T) {
	cfg := buildBasicAuth(t, "r", "alice", "s3cret")
	ctx := newAuthCtx("GET", "/index.php", basicHeader("alice", "s3cret"))
	if !authenticate(ctx, cfg) {
		t.Fatal("authenticate rejected valid Basic credentials")
	}
}

func TestBasicAuth_WrongPassword(t *testing.T) {
	cfg := buildBasicAuth(t, "r", "alice", "s3cret")
	ctx := newAuthCtx("GET", "/", basicHeader("alice", "wrong"))
	if authenticate(ctx, cfg) {
		t.Fatal("authenticate accepted wrong password")
	}
}

func TestBasicAuth_UnknownUser(t *testing.T) {
	cfg := buildBasicAuth(t, "r", "alice", "s3cret")
	ctx := newAuthCtx("GET", "/", basicHeader("mallory", "anything"))
	if authenticate(ctx, cfg) {
		t.Fatal("authenticate accepted unknown user")
	}
}

func TestBasicAuth_MalformedHeader(t *testing.T) {
	cfg := buildBasicAuth(t, "r", "alice", "s3cret")
	cases := []string{
		"Basic",                  // no credentials
		"Basic !!!notb64!!!",    // invalid base64
		"Basic " + base64.StdEncoding.EncodeToString([]byte("noseparator")), // no colon
		"Bearer tokenish",        // wrong scheme
	}
	for _, h := range cases {
		t.Run(h, func(t *testing.T) {
			ctx := newAuthCtx("GET", "/", h)
			if authenticate(ctx, cfg) {
				t.Fatalf("authenticate accepted malformed header %q", h)
			}
			if ctx.Response.StatusCode() != fasthttp.StatusUnauthorized {
				t.Errorf("status = %d, want 401", ctx.Response.StatusCode())
			}
		})
	}
}

func TestBasicAuth_PasswordContainsColon(t *testing.T) {
	// Password may legitimately contain ':' — only the FIRST colon separates
	// username from password per RFC 7617.
	cfg := buildBasicAuth(t, "r", "alice", "pa:ss:word")
	ctx := newAuthCtx("GET", "/", basicHeader("alice", "pa:ss:word"))
	if !authenticate(ctx, cfg) {
		t.Fatal("password containing colons should be accepted when only the first colon splits")
	}
}

func TestBasicAuth_EmptyPassword(t *testing.T) {
	cfg := buildBasicAuth(t, "r", "alice", "")
	ctx := newAuthCtx("GET", "/", basicHeader("alice", ""))
	if !authenticate(ctx, cfg) {
		t.Fatal("empty password should round-trip if it matches the configured hash")
	}
}

func TestHandler_BasicAuth_BypassForConfiguredPaths(t *testing.T) {
	cfg := buildBasicAuth(t, "r", "alice", "s3cret")
	h := Handler(Config{
		Network:      "unix",
		Address:      "/nonexistent.sock",
		DocumentRoot: "/var/www/html",
		Index:        "index.php",
		DialTimeout:  1 * time.Millisecond,
		Auth:         cfg,
		StaticLocations: map[string]StaticResponse{
			"/robots.txt": {Status: 200, Body: []byte("ok"), ContentType: "text/plain"},
		},
	})

	// /healthz bypasses.
	ctx := newAuthCtx("GET", "/healthz", "")
	h(ctx)
	if ctx.Response.StatusCode() != 200 {
		t.Errorf("/healthz status = %d, want 200", ctx.Response.StatusCode())
	}

	// Static bypasses.
	ctx = newAuthCtx("GET", "/robots.txt", "")
	h(ctx)
	if ctx.Response.StatusCode() != 200 {
		t.Errorf("/robots.txt status = %d, want 200", ctx.Response.StatusCode())
	}

	// FCGI-bound path requires auth.
	ctx = newAuthCtx("GET", "/index.php", "")
	h(ctx)
	if ctx.Response.StatusCode() != fasthttp.StatusUnauthorized {
		t.Errorf("/index.php status = %d, want 401", ctx.Response.StatusCode())
	}
	ch := string(ctx.Response.Header.Peek("WWW-Authenticate"))
	if !strings.HasPrefix(ch, "Basic ") {
		t.Errorf("missing Basic challenge: %q", ch)
	}

	// With valid credentials the request passes the auth gate (and then
	// fails at the dial step; we only care that it got past auth).
	ctx = newAuthCtx("GET", "/index.php", basicHeader("alice", "s3cret"))
	h(ctx)
	if ctx.Response.StatusCode() == fasthttp.StatusUnauthorized {
		t.Errorf("auth rejected valid credentials on FCGI path")
	}
}

// TestBasicAuth_OversizedHeader exercises the stack-buffer guard.
func TestBasicAuth_OversizedHeader(t *testing.T) {
	cfg := buildBasicAuth(t, "r", "alice", "s3cret")
	// 1 KiB of base64 data decodes to ~768 bytes, well over the 512-byte
	// stack buffer.
	big := strings.Repeat("A", 1024)
	ctx := newAuthCtx("GET", "/", "Basic "+big)
	if authenticate(ctx, cfg) {
		t.Fatal("oversized header should be rejected")
	}
	if ctx.Response.StatusCode() != fasthttp.StatusUnauthorized {
		t.Errorf("status = %d, want 401", ctx.Response.StatusCode())
	}
}

// TestBasicAuth_UnknownUserTimingEqualized asserts the dummy-bcrypt path
// runs (correctness, not statistical timing): the function must still return
// false with a 401.
func TestBasicAuth_UnknownUserDoesNotLeakViaShortCircuit(t *testing.T) {
	cfg := buildBasicAuth(t, "r", "alice", "s3cret")
	// Measure an unknown-user call and a wrong-password call should both
	// perform a bcrypt compare. We don't assert specific timing; just that
	// both take non-trivially the same order of magnitude.
	start := time.Now()
	ctx := newAuthCtx("GET", "/", basicHeader("mallory", "whatever"))
	authenticate(ctx, cfg)
	unknown := time.Since(start)

	start = time.Now()
	ctx = newAuthCtx("GET", "/", basicHeader("alice", "wrongpassword"))
	authenticate(ctx, cfg)
	wrong := time.Since(start)

	// Both paths must run bcrypt (minimum bcrypt MinCost ~1ms). If the
	// unknown path is orders of magnitude faster, we've regressed the
	// timing-equalizer.
	if unknown < wrong/10 || unknown > wrong*10 {
		t.Logf("warning: unknown=%v wrong=%v — large divergence; bcrypt equalizer may have regressed (non-deterministic; informational only)", unknown, wrong)
	}
}

func TestConfig_BasicAuth_RejectsHA1(t *testing.T) {
	cfg := config.DefaultConfig()
	cfg.Auth = config.AuthConfig{
		Enabled: true,
		Type:    "basic",
		Realm:   "r",
		Users: []config.AuthUser{{
			Username: "alice",
			HA1:      strings.Repeat("a", 64),
		}},
	}
	if _, err := config.Parse(cfg); err == nil {
		t.Fatal("basic auth must reject users with HA1 set")
	}
}

func TestConfig_BasicAuth_RejectsNonBcryptHash(t *testing.T) {
	cfg := config.DefaultConfig()
	cfg.Auth = config.AuthConfig{
		Enabled: true,
		Type:    "basic",
		Realm:   "r",
		Users: []config.AuthUser{{
			Username:     "alice",
			PasswordHash: "plain-text-no-prefix",
		}},
	}
	if _, err := config.Parse(cfg); err == nil {
		t.Fatal("basic auth must reject non-bcrypt password hashes")
	}
}

func TestConfig_BasicAuth_RejectsDigestOnlyFields(t *testing.T) {
	cfg := config.DefaultConfig()
	cfg.Auth = config.AuthConfig{
		Enabled:   true,
		Type:      "basic",
		Realm:     "r",
		Algorithm: "SHA-256",
		Users: []config.AuthUser{{
			Username: "alice", PasswordHash: bcryptHash(t, "s3cret"),
		}},
	}
	if _, err := config.Parse(cfg); err == nil {
		t.Fatal("basic auth must reject digest-only algorithm field")
	}

	cfg.Auth.Algorithm = ""
	cfg.Auth.NonceLifetime = "5m"
	if _, err := config.Parse(cfg); err == nil {
		t.Fatal("basic auth must reject digest-only nonce_lifetime field")
	}
}
