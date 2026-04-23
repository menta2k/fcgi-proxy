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
	if authenticate(ctx, cfg, nil) {
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
	if !authenticate(ctx, cfg, nil) {
		t.Fatal("authenticate rejected valid Basic credentials")
	}
}

func TestBasicAuth_WrongPassword(t *testing.T) {
	cfg := buildBasicAuth(t, "r", "alice", "s3cret")
	ctx := newAuthCtx("GET", "/", basicHeader("alice", "wrong"))
	if authenticate(ctx, cfg, nil) {
		t.Fatal("authenticate accepted wrong password")
	}
}

func TestBasicAuth_UnknownUser(t *testing.T) {
	cfg := buildBasicAuth(t, "r", "alice", "s3cret")
	ctx := newAuthCtx("GET", "/", basicHeader("mallory", "anything"))
	if authenticate(ctx, cfg, nil) {
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
			if authenticate(ctx, cfg, nil) {
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
	if !authenticate(ctx, cfg, nil) {
		t.Fatal("password containing colons should be accepted when only the first colon splits")
	}
}

func TestBasicAuth_EmptyPassword(t *testing.T) {
	cfg := buildBasicAuth(t, "r", "alice", "")
	ctx := newAuthCtx("GET", "/", basicHeader("alice", ""))
	if !authenticate(ctx, cfg, nil) {
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
	if authenticate(ctx, cfg, nil) {
		t.Fatal("oversized header should be rejected")
	}
	if ctx.Response.StatusCode() != fasthttp.StatusUnauthorized {
		t.Errorf("status = %d, want 401", ctx.Response.StatusCode())
	}
}

// TestBasicAuth_DummyBcryptCostMatchesMaxUserCost is the deterministic
// replacement for the old timing-smoke test: we assert the dummy hash was
// generated at the same cost as the highest-cost real user hash. That is
// the mechanism by which an unknown-user compare takes the same time as a
// wrong-password compare against the slowest real user.
func TestBasicAuth_DummyBcryptCostMatchesMaxUserCost(t *testing.T) {
	// MinCost keeps the test fast; the contract is that whatever the
	// operator's real hash cost is, the dummy matches it.
	realHash := bcryptHash(t, "s3cret") // generated at bcrypt.MinCost
	cfg := config.DefaultConfig()
	cfg.Auth = config.AuthConfig{
		Enabled: true,
		Type:    "basic",
		Realm:   "r",
		Users:   []config.AuthUser{{Username: "alice", PasswordHash: realHash}},
	}
	parsed, err := config.Parse(cfg)
	if err != nil {
		t.Fatalf("config.Parse: %v", err)
	}
	realCost, err := bcrypt.Cost([]byte(realHash))
	if err != nil {
		t.Fatalf("bcrypt.Cost real: %v", err)
	}
	dummyCost, err := bcrypt.Cost(parsed.Auth.DummyBcrypt)
	if err != nil {
		t.Fatalf("bcrypt.Cost dummy: %v", err)
	}
	if dummyCost != realCost {
		t.Errorf("dummy bcrypt cost = %d, want %d (max user cost)", dummyCost, realCost)
	}
}

func TestBasicAuth_CacheHitSkipsBcrypt(t *testing.T) {
	cfg := buildBasicAuth(t, "r", "alice", "s3cret")
	cache := newPasswordCache(time.Minute, 100)

	// Miss → runs bcrypt → caches.
	ctx := newAuthCtx("GET", "/", basicHeader("alice", "s3cret"))
	if !authenticate(ctx, cfg, cache) {
		t.Fatal("first auth should succeed")
	}
	h, m := cache.Stats()
	if h != 0 || m != 1 {
		t.Errorf("after 1st: hits=%d misses=%d, want 0/1", h, m)
	}
	if cache.Len() != 1 {
		t.Errorf("cache Len = %d, want 1", cache.Len())
	}

	// Hit → no bcrypt work.
	ctx = newAuthCtx("GET", "/", basicHeader("alice", "s3cret"))
	if !authenticate(ctx, cfg, cache) {
		t.Fatal("second auth should succeed via cache")
	}
	h, m = cache.Stats()
	if h != 1 || m != 1 {
		t.Errorf("after 2nd: hits=%d misses=%d, want 1/1", h, m)
	}
}

func TestBasicAuth_WrongPasswordDoesNotCache(t *testing.T) {
	cfg := buildBasicAuth(t, "r", "alice", "s3cret")
	cache := newPasswordCache(time.Minute, 100)

	ctx := newAuthCtx("GET", "/", basicHeader("alice", "wrong"))
	if authenticate(ctx, cfg, cache) {
		t.Fatal("wrong password should not authenticate")
	}
	if cache.Len() != 0 {
		t.Errorf("failures must not populate the cache; Len = %d", cache.Len())
	}
}

func TestBasicAuth_UnknownUserDoesNotCache(t *testing.T) {
	cfg := buildBasicAuth(t, "r", "alice", "s3cret")
	cache := newPasswordCache(time.Minute, 100)

	ctx := newAuthCtx("GET", "/", basicHeader("mallory", "anything"))
	if authenticate(ctx, cfg, cache) {
		t.Fatal("unknown user should not authenticate")
	}
	if cache.Len() != 0 {
		t.Errorf("unknown users must not populate the cache; Len = %d", cache.Len())
	}
	// Also: the cache check must not have been reached on the unknown-user
	// short-circuit, so hits and misses both remain zero.
	h, m := cache.Stats()
	if h != 0 || m != 0 {
		t.Errorf("cache touched on unknown user: hits=%d misses=%d", h, m)
	}
}

func TestBasicAuth_CacheHitSurvivesDistinctContexts(t *testing.T) {
	cfg := buildBasicAuth(t, "r", "alice", "s3cret")
	cache := newPasswordCache(time.Minute, 100)

	for i := 0; i < 5; i++ {
		ctx := newAuthCtx("GET", "/", basicHeader("alice", "s3cret"))
		if !authenticate(ctx, cfg, cache) {
			t.Fatalf("iter %d: auth should succeed", i)
		}
	}
	h, m := cache.Stats()
	if m != 1 {
		t.Errorf("expected exactly 1 bcrypt miss across 5 requests, got %d", m)
	}
	if h != 4 {
		t.Errorf("expected 4 cache hits, got %d", h)
	}
}

// BenchmarkBasicAuth_CachedVsUncached compares the cost of a repeat-auth
// request against an unauthenticated one at a realistic bcrypt cost. Run with:
//
//	go test -run='^$' -bench=BenchmarkBasicAuth_CachedVsUncached ./proxy/
//
// Note: cost=10 bcrypt is ~50ms on typical hardware, so the uncached sub-
// benchmark is intentionally slow — we care about the ratio, not wall time.
func BenchmarkBasicAuth_CachedVsUncached(b *testing.B) {
	// MinCost keeps the bench fast; the ratio (cached ~ns, uncached ~ms)
	// scales linearly with cost, so MinCost is representative.
	hash, err := bcrypt.GenerateFromPassword([]byte("s3cret"), bcrypt.MinCost)
	if err != nil {
		b.Fatal(err)
	}
	cfg := config.DefaultConfig()
	cfg.Auth = config.AuthConfig{
		Enabled: true,
		Type:    "basic",
		Realm:   "r",
		Users:   []config.AuthUser{{Username: "alice", PasswordHash: string(hash)}},
	}
	parsed, err := config.Parse(cfg)
	if err != nil {
		b.Fatal(err)
	}
	header := basicHeader("alice", "s3cret")

	b.Run("uncached", func(b *testing.B) {
		b.ReportAllocs()
		for b.Loop() {
			ctx := newAuthCtx("GET", "/", header)
			if !authenticate(ctx, parsed.Auth, nil) {
				b.Fatal("auth failed")
			}
		}
	})
	b.Run("cached", func(b *testing.B) {
		cache := newPasswordCache(time.Minute, 100)
		// Prime the cache.
		priming := newAuthCtx("GET", "/", header)
		if !authenticate(priming, parsed.Auth, cache) {
			b.Fatal("priming failed")
		}
		b.ResetTimer()
		b.ReportAllocs()
		for b.Loop() {
			ctx := newAuthCtx("GET", "/", header)
			if !authenticate(ctx, parsed.Auth, cache) {
				b.Fatal("cached auth failed")
			}
		}
	})
}

func TestBasicAuth_CacheDisabledNilAlwaysRunsBcrypt(t *testing.T) {
	// With cache==nil the hot path always calls bcrypt. This mirrors the
	// operator explicitly setting password_cache.enabled=false.
	cfg := buildBasicAuth(t, "r", "alice", "s3cret")
	for i := 0; i < 3; i++ {
		ctx := newAuthCtx("GET", "/", basicHeader("alice", "s3cret"))
		if !authenticate(ctx, cfg, nil) {
			t.Fatalf("iter %d: nil cache should still authenticate", i)
		}
	}
}

// With two user hashes at different costs, the dummy must match the MAX.
func TestBasicAuth_DummyBcryptCostMatchesMax(t *testing.T) {
	low, err := bcrypt.GenerateFromPassword([]byte("a"), bcrypt.MinCost)
	if err != nil {
		t.Fatalf("bcrypt.GenerateFromPassword low: %v", err)
	}
	high, err := bcrypt.GenerateFromPassword([]byte("b"), bcrypt.MinCost+2)
	if err != nil {
		t.Fatalf("bcrypt.GenerateFromPassword high: %v", err)
	}
	cfg := config.DefaultConfig()
	cfg.Auth = config.AuthConfig{
		Enabled: true,
		Type:    "basic",
		Realm:   "r",
		Users: []config.AuthUser{
			{Username: "alice", PasswordHash: string(low)},
			{Username: "bob", PasswordHash: string(high)},
		},
	}
	parsed, err := config.Parse(cfg)
	if err != nil {
		t.Fatalf("config.Parse: %v", err)
	}
	got, err := bcrypt.Cost(parsed.Auth.DummyBcrypt)
	if err != nil {
		t.Fatalf("bcrypt.Cost: %v", err)
	}
	if got != bcrypt.MinCost+2 {
		t.Errorf("dummy cost = %d, want %d (max of configured hashes)", got, bcrypt.MinCost+2)
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
