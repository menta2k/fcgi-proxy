package proxy

import (
	"strings"
	"testing"

	"github.com/menta2k/fcgi-proxy/config"
	"github.com/valyala/fasthttp"
)

func enabledCORS(t *testing.T, c config.CORSConfig) config.ParsedCORS {
	t.Helper()
	cfg := config.DefaultConfig()
	cfg.CORS = c
	parsed, err := config.Parse(cfg)
	if err != nil {
		t.Fatalf("unexpected parse error: %v", err)
	}
	return parsed.CORS
}

func newCtx(method, origin, acRequestMethod, acRequestHeaders string) *fasthttp.RequestCtx {
	ctx := &fasthttp.RequestCtx{}
	ctx.Request.Header.SetMethod(method)
	ctx.Request.SetRequestURI("/")
	if origin != "" {
		ctx.Request.Header.Set("Origin", origin)
	}
	if acRequestMethod != "" {
		ctx.Request.Header.Set("Access-Control-Request-Method", acRequestMethod)
	}
	if acRequestHeaders != "" {
		ctx.Request.Header.Set("Access-Control-Request-Headers", acRequestHeaders)
	}
	return ctx
}

func TestHandleCORS_Disabled(t *testing.T) {
	ctx := newCtx("GET", "https://app.example.com", "", "")
	decision := handleCORS(ctx, config.ParsedCORS{Enabled: false})
	if decision.handled || decision.originAllowed {
		t.Fatalf("expected no-op decision, got %+v", decision)
	}
	if got := string(ctx.Response.Header.Peek("Access-Control-Allow-Origin")); got != "" {
		t.Errorf("no CORS headers should be written when disabled, got %q", got)
	}
}

func TestHandleCORS_NoOriginHeader(t *testing.T) {
	cors := enabledCORS(t, config.CORSConfig{
		Enabled:        true,
		AllowedOrigins: []string{"https://app.example.com"},
	})
	ctx := newCtx("GET", "", "", "")
	decision := handleCORS(ctx, cors)
	if decision.handled || decision.originAllowed {
		t.Fatalf("same-origin requests should not trigger CORS, got %+v", decision)
	}
}

func TestHandleCORS_Preflight_Allowed(t *testing.T) {
	cors := enabledCORS(t, config.CORSConfig{
		Enabled:        true,
		AllowedOrigins: []string{"https://app.example.com"},
		AllowedMethods: []string{"GET", "POST"},
		AllowedHeaders: []string{"Content-Type", "Authorization"},
		MaxAge:         "10m",
	})
	ctx := newCtx("OPTIONS", "https://app.example.com", "POST", "Content-Type")
	decision := handleCORS(ctx, cors)
	if !decision.handled {
		t.Fatal("preflight should be handled by middleware")
	}
	if ctx.Response.StatusCode() != fasthttp.StatusNoContent {
		t.Errorf("status = %d, want 204", ctx.Response.StatusCode())
	}
	if got := string(ctx.Response.Header.Peek("Access-Control-Allow-Origin")); got != "https://app.example.com" {
		t.Errorf("Allow-Origin = %q", got)
	}
	if got := string(ctx.Response.Header.Peek("Access-Control-Allow-Methods")); got != "GET, POST" {
		t.Errorf("Allow-Methods = %q", got)
	}
	if got := string(ctx.Response.Header.Peek("Access-Control-Allow-Headers")); got != "Content-Type, Authorization" {
		t.Errorf("Allow-Headers = %q", got)
	}
	if got := string(ctx.Response.Header.Peek("Access-Control-Max-Age")); got != "600" {
		t.Errorf("Max-Age = %q, want 600", got)
	}
	vary := string(ctx.Response.Header.Peek("Vary"))
	if !strings.Contains(vary, "Origin") {
		t.Errorf("Vary = %q, must contain Origin", vary)
	}
}

func TestHandleCORS_Preflight_Denied(t *testing.T) {
	cors := enabledCORS(t, config.CORSConfig{
		Enabled:        true,
		AllowedOrigins: []string{"https://app.example.com"},
		AllowedMethods: []string{"GET"},
	})
	ctx := newCtx("OPTIONS", "https://evil.example.com", "POST", "")
	decision := handleCORS(ctx, cors)
	if !decision.handled {
		t.Fatal("denied preflight should still be terminal")
	}
	if ctx.Response.StatusCode() != fasthttp.StatusForbidden {
		t.Errorf("status = %d, want 403", ctx.Response.StatusCode())
	}
	if got := string(ctx.Response.Header.Peek("Access-Control-Allow-Origin")); got != "" {
		t.Errorf("rejected preflight must not leak Allow-Origin, got %q", got)
	}
}

func TestHandleCORS_SimpleRequest_Allowed(t *testing.T) {
	cors := enabledCORS(t, config.CORSConfig{
		Enabled:        true,
		AllowedOrigins: []string{"https://app.example.com"},
		ExposedHeaders: []string{"X-Request-Id"},
	})
	ctx := newCtx("GET", "https://app.example.com", "", "")
	decision := handleCORS(ctx, cors)
	if decision.handled {
		t.Fatal("simple request must not be terminated by CORS middleware")
	}
	if !decision.originAllowed {
		t.Fatal("expected originAllowed=true for whitelisted origin")
	}

	applyCORSResponseHeaders(ctx, cors, decision)
	if got := string(ctx.Response.Header.Peek("Access-Control-Allow-Origin")); got != "https://app.example.com" {
		t.Errorf("Allow-Origin = %q", got)
	}
	if got := string(ctx.Response.Header.Peek("Access-Control-Expose-Headers")); got != "X-Request-Id" {
		t.Errorf("Expose-Headers = %q", got)
	}
	// Allow-Methods/Headers are preflight-only.
	if got := ctx.Response.Header.Peek("Access-Control-Allow-Methods"); len(got) != 0 {
		t.Errorf("Allow-Methods should be omitted on simple requests, got %q", got)
	}
}

func TestHandleCORS_SimpleRequest_OriginNotAllowed(t *testing.T) {
	cors := enabledCORS(t, config.CORSConfig{
		Enabled:        true,
		AllowedOrigins: []string{"https://app.example.com"},
	})
	ctx := newCtx("GET", "https://other.example.com", "", "")
	decision := handleCORS(ctx, cors)
	if decision.handled {
		t.Fatal("non-preflight requests must not be short-circuited even if origin is unknown")
	}
	if decision.originAllowed {
		t.Fatal("originAllowed must be false for unknown origin")
	}

	applyCORSResponseHeaders(ctx, cors, decision)
	if got := string(ctx.Response.Header.Peek("Access-Control-Allow-Origin")); got != "" {
		t.Errorf("Allow-Origin must be absent for unknown origin, got %q", got)
	}
}

func TestHandleCORS_Wildcard_WithoutCredentials(t *testing.T) {
	cors := enabledCORS(t, config.CORSConfig{
		Enabled:        true,
		AllowedOrigins: []string{"*"},
	})
	ctx := newCtx("GET", "https://anywhere.example.org", "", "")
	decision := handleCORS(ctx, cors)
	applyCORSResponseHeaders(ctx, cors, decision)
	if got := string(ctx.Response.Header.Peek("Access-Control-Allow-Origin")); got != "*" {
		t.Errorf("Allow-Origin = %q, want \"*\"", got)
	}
	if got := string(ctx.Response.Header.Peek("Access-Control-Allow-Credentials")); got != "" {
		t.Errorf("Allow-Credentials must be absent, got %q", got)
	}
}

func TestHandleCORS_Credentials_EchoesOrigin(t *testing.T) {
	cors := enabledCORS(t, config.CORSConfig{
		Enabled:          true,
		AllowedOrigins:   []string{"https://app.example.com"},
		AllowCredentials: true,
	})
	ctx := newCtx("GET", "https://app.example.com", "", "")
	decision := handleCORS(ctx, cors)
	applyCORSResponseHeaders(ctx, cors, decision)
	if got := string(ctx.Response.Header.Peek("Access-Control-Allow-Origin")); got != "https://app.example.com" {
		t.Errorf("Allow-Origin = %q", got)
	}
	if got := string(ctx.Response.Header.Peek("Access-Control-Allow-Credentials")); got != "true" {
		t.Errorf("Allow-Credentials = %q, want true", got)
	}
}

func TestHandleCORS_Preflight_EchoesRequestedHeadersWhenUnset(t *testing.T) {
	cors := enabledCORS(t, config.CORSConfig{
		Enabled:        true,
		AllowedOrigins: []string{"https://app.example.com"},
		AllowedMethods: []string{"GET", "POST"},
	})
	ctx := newCtx("OPTIONS", "https://app.example.com", "POST", "X-Custom,Content-Type")
	decision := handleCORS(ctx, cors)
	if !decision.handled {
		t.Fatal("expected preflight handled")
	}
	if got := string(ctx.Response.Header.Peek("Access-Control-Allow-Headers")); got != "X-Custom,Content-Type" {
		t.Errorf("Allow-Headers = %q, expected echo of request", got)
	}
}

func TestHandler_Preflight_IntegratedWithProxy(t *testing.T) {
	cors := enabledCORS(t, config.CORSConfig{
		Enabled:        true,
		AllowedOrigins: []string{"https://app.example.com"},
		AllowedMethods: []string{"GET", "POST"},
	})
	h := Handler(Config{
		Network:      "tcp",
		Address:      "127.0.0.1:9000",
		DocumentRoot: "/var/www/html",
		Index:        "index.php",
		CORS:         cors,
	})
	ctx := newCtx("OPTIONS", "https://app.example.com", "POST", "")
	h(ctx)
	if ctx.Response.StatusCode() != fasthttp.StatusNoContent {
		t.Errorf("preflight via Handler status = %d, want 204", ctx.Response.StatusCode())
	}
	if got := string(ctx.Response.Header.Peek("Access-Control-Allow-Origin")); got != "https://app.example.com" {
		t.Errorf("Allow-Origin = %q", got)
	}
}

// fasthttp's request parser normalizes CR/LF to spaces inside header values
// before they reach our handler, so the primary CRLF-injection vector is
// already closed at the edge. We still check explicitly in handleCORS as
// defense in depth. This test exercises the NUL-byte branch (fasthttp does not
// strip NUL) and the direct-byte path.
func TestHandleCORS_Preflight_NullByteInRequestHeadersRejected(t *testing.T) {
	cors := enabledCORS(t, config.CORSConfig{
		Enabled:        true,
		AllowedOrigins: []string{"https://app.example.com"},
	})
	ctx := newCtx("OPTIONS", "https://app.example.com", "POST", "X-Custom\x00bogus")
	decision := handleCORS(ctx, cors)
	if !decision.handled {
		t.Fatal("injection attempt must terminate in middleware")
	}
	if ctx.Response.StatusCode() != fasthttp.StatusBadRequest {
		t.Errorf("status = %d, want 400", ctx.Response.StatusCode())
	}
	if got := string(ctx.Response.Header.Peek("Access-Control-Allow-Headers")); got != "" {
		t.Errorf("Allow-Headers must not be written on rejection, got %q", got)
	}
	vary := string(ctx.Response.Header.Peek("Vary"))
	if !strings.Contains(vary, "Origin") {
		t.Errorf("Vary = %q, must contain Origin", vary)
	}
}

// TestHandleCORS_FastHTTPNormalizesCRLF documents the pre-normalization
// behavior we rely on: CR and LF in header values are stripped by fasthttp's
// request parser, so they can never appear in Peek(...) output.
func TestHandleCORS_FastHTTPNormalizesCRLF(t *testing.T) {
	ctx := newCtx("OPTIONS", "https://app.example.com", "POST", "X-Custom\r\nSet-Cookie: x=1")
	got := ctx.Request.Header.Peek("Access-Control-Request-Headers")
	for _, b := range got {
		if b == '\r' || b == '\n' {
			t.Fatalf("fasthttp no longer strips CR/LF from header values (got %q) — the handleCORS CRLF check is no longer dead defense-in-depth", got)
		}
	}
}

func TestHandleCORS_Preflight_Rejection_EmitsVary(t *testing.T) {
	cors := enabledCORS(t, config.CORSConfig{
		Enabled:        true,
		AllowedOrigins: []string{"https://app.example.com"},
	})
	ctx := newCtx("OPTIONS", "https://evil.example.com", "POST", "")
	handleCORS(ctx, cors)
	vary := string(ctx.Response.Header.Peek("Vary"))
	if !strings.Contains(vary, "Origin") {
		t.Errorf("rejection must emit Vary: Origin, got %q", vary)
	}
}

func TestHandleCORS_SimpleRequest_DisallowedOriginStillEmitsVary(t *testing.T) {
	cors := enabledCORS(t, config.CORSConfig{
		Enabled:        true,
		AllowedOrigins: []string{"https://app.example.com"},
	})
	ctx := newCtx("GET", "https://other.example.com", "", "")
	decision := handleCORS(ctx, cors)
	if decision.handled {
		t.Fatal("simple request must not be short-circuited")
	}
	applyCORSResponseHeaders(ctx, cors, decision)
	vary := string(ctx.Response.Header.Peek("Vary"))
	if !strings.Contains(vary, "Origin") {
		t.Errorf("Vary = %q, must contain Origin to prevent cache poisoning", vary)
	}
	if got := string(ctx.Response.Header.Peek("Access-Control-Allow-Origin")); got != "" {
		t.Errorf("Allow-Origin must stay absent for disallowed origin, got %q", got)
	}
}

func TestHandleCORS_OriginCaseInsensitive(t *testing.T) {
	cors := enabledCORS(t, config.CORSConfig{
		Enabled:        true,
		AllowedOrigins: []string{"https://app.example.com"},
	})
	ctx := newCtx("GET", "HTTPS://App.Example.COM", "", "")
	decision := handleCORS(ctx, cors)
	if !decision.originAllowed {
		t.Fatal("upper-case origin should match lower-case allowlist entry")
	}
	applyCORSResponseHeaders(ctx, cors, decision)
	// Response echoes the original (client-supplied) origin bytes verbatim.
	if got := string(ctx.Response.Header.Peek("Access-Control-Allow-Origin")); got != "HTTPS://App.Example.COM" {
		t.Errorf("Allow-Origin = %q, expected echo of client value", got)
	}
}

func TestHandleCORS_VaryNotDuplicated(t *testing.T) {
	cors := enabledCORS(t, config.CORSConfig{
		Enabled:        true,
		AllowedOrigins: []string{"https://app.example.com"},
	})
	ctx := newCtx("GET", "https://app.example.com", "", "")
	decision := handleCORS(ctx, cors)
	applyCORSResponseHeaders(ctx, cors, decision)
	applyCORSResponseHeaders(ctx, cors, decision) // idempotent

	count := 0
	for _, v := range ctx.Response.Header.PeekAll("Vary") {
		if strings.Contains(string(v), "Origin") {
			count++
		}
	}
	if count != 1 {
		t.Errorf("Vary: Origin emitted %d times, want 1", count)
	}
}

func TestIsCORSRequestHeader(t *testing.T) {
	tests := []struct {
		key  string
		want bool
	}{
		{"Origin", true},
		{"origin", true},
		{"ORIGIN", true},
		{"Access-Control-Request-Method", true},
		{"access-control-request-headers", true},
		{"Host", false},
		{"X-Origin", false},
		{"Access-Control-Allow-Origin", false}, // response header, not request
		{"", false},
	}
	for _, tc := range tests {
		t.Run(tc.key, func(t *testing.T) {
			if got := isCORSRequestHeader([]byte(tc.key)); got != tc.want {
				t.Errorf("isCORSRequestHeader(%q) = %v, want %v", tc.key, got, tc.want)
			}
		})
	}
}

func TestOriginAllowed_ZeroAllocFastPath(t *testing.T) {
	cors := enabledCORS(t, config.CORSConfig{
		Enabled:        true,
		AllowedOrigins: []string{"https://app.example.com"},
	})
	origin := []byte("https://app.example.com")
	allocs := testing.AllocsPerRun(100, func() {
		if !originAllowed(cors, origin) {
			t.Fatal("origin should match")
		}
	})
	if allocs != 0 {
		t.Errorf("originAllowed fast path allocated %.1f times per run, want 0", allocs)
	}
}

func TestOriginAllowed_SlowPathCaseFoldZeroAlloc(t *testing.T) {
	cors := enabledCORS(t, config.CORSConfig{
		Enabled:        true,
		AllowedOrigins: []string{"https://app.example.com"},
	})
	origin := []byte("HTTPS://App.Example.COM")
	allocs := testing.AllocsPerRun(100, func() {
		if !originAllowed(cors, origin) {
			t.Fatal("origin should match case-insensitively")
		}
	})
	if allocs != 0 {
		t.Errorf("originAllowed slow path allocated %.1f times per run, want 0", allocs)
	}
}

func TestHandler_Healthz_IncludesCORSWhenOriginMatches(t *testing.T) {
	cors := enabledCORS(t, config.CORSConfig{
		Enabled:        true,
		AllowedOrigins: []string{"https://app.example.com"},
	})
	h := Handler(Config{
		Network:      "tcp",
		Address:      "127.0.0.1:9000",
		DocumentRoot: "/var/www/html",
		Index:        "index.php",
		CORS:         cors,
	})
	ctx := newCtx("GET", "https://app.example.com", "", "")
	ctx.Request.SetRequestURI("/healthz")
	h(ctx)
	if ctx.Response.StatusCode() != fasthttp.StatusOK {
		t.Errorf("status = %d, want 200", ctx.Response.StatusCode())
	}
	if got := string(ctx.Response.Header.Peek("Access-Control-Allow-Origin")); got != "https://app.example.com" {
		t.Errorf("Allow-Origin = %q", got)
	}
}
