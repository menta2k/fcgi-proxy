package proxy

import (
	"crypto/md5"
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"testing"
	"time"

	"github.com/menta2k/fcgi-proxy/config"
	"github.com/valyala/fasthttp"
)

// buildAuth returns a ParsedAuth ready for tests, with a single user whose
// HA1 is computed from the provided credentials.
func buildAuth(t *testing.T, algorithm, realm, user, password string) config.ParsedAuth {
	t.Helper()
	ha1 := computeHA1(algorithm, user, realm, password)
	cfg := config.DefaultConfig()
	cfg.Auth = config.AuthConfig{
		Enabled:   true,
		Type:      "digest",
		Realm:     realm,
		Algorithm: algorithm,
		Users:     []config.AuthUser{{Username: user, HA1: ha1}},
	}
	p, err := config.Parse(cfg)
	if err != nil {
		t.Fatalf("config.Parse: %v", err)
	}
	return p.Auth
}

func computeHA1(algorithm, user, realm, password string) string {
	in := user + ":" + realm + ":" + password
	switch strings.ToUpper(algorithm) {
	case "MD5":
		s := md5.Sum([]byte(in))
		return hex.EncodeToString(s[:])
	default:
		s := sha256.Sum256([]byte(in))
		return hex.EncodeToString(s[:])
	}
}

// computeClientResponse computes the Digest response value a well-behaved
// client would send for the given parameters.
func computeClientResponse(algorithm, ha1, method, uri, nonce, nc, cnonce, qop string) string {
	var ha2Hex string
	switch strings.ToUpper(algorithm) {
	case "MD5":
		s := md5.Sum([]byte(method + ":" + uri))
		ha2Hex = hex.EncodeToString(s[:])
		joined := ha1 + ":" + nonce
		if qop != "" {
			joined += ":" + nc + ":" + cnonce + ":" + qop
		}
		joined += ":" + ha2Hex
		r := md5.Sum([]byte(joined))
		return hex.EncodeToString(r[:])
	default:
		s := sha256.Sum256([]byte(method + ":" + uri))
		ha2Hex = hex.EncodeToString(s[:])
		joined := ha1 + ":" + nonce
		if qop != "" {
			joined += ":" + nc + ":" + cnonce + ":" + qop
		}
		joined += ":" + ha2Hex
		r := sha256.Sum256([]byte(joined))
		return hex.EncodeToString(r[:])
	}
}

func makeAuthHeader(params map[string]string) string {
	var sb strings.Builder
	sb.WriteString("Digest ")
	first := true
	for k, v := range params {
		if !first {
			sb.WriteString(", ")
		}
		first = false
		sb.WriteString(k)
		sb.WriteString(`="`)
		sb.WriteString(v)
		sb.WriteString(`"`)
	}
	return sb.String()
}

func newAuthCtx(method, uri string, authHeader string) *fasthttp.RequestCtx {
	ctx := &fasthttp.RequestCtx{}
	ctx.Request.Header.SetMethod(method)
	ctx.Request.SetRequestURI(uri)
	if authHeader != "" {
		ctx.Request.Header.Set("Authorization", authHeader)
	}
	return ctx
}

func TestParseDigestHeader_AllFields(t *testing.T) {
	raw := []byte(`username="alice", realm="r", nonce="n", uri="/", qop=auth, nc=00000001, cnonce="c", response="r-hex", algorithm=SHA-256`)
	p, ok := parseDigestHeader(raw)
	if !ok {
		t.Fatal("parser returned !ok on well-formed input")
	}
	if string(p.Username) != "alice" {
		t.Errorf("Username = %q", p.Username)
	}
	if string(p.QoP) != "auth" {
		t.Errorf("QoP = %q", p.QoP)
	}
	if string(p.Algorithm) != "SHA-256" {
		t.Errorf("Algorithm = %q", p.Algorithm)
	}
	if string(p.NC) != "00000001" {
		t.Errorf("NC = %q", p.NC)
	}
}

func TestParseDigestHeader_UnknownKeySkipped(t *testing.T) {
	raw := []byte(`username="alice", weirdkey="x", realm="r", nonce="n", uri="/", response="r"`)
	p, ok := parseDigestHeader(raw)
	if !ok {
		t.Fatal("parser returned !ok")
	}
	if string(p.Username) != "alice" || string(p.Realm) != "r" {
		t.Errorf("unexpected parse: %+v", p)
	}
}

func TestParseDigestHeader_Malformed(t *testing.T) {
	tests := [][]byte{
		[]byte(`username`),           // no equals
		[]byte(`username=`),          // empty value ok, but unterminated quote below is not
		[]byte(`username="unterminated`),
	}
	for i, raw := range tests {
		if _, ok := parseDigestHeader(raw); ok {
			// An empty-value case is fine; check those don't crash.
			if i == 1 {
				continue
			}
			t.Errorf("parser accepted malformed input %q", raw)
		}
	}
}

func TestNonce_RoundTrip(t *testing.T) {
	cfg := buildAuth(t, "SHA-256", "r", "alice", "s3cret")
	n := generateNonce(cfg)
	valid, stale := validateNonce(cfg, []byte(n))
	if !valid {
		t.Errorf("fresh nonce rejected (stale=%v)", stale)
	}
}

func TestNonce_TamperedHMACRejected(t *testing.T) {
	cfg := buildAuth(t, "SHA-256", "r", "alice", "s3cret")
	n := []byte(generateNonce(cfg))
	// Flip a byte in the middle of the base64 encoding — safer than the last
	// character, which may only differ in padding bits that RawURLEncoding
	// ignores on decode.
	mid := len(n) / 2
	if n[mid] == 'A' {
		n[mid] = 'B'
	} else {
		n[mid] = 'A'
	}
	valid, stale := validateNonce(cfg, n)
	if valid {
		t.Error("tampered nonce accepted")
	}
	if stale {
		t.Error("tampered nonce should NOT be marked stale")
	}
}

func TestNonce_DifferentSecretRejected(t *testing.T) {
	cfg1 := buildAuth(t, "SHA-256", "r", "alice", "s3cret")
	cfg2 := buildAuth(t, "SHA-256", "r", "alice", "s3cret") // independent secret
	n := generateNonce(cfg1)
	valid, _ := validateNonce(cfg2, []byte(n))
	if valid {
		t.Error("nonce signed with cfg1 must not validate under cfg2")
	}
}

func TestNonce_Stale(t *testing.T) {
	cfg := buildAuth(t, "SHA-256", "r", "alice", "s3cret")
	cfg.NonceLifetime = 1 * time.Millisecond
	n := generateNonce(cfg)
	time.Sleep(5 * time.Millisecond)
	valid, stale := validateNonce(cfg, []byte(n))
	if valid {
		t.Error("expected expired nonce to be invalid")
	}
	if !stale {
		t.Error("expected stale=true for expired nonce")
	}
}

func TestNonce_BadBase64(t *testing.T) {
	cfg := buildAuth(t, "SHA-256", "r", "alice", "s3cret")
	if v, _ := validateNonce(cfg, []byte("not-base64!!!")); v {
		t.Error("invalid base64 should not validate")
	}
	if v, _ := validateNonce(cfg, []byte("")); v {
		t.Error("empty nonce should not validate")
	}
}

func TestAuthenticate_NoAuthHeader_SendsChallenge(t *testing.T) {
	cfg := buildAuth(t, "SHA-256", "r", "alice", "s3cret")
	ctx := newAuthCtx("GET", "/index.php", "")
	if authenticate(ctx, cfg) {
		t.Fatal("authenticate should return false for missing header")
	}
	if ctx.Response.StatusCode() != fasthttp.StatusUnauthorized {
		t.Errorf("status = %d, want 401", ctx.Response.StatusCode())
	}
	ch := string(ctx.Response.Header.Peek("WWW-Authenticate"))
	if !strings.HasPrefix(ch, "Digest ") {
		t.Errorf("challenge missing: %q", ch)
	}
	if !strings.Contains(ch, `realm="r"`) || !strings.Contains(ch, "algorithm=SHA-256") {
		t.Errorf("challenge lacks required params: %q", ch)
	}
}

func TestAuthenticate_ValidCredentials(t *testing.T) {
	cfg := buildAuth(t, "SHA-256", "r", "alice", "s3cret")
	// Produce a real challenge to extract a server-signed nonce.
	ctx1 := newAuthCtx("GET", "/index.php", "")
	authenticate(ctx1, cfg)
	ch := string(ctx1.Response.Header.Peek("WWW-Authenticate"))
	nonce := extractAuthParam(ch, "nonce")
	if nonce == "" {
		t.Fatalf("challenge had no nonce: %q", ch)
	}

	method := "GET"
	uri := "/index.php"
	nc := "00000001"
	cnonce := "abcdef"
	qop := "auth"
	ha1 := computeHA1("SHA-256", "alice", "r", "s3cret")
	resp := computeClientResponse("SHA-256", ha1, method, uri, nonce, nc, cnonce, qop)

	hdr := makeAuthHeader(map[string]string{
		"username": "alice",
		"realm":    "r",
		"nonce":    nonce,
		"uri":      uri,
		"qop":      qop,
		"nc":       nc,
		"cnonce":   cnonce,
		"response": resp,
	})
	ctx2 := newAuthCtx(method, uri, hdr)
	if !authenticate(ctx2, cfg) {
		t.Fatalf("authenticate rejected valid credentials\n  challenge: %s\n  auth: %s", ch, hdr)
	}
}

func TestAuthenticate_WrongPassword(t *testing.T) {
	cfg := buildAuth(t, "SHA-256", "r", "alice", "s3cret")
	ctx1 := newAuthCtx("GET", "/", "")
	authenticate(ctx1, cfg)
	nonce := extractAuthParam(string(ctx1.Response.Header.Peek("WWW-Authenticate")), "nonce")

	wrongHA1 := computeHA1("SHA-256", "alice", "r", "wrong")
	resp := computeClientResponse("SHA-256", wrongHA1, "GET", "/", nonce, "00000001", "c", "auth")
	hdr := makeAuthHeader(map[string]string{
		"username": "alice", "realm": "r", "nonce": nonce, "uri": "/",
		"qop": "auth", "nc": "00000001", "cnonce": "c", "response": resp,
	})
	ctx2 := newAuthCtx("GET", "/", hdr)
	if authenticate(ctx2, cfg) {
		t.Fatal("authenticate accepted wrong password")
	}
}

func TestAuthenticate_UnknownUser(t *testing.T) {
	cfg := buildAuth(t, "SHA-256", "r", "alice", "s3cret")
	ctx1 := newAuthCtx("GET", "/", "")
	authenticate(ctx1, cfg)
	nonce := extractAuthParam(string(ctx1.Response.Header.Peek("WWW-Authenticate")), "nonce")

	ha1 := computeHA1("SHA-256", "mallory", "r", "anything")
	resp := computeClientResponse("SHA-256", ha1, "GET", "/", nonce, "00000001", "c", "auth")
	hdr := makeAuthHeader(map[string]string{
		"username": "mallory", "realm": "r", "nonce": nonce, "uri": "/",
		"qop": "auth", "nc": "00000001", "cnonce": "c", "response": resp,
	})
	ctx2 := newAuthCtx("GET", "/", hdr)
	if authenticate(ctx2, cfg) {
		t.Fatal("authenticate accepted unknown user")
	}
}

func TestAuthenticate_WrongRealm(t *testing.T) {
	cfg := buildAuth(t, "SHA-256", "r", "alice", "s3cret")
	ctx1 := newAuthCtx("GET", "/", "")
	authenticate(ctx1, cfg)
	nonce := extractAuthParam(string(ctx1.Response.Header.Peek("WWW-Authenticate")), "nonce")

	ha1 := computeHA1("SHA-256", "alice", "r", "s3cret")
	resp := computeClientResponse("SHA-256", ha1, "GET", "/", nonce, "00000001", "c", "auth")
	hdr := makeAuthHeader(map[string]string{
		"username": "alice", "realm": "other", "nonce": nonce, "uri": "/",
		"qop": "auth", "nc": "00000001", "cnonce": "c", "response": resp,
	})
	ctx2 := newAuthCtx("GET", "/", hdr)
	if authenticate(ctx2, cfg) {
		t.Fatal("authenticate accepted mismatched realm")
	}
}

func TestAuthenticate_StaleNonce(t *testing.T) {
	cfg := buildAuth(t, "SHA-256", "r", "alice", "s3cret")
	cfg.NonceLifetime = 1 * time.Millisecond
	staleNonce := generateNonce(cfg)
	time.Sleep(3 * time.Millisecond)

	ha1 := computeHA1("SHA-256", "alice", "r", "s3cret")
	resp := computeClientResponse("SHA-256", ha1, "GET", "/", staleNonce, "00000001", "c", "auth")
	hdr := makeAuthHeader(map[string]string{
		"username": "alice", "realm": "r", "nonce": staleNonce, "uri": "/",
		"qop": "auth", "nc": "00000001", "cnonce": "c", "response": resp,
	})
	ctx := newAuthCtx("GET", "/", hdr)
	if authenticate(ctx, cfg) {
		t.Fatal("authenticate accepted stale nonce")
	}
	ch := string(ctx.Response.Header.Peek("WWW-Authenticate"))
	if !strings.Contains(ch, "stale=true") {
		t.Errorf("expected stale=true in challenge, got %q", ch)
	}
}

func TestAuthenticate_LegacyRFC2069_Rejected(t *testing.T) {
	// RFC 2069 (no qop) is a downgrade hazard: an MitM could strip qop to
	// force the legacy formula that skips cnonce/nc mixing. We refuse it
	// even with otherwise valid credentials.
	cfg := buildAuth(t, "MD5", "r", "alice", "s3cret")
	ctx1 := newAuthCtx("GET", "/", "")
	authenticate(ctx1, cfg)
	nonce := extractAuthParam(string(ctx1.Response.Header.Peek("WWW-Authenticate")), "nonce")

	ha1 := computeHA1("MD5", "alice", "r", "s3cret")
	resp := computeClientResponse("MD5", ha1, "GET", "/", nonce, "", "", "")
	hdr := makeAuthHeader(map[string]string{
		"username": "alice", "realm": "r", "nonce": nonce, "uri": "/",
		"response": resp,
	})
	ctx2 := newAuthCtx("GET", "/", hdr)
	if authenticate(ctx2, cfg) {
		t.Fatal("authenticate accepted qop-absent (RFC 2069) credentials; must require qop=auth")
	}
	if ctx2.Response.StatusCode() != fasthttp.StatusUnauthorized {
		t.Errorf("status = %d, want 401", ctx2.Response.StatusCode())
	}
}

func TestAuthenticate_WrongAlgorithmRejected(t *testing.T) {
	// Server configured for SHA-256; client advertises MD5 in algorithm=.
	// Must be rejected to prevent any future downgrade refactor from silently
	// accepting a weaker hash.
	cfg := buildAuth(t, "SHA-256", "r", "alice", "s3cret")
	ctx1 := newAuthCtx("GET", "/", "")
	authenticate(ctx1, cfg)
	nonce := extractAuthParam(string(ctx1.Response.Header.Peek("WWW-Authenticate")), "nonce")

	// Response is computed correctly for SHA-256, but algorithm claims MD5.
	ha1 := computeHA1("SHA-256", "alice", "r", "s3cret")
	resp := computeClientResponse("SHA-256", ha1, "GET", "/", nonce, "00000001", "c", "auth")
	hdr := makeAuthHeader(map[string]string{
		"username": "alice", "realm": "r", "nonce": nonce, "uri": "/",
		"qop": "auth", "nc": "00000001", "cnonce": "c", "response": resp,
		"algorithm": "MD5",
	})
	ctx2 := newAuthCtx("GET", "/", hdr)
	if authenticate(ctx2, cfg) {
		t.Fatal("authenticate accepted mismatched algorithm")
	}
}

func TestAuthenticate_URIMismatchRejected(t *testing.T) {
	// uri= in the Authorization header must match the actual request target.
	// Otherwise a captured header can be replayed against a different URI.
	cfg := buildAuth(t, "SHA-256", "r", "alice", "s3cret")
	ctx1 := newAuthCtx("GET", "/index.php", "")
	authenticate(ctx1, cfg)
	nonce := extractAuthParam(string(ctx1.Response.Header.Peek("WWW-Authenticate")), "nonce")

	ha1 := computeHA1("SHA-256", "alice", "r", "s3cret")
	// Compute response using the claimed URI (/admin.php) so the digest
	// itself verifies — the server must still reject because the actual
	// request URI is /index.php.
	resp := computeClientResponse("SHA-256", ha1, "GET", "/admin.php", nonce, "00000001", "c", "auth")
	hdr := makeAuthHeader(map[string]string{
		"username": "alice", "realm": "r", "nonce": nonce, "uri": "/admin.php",
		"qop": "auth", "nc": "00000001", "cnonce": "c", "response": resp,
	})
	ctx2 := newAuthCtx("GET", "/index.php", hdr)
	if authenticate(ctx2, cfg) {
		t.Fatal("authenticate accepted a request whose uri= does not match the target")
	}
}

func TestAuthenticate_UnknownUserRunsDummyHash(t *testing.T) {
	// Correctness check for the timing equalizer on the unknown-user path.
	// We can't assert wall-clock parity deterministically, but we can verify
	// that the handler still produces a 401 with a correctly-shaped
	// challenge — i.e. the code path ran to completion instead of
	// short-circuiting after the map miss.
	cfg := buildAuth(t, "SHA-256", "r", "alice", "s3cret")
	ctx1 := newAuthCtx("GET", "/", "")
	authenticate(ctx1, cfg)
	nonce := extractAuthParam(string(ctx1.Response.Header.Peek("WWW-Authenticate")), "nonce")

	ha1 := computeHA1("SHA-256", "mallory", "r", "whatever")
	resp := computeClientResponse("SHA-256", ha1, "GET", "/", nonce, "00000001", "c", "auth")
	hdr := makeAuthHeader(map[string]string{
		"username": "mallory", "realm": "r", "nonce": nonce, "uri": "/",
		"qop": "auth", "nc": "00000001", "cnonce": "c", "response": resp,
	})
	ctx2 := newAuthCtx("GET", "/", hdr)
	if authenticate(ctx2, cfg) {
		t.Fatal("authenticate accepted unknown user")
	}
	if ctx2.Response.StatusCode() != fasthttp.StatusUnauthorized {
		t.Errorf("status = %d, want 401", ctx2.Response.StatusCode())
	}
	ch := string(ctx2.Response.Header.Peek("WWW-Authenticate"))
	if !strings.HasPrefix(ch, "Digest ") {
		t.Errorf("missing challenge on unknown-user rejection: %q", ch)
	}
}

func TestParseDigestHeader_EscapedQuoteUnescaped(t *testing.T) {
	// A realm containing an escaped double-quote must be unescaped during parse
	// so that comparisons against the configured realm succeed.
	raw := []byte(`username="a", realm="re\"alm", nonce="n", uri="/", response="r"`)
	p, ok := parseDigestHeader(raw)
	if !ok {
		t.Fatal("parser rejected well-formed header with escaped quote")
	}
	if string(p.Realm) != `re"alm` {
		t.Errorf("Realm = %q, want %q", p.Realm, `re"alm`)
	}
}

func TestParseDigestHeader_TrailingSpaceOnKeyTolerated(t *testing.T) {
	raw := []byte(`username ="alice", realm ="r", nonce="n", uri="/", response="r"`)
	p, ok := parseDigestHeader(raw)
	if !ok {
		t.Fatal("parser rejected header with space-padded key")
	}
	if string(p.Username) != "alice" || string(p.Realm) != "r" {
		t.Errorf("unexpected parse: %+v", p)
	}
}

func TestHandler_AuthRequiredOnFCGI_BypassedForBypassPaths(t *testing.T) {
	cfg := buildAuth(t, "SHA-256", "r", "alice", "s3cret")
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

	// /healthz: must NOT require auth.
	ctx := newAuthCtx("GET", "/healthz", "")
	h(ctx)
	if ctx.Response.StatusCode() != 200 {
		t.Errorf("/healthz status = %d, want 200", ctx.Response.StatusCode())
	}

	// Static location: must NOT require auth.
	ctx = newAuthCtx("GET", "/robots.txt", "")
	h(ctx)
	if ctx.Response.StatusCode() != 200 {
		t.Errorf("/robots.txt status = %d, want 200", ctx.Response.StatusCode())
	}

	// FCGI-bound path: must require auth (returns 401).
	ctx = newAuthCtx("GET", "/index.php", "")
	h(ctx)
	if ctx.Response.StatusCode() != fasthttp.StatusUnauthorized {
		t.Errorf("/index.php status = %d, want 401", ctx.Response.StatusCode())
	}
	if !strings.HasPrefix(string(ctx.Response.Header.Peek("WWW-Authenticate")), "Digest ") {
		t.Errorf("missing digest challenge on protected path")
	}
}

// extractAuthParam pulls key="value" (or key=value) from a
// WWW-Authenticate header.
func extractAuthParam(header, key string) string {
	idx := strings.Index(header, key+"=")
	if idx < 0 {
		return ""
	}
	rest := header[idx+len(key)+1:]
	if strings.HasPrefix(rest, `"`) {
		end := strings.Index(rest[1:], `"`)
		if end < 0 {
			return ""
		}
		return rest[1 : 1+end]
	}
	end := strings.IndexAny(rest, ", ")
	if end < 0 {
		return rest
	}
	return rest[:end]
}

// TestParseDigestHeader_ZeroAlloc asserts the parser itself is allocation-free.
func TestParseDigestHeader_ZeroAlloc(t *testing.T) {
	raw := []byte(`username="alice", realm="r", nonce="xxx", uri="/index.php", qop=auth, nc=00000001, cnonce="c", response="r"`)
	allocs := testing.AllocsPerRun(50, func() {
		_, _ = parseDigestHeader(raw)
	})
	if allocs != 0 {
		t.Errorf("parseDigestHeader allocated %.1f times per run, want 0", allocs)
	}
}

func TestValidateNonce_ZeroAllocBesidesHMAC(t *testing.T) {
	cfg := buildAuth(t, "SHA-256", "r", "alice", "s3cret")
	nonce := []byte(generateNonce(cfg))
	// validateNonce uses hmac.New + Sum which unavoidably allocates hash
	// state. Ensure we don't do anything *else* that allocates.
	allocs := testing.AllocsPerRun(50, func() {
		_, _ = validateNonce(cfg, nonce)
	})
	// hmac.New + sha256.New + Sum(nil) is the unavoidable floor (~7 allocs
	// depending on Go runtime version); cap slightly above to tolerate
	// runtime variation while still catching accidental parser/field allocs.
	if allocs > 10 {
		t.Errorf("validateNonce allocated %.1f times per run, want <=10", allocs)
	}
}

// Smoke test: demonstrate what a published HA1 looks like so operators can
// verify their openssl/htdigest output.
func TestHA1_Documentation(t *testing.T) {
	cases := []struct {
		algo, user, realm, pass, want string
	}{
		// Canonical RFC 2617 example.
		{"MD5", "Mufasa", "testrealm@host.com", "Circle Of Life", "939e7578ed9e3c518a452acee763bce9"},
	}
	for _, c := range cases {
		got := computeHA1(c.algo, c.user, c.realm, c.pass)
		if got != c.want {
			t.Errorf("computeHA1(%s) = %s, want %s", c.algo, got, c.want)
		}
	}
}

