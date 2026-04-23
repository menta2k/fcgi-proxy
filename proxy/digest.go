package proxy

import (
	"bytes"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"strings"
	"time"

	"github.com/menta2k/fcgi-proxy/config"
	"github.com/valyala/fasthttp"
)

// digestParams holds byte slices pointing into the original Authorization
// header. Zero-copy: parseDigestHeader does not allocate new strings.
type digestParams struct {
	Username  []byte
	Realm     []byte
	Nonce     []byte
	URI       []byte
	QoP       []byte
	NC        []byte
	CNonce    []byte
	Response  []byte
	Algorithm []byte
	Opaque    []byte
}

// parseDigestHeader parses the bytes after "Digest " in an Authorization
// header. Returns the parsed parameters and true on structural success —
// validation of individual field contents happens in the authenticator.
//
// The parser recognizes: key=value and key="value" (with backslash-escaped
// double quotes inside the quoted form). Unknown keys are silently skipped.
// Leading/trailing whitespace around the key is tolerated so that
// "username =..." is accepted even though RFC 7235 does not require it.
// Values containing backslash escapes are unescaped into a fresh slice —
// well-formed headers (the vast majority) stay zero-alloc.
func parseDigestHeader(b []byte) (digestParams, bool) {
	var p digestParams
	i := 0
	n := len(b)
	for i < n {
		// Skip leading whitespace and commas.
		for i < n && (b[i] == ' ' || b[i] == '\t' || b[i] == ',') {
			i++
		}
		if i >= n {
			break
		}
		// Read key: up to '='.
		keyStart := i
		for i < n && b[i] != '=' && b[i] != ',' {
			i++
		}
		if i >= n || b[i] != '=' {
			return digestParams{}, false
		}
		key := b[keyStart:i]
		// Trim trailing whitespace so "key =value" parses the same as "key=value".
		for len(key) > 0 && (key[len(key)-1] == ' ' || key[len(key)-1] == '\t') {
			key = key[:len(key)-1]
		}
		i++ // consume '='

		// Read value: quoted or bare.
		var val []byte
		if i < n && b[i] == '"' {
			i++ // consume opening quote
			valStart := i
			escaped := false
			for i < n && b[i] != '"' {
				if b[i] == '\\' && i+1 < n {
					escaped = true
					i += 2
					continue
				}
				i++
			}
			if i >= n {
				return digestParams{}, false
			}
			raw := b[valStart:i]
			if escaped {
				val = unescapeQuotedString(raw)
			} else {
				val = raw
			}
			i++ // consume closing quote
		} else {
			valStart := i
			for i < n && b[i] != ',' && b[i] != ' ' && b[i] != '\t' {
				i++
			}
			val = b[valStart:i]
		}

		assignDigestField(&p, key, val)
	}
	return p, true
}

// unescapeQuotedString returns s with each `\X` two-byte escape replaced by
// the single byte X. Allocates once per call — only invoked when the parser
// actually saw a backslash inside the quoted value, which is rare.
func unescapeQuotedString(s []byte) []byte {
	out := make([]byte, 0, len(s))
	for i := 0; i < len(s); i++ {
		if s[i] == '\\' && i+1 < len(s) {
			out = append(out, s[i+1])
			i++
			continue
		}
		out = append(out, s[i])
	}
	return out
}

func assignDigestField(p *digestParams, key, val []byte) {
	// Case-insensitive key match against a small fixed set.
	switch {
	case byteEqualFold(key, "username"):
		p.Username = val
	case byteEqualFold(key, "realm"):
		p.Realm = val
	case byteEqualFold(key, "nonce"):
		p.Nonce = val
	case byteEqualFold(key, "uri"):
		p.URI = val
	case byteEqualFold(key, "qop"):
		p.QoP = val
	case byteEqualFold(key, "nc"):
		p.NC = val
	case byteEqualFold(key, "cnonce"):
		p.CNonce = val
	case byteEqualFold(key, "response"):
		p.Response = val
	case byteEqualFold(key, "algorithm"):
		p.Algorithm = val
	case byteEqualFold(key, "opaque"):
		p.Opaque = val
	}
}

// byteEqualFold compares b to a lowercase ASCII literal for case-insensitive
// equality. Zero-alloc.
func byteEqualFold(b []byte, lower string) bool {
	if len(b) != len(lower) {
		return false
	}
	for i := range len(lower) {
		c := b[i]
		if c >= 'A' && c <= 'Z' {
			c += 'a' - 'A'
		}
		if c != lower[i] {
			return false
		}
	}
	return true
}

// Nonce layout:
//   bytes 0..8    uint64 big-endian unix-nano timestamp
//   bytes 8..24   16 random bytes
//   bytes 24..40  first 16 bytes of HMAC-SHA256(secret, ts||rand)
// Base64 (no padding) gives a 54-byte ASCII nonce.
const (
	nonceRawLen = 40
	nonceTagLen = 16
)

var nonceB64 = base64.RawURLEncoding

// generateNonce produces a fresh stateless nonce.
func generateNonce(cfg config.ParsedAuth) string {
	var raw [nonceRawLen]byte
	binary.BigEndian.PutUint64(raw[0:8], uint64(time.Now().UnixNano()))
	if _, err := rand.Read(raw[8:24]); err != nil {
		// rand.Read only fails on catastrophic OS-level errors; panic is
		// acceptable here. We never reach FCGI without a valid nonce.
		panic("fcgi-proxy: crypto/rand failure: " + err.Error())
	}
	mac := hmac.New(sha256.New, cfg.NonceSecret)
	mac.Write(raw[:24])
	copy(raw[24:], mac.Sum(nil)[:nonceTagLen])
	return nonceB64.EncodeToString(raw[:])
}

// validateNonce checks structural validity, HMAC authenticity, and age.
// Returns (valid, stale). valid=false and stale=true together mean the nonce
// was authentic but too old; clients should retry against a fresh challenge.
func validateNonce(cfg config.ParsedAuth, nonce []byte) (valid, stale bool) {
	if len(nonce) == 0 {
		return false, false
	}
	// Decode into a stack-sized buffer to avoid heap allocation.
	var raw [nonceRawLen]byte
	n, err := nonceB64.Decode(raw[:], nonce)
	if err != nil || n != nonceRawLen {
		return false, false
	}
	mac := hmac.New(sha256.New, cfg.NonceSecret)
	mac.Write(raw[:24])
	expected := mac.Sum(nil)[:nonceTagLen]
	if subtle.ConstantTimeCompare(expected, raw[24:]) != 1 {
		return false, false
	}
	issued := time.Unix(0, int64(binary.BigEndian.Uint64(raw[0:8])))
	age := time.Since(issued)
	if age < 0 || age > cfg.NonceLifetime {
		return false, true
	}
	return true, false
}

// authenticate dispatches the incoming request to the configured auth
// scheme. On failure it writes a 401 challenge and returns false; the caller
// should stop processing but may still apply trailing response headers
// (CORS, response_headers) before returning.
func authenticate(ctx *fasthttp.RequestCtx, cfg config.ParsedAuth) bool {
	if cfg.Type == config.AuthTypeBasic {
		return authenticateBasic(ctx, cfg)
	}
	return authenticateDigest(ctx, cfg)
}

// authenticateDigest validates an RFC 7616 Digest Authorization header.
func authenticateDigest(ctx *fasthttp.RequestCtx, cfg config.ParsedAuth) bool {
	auth := ctx.Request.Header.Peek("Authorization")
	if len(auth) < 7 || !byteEqualFold(auth[:6], "digest") || auth[6] != ' ' {
		sendAuthChallenge(ctx, cfg, false)
		return false
	}
	params, ok := parseDigestHeader(auth[7:])
	if !ok {
		sendAuthChallenge(ctx, cfg, false)
		return false
	}
	if len(params.Username) == 0 || len(params.Nonce) == 0 ||
		len(params.URI) == 0 || len(params.Response) == 0 {
		sendAuthChallenge(ctx, cfg, false)
		return false
	}
	// Realm must match. Constant-time compare: public value, so a timing
	// leak here is harmless, but consistency with the response compare is
	// cleaner and future-proof.
	if len(params.Realm) != len(cfg.RealmBytes) ||
		subtle.ConstantTimeCompare(params.Realm, cfg.RealmBytes) != 1 {
		sendAuthChallenge(ctx, cfg, false)
		return false
	}
	// If the client echoed an algorithm, it must match the one we advertised.
	// Silently accepting a mismatch would be a downgrade hazard if a future
	// refactor ever used params.Algorithm to select the hash function.
	if len(params.Algorithm) > 0 && !byteEqualFold(params.Algorithm, cfg.AlgorithmName) {
		sendAuthChallenge(ctx, cfg, false)
		return false
	}
	// Require qop=auth. Our challenge always advertises it, and accepting a
	// qop-absent response would let an MitM strip qop and force the legacy
	// RFC 2069 formula that lacks cnonce/nc mixing.
	if !byteEqualFold(params.QoP, "auth") {
		sendAuthChallenge(ctx, cfg, false)
		return false
	}
	// The uri= parameter must match the actual request target (RFC 7616 §3.4).
	// Without this check, a captured Authorization header can be replayed
	// against a different URI within the nonce lifetime.
	if !bytes.Equal(params.URI, ctx.RequestURI()) {
		sendAuthChallenge(ctx, cfg, false)
		return false
	}
	// Validate nonce: stale ones get stale=true so clients re-auth silently.
	valid, stale := validateNonce(cfg, params.Nonce)
	if !valid {
		sendAuthChallenge(ctx, cfg, stale)
		return false
	}
	// Username is the map key. A string conversion via m[string(bytes)] is
	// compiler-optimized to zero-alloc for map lookups.
	ha1, userOK := cfg.Users[string(params.Username)]
	if !userOK {
		// Equalize timing with the known-user-wrong-password path by running
		// the same hashing work against a sentinel HA1. Prevents user
		// enumeration via response-time analysis. The compare always fails
		// by construction — DummyHA1 is never a real credential — but
		// constant-time keeps the branch indistinguishable.
		dummy := computeDigestResponse(cfg, cfg.DummyHA1, params, ctx.Method())
		_ = subtle.ConstantTimeCompare(dummy, params.Response)
		sendAuthChallenge(ctx, cfg, false)
		return false
	}
	// Compute expected response (hex-encoded) and compare against the
	// hex-encoded value the client sent, constant-time.
	expected := computeDigestResponse(cfg, ha1, params, ctx.Method())
	if subtle.ConstantTimeCompare(expected, params.Response) != 1 {
		sendAuthChallenge(ctx, cfg, false)
		return false
	}
	return true
}

// computeDigestResponse computes the expected response digest for RFC 7616
// qop="auth". Returns the HEX-encoded digest, matching the format the client
// sends in the `response=` field so a constant-time compare works directly.
//
//	HA2      = H(method:digestURI)
//	response = H(HA1:nonce:nc:cnonce:qop:HA2)
//
// Callers must have already validated that QoP == "auth"; this function
// does not branch on qop content.
func computeDigestResponse(cfg config.ParsedAuth, ha1 []byte, p digestParams, method []byte) []byte {
	h := cfg.HashNew()

	// HA2 = H(method:uri)
	ha1Hex := hexEncode(ha1)
	h.Write(method)
	h.Write([]byte{':'})
	h.Write(p.URI)
	ha2Hex := hexEncode(h.Sum(nil))

	h.Reset()
	h.Write(ha1Hex)
	h.Write([]byte{':'})
	h.Write(p.Nonce)
	h.Write([]byte{':'})
	h.Write(p.NC)
	h.Write([]byte{':'})
	h.Write(p.CNonce)
	h.Write([]byte{':'})
	h.Write(p.QoP)
	h.Write([]byte{':'})
	h.Write(ha2Hex)

	// Hex-encode the final digest for the constant-time compare.
	return hexEncode(h.Sum(nil))
}

// hexEncode returns the lowercase hex encoding of b. Unavoidable allocation
// on the digest hot path — hash output must be hex-stringified for the
// compare against the client's hex response.
func hexEncode(b []byte) []byte {
	out := make([]byte, hex.EncodedLen(len(b)))
	hex.Encode(out, b)
	return out
}

// sendAuthChallenge writes a 401 response with a fresh WWW-Authenticate
// Digest challenge. When stale is true the challenge includes stale=true so
// compliant clients re-authenticate silently.
func sendAuthChallenge(ctx *fasthttp.RequestCtx, cfg config.ParsedAuth, stale bool) {
	nonce := generateNonce(cfg)
	var sb strings.Builder
	sb.Grow(256)
	sb.WriteString(`Digest realm="`)
	sb.WriteString(cfg.Realm)
	sb.WriteString(`", nonce="`)
	sb.WriteString(nonce)
	sb.WriteString(`", algorithm=`)
	sb.WriteString(cfg.AlgorithmName)
	sb.WriteString(`, qop="auth", charset=UTF-8`)
	if stale {
		sb.WriteString(`, stale=true`)
	}
	ctx.Response.Header.Set("WWW-Authenticate", sb.String())
	ctx.SetStatusCode(fasthttp.StatusUnauthorized)
	ctx.SetContentType("text/plain; charset=utf-8")
	ctx.SetBodyString("401 Unauthorized")
}

