package proxy

import (
	"encoding/base64"
	"time"

	"github.com/menta2k/fcgi-proxy/config"
	"github.com/valyala/fasthttp"
	"golang.org/x/crypto/bcrypt"
)

// authenticateBasic validates an incoming Basic Authorization header.
// On failure it writes a 401 challenge and returns false. When cache is
// non-nil, a previously-successful (hash, password) pair within the TTL
// window skips the bcrypt verification entirely.
func authenticateBasic(ctx *fasthttp.RequestCtx, cfg config.ParsedAuth, cache *passwordCache) bool {
	auth := ctx.Request.Header.Peek("Authorization")
	if len(auth) < 7 || !byteEqualFold(auth[:5], "basic") || auth[5] != ' ' {
		sendBasicChallenge(ctx, cfg)
		return false
	}
	encoded := auth[6:]

	// Decode base64 into a stack buffer. A realistic "user:password" payload
	// fits comfortably in 512 bytes; anything larger is rejected rather than
	// spilling to heap on a contested hot path.
	var buf [512]byte
	if base64.StdEncoding.DecodedLen(len(encoded)) > len(buf) {
		sendBasicChallenge(ctx, cfg)
		return false
	}
	n, err := base64.StdEncoding.Decode(buf[:], encoded)
	if err != nil {
		sendBasicChallenge(ctx, cfg)
		return false
	}
	decoded := buf[:n]

	// Split on first ':' — RFC 7617 requires exactly one separator.
	sep := -1
	for i, c := range decoded {
		if c == ':' {
			sep = i
			break
		}
	}
	if sep < 0 {
		sendBasicChallenge(ctx, cfg)
		return false
	}
	username := decoded[:sep]
	password := decoded[sep+1:]

	// Timing equalizer: when the user is unknown, compare the supplied
	// password against a dummy bcrypt hash built at the SAME cost as the
	// most-expensive real hash in the configured user map. This makes
	// unknown-user and wrong-password paths run the same wall-clock work,
	// closing the user-enumeration side channel.
	hash, userOK := cfg.Users[string(username)]
	if !userOK {
		_ = bcrypt.CompareHashAndPassword(cfg.DummyBcrypt, password)
		sendBasicChallenge(ctx, cfg)
		return false
	}

	// Fast path: recently-verified credentials skip the bcrypt compare.
	// Only successful outcomes are cached, so a cache hit is proof of a
	// prior full verification against this exact stored hash.
	var key [32]byte
	if cache != nil {
		key = cacheKey(hash, password)
		if cache.check(key, time.Now()) {
			return true
		}
	}

	if err := bcrypt.CompareHashAndPassword(hash, password); err != nil {
		sendBasicChallenge(ctx, cfg)
		return false
	}

	if cache != nil {
		cache.set(key, time.Now())
	}
	return true
}

func sendBasicChallenge(ctx *fasthttp.RequestCtx, cfg config.ParsedAuth) {
	// charset=UTF-8 per RFC 7617 §2.1 makes browsers submit UTF-8 credentials
	// consistently instead of falling back to ISO-8859-1.
	ctx.Response.Header.Set("WWW-Authenticate",
		`Basic realm="`+cfg.Realm+`", charset="UTF-8"`)
	ctx.SetStatusCode(fasthttp.StatusUnauthorized)
	ctx.SetContentType("text/plain; charset=utf-8")
	ctx.SetBodyString("401 Unauthorized")
}
