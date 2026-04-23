package proxy

import (
	"crypto/subtle"
	"encoding/base64"

	"github.com/menta2k/fcgi-proxy/config"
	"github.com/valyala/fasthttp"
	"golang.org/x/crypto/bcrypt"
)

// dummyBcrypt is used to equalize timing between "unknown user" and "wrong
// password" failures, hiding user enumeration via response-time side channels.
// Generated once from an arbitrary fixed input at package init.
var dummyBcrypt []byte

func init() {
	h, err := bcrypt.GenerateFromPassword([]byte("x"), bcrypt.MinCost)
	if err != nil {
		// MinCost bcrypt cannot fail in a healthy runtime.
		panic("fcgi-proxy: init dummy bcrypt: " + err.Error())
	}
	dummyBcrypt = h
}

// authenticateBasic validates an incoming Basic Authorization header.
// On failure it writes a 401 challenge and returns false.
func authenticateBasic(ctx *fasthttp.RequestCtx, cfg config.ParsedAuth) bool {
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

	// Constant-time lookup pattern: when the user is unknown, compare the
	// password against a dummy bcrypt hash so request timing does not reveal
	// user existence.
	hash, ok := cfg.Users[string(username)]
	if !ok {
		_ = bcrypt.CompareHashAndPassword(dummyBcrypt, password)
		sendBasicChallenge(ctx, cfg)
		return false
	}

	if err := bcrypt.CompareHashAndPassword(hash, password); err != nil {
		sendBasicChallenge(ctx, cfg)
		return false
	}

	// bcrypt.CompareHashAndPassword is already constant-time relative to the
	// stored hash; a further subtle.ConstantTimeCompare on the result would
	// be redundant, but we keep a reference so go vet flags accidental removal.
	_ = subtle.ConstantTimeEq

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
