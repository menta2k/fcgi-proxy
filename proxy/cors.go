package proxy

import (
	"bytes"
	"strconv"

	"github.com/menta2k/fcgi-proxy/config"
	"github.com/valyala/fasthttp"
)

// corsDecision captures what the CORS middleware decided for a request.
type corsDecision struct {
	// handled is true when the middleware has already written the full response
	// (a preflight answer or a rejection). Callers must stop.
	handled bool
	// originAllowed is true when the request carried an Origin that matched the
	// configured allowlist. Response-time CORS headers should only be emitted
	// when this is true.
	originAllowed bool
	// crossOrigin is true when CORS is enabled and the request carried an Origin
	// header. It drives the Vary: Origin emission even for rejected origins, so
	// shared caches do not serve the wrong body cross-origin.
	crossOrigin bool
	// origin is a reference into the fasthttp request header buffer; do not hold
	// past the request handler. Empty for same-origin requests.
	origin []byte
}

// handleCORS inspects the request, answers preflights directly, and reports
// whether simple-request CORS headers should be written on the response.
func handleCORS(ctx *fasthttp.RequestCtx, cfg config.ParsedCORS) corsDecision {
	if !cfg.Enabled {
		return corsDecision{}
	}

	origin := ctx.Request.Header.Peek("Origin")
	if len(origin) == 0 {
		return corsDecision{}
	}

	allowed := originAllowed(cfg, origin)

	// Preflight: OPTIONS with Access-Control-Request-Method.
	if isPreflight(ctx) {
		if !allowed {
			// Cache-safety: emit Vary: Origin even on rejection so a shared
			// cache does not serve this 403 back to an allowed origin.
			ctx.Response.Header.Set("Vary", "Origin")
			ctx.SetStatusCode(fasthttp.StatusForbidden)
			ctx.SetContentType("text/plain")
			ctx.SetBodyString("CORS origin not allowed")
			return corsDecision{handled: true, crossOrigin: true}
		}
		// Reject control characters in the echoed request-headers list before
		// it reaches the response writer. Prevents CRLF injection via a
		// malicious Access-Control-Request-Headers value.
		if reqHeaders := ctx.Request.Header.Peek("Access-Control-Request-Headers"); bytes.ContainsAny(reqHeaders, "\r\n\x00") {
			ctx.Response.Header.Set("Vary", "Origin")
			ctx.SetStatusCode(fasthttp.StatusBadRequest)
			ctx.SetContentType("text/plain")
			ctx.SetBodyString("invalid Access-Control-Request-Headers")
			return corsDecision{handled: true, crossOrigin: true}
		}
		writeCORSHeaders(ctx, cfg, origin, true)
		ctx.SetStatusCode(fasthttp.StatusNoContent)
		ctx.ResetBody()
		return corsDecision{handled: true, originAllowed: true, crossOrigin: true, origin: origin}
	}

	return corsDecision{originAllowed: allowed, crossOrigin: true, origin: origin}
}

// applyCORSResponseHeaders writes Access-Control-* headers on a non-preflight
// response. Safe to call on any response path; no-ops when CORS is disabled or
// the request was same-origin.
func applyCORSResponseHeaders(ctx *fasthttp.RequestCtx, cfg config.ParsedCORS, decision corsDecision) {
	if !cfg.Enabled || !decision.crossOrigin {
		return
	}
	if !decision.originAllowed {
		// Origin wasn't allowed — we emit only Vary: Origin so a shared cache
		// keyed on URL+method doesn't serve this origin-less response back to
		// a client whose origin would have been accepted.
		ctx.Response.Header.Set("Vary", "Origin")
		return
	}
	writeCORSHeaders(ctx, cfg, decision.origin, false)
}

// writeCORSHeaders emits the Access-Control-* headers for the given request.
// When preflight is true, request-specific headers (Max-Age, Allow-Methods,
// Allow-Headers) are included.
func writeCORSHeaders(ctx *fasthttp.RequestCtx, cfg config.ParsedCORS, origin []byte, preflight bool) {
	// Use Set for the first Vary write so repeated invocations don't accumulate
	// duplicate entries. A second Vary (for Access-Control-Request-Headers) is
	// added below with Add.
	ctx.Response.Header.Set("Vary", "Origin")

	if cfg.AllowAllOrigins && !cfg.AllowCredentials {
		ctx.Response.Header.Set("Access-Control-Allow-Origin", "*")
	} else {
		ctx.Response.Header.SetBytesV("Access-Control-Allow-Origin", origin)
	}

	if cfg.AllowCredentials {
		ctx.Response.Header.Set("Access-Control-Allow-Credentials", "true")
	}

	if preflight {
		if cfg.AllowedMethods != "" {
			ctx.Response.Header.Set("Access-Control-Allow-Methods", cfg.AllowedMethods)
		}
		if cfg.AllowedHeaders != "" {
			ctx.Response.Header.Set("Access-Control-Allow-Headers", cfg.AllowedHeaders)
			ctx.Response.Header.Add("Vary", "Access-Control-Request-Headers")
		} else if reqHeaders := ctx.Request.Header.Peek("Access-Control-Request-Headers"); len(reqHeaders) > 0 {
			// Echo the requested headers when none are explicitly configured —
			// same default behavior as rs/cors. CRLF/NUL already rejected above.
			ctx.Response.Header.SetBytesV("Access-Control-Allow-Headers", reqHeaders)
			ctx.Response.Header.Add("Vary", "Access-Control-Request-Headers")
		}
		if cfg.MaxAgeSeconds > 0 {
			ctx.Response.Header.Set("Access-Control-Max-Age", strconv.Itoa(cfg.MaxAgeSeconds))
		}
		return
	}

	if cfg.ExposedHeaders != "" {
		ctx.Response.Header.Set("Access-Control-Expose-Headers", cfg.ExposedHeaders)
	}
}

func isPreflight(ctx *fasthttp.RequestCtx) bool {
	if !ctx.IsOptions() {
		return false
	}
	return len(ctx.Request.Header.Peek("Access-Control-Request-Method")) > 0
}

// originAllowed performs a case-insensitive lookup against the parsed origin
// allowlist. The fast path (already-lowercase origin) is zero-alloc thanks to
// the Go compiler's m[string(byteSlice)] optimization. The slow path copies
// into a fixed-size stack buffer and re-hits the same optimization — also
// zero-alloc — and only lower-cases characters that need it.
func originAllowed(cfg config.ParsedCORS, origin []byte) bool {
	if cfg.AllowAllOrigins {
		return true
	}
	if len(origin) == 0 {
		return false
	}
	// Fast path: origin is already lowercase ASCII.
	if !containsUpperASCII(origin) {
		_, ok := cfg.AllowedOrigins[string(origin)]
		return ok
	}
	// Slow path: lowercase into a stack buffer. Origins longer than the buffer
	// are rejected — anything near 256 bytes is not a legitimate origin.
	var buf [256]byte
	if len(origin) > len(buf) {
		return false
	}
	lowered := buf[:len(origin)]
	for i, b := range origin {
		if b >= 'A' && b <= 'Z' {
			b += 'a' - 'A'
		}
		lowered[i] = b
	}
	_, ok := cfg.AllowedOrigins[string(lowered)]
	return ok
}

// containsUpperASCII reports whether b contains any A-Z byte.
func containsUpperASCII(b []byte) bool {
	for _, c := range b {
		if c >= 'A' && c <= 'Z' {
			return true
		}
	}
	return false
}
