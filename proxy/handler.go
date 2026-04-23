package proxy

import (
	"bytes"
	"fmt"
	"log"
	"net"
	"path"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/menta2k/fcgi-proxy/config"
	"github.com/menta2k/fcgi-proxy/fcgi"
	"github.com/menta2k/fcgi-proxy/proxy/locationcache"
	"github.com/valyala/fasthttp"
)

// Config holds proxy configuration.
type Config struct {
	// Network is the FastCGI upstream network type ("tcp" or "unix").
	Network string
	// Address is the FastCGI upstream address (e.g., "127.0.0.1:9000" or "/run/php/php-fpm.sock").
	Address string
	// DocumentRoot is the root directory for PHP scripts on the upstream server.
	DocumentRoot string
	// Index is the default index file (default: "index.php").
	Index string
	// ListenPort is the port the proxy listens on (for SERVER_PORT).
	ListenPort string
	// DialTimeout for upstream connections.
	DialTimeout time.Duration
	// ReadTimeout for upstream reads.
	ReadTimeout time.Duration
	// WriteTimeout for upstream writes.
	WriteTimeout time.Duration
	// ResponseHeaders are additional headers added to every response.
	ResponseHeaders map[string]string
	// Locations defines external proxy locations with caching.
	Locations []locationcache.Location
	// LocationCache is an optional pre-built cache (for testing). If set, Locations is ignored.
	LocationCache *locationcache.Cache
	// Pool configures the FastCGI connection pool.
	Pool fcgi.PoolConfig
	// CORS configures Cross-Origin Resource Sharing. When Enabled is false,
	// CORS handling is a no-op.
	CORS config.ParsedCORS
}

// Headers that must not be forwarded from the upstream response (lowercase for case-insensitive lookup).
var hopByHopHeaders = map[string]bool{
	"connection":          true,
	"keep-alive":          true,
	"transfer-encoding":   true,
	"te":                  true,
	"trailer":             true,
	"upgrade":             true,
	"proxy-authenticate":  true,
	"proxy-authorization": true,
}

// Headers from the client that must not be forwarded as CGI params (lowercase).
// "proxy" blocks httpoxy (CVE-2016-5385).
var blockedRequestHeaders = map[string]bool{
	"content-type":      true,
	"content-length":    true,
	"connection":        true,
	"transfer-encoding": true,
	"proxy":             true,
	"x-forwarded-for":   true, // prevent client IP spoofing
	"x-real-ip":         true, // prevent client IP spoofing
	"trailer":           true, // HTTP framing detail, not relevant to CGI
}


// Handler creates a fasthttp.RequestHandler that proxies to the FastCGI upstream.
func Handler(cfg Config) fasthttp.RequestHandler {
	if cfg.Index == "" {
		cfg.Index = "index.php"
	}
	if cfg.ListenPort == "" {
		cfg.ListenPort = "80"
	}

	client := fcgi.NewClient(fcgi.ClientConfig{
		Network:      cfg.Network,
		Address:      cfg.Address,
		DialTimeout:  cfg.DialTimeout,
		ReadTimeout:  cfg.ReadTimeout,
		WriteTimeout: cfg.WriteTimeout,
		Pool:         cfg.Pool,
	})

	// Build location cache for external proxy locations.
	var locCache *locationcache.Cache
	if cfg.LocationCache != nil {
		locCache = cfg.LocationCache
	} else if len(cfg.Locations) > 0 {
		locCache = locationcache.New(cfg.Locations, cfg.ReadTimeout)
	}

	cleanDocRoot := filepath.Clean(cfg.DocumentRoot)

	return func(ctx *fasthttp.RequestCtx) {
		// CORS runs first so preflights are answered without touching the
		// upstream and so every response path can receive CORS headers.
		corsResult := handleCORS(ctx, cfg.CORS)
		if corsResult.handled {
			return
		}

		uriPath := string(ctx.URI().Path())

		// Health check endpoint — responds without touching the upstream.
		// Intentionally skips response_headers injection (health checks go to
		// load balancers, not browsers — security headers are not needed here).
		if uriPath == "/healthz" {
			ctx.SetStatusCode(fasthttp.StatusOK)
			ctx.SetContentType("text/plain")
			ctx.SetBodyString("ok")
			applyCORSResponseHeaders(ctx, cfg.CORS, corsResult)
			return
		}

		// Serve from location cache if the path matches a configured location.
		if locCache != nil {
			if loc, ok := locCache.Match(uriPath); ok {
				serveLocationCache(ctx, locCache, loc, cfg.ResponseHeaders)
				applyCORSResponseHeaders(ctx, cfg.CORS, corsResult)
				return
			}
		}

		// Reject null bytes in the URI — prevents null byte injection into CGI params.
		if strings.ContainsRune(uriPath, 0) || strings.ContainsRune(string(ctx.URI().QueryString()), 0) {
			ctx.Error("Bad Request", fasthttp.StatusBadRequest)
			return
		}

		scriptFilename, scriptName, pathInfo, err := resolveScript(uriPath, cleanDocRoot, cfg)
		if err != nil {
			ctx.Error("Not Found", fasthttp.StatusNotFound)
			return
		}

		body := ctx.PostBody()
		params := buildParams(ctx, cfg, cleanDocRoot, scriptFilename, scriptName, pathInfo, body)

		req := fcgi.Request{
			Params: params,
		}
		if len(body) > 0 {
			req.Stdin = bytes.NewReader(body)
		}

		resp, err := client.Do(req)
		if err != nil {
			log.Printf("fcgi upstream error: %v", err)
			ctx.Error("Bad Gateway", fasthttp.StatusBadGateway)
			return
		}

		if len(resp.Stderr) > 0 {
			log.Printf("fcgi stderr: %s", truncate(resp.Stderr, 4096))
		}

		ctx.SetStatusCode(resp.StatusCode)

		requestPath := string(ctx.URI().Path())
		for key, vals := range resp.Headers {
			if hopByHopHeaders[strings.ToLower(key)] {
				continue
			}
			for _, val := range vals {
				if strings.EqualFold(key, "Location") && strings.HasPrefix(val, "./") {
					val = fixRelativeLocation(requestPath, val)
				}
				ctx.Response.Header.Add(key, val)
			}
		}

		// Add configured response headers. Uses Set (not Add) so configured values
		// override any same-named header from the upstream. Be careful not to override
		// application-critical headers like Set-Cookie or Content-Type unless intended.
		for key, val := range cfg.ResponseHeaders {
			ctx.Response.Header.Set(key, val)
		}

		ctx.SetBody(resp.Body)

		// Apply CORS headers last so they take precedence over any upstream or
		// response_headers-provided Access-Control-* values.
		applyCORSResponseHeaders(ctx, cfg.CORS, corsResult)
	}
}

func buildParams(ctx *fasthttp.RequestCtx, cfg Config, docRoot, scriptFilename, scriptName, pathInfo string, body []byte) map[string]string {
	queryString := string(ctx.URI().QueryString())
	method := string(ctx.Method())
	host := string(ctx.Host())
	remoteAddr := ctx.RemoteAddr().String()
	remoteHost, remotePort := splitAddrPort(remoteAddr)

	// Strip port from host for SERVER_NAME (CGI spec expects hostname only).
	serverName := stripPort(host)

	// Derive SERVER_PROTOCOL from the actual request.
	serverProtocol := "HTTP/1.0"
	if ctx.Request.Header.IsHTTP11() {
		serverProtocol = "HTTP/1.1"
	}

	// Pre-size map: 16 base params + ~10 HTTP_ headers + 2 forwarding headers.
	params := make(map[string]string, 28)
	params["GATEWAY_INTERFACE"] = "FastCGI/1.0"
	params["SERVER_PROTOCOL"] = serverProtocol
	params["SERVER_SOFTWARE"] = "fcgi-proxy"
	params["REQUEST_METHOD"] = method
	params["REQUEST_URI"] = string(ctx.RequestURI())
	params["SCRIPT_NAME"] = scriptName
	params["SCRIPT_FILENAME"] = scriptFilename
	params["PATH_INFO"] = pathInfo
	params["QUERY_STRING"] = queryString
	params["DOCUMENT_ROOT"] = docRoot
	params["DOCUMENT_URI"] = scriptName + pathInfo
	params["SERVER_NAME"] = serverName
	params["SERVER_PORT"] = cfg.ListenPort
	params["REMOTE_ADDR"] = remoteHost
	params["REMOTE_PORT"] = remotePort

	contentType := ctx.Request.Header.ContentType()
	if len(contentType) > 0 {
		params["CONTENT_TYPE"] = string(contentType)
	}

	// Derive CONTENT_LENGTH from actual body size, not the header value.
	// This correctly handles chunked transfers where ContentLength() returns -1.
	if len(body) > 0 {
		params["CONTENT_LENGTH"] = strconv.Itoa(len(body))
	}

	if ctx.IsTLS() {
		params["HTTPS"] = "on"
		// SERVER_PORT is already set from cfg.ListenPort above.
	}

	// Reusable buffer for building HTTP_* env key names to avoid
	// per-header string(key) + ToUpper + ReplaceAll allocations.
	var envKeyBuf [256]byte
	corsEnabled := cfg.CORS.Enabled
	for key, val := range ctx.Request.Header.All() {
		// Check blocklist using byte comparison to avoid string(key) allocation.
		if isBlockedHeader(key) {
			continue
		}
		// When the proxy is the CORS authority, do not forward Origin or the
		// Access-Control-Request-* preflight negotiation headers to the
		// backend — prevents dual-CORS authority and duplicate response
		// headers from backend-emitted CORS logic.
		if corsEnabled && isCORSRequestHeader(key) {
			continue
		}

		// Build "HTTP_" + UPPER(key) with - replaced by _, in a single pass.
		envKey, ok := buildEnvKey(envKeyBuf[:0], key)
		if !ok {
			continue
		}
		envKeyStr := string(envKey)

		v := string(val)
		// Comma-join duplicate headers per RFC 3875 §4.1.18.
		if existing, existsAlready := params[envKeyStr]; existsAlready {
			params[envKeyStr] = existing + ", " + v
		} else {
			params[envKeyStr] = v
		}
	}

	// Set authoritative forwarding headers from the actual remote address.
	params["HTTP_X_FORWARDED_FOR"] = remoteHost
	params["HTTP_X_REAL_IP"] = remoteHost

	return params
}

// resolveScript determines SCRIPT_FILENAME, SCRIPT_NAME, and PATH_INFO from the URI.
// Returns an error if the resolved path escapes the document root.
func resolveScript(uri, docRoot string, cfg Config) (scriptFilename, scriptName, pathInfo string, err error) {
	scriptName, pathInfo = splitScriptPath(uri, cfg.Index)

	// Clean the script path and join with docroot.
	cleaned := filepath.Clean("/" + scriptName)
	scriptFilename = filepath.Join(docRoot, cleaned)

	// Verify the result is still under the document root.
	rel, relErr := filepath.Rel(docRoot, scriptFilename)
	if relErr != nil || rel == ".." || strings.HasPrefix(rel, "../") {
		return "", "", "", fmt.Errorf("path traversal blocked: %s", uri)
	}

	scriptName = cleaned

	// Clean PATH_INFO to remove .. sequences before passing to upstream.
	if pathInfo != "" {
		pathInfo = path.Clean(pathInfo)
	}

	return scriptFilename, scriptName, pathInfo, nil
}

// splitScriptPath splits the URI into script name and path info.
// Only .php extensions are detected; all other URIs route through the index file.
// This matches the front-controller pattern used by Laravel, Symfony, WordPress, etc.
func splitScriptPath(uri, index string) (scriptName, pathInfo string) {
	lowerURI := strings.ToLower(uri)
	if strings.HasSuffix(lowerURI, ".php") {
		return uri, ""
	}
	if idx := strings.Index(lowerURI, ".php/"); idx != -1 {
		return uri[:idx+4], uri[idx+4:]
	}
	if uri == "/" || strings.HasSuffix(uri, "/") {
		return uri + index, ""
	}
	return "/" + index, uri
}

// fixRelativeLocation resolves a relative ./ Location URL against the request path.
// Uses path (not filepath) to produce correct URL paths on all platforms.
// Preserves trailing slashes from the original location.
func fixRelativeLocation(requestPath, location string) string {
	trailingSlash := strings.HasSuffix(location, "/")
	dir := requestPath
	if !strings.HasSuffix(dir, "/") {
		dir = path.Dir(dir)
	}
	result := path.Join(dir, location[2:])
	if !strings.HasPrefix(result, "/") {
		result = "/" + result
	}
	if trailingSlash && !strings.HasSuffix(result, "/") {
		result += "/"
	}
	return result
}

// splitAddrPort splits a remote address into host and port using net.SplitHostPort.
// Correctly handles IPv6 addresses like [::1]:8080.
func splitAddrPort(addr string) (string, string) {
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return addr, "0"
	}
	return host, port
}

// stripPort removes the port from a host:port string.
// Rejects null bytes and control characters that could pollute CGI params.
func stripPort(hostport string) string {
	host, _, err := net.SplitHostPort(hostport)
	if err != nil {
		host = hostport
	}
	if strings.ContainsAny(host, "\x00\r\n") {
		return "localhost"
	}
	return host
}

func truncate(data []byte, maxLen int) []byte {
	if len(data) <= maxLen {
		return data
	}
	return data[:maxLen]
}

// isBlockedHeader checks if a header name (as bytes) matches the blocklist.
// Uses byte-level toLower with a fixed stack buffer — zero heap allocations.
// All blocked headers are shorter than 64 bytes; longer keys are not blocked.
func isBlockedHeader(key []byte) bool {
	if len(key) > 64 {
		return false
	}
	var lowerBuf [64]byte
	lower := lowerBuf[:len(key)]
	for i, b := range key {
		if b >= 'A' && b <= 'Z' {
			b += 'a' - 'A'
		}
		lower[i] = b
	}
	return blockedRequestHeaders[string(lower)]
}

// isCORSRequestHeader reports whether a header name (as bytes) identifies a
// CORS negotiation header that must not reach the FCGI backend when the proxy
// is the CORS authority. Zero-allocation byte-level match.
func isCORSRequestHeader(key []byte) bool {
	switch len(key) {
	case 6: // Origin
		return asciiEqualFold(key, "origin")
	case 29: // Access-Control-Request-Method
		return asciiEqualFold(key, "access-control-request-method")
	case 30: // Access-Control-Request-Headers
		return asciiEqualFold(key, "access-control-request-headers")
	}
	return false
}

// asciiEqualFold compares a byte slice to a lowercase ASCII string of the same
// length, case-insensitively. Zero allocations.
func asciiEqualFold(a []byte, lower string) bool {
	if len(a) != len(lower) {
		return false
	}
	for i := range len(lower) {
		c := a[i]
		if c >= 'A' && c <= 'Z' {
			c += 'a' - 'A'
		}
		if c != lower[i] {
			return false
		}
	}
	return true
}

// buildEnvKey builds "HTTP_" + UPPER(key with - replaced by _) in a single pass.
// Returns the built key and false if any character is not alphanumeric/hyphen,
// or if the key is empty, too long (>251 to fit in 256-byte stack buf), or digit-only.
// Zero heap allocations when len(key) <= 251.
func buildEnvKey(buf, key []byte) ([]byte, bool) {
	if len(key) == 0 || len(key) > 251 {
		return nil, false
	}
	buf = append(buf, "HTTP_"...)
	hasLetter := false
	for _, b := range key {
		switch {
		case b >= 'a' && b <= 'z':
			buf = append(buf, b-('a'-'A'))
			hasLetter = true
		case b >= 'A' && b <= 'Z':
			buf = append(buf, b)
			hasLetter = true
		case b >= '0' && b <= '9':
			buf = append(buf, b)
		case b == '-':
			buf = append(buf, '_')
		default:
			return nil, false
		}
	}
	if !hasLetter {
		return nil, false
	}
	return buf, true
}

// serveLocationCache serves a response from the location cache.
// Only 200 responses are forwarded to clients. Non-200 upstream responses
// result in a 502 Bad Gateway to prevent forwarding arbitrary status codes/bodies.
func serveLocationCache(ctx *fasthttp.RequestCtx, cache *locationcache.Cache, loc locationcache.Location, responseHeaders map[string]string) {
	entry, err := cache.Get(loc)
	if err != nil {
		log.Printf("location cache error for %s: %v", loc.Path, err)
		ctx.Error("Bad Gateway", fasthttp.StatusBadGateway)
		return
	}

	if entry.StatusCode != 200 {
		log.Printf("location cache: upstream %s returned %d", loc.Path, entry.StatusCode)
		ctx.Error("Bad Gateway", fasthttp.StatusBadGateway)
		return
	}

	ctx.SetStatusCode(200)
	if entry.ContentType != "" {
		ctx.SetContentType(entry.ContentType)
	}
	ctx.SetBody(entry.Body)

	if entry.FromCache {
		ctx.Response.Header.Set("X-Cache", "HIT")
	} else {
		ctx.Response.Header.Set("X-Cache", "MISS")
	}

	for key, val := range responseHeaders {
		ctx.Response.Header.Set(key, val)
	}
}
