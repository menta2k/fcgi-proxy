package proxy

import (
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/valyala/fasthttp"
)

func TestResolveScript_Basic(t *testing.T) {
	cfg := Config{Index: "index.php"}
	docRoot := "/var/www/html"

	tests := []struct {
		name           string
		uri            string
		wantFilename   string
		wantScriptName string
		wantPathInfo   string
		wantErr        bool
	}{
		{
			name:           "direct php file",
			uri:            "/app.php",
			wantFilename:   "/var/www/html/app.php",
			wantScriptName: "/app.php",
			wantPathInfo:   "",
		},
		{
			name:           "php with path info",
			uri:            "/index.php/api/users",
			wantFilename:   "/var/www/html/index.php",
			wantScriptName: "/index.php",
			wantPathInfo:   "/api/users",
		},
		{
			name:           "root path",
			uri:            "/",
			wantFilename:   "/var/www/html/index.php",
			wantScriptName: "/index.php",
			wantPathInfo:   "",
		},
		{
			name:           "directory path",
			uri:            "/admin/",
			wantFilename:   "/var/www/html/admin/index.php",
			wantScriptName: "/admin/index.php",
			wantPathInfo:   "",
		},
		{
			name:           "non-php path uses index",
			uri:            "/api/users",
			wantFilename:   "/var/www/html/index.php",
			wantScriptName: "/index.php",
			wantPathInfo:   "/api/users",
		},
		{
			name:           "nested php file",
			uri:            "/admin/dashboard.php",
			wantFilename:   "/var/www/html/admin/dashboard.php",
			wantScriptName: "/admin/dashboard.php",
			wantPathInfo:   "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			filename, scriptName, pathInfo, err := resolveScript(tt.uri, docRoot, cfg)
			if tt.wantErr {
				if err == nil {
					t.Fatal("expected error, got nil")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if filename != tt.wantFilename {
				t.Errorf("filename = %q, want %q", filename, tt.wantFilename)
			}
			if scriptName != tt.wantScriptName {
				t.Errorf("scriptName = %q, want %q", scriptName, tt.wantScriptName)
			}
			if pathInfo != tt.wantPathInfo {
				t.Errorf("pathInfo = %q, want %q", pathInfo, tt.wantPathInfo)
			}
		})
	}
}

// escapesDocRoot mirrors the production filepath.Rel check to verify
// that a resolved filename stays within the document root.
func escapesDocRoot(filename, docRoot string) bool {
	rel, err := filepath.Rel(docRoot, filename)
	return err != nil || rel == ".." || strings.HasPrefix(rel, "../")
}

func TestResolveScript_PathTraversal(t *testing.T) {
	cfg := Config{Index: "index.php"}
	docRoot := "/var/www/html"

	// These attacks are neutralized by filepath.Clean — they resolve inside docroot.
	// The key invariant is that no result ever escapes docroot.
	neutralized := []struct {
		uri      string
		wantFile string
	}{
		{"/../../../etc/passwd.php", "/var/www/html/etc/passwd.php"},
		{"/../../etc/passwd.php", "/var/www/html/etc/passwd.php"},
		{"//etc/passwd.php", "/var/www/html/etc/passwd.php"},
		{"/admin/../../etc/shadow.php", "/var/www/html/etc/shadow.php"},
		{"/../index.php", "/var/www/html/index.php"},
	}

	for _, tt := range neutralized {
		t.Run(tt.uri, func(t *testing.T) {
			filename, _, _, err := resolveScript(tt.uri, docRoot, cfg)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if filename != tt.wantFile {
				t.Errorf("filename = %q, want %q", filename, tt.wantFile)
			}
		})
	}

	// Verify the filepath.Rel-based invariant: no result escapes docroot.
	for _, tt := range neutralized {
		t.Run("boundary_check_"+tt.uri, func(t *testing.T) {
			filename, _, _, _ := resolveScript(tt.uri, docRoot, cfg)
			if filename != "" && escapesDocRoot(filename, docRoot) {
				t.Errorf("filename %q escapes docroot %q", filename, docRoot)
			}
		})
	}
}

// Verify that adjacent directory names don't pass the boundary check.
func TestEscapesDocRoot_AdjacentDir(t *testing.T) {
	if !escapesDocRoot("/var/www/htmlsibling/index.php", "/var/www/html") {
		t.Error("expected /var/www/htmlsibling to escape /var/www/html")
	}
	if escapesDocRoot("/var/www/html/sub/index.php", "/var/www/html") {
		t.Error("expected /var/www/html/sub to NOT escape /var/www/html")
	}
}

func TestResolveScript_EncodedTraversal(t *testing.T) {
	cfg := Config{Index: "index.php"}
	docRoot := "/var/www/html"

	// Raw percent-encoded characters are treated as literal by filepath.Clean.
	// fasthttp decodes them before they reach the handler, so this tests the
	// fallback behavior if encoded input somehow arrives.
	filename, _, _, err := resolveScript("/..%2F..%2Fetc/passwd.php", docRoot, cfg)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if escapesDocRoot(filename, docRoot) {
		t.Errorf("filename %q escapes docroot", filename)
	}
}

func TestResolveScript_PathTraversal_Safe(t *testing.T) {
	cfg := Config{Index: "index.php"}
	docRoot := "/var/www/html"

	safe := []struct {
		uri      string
		wantFile string
	}{
		{"/index.php", "/var/www/html/index.php"},
		{"/sub/../index.php", "/var/www/html/index.php"},
		{"/./index.php", "/var/www/html/index.php"},
	}

	for _, tt := range safe {
		t.Run(tt.uri, func(t *testing.T) {
			filename, _, _, err := resolveScript(tt.uri, docRoot, cfg)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if filename != tt.wantFile {
				t.Errorf("filename = %q, want %q", filename, tt.wantFile)
			}
		})
	}
}

func TestSplitScriptPath_CaseInsensitive(t *testing.T) {
	tests := []struct {
		uri        string
		wantScript string
	}{
		{"/index.PHP", "/index.PHP"},
		{"/Index.Php", "/Index.Php"},
		{"/test.PHP/path", "/test.PHP"},
	}

	for _, tt := range tests {
		t.Run(tt.uri, func(t *testing.T) {
			script, _ := splitScriptPath(tt.uri, "index.php")
			if script != tt.wantScript {
				t.Errorf("script = %q, want %q", script, tt.wantScript)
			}
		})
	}
}

func TestFixRelativeLocation(t *testing.T) {
	tests := []struct {
		name        string
		requestPath string
		location    string
		want        string
	}{
		{
			name:        "simple relative",
			requestPath: "/admin/page.php",
			location:    "./other",
			want:        "/admin/other",
		},
		{
			name:        "from root",
			requestPath: "/index.php",
			location:    "./login",
			want:        "/login",
		},
		{
			name:        "trailing slash preserved",
			requestPath: "/admin/page.php",
			location:    "./subdir/",
			want:        "/admin/subdir/",
		},
		{
			name:        "directory request path",
			requestPath: "/admin/",
			location:    "./dashboard",
			want:        "/admin/dashboard",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := fixRelativeLocation(tt.requestPath, tt.location)
			if got != tt.want {
				t.Errorf("fixRelativeLocation(%q, %q) = %q, want %q", tt.requestPath, tt.location, got, tt.want)
			}
		})
	}
}

func TestSplitAddrPort(t *testing.T) {
	tests := []struct {
		addr     string
		wantHost string
		wantPort string
	}{
		{"127.0.0.1:9000", "127.0.0.1", "9000"},
		{"localhost", "localhost", "0"},
		{"[::1]:8080", "::1", "8080"},
	}

	for _, tt := range tests {
		t.Run(tt.addr, func(t *testing.T) {
			host, port := splitAddrPort(tt.addr)
			if host != tt.wantHost || port != tt.wantPort {
				t.Errorf("splitAddrPort(%q) = (%q, %q), want (%q, %q)", tt.addr, host, port, tt.wantHost, tt.wantPort)
			}
		})
	}
}

func TestStripPort(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{"example.com:8080", "example.com"},
		{"example.com", "example.com"},
		{"[::1]:443", "::1"},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			got := stripPort(tt.input)
			if got != tt.want {
				t.Errorf("stripPort(%q) = %q, want %q", tt.input, got, tt.want)
			}
		})
	}
}

func TestStripPort_NullByte(t *testing.T) {
	got := stripPort("evil.com\x00")
	if got != "localhost" {
		t.Errorf("stripPort with null byte = %q, want %q", got, "localhost")
	}
}

func TestStripPort_CRLF(t *testing.T) {
	got := stripPort("evil.com\r\ninjected")
	if got != "localhost" {
		t.Errorf("stripPort with CRLF = %q, want %q", got, "localhost")
	}
}

func TestTruncate(t *testing.T) {
	data := []byte("hello world")
	if got := truncate(data, 5); string(got) != "hello" {
		t.Errorf("truncate(11, 5) = %q, want %q", got, "hello")
	}
	if got := truncate(data, 100); string(got) != "hello world" {
		t.Errorf("truncate(11, 100) = %q, want full string", got)
	}
}

func TestIsBlockedHeader_LongKey(t *testing.T) {
	// Keys longer than 64 bytes are never blocked.
	longKey := make([]byte, 100)
	for i := range longKey {
		longKey[i] = 'x'
	}
	if isBlockedHeader(longKey) {
		t.Error("long key should not be blocked")
	}
}

func TestIsBlockedHeader_AllBlocked(t *testing.T) {
	blocked := []string{
		"Content-Type", "content-type", "CONTENT-TYPE",
		"Content-Length", "Connection", "Transfer-Encoding",
		"Proxy", "PROXY", "X-Forwarded-For", "X-Real-IP", "Trailer",
	}
	for _, h := range blocked {
		if !isBlockedHeader([]byte(h)) {
			t.Errorf("%q should be blocked", h)
		}
	}
}

func TestIsBlockedHeader_NotBlocked(t *testing.T) {
	notBlocked := []string{"Accept", "Host", "X-Custom", "Authorization"}
	for _, h := range notBlocked {
		if isBlockedHeader([]byte(h)) {
			t.Errorf("%q should not be blocked", h)
		}
	}
}

func TestBuildEnvKey_Valid(t *testing.T) {
	tests := []struct {
		key  string
		want string
	}{
		{"Accept", "HTTP_ACCEPT"},
		{"x-custom", "HTTP_X_CUSTOM"},
		{"X-Forwarded-Proto", "HTTP_X_FORWARDED_PROTO"},
		{"Host", "HTTP_HOST"},
	}
	var buf [256]byte
	for _, tt := range tests {
		t.Run(tt.key, func(t *testing.T) {
			got, ok := buildEnvKey(buf[:0], []byte(tt.key))
			if !ok {
				t.Fatalf("buildEnvKey(%q) returned false", tt.key)
			}
			if string(got) != tt.want {
				t.Errorf("buildEnvKey(%q) = %q, want %q", tt.key, got, tt.want)
			}
		})
	}
}

func TestBuildEnvKey_Rejected(t *testing.T) {
	tests := []struct {
		name string
		key  string
	}{
		{"empty", ""},
		{"too long", string(make([]byte, 252))},
		{"digit only", "123"},
		{"space", "X Custom"},
		{"colon", "X:Custom"},
		{"underscore", "X_Custom"},
		{"null byte", "X\x00Custom"},
	}
	var buf [256]byte
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, ok := buildEnvKey(buf[:0], []byte(tt.key))
			if ok {
				t.Errorf("buildEnvKey(%q) should be rejected", tt.key)
			}
		})
	}
}

func TestFixRelativeLocation_NoTrailingSlash(t *testing.T) {
	got := fixRelativeLocation("/admin/page.php", "./other")
	if got != "/admin/other" {
		t.Errorf("got %q, want /admin/other", got)
	}
}

func TestResolveScript_CleanPathInfo(t *testing.T) {
	cfg := Config{Index: "index.php"}
	_, _, pathInfo, err := resolveScript("/index.php/../../../etc/passwd", "/var/www/html", cfg)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// path.Clean should remove the .. sequences from PATH_INFO
	if strings.Contains(pathInfo, "..") {
		t.Errorf("pathInfo should be cleaned, got %q", pathInfo)
	}
}

func newHandlerCtx(method, uri string) *fasthttp.RequestCtx {
	ctx := &fasthttp.RequestCtx{}
	ctx.Request.Header.SetMethod(method)
	ctx.Request.SetRequestURI(uri)
	return ctx
}

func TestHandler_StaticLocation_ServesInlineBody(t *testing.T) {
	body := "Sitemap: https://example.com/sitemap.xml\nUser-agent: *\nDisallow:"
	h := Handler(Config{
		Network:      "tcp",
		Address:      "127.0.0.1:9000",
		DocumentRoot: "/var/www/html",
		Index:        "index.php",
		StaticLocations: map[string]StaticResponse{
			"/robots.txt": {Status: 200, Body: []byte(body), ContentType: "text/plain"},
		},
	})
	ctx := newHandlerCtx("GET", "/robots.txt")
	h(ctx)
	if ctx.Response.StatusCode() != 200 {
		t.Errorf("status = %d, want 200", ctx.Response.StatusCode())
	}
	if got := string(ctx.Response.Body()); got != body {
		t.Errorf("body = %q, want %q", got, body)
	}
	if got := string(ctx.Response.Header.ContentType()); got != "text/plain" {
		t.Errorf("content-type = %q", got)
	}
}

func TestHandler_StaticLocation_RespectsResponseHeaders(t *testing.T) {
	h := Handler(Config{
		Network:      "tcp",
		Address:      "127.0.0.1:9000",
		DocumentRoot: "/var/www/html",
		Index:        "index.php",
		ResponseHeaders: map[string]string{
			"X-Frame-Options": "DENY",
		},
		StaticLocations: map[string]StaticResponse{
			"/robots.txt": {Status: 200, Body: []byte("ok"), ContentType: "text/plain"},
		},
	})
	ctx := newHandlerCtx("GET", "/robots.txt")
	h(ctx)
	if got := string(ctx.Response.Header.Peek("X-Frame-Options")); got != "DENY" {
		t.Errorf("X-Frame-Options = %q, want DENY", got)
	}
}

func TestHandler_StaticLocation_OnlyExactPath(t *testing.T) {
	h := Handler(Config{
		// Point at an unreachable unix socket so the FCGI fall-through fails
		// fast without a long TCP dial, keeping this test well under 1s.
		Network:      "unix",
		Address:      "/nonexistent.sock",
		DocumentRoot: "/var/www/html",
		Index:        "index.php",
		DialTimeout:  1 * time.Millisecond,
		StaticLocations: map[string]StaticResponse{
			"/robots.txt": {Status: 200, Body: []byte("ok"), ContentType: "text/plain"},
		},
	})
	// /robots.txt/extra does not exact-match; should not serve the static entry.
	// It falls through to the FCGI path and returns 502 — the important thing
	// is it's NOT the static body.
	ctx := newHandlerCtx("GET", "/robots.txt/extra")
	h(ctx)
	if got := string(ctx.Response.Body()); got == "ok" {
		t.Errorf("static response leaked onto non-matching path")
	}
}

func TestHandler_StaticLocation_ZeroAllocHotPath(t *testing.T) {
	body := []byte("User-agent: *\nDisallow:")
	h := Handler(Config{
		Network:      "tcp",
		Address:      "127.0.0.1:9000",
		DocumentRoot: "/var/www/html",
		Index:        "index.php",
		StaticLocations: map[string]StaticResponse{
			"/robots.txt": {Status: 200, Body: body, ContentType: "text/plain"},
		},
	})
	ctx := newHandlerCtx("GET", "/robots.txt")
	// Warm-up: first call exercises fasthttp's internal growth paths.
	h(ctx)
	allocs := testing.AllocsPerRun(50, func() {
		ctx.Response.Reset()
		h(ctx)
	})
	// fasthttp internally allocates for status-line serialization on a fresh
	// response; we only care that the static-serve logic itself doesn't
	// add noticeable allocations beyond that. A handful (<5) is expected from
	// fasthttp's own machinery; anything >20 means we're copying the body.
	if allocs > 5 {
		t.Errorf("static serve allocated %.1f times per run, want ≤5", allocs)
	}
}
