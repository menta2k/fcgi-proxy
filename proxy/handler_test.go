package proxy

import (
	"path/filepath"
	"strings"
	"testing"
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
