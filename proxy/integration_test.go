package proxy

import (
	"net"
	"testing"
	"time"

	"github.com/menta2k/fcgi-proxy/fcgi"
	"github.com/valyala/fasthttp"
	"github.com/valyala/fasthttp/fasthttputil"
)

// mockFCGIServer reads a request and echoes the CGI params as the response body.
func mockFCGIServer(t *testing.T, ln net.Listener) {
	t.Helper()
	for {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		go handleFCGIConn(t, conn)
	}
}

func handleFCGIConn(t *testing.T, conn net.Conn) {
	t.Helper()
	defer conn.Close()

	var params []byte
	for {
		rec, err := fcgi.ReadRecord(conn)
		if err != nil {
			return
		}
		if rec.Header.Type == fcgi.TypeParams && len(rec.Content) > 0 {
			params = append(params, rec.Content...)
		}
		if rec.Header.Type == fcgi.TypeStdin && len(rec.Content) == 0 {
			break
		}
	}

	// Decode params and format them as "KEY=VALUE\n" for assertion.
	decoded, err := fcgi.DecodeParams(params)
	if err != nil {
		t.Logf("mock: decode params error: %v", err)
		return
	}

	var body []byte
	for k, v := range decoded {
		body = append(body, []byte(k+"="+v+"\n")...)
	}

	stdout := append([]byte("Content-Type: text/plain\r\nStatus: 200 OK\r\n\r\n"), body...)
	_ = fcgi.WriteRecord(conn, fcgi.TypeStdout, 1, stdout)
	_ = fcgi.WriteRecord(conn, fcgi.TypeStdout, 1, nil)

	endContent := make([]byte, 8)
	_ = fcgi.WriteRecord(conn, fcgi.TypeEndRequest, 1, endContent)
}

func startMockFCGI(t *testing.T) net.Listener {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	go mockFCGIServer(t, ln)
	t.Cleanup(func() { ln.Close() })
	return ln
}

func TestHandler_Healthz(t *testing.T) {
	ln := startMockFCGI(t)

	handler := Handler(Config{
		Network:      "tcp",
		Address:      ln.Addr().String(),
		DocumentRoot: "/var/www/html",
		Index:        "index.php",
		ListenPort:   "8080",
		DialTimeout:  2 * time.Second,
		ReadTimeout:  2 * time.Second,
		WriteTimeout: 2 * time.Second,
	})

	// Use in-memory listener for fasthttp.
	inmem := fasthttputil.NewInmemoryListener()
	defer inmem.Close()

	server := &fasthttp.Server{Handler: handler}
	go server.Serve(inmem)

	req := fasthttp.AcquireRequest()
	resp := fasthttp.AcquireResponse()
	defer fasthttp.ReleaseRequest(req)
	defer fasthttp.ReleaseResponse(resp)

	req.SetRequestURI("http://test/healthz")
	req.Header.SetMethod("GET")

	client := &fasthttp.HostClient{
		Dial: func(addr string) (net.Conn, error) {
			return inmem.Dial()
		},
	}

	if err := client.Do(req, resp); err != nil {
		t.Fatalf("request error: %v", err)
	}

	if resp.StatusCode() != 200 {
		t.Errorf("status = %d, want 200", resp.StatusCode())
	}
	if string(resp.Body()) != "ok" {
		t.Errorf("body = %q, want %q", resp.Body(), "ok")
	}
}

func TestHandler_ProxyRequest(t *testing.T) {
	ln := startMockFCGI(t)

	handler := Handler(Config{
		Network:      "tcp",
		Address:      ln.Addr().String(),
		DocumentRoot: "/var/www/html",
		Index:        "index.php",
		ListenPort:   "8080",
		DialTimeout:  2 * time.Second,
		ReadTimeout:  2 * time.Second,
		WriteTimeout: 2 * time.Second,
	})

	inmem := fasthttputil.NewInmemoryListener()
	defer inmem.Close()

	server := &fasthttp.Server{Handler: handler}
	go server.Serve(inmem)

	req := fasthttp.AcquireRequest()
	resp := fasthttp.AcquireResponse()
	defer fasthttp.ReleaseRequest(req)
	defer fasthttp.ReleaseResponse(resp)

	req.SetRequestURI("http://example.com:8080/index.php?foo=bar")
	req.Header.SetMethod("GET")
	req.Header.Set("X-Custom", "hello")

	client := &fasthttp.HostClient{
		Dial: func(addr string) (net.Conn, error) {
			return inmem.Dial()
		},
	}

	if err := client.Do(req, resp); err != nil {
		t.Fatalf("request error: %v", err)
	}

	if resp.StatusCode() != 200 {
		t.Errorf("status = %d, want 200", resp.StatusCode())
	}

	body := string(resp.Body())

	// Verify key CGI params were sent to upstream.
	assertContains(t, body, "REQUEST_METHOD=GET")
	assertContains(t, body, "SCRIPT_FILENAME=/var/www/html/index.php")
	assertContains(t, body, "QUERY_STRING=foo=bar")
	assertContains(t, body, "SERVER_PORT=8080")
	assertContains(t, body, "HTTP_X_CUSTOM=hello")
	assertContains(t, body, "SCRIPT_NAME=/index.php")
	assertContains(t, body, "DOCUMENT_ROOT=/var/www/html")
	assertContains(t, body, "SERVER_SOFTWARE=fcgi-proxy")
}

func TestHandler_BlockedHeaders(t *testing.T) {
	ln := startMockFCGI(t)

	handler := Handler(Config{
		Network:      "tcp",
		Address:      ln.Addr().String(),
		DocumentRoot: "/var/www/html",
		Index:        "index.php",
		ListenPort:   "8080",
		DialTimeout:  2 * time.Second,
		ReadTimeout:  2 * time.Second,
		WriteTimeout: 2 * time.Second,
	})

	inmem := fasthttputil.NewInmemoryListener()
	defer inmem.Close()

	server := &fasthttp.Server{Handler: handler}
	go server.Serve(inmem)

	req := fasthttp.AcquireRequest()
	resp := fasthttp.AcquireResponse()
	defer fasthttp.ReleaseRequest(req)
	defer fasthttp.ReleaseResponse(resp)

	req.SetRequestURI("http://example.com/index.php")
	req.Header.SetMethod("GET")
	// These should be blocked:
	req.Header.Set("Proxy", "http://evil.com")
	req.Header.Set("X-Forwarded-For", "1.2.3.4")
	req.Header.Set("X-Real-IP", "5.6.7.8")
	req.Header.Set("Trailer", "chunked")

	client := &fasthttp.HostClient{
		Dial: func(addr string) (net.Conn, error) {
			return inmem.Dial()
		},
	}

	if err := client.Do(req, resp); err != nil {
		t.Fatalf("request error: %v", err)
	}

	body := string(resp.Body())

	// Blocked headers should NOT appear with client-supplied values.
	assertNotContains(t, body, "HTTP_PROXY=http://evil.com")
	assertNotContains(t, body, "HTTP_X_FORWARDED_FOR=1.2.3.4")
	assertNotContains(t, body, "HTTP_X_REAL_IP=5.6.7.8")
	assertNotContains(t, body, "HTTP_TRAILER=chunked")

	// Authoritative values should be present (from the actual remote addr).
	assertContains(t, body, "HTTP_X_FORWARDED_FOR=")
	assertContains(t, body, "HTTP_X_REAL_IP=")
}

func TestHandler_PostWithBody(t *testing.T) {
	ln := startMockFCGI(t)

	handler := Handler(Config{
		Network:      "tcp",
		Address:      ln.Addr().String(),
		DocumentRoot: "/var/www/html",
		Index:        "index.php",
		ListenPort:   "8080",
		DialTimeout:  2 * time.Second,
		ReadTimeout:  2 * time.Second,
		WriteTimeout: 2 * time.Second,
	})

	inmem := fasthttputil.NewInmemoryListener()
	defer inmem.Close()

	server := &fasthttp.Server{Handler: handler}
	go server.Serve(inmem)

	req := fasthttp.AcquireRequest()
	resp := fasthttp.AcquireResponse()
	defer fasthttp.ReleaseRequest(req)
	defer fasthttp.ReleaseResponse(resp)

	req.SetRequestURI("http://example.com/index.php")
	req.Header.SetMethod("POST")
	req.Header.SetContentType("application/x-www-form-urlencoded")
	req.SetBodyString("key=value")

	client := &fasthttp.HostClient{
		Dial: func(addr string) (net.Conn, error) {
			return inmem.Dial()
		},
	}

	if err := client.Do(req, resp); err != nil {
		t.Fatalf("request error: %v", err)
	}

	body := string(resp.Body())
	assertContains(t, body, "REQUEST_METHOD=POST")
	assertContains(t, body, "CONTENT_TYPE=application/x-www-form-urlencoded")
	assertContains(t, body, "CONTENT_LENGTH=9")
}

func TestHandler_NullByteRejected(t *testing.T) {
	ln := startMockFCGI(t)

	handler := Handler(Config{
		Network:      "tcp",
		Address:      ln.Addr().String(),
		DocumentRoot: "/var/www/html",
		Index:        "index.php",
		ListenPort:   "8080",
		DialTimeout:  2 * time.Second,
		ReadTimeout:  2 * time.Second,
		WriteTimeout: 2 * time.Second,
	})

	inmem := fasthttputil.NewInmemoryListener()
	defer inmem.Close()

	server := &fasthttp.Server{Handler: handler}
	go server.Serve(inmem)

	req := fasthttp.AcquireRequest()
	resp := fasthttp.AcquireResponse()
	defer fasthttp.ReleaseRequest(req)
	defer fasthttp.ReleaseResponse(resp)

	// Null byte in query string.
	req.SetRequestURI("http://example.com/index.php?foo=\x00bar")
	req.Header.SetMethod("GET")
	req.Header.SetHost("example.com")

	client := &fasthttp.HostClient{
		Dial: func(addr string) (net.Conn, error) {
			return inmem.Dial()
		},
	}

	if err := client.Do(req, resp); err != nil {
		t.Fatalf("request error: %v", err)
	}

	if resp.StatusCode() != 400 {
		t.Errorf("status = %d, want 400 for null byte in query", resp.StatusCode())
	}
}

func TestHandler_ResponseHeaders(t *testing.T) {
	ln := startMockFCGI(t)

	handler := Handler(Config{
		Network:      "tcp",
		Address:      ln.Addr().String(),
		DocumentRoot: "/var/www/html",
		Index:        "index.php",
		ListenPort:   "8080",
		DialTimeout:  2 * time.Second,
		ReadTimeout:  2 * time.Second,
		WriteTimeout: 2 * time.Second,
		ResponseHeaders: map[string]string{
			"X-Custom-Header":        "custom-value",
			"X-Content-Type-Options": "nosniff",
			"X-Frame-Options":        "DENY",
		},
	})

	inmem := fasthttputil.NewInmemoryListener()
	defer inmem.Close()

	server := &fasthttp.Server{Handler: handler}
	go server.Serve(inmem)

	req := fasthttp.AcquireRequest()
	resp := fasthttp.AcquireResponse()
	defer fasthttp.ReleaseRequest(req)
	defer fasthttp.ReleaseResponse(resp)

	req.SetRequestURI("http://example.com/index.php")
	req.Header.SetMethod("GET")

	client := &fasthttp.HostClient{
		Dial: func(addr string) (net.Conn, error) {
			return inmem.Dial()
		},
	}

	if err := client.Do(req, resp); err != nil {
		t.Fatalf("request error: %v", err)
	}

	if resp.StatusCode() != 200 {
		t.Errorf("status = %d, want 200", resp.StatusCode())
	}

	// Verify configured response headers are present.
	if got := string(resp.Header.Peek("X-Custom-Header")); got != "custom-value" {
		t.Errorf("X-Custom-Header = %q, want %q", got, "custom-value")
	}
	if got := string(resp.Header.Peek("X-Content-Type-Options")); got != "nosniff" {
		t.Errorf("X-Content-Type-Options = %q, want %q", got, "nosniff")
	}
	if got := string(resp.Header.Peek("X-Frame-Options")); got != "DENY" {
		t.Errorf("X-Frame-Options = %q, want %q", got, "DENY")
	}
}

func TestHandler_ResponseHeaders_Empty(t *testing.T) {
	ln := startMockFCGI(t)

	// No response headers configured — should still work fine.
	handler := Handler(Config{
		Network:      "tcp",
		Address:      ln.Addr().String(),
		DocumentRoot: "/var/www/html",
		Index:        "index.php",
		ListenPort:   "8080",
		DialTimeout:  2 * time.Second,
		ReadTimeout:  2 * time.Second,
		WriteTimeout: 2 * time.Second,
	})

	inmem := fasthttputil.NewInmemoryListener()
	defer inmem.Close()

	server := &fasthttp.Server{Handler: handler}
	go server.Serve(inmem)

	req := fasthttp.AcquireRequest()
	resp := fasthttp.AcquireResponse()
	defer fasthttp.ReleaseRequest(req)
	defer fasthttp.ReleaseResponse(resp)

	req.SetRequestURI("http://example.com/index.php")
	req.Header.SetMethod("GET")

	client := &fasthttp.HostClient{
		Dial: func(addr string) (net.Conn, error) {
			return inmem.Dial()
		},
	}

	if err := client.Do(req, resp); err != nil {
		t.Fatalf("request error: %v", err)
	}

	if resp.StatusCode() != 200 {
		t.Errorf("status = %d, want 200", resp.StatusCode())
	}
}

func TestHandler_ResponseHeaders_Override(t *testing.T) {
	ln := startMockFCGI(t)

	// The mock server sends "Content-Type: text/plain" in the response.
	// Configure response_headers to override it.
	handler := Handler(Config{
		Network:      "tcp",
		Address:      ln.Addr().String(),
		DocumentRoot: "/var/www/html",
		Index:        "index.php",
		ListenPort:   "8080",
		DialTimeout:  2 * time.Second,
		ReadTimeout:  2 * time.Second,
		WriteTimeout: 2 * time.Second,
		ResponseHeaders: map[string]string{
			"Content-Type": "application/json",
		},
	})

	inmem := fasthttputil.NewInmemoryListener()
	defer inmem.Close()

	server := &fasthttp.Server{Handler: handler}
	go server.Serve(inmem)

	req := fasthttp.AcquireRequest()
	resp := fasthttp.AcquireResponse()
	defer fasthttp.ReleaseRequest(req)
	defer fasthttp.ReleaseResponse(resp)

	req.SetRequestURI("http://example.com/index.php")
	req.Header.SetMethod("GET")

	client := &fasthttp.HostClient{
		Dial: func(addr string) (net.Conn, error) {
			return inmem.Dial()
		},
	}

	if err := client.Do(req, resp); err != nil {
		t.Fatalf("request error: %v", err)
	}

	// The configured value should override the upstream value.
	got := string(resp.Header.ContentType())
	if got != "application/json" {
		t.Errorf("Content-Type = %q, want %q (configured override)", got, "application/json")
	}
}

func TestHandler_Healthz_NoResponseHeaders(t *testing.T) {
	ln := startMockFCGI(t)

	handler := Handler(Config{
		Network:      "tcp",
		Address:      ln.Addr().String(),
		DocumentRoot: "/var/www/html",
		Index:        "index.php",
		ListenPort:   "8080",
		DialTimeout:  2 * time.Second,
		ReadTimeout:  2 * time.Second,
		WriteTimeout: 2 * time.Second,
		ResponseHeaders: map[string]string{
			"X-Custom-Header": "should-not-appear",
		},
	})

	inmem := fasthttputil.NewInmemoryListener()
	defer inmem.Close()

	server := &fasthttp.Server{Handler: handler}
	go server.Serve(inmem)

	req := fasthttp.AcquireRequest()
	resp := fasthttp.AcquireResponse()
	defer fasthttp.ReleaseRequest(req)
	defer fasthttp.ReleaseResponse(resp)

	req.SetRequestURI("http://example.com/healthz")
	req.Header.SetMethod("GET")

	client := &fasthttp.HostClient{
		Dial: func(addr string) (net.Conn, error) {
			return inmem.Dial()
		},
	}

	if err := client.Do(req, resp); err != nil {
		t.Fatalf("request error: %v", err)
	}

	if resp.StatusCode() != 200 {
		t.Errorf("status = %d, want 200", resp.StatusCode())
	}
	if string(resp.Body()) != "ok" {
		t.Errorf("body = %q, want %q", resp.Body(), "ok")
	}

	// Response headers should NOT be present on /healthz.
	if got := string(resp.Header.Peek("X-Custom-Header")); got != "" {
		t.Errorf("X-Custom-Header on /healthz = %q, want empty (headers should be skipped)", got)
	}
}

func assertContains(t *testing.T, body, substr string) {
	t.Helper()
	if len(body) == 0 {
		t.Errorf("body is empty, expected to contain %q", substr)
		return
	}
	found := false
	for _, line := range splitLines(body) {
		if line == substr || (len(substr) > 0 && len(line) >= len(substr) && line[:len(substr)] == substr) {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("body does not contain %q:\n%s", substr, body)
	}
}

func assertNotContains(t *testing.T, body, substr string) {
	t.Helper()
	for _, line := range splitLines(body) {
		if line == substr {
			t.Errorf("body should not contain %q but does:\n%s", substr, body)
			return
		}
	}
}

func splitLines(s string) []string {
	var lines []string
	for len(s) > 0 {
		idx := 0
		for idx < len(s) && s[idx] != '\n' {
			idx++
		}
		line := s[:idx]
		if len(line) > 0 && line[len(line)-1] == '\r' {
			line = line[:len(line)-1]
		}
		lines = append(lines, line)
		if idx < len(s) {
			s = s[idx+1:]
		} else {
			break
		}
	}
	return lines
}
