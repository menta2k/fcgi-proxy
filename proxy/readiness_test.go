package proxy

import (
	"errors"
	"net"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/menta2k/fcgi-proxy/config"
	"github.com/menta2k/fcgi-proxy/fcgi"
	"github.com/valyala/fasthttp"
	"github.com/valyala/fasthttp/fasthttputil"
)

// statusPageServer accepts FastCGI connections and responds based on the
// configured behavior function. Each connection is handled independently so
// the test can reuse a single listener for multiple requests (including
// retries) while varying the reply per-call.
func statusPageServer(t *testing.T, ln net.Listener, connCount *atomic.Int32, handle func(conn net.Conn, callIdx int32)) {
	t.Helper()
	for {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		idx := connCount.Add(1)
		go func() {
			defer conn.Close()
			handle(conn, idx-1)
		}()
	}
}

// readStdinEnd drains a request until the empty Stdin record and returns the
// decoded params map.
func readStdinEnd(t *testing.T, conn net.Conn) map[string]string {
	t.Helper()
	var raw []byte
	for {
		rec, err := fcgi.ReadRecord(conn)
		if err != nil {
			return nil
		}
		if rec.Header.Type == fcgi.TypeParams && len(rec.Content) > 0 {
			raw = append(raw, rec.Content...)
		}
		if rec.Header.Type == fcgi.TypeStdin && len(rec.Content) == 0 {
			break
		}
	}
	p, _ := fcgi.DecodeParams(raw)
	return p
}

func writeStatus200(conn net.Conn) {
	body := "Content-Type: text/plain\r\nStatus: 200 OK\r\n\r\npool: www\nprocesses: 5\n"
	_ = fcgi.WriteRecord(conn, fcgi.TypeStdout, 1, []byte(body))
	_ = fcgi.WriteRecord(conn, fcgi.TypeStdout, 1, nil)
	endContent := make([]byte, 8)
	_ = fcgi.WriteRecord(conn, fcgi.TypeEndRequest, 1, endContent)
}

func writeStatus500(conn net.Conn) {
	body := "Content-Type: text/plain\r\nStatus: 500 Internal Server Error\r\n\r\n"
	_ = fcgi.WriteRecord(conn, fcgi.TypeStdout, 1, []byte(body))
	_ = fcgi.WriteRecord(conn, fcgi.TypeStdout, 1, nil)
	endContent := make([]byte, 8)
	_ = fcgi.WriteRecord(conn, fcgi.TypeEndRequest, 1, endContent)
}

func newReadinessHandler(t *testing.T, upstream net.Listener, enabled bool) fasthttp.RequestHandler {
	t.Helper()
	cfg := Config{
		Network:      "tcp",
		Address:      upstream.Addr().String(),
		DocumentRoot: "/var/www/html",
		Index:        "index.php",
		ListenPort:   "8080",
		DialTimeout:  2 * time.Second,
		ReadTimeout:  2 * time.Second,
		WriteTimeout: 2 * time.Second,
		Readiness: config.ParsedReadiness{
			Enabled:    enabled,
			StatusPath: "/status",
			Timeout:    500 * time.Millisecond,
		},
	}
	return Handler(cfg)
}

func doReadyz(t *testing.T, handler fasthttp.RequestHandler) (int, string) {
	t.Helper()
	inmem := fasthttputil.NewInmemoryListener()
	defer inmem.Close()

	server := &fasthttp.Server{Handler: handler}
	go func() { _ = server.Serve(inmem) }()

	client := &fasthttp.HostClient{
		Dial: func(addr string) (net.Conn, error) { return inmem.Dial() },
	}

	req := fasthttp.AcquireRequest()
	resp := fasthttp.AcquireResponse()
	defer fasthttp.ReleaseRequest(req)
	defer fasthttp.ReleaseResponse(resp)

	req.SetRequestURI("http://test/readyz")
	req.Header.SetMethod("GET")

	if err := client.Do(req, resp); err != nil {
		t.Fatalf("request error: %v", err)
	}
	return resp.StatusCode(), string(resp.Body())
}

// TestReadyz_UpstreamReady verifies /readyz returns 200 when PHP-FPM's
// status page responds successfully.
func TestReadyz_UpstreamReady(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	var conns atomic.Int32
	var sawStatusPath atomic.Bool
	go statusPageServer(t, ln, &conns, func(conn net.Conn, _ int32) {
		params := readStdinEnd(t, conn)
		if params["SCRIPT_FILENAME"] == "/status" {
			sawStatusPath.Store(true)
		}
		writeStatus200(conn)
	})

	handler := newReadinessHandler(t, ln, true)
	status, body := doReadyz(t, handler)

	if status != 200 {
		t.Errorf("status = %d, want 200", status)
	}
	if body != "ready" {
		t.Errorf("body = %q, want %q", body, "ready")
	}
	if !sawStatusPath.Load() {
		t.Errorf("upstream did not receive SCRIPT_FILENAME=/status")
	}
	// Body is not echoed to the caller, regardless of what upstream returned.
	if want := "pool: www"; body == want {
		t.Errorf("body leaked upstream response: %q", body)
	}
}

// TestReadyz_UpstreamDown verifies /readyz returns 503 when the upstream
// is unreachable (dial fails and retry also fails).
func TestReadyz_UpstreamDown(t *testing.T) {
	// Pick a port, then close the listener — dials will be refused.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().String()
	ln.Close()

	// Use the closed-listener address in the handler config.
	closedLn := &closedAddr{addr: addr}
	handler := newReadinessHandler(t, closedLn, true)

	status, body := doReadyz(t, handler)
	if status != 503 {
		t.Errorf("status = %d, want 503", status)
	}
	if body != "not ready" {
		t.Errorf("body = %q, want %q", body, "not ready")
	}
}

// TestReadyz_FirstAttemptFails_RetrySucceeds simulates PHP-FPM restart:
// the first FCGI attempt fails, then the retry succeeds. /readyz must
// return 200 because one blip is not a real failure.
func TestReadyz_FirstAttemptFails_RetrySucceeds(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	var conns atomic.Int32
	go statusPageServer(t, ln, &conns, func(conn net.Conn, idx int32) {
		if idx == 0 {
			// First connection: hang up before responding.
			conn.Close()
			return
		}
		// Subsequent connections behave normally.
		readStdinEnd(t, conn)
		writeStatus200(conn)
	})

	handler := newReadinessHandler(t, ln, true)
	status, _ := doReadyz(t, handler)

	if status != 200 {
		t.Errorf("status = %d, want 200 (retry should have succeeded)", status)
	}
	if got := conns.Load(); got < 2 {
		t.Errorf("expected at least 2 upstream connections (first + retry), got %d", got)
	}
}

// TestReadyz_UpstreamNon2xx verifies a non-success status from the status
// page still fails the probe (PHP-FPM returning 500 is unhealthy).
func TestReadyz_UpstreamNon2xx(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	var conns atomic.Int32
	go statusPageServer(t, ln, &conns, func(conn net.Conn, _ int32) {
		readStdinEnd(t, conn)
		writeStatus500(conn)
	})

	handler := newReadinessHandler(t, ln, true)
	status, body := doReadyz(t, handler)

	if status != 503 {
		t.Errorf("status = %d, want 503", status)
	}
	if body != "not ready" {
		t.Errorf("body = %q, want %q", body, "not ready")
	}
	// Two attempts (first + retry), both 500. No extra retries beyond that.
	if got := conns.Load(); got != 2 {
		t.Errorf("expected 2 attempts, got %d", got)
	}
}

// TestReadyz_Disabled verifies that /readyz returns 200 without probing
// when readiness is disabled in config.
func TestReadyz_Disabled(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	var conns atomic.Int32
	go statusPageServer(t, ln, &conns, func(conn net.Conn, _ int32) {
		readStdinEnd(t, conn)
		writeStatus200(conn)
	})

	handler := newReadinessHandler(t, ln, false)
	status, body := doReadyz(t, handler)

	if status != 200 {
		t.Errorf("status = %d, want 200", status)
	}
	if body != "ready" {
		t.Errorf("body = %q, want %q", body, "ready")
	}
	if got := conns.Load(); got != 0 {
		t.Errorf("disabled readiness must not probe upstream, saw %d connections", got)
	}
}

// closedAddr satisfies net.Listener enough for newReadinessHandler to read
// its address without accepting any connections.
type closedAddr struct {
	addr string
}

func (c *closedAddr) Accept() (net.Conn, error) { return nil, net.ErrClosed }
func (c *closedAddr) Close() error               { return nil }
func (c *closedAddr) Addr() net.Addr             { return &fakeAddr{s: c.addr} }

type fakeAddr struct{ s string }

func (f *fakeAddr) Network() string { return "tcp" }
func (f *fakeAddr) String() string  { return f.s }

// TestNewReadinessProber_Disabled verifies that readiness.enabled=false
// produces a nil prober (signalling "no probing" to the handler).
func TestNewReadinessProber_Disabled(t *testing.T) {
	cfg := Config{
		Network: "tcp",
		Address: "127.0.0.1:9000",
		Readiness: config.ParsedReadiness{
			Enabled: false,
		},
	}
	if p := newReadinessProber(cfg); p != nil {
		t.Errorf("expected nil prober when readiness disabled, got %+v", p)
	}
}

// TestReadinessProber_Close verifies close() is safe to call and tolerates
// a nil client (the prober constructor always sets one, but defensive code
// should survive a zero value too).
func TestReadinessProber_Close(t *testing.T) {
	cfg := Config{
		Network: "tcp",
		Address: "127.0.0.1:9000",
		Readiness: config.ParsedReadiness{
			Enabled:    true,
			StatusPath: "/status",
			Timeout:    500 * time.Millisecond,
		},
	}
	p := newReadinessProber(cfg)
	if p == nil {
		t.Fatal("expected non-nil prober")
	}
	p.close() // must not panic
	// Zero-value prober (no client) must also close cleanly.
	(&readinessProber{}).close()
}

// TestProbeError_AllPaths exercises each branch of probeError directly,
// including the "success" branch that the retry logic never reaches (it
// only calls probeError when the probe has already failed).
func TestProbeError_AllPaths(t *testing.T) {
	t.Run("transport_error", func(t *testing.T) {
		want := errors.New("dial refused")
		got := probeError(fcgi.Response{}, want)
		if got != want {
			t.Errorf("got %v, want %v", got, want)
		}
	})
	t.Run("success_status_returns_nil", func(t *testing.T) {
		got := probeError(fcgi.Response{StatusCode: 200}, nil)
		if got != nil {
			t.Errorf("got %v, want nil on 2xx", got)
		}
	})
	t.Run("non_success_status", func(t *testing.T) {
		got := probeError(fcgi.Response{StatusCode: 503}, nil)
		if got == nil {
			t.Fatal("expected error for 503 status")
		}
		if !strings.Contains(got.Error(), "503") {
			t.Errorf("error = %v, want mention of 503", got)
		}
	})
}

// TestTruncateErr covers the nil, short, and long cases — the second and
// third branches are not reliably hit by the end-to-end /readyz tests.
func TestTruncateErr(t *testing.T) {
	t.Run("nil", func(t *testing.T) {
		if got := truncateErr(nil, 10); got != nil {
			t.Errorf("got %v, want nil", got)
		}
	})
	t.Run("under_limit_returns_original", func(t *testing.T) {
		orig := errors.New("short")
		got := truncateErr(orig, 10)
		if got != orig {
			t.Errorf("expected original error pointer when under limit, got %v", got)
		}
	})
	t.Run("over_limit_truncates", func(t *testing.T) {
		long := errors.New(strings.Repeat("x", 500))
		got := truncateErr(long, 50)
		if got == nil {
			t.Fatal("expected non-nil truncated error")
		}
		msg := got.Error()
		// 50 x's + the ellipsis suffix
		if !strings.HasPrefix(msg, strings.Repeat("x", 50)) {
			t.Errorf("truncated message missing prefix: %q", msg)
		}
		if !strings.HasSuffix(msg, "…") {
			t.Errorf("truncated message missing ellipsis suffix: %q", msg)
		}
		if len(msg) >= len(long.Error()) {
			t.Errorf("truncated length = %d, want less than original %d", len(msg), len(long.Error()))
		}
	})
}

// TestReadinessProber_BuildParams verifies the CGI params include the
// configured SCRIPT_FILENAME/SCRIPT_NAME so PHP-FPM routes to its status
// handler rather than looking for a PHP file on disk.
func TestReadinessProber_BuildParams(t *testing.T) {
	cfg := Config{
		Network:      "tcp",
		Address:      "127.0.0.1:9000",
		DocumentRoot: "/srv/app",
		ListenPort:   "9090",
		Readiness: config.ParsedReadiness{
			Enabled:    true,
			StatusPath: "/fpm-status",
			Timeout:    500 * time.Millisecond,
		},
	}
	p := newReadinessProber(cfg)
	if p == nil {
		t.Fatal("expected non-nil prober")
	}
	defer p.close()

	params := p.buildParams()
	want := map[string]string{
		"SCRIPT_FILENAME": "/fpm-status",
		"SCRIPT_NAME":     "/fpm-status",
		"REQUEST_URI":     "/fpm-status",
		"DOCUMENT_URI":    "/fpm-status",
		"DOCUMENT_ROOT":   "/srv/app",
		"SERVER_PORT":     "9090",
		"REQUEST_METHOD":  "GET",
		"SERVER_NAME":     "readyz",
	}
	for k, v := range want {
		if got := params[k]; got != v {
			t.Errorf("params[%q] = %q, want %q", k, got, v)
		}
	}
}
