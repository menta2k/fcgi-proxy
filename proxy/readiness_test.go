package proxy

import (
	"net"
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
