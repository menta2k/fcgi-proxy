package fcgi

import (
	"bytes"
	"io"
	"net"
	"sync/atomic"
	"testing"
	"time"
)

// drainRequest consumes FastCGI records from conn until the terminating
// empty-stdin record arrives, returning the accumulated stdin payload.
func drainRequest(t *testing.T, conn net.Conn) []byte {
	t.Helper()
	var stdin bytes.Buffer
	for {
		rec, err := ReadRecord(conn)
		if err != nil {
			return stdin.Bytes()
		}
		if rec.Header.Type == TypeStdin {
			if len(rec.Content) == 0 {
				return stdin.Bytes()
			}
			stdin.Write(rec.Content)
		}
	}
}

// writeOKResponse sends a minimal successful FastCGI response on conn.
func writeOKResponse(t *testing.T, conn net.Conn, body string) {
	t.Helper()
	stdout := "Content-Type: text/plain\r\nStatus: 200 OK\r\n\r\n" + body
	if err := writeStream(conn, TypeStdout, 1, []byte(stdout)); err != nil {
		t.Logf("writeStream: %v", err)
		return
	}
	if err := WriteRecord(conn, TypeStdout, 1, nil); err != nil {
		t.Logf("WriteRecord stdout end: %v", err)
		return
	}
	endContent := make([]byte, 8)
	endContent[4] = StatusRequestComplete
	if err := WriteRecord(conn, TypeEndRequest, 1, endContent); err != nil {
		t.Logf("WriteRecord end: %v", err)
	}
}

func newRetryTestClient(t *testing.T, addr string) *Client {
	t.Helper()
	return NewClient(ClientConfig{
		Network:      "tcp",
		Address:      addr,
		DialTimeout:  2 * time.Second,
		ReadTimeout:  2 * time.Second,
		WriteTimeout: 2 * time.Second,
	})
}

// TestClient_Do_RetriesPooledStaleConn verifies that when a pooled
// connection is stale (peer closed it while idle, e.g. PHP-FPM worker
// exited after pm.max_requests), Do transparently retries on a fresh
// connection and the caller sees a successful response.
func TestClient_Do_RetriesPooledStaleConn(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	// First accept: simulate a keep-alive worker that has already exited —
	// close the socket immediately. Second accept: serve the retried request.
	serverDone := make(chan struct{})
	go func() {
		defer close(serverDone)
		c1, err := ln.Accept()
		if err != nil {
			return
		}
		c1.Close()

		c2, err := ln.Accept()
		if err != nil {
			return
		}
		defer c2.Close()
		drainRequest(t, c2)
		writeOKResponse(t, c2, "retried")
	}()

	client := newRetryTestClient(t, ln.Addr().String())
	defer client.Close()

	// Prime the pool with the "stale" connection. The seed lands in the
	// idle list; pool.Get() hands it out on the next Do call without any
	// liveness probe.
	seed, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatalf("seed dial: %v", err)
	}
	// Let the server close its side before we enqueue the conn.
	time.Sleep(50 * time.Millisecond)
	client.pool.Put(seed)

	resp, err := client.Do(Request{Params: map[string]string{"REQUEST_METHOD": "GET"}})
	if err != nil {
		t.Fatalf("Do error after retry: %v", err)
	}
	if resp.StatusCode != 200 {
		t.Errorf("status = %d, want 200", resp.StatusCode)
	}
	if string(resp.Body) != "retried" {
		t.Errorf("body = %q, want %q", resp.Body, "retried")
	}

	select {
	case <-serverDone:
	case <-time.After(2 * time.Second):
		t.Error("server goroutine did not complete")
	}
}

// TestClient_Do_NoRetryOnFreshDial verifies that a fresh-dialed connection
// that fails is not retried — retry is only safe for stale pool reuse.
func TestClient_Do_NoRetryOnFreshDial(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	var accepts atomic.Int32
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			accepts.Add(1)
			c.Close()
		}
	}()

	client := newRetryTestClient(t, ln.Addr().String())
	defer client.Close()

	// Pool is empty: pool.Get returns reused=false. Even though the upstream
	// closes and we see a stale-shaped error, Do must not retry.
	_, err = client.Do(Request{Params: map[string]string{"REQUEST_METHOD": "GET"}})
	if err == nil {
		t.Fatal("expected error")
	}

	// Give the Accept loop a moment to settle; a second dial would bump the counter.
	time.Sleep(100 * time.Millisecond)
	if got := accepts.Load(); got != 1 {
		t.Errorf("accept count = %d, want 1 (no retry on fresh dial)", got)
	}
}

// TestClient_Do_NoRetryAfterPartialResponse verifies that once any
// response bytes have been consumed, Do does not retry — retrying at
// that point could trigger duplicate upstream side effects.
func TestClient_Do_NoRetryAfterPartialResponse(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	var accepts atomic.Int32
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			accepts.Add(1)
			drainRequest(t, c)
			// Send a partial stdout record, then slam the connection shut
			// without writing an EndRequest — upstream "crashed" mid-response.
			partial := "Content-Type: text/plain\r\n\r\npartial"
			_ = WriteRecord(c, TypeStdout, 1, []byte(partial))
			c.Close()
		}
	}()

	client := newRetryTestClient(t, ln.Addr().String())
	defer client.Close()

	// Seed the pool so reused=true on the first Get.
	seed, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatalf("seed dial: %v", err)
	}
	client.pool.Put(seed)

	_, err = client.Do(Request{Params: map[string]string{"REQUEST_METHOD": "POST"}})
	if err == nil {
		t.Fatal("expected error after mid-response close")
	}

	time.Sleep(100 * time.Millisecond)
	if got := accepts.Load(); got != 1 {
		t.Errorf("accept count = %d, want 1 (no retry after bytes received)", got)
	}
}

// TestClient_Do_RetryPostWithBytesReader verifies that a POST body backed
// by an io.Seeker is correctly rewound and resent on retry, so the fresh
// upstream sees the full original payload.
func TestClient_Do_RetryPostWithBytesReader(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	bodyGot := make(chan []byte, 1)
	go func() {
		// First accept: close to simulate stale worker.
		c1, err := ln.Accept()
		if err != nil {
			return
		}
		c1.Close()

		// Second accept: capture stdin and reply.
		c2, err := ln.Accept()
		if err != nil {
			return
		}
		defer c2.Close()
		bodyGot <- drainRequest(t, c2)
		writeOKResponse(t, c2, "ok")
	}()

	client := newRetryTestClient(t, ln.Addr().String())
	defer client.Close()

	seed, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatalf("seed dial: %v", err)
	}
	time.Sleep(50 * time.Millisecond)
	client.pool.Put(seed)

	payload := []byte(`{"k":"v"}`)
	resp, err := client.Do(Request{
		Params: map[string]string{"REQUEST_METHOD": "POST", "CONTENT_LENGTH": "9"},
		Stdin:  bytes.NewReader(payload),
	})
	if err != nil {
		t.Fatalf("Do error: %v", err)
	}
	if resp.StatusCode != 200 {
		t.Errorf("status = %d, want 200", resp.StatusCode)
	}

	select {
	case got := <-bodyGot:
		if !bytes.Equal(got, payload) {
			t.Errorf("upstream received body %q, want %q", got, payload)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("server did not capture request body")
	}
}

// nonSeekableReader hides any Seek method on the underlying reader so the
// type assertion in rewindStdin fails.
type nonSeekableReader struct{ r io.Reader }

func (n *nonSeekableReader) Read(p []byte) (int, error) { return n.r.Read(p) }

// TestClient_Do_NoRetryWithNonSeekableBody verifies that when the request
// body cannot be rewound, Do surfaces the original error instead of
// retrying and risking a truncated second request.
func TestClient_Do_NoRetryWithNonSeekableBody(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	var accepts atomic.Int32
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			accepts.Add(1)
			c.Close()
		}
	}()

	client := newRetryTestClient(t, ln.Addr().String())
	defer client.Close()

	seed, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatalf("seed dial: %v", err)
	}
	time.Sleep(50 * time.Millisecond)
	client.pool.Put(seed)

	_, err = client.Do(Request{
		Params: map[string]string{"REQUEST_METHOD": "POST"},
		Stdin:  &nonSeekableReader{r: bytes.NewReader([]byte("payload"))},
	})
	if err == nil {
		t.Fatal("expected error; retry must be skipped when body is non-seekable")
	}

	time.Sleep(100 * time.Millisecond)
	// Exactly one accept: the seeded stale connection. No fresh-dial retry.
	if got := accepts.Load(); got != 1 {
		t.Errorf("accept count = %d, want 1 (no retry with non-seekable body)", got)
	}
}

func TestIsStaleConnErr(t *testing.T) {
	cases := []struct {
		name string
		err  error
		want bool
	}{
		{"nil", nil, false},
		{"eof", io.EOF, true},
		{"unexpected eof", io.ErrUnexpectedEOF, true},
		{"broken pipe msg", &net.OpError{Op: "write", Err: errString("broken pipe")}, true},
		{"connection reset msg", &net.OpError{Op: "read", Err: errString("connection reset by peer")}, true},
		{"closed network msg", &net.OpError{Op: "read", Err: errString("use of closed network connection")}, true},
		{"timeout not stale", timeoutErr{}, false},
		{"generic error", errString("something else"), false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := isStaleConnErr(tc.err); got != tc.want {
				t.Errorf("isStaleConnErr(%v) = %v, want %v", tc.err, got, tc.want)
			}
		})
	}
}

type errString string

func (e errString) Error() string { return string(e) }

type timeoutErr struct{}

func (timeoutErr) Error() string   { return "i/o timeout" }
func (timeoutErr) Timeout() bool   { return true }
func (timeoutErr) Temporary() bool { return true }
