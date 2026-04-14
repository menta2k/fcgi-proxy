package fcgi

import (
	"bytes"
	"io"
	"net"
	"testing"
	"time"
)

func TestParseHTTPResponse_WithHeaders(t *testing.T) {
	stdout := []byte("Content-Type: text/html\r\nX-Custom: foo\r\n\r\n<html>body</html>")
	resp, err := parseHTTPResponse(stdout, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp.StatusCode != 200 {
		t.Errorf("status = %d, want 200", resp.StatusCode)
	}
	// textproto canonicalizes header keys
	if ct := resp.Headers["Content-Type"]; len(ct) != 1 || ct[0] != "text/html" {
		t.Errorf("Content-Type = %v, want [text/html]", ct)
	}
	if xc := resp.Headers["X-Custom"]; len(xc) != 1 || xc[0] != "foo" {
		t.Errorf("X-Custom = %v, want [foo]", xc)
	}
	if string(resp.Body) != "<html>body</html>" {
		t.Errorf("body = %q, want %q", resp.Body, "<html>body</html>")
	}
}

func TestParseHTTPResponse_StatusHeader(t *testing.T) {
	stdout := []byte("Status: 404 Not Found\r\nContent-Type: text/plain\r\n\r\nNot Found")
	resp, err := parseHTTPResponse(stdout, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp.StatusCode != 404 {
		t.Errorf("status = %d, want 404", resp.StatusCode)
	}
	// Status header should not appear in response headers
	if _, ok := resp.Headers["Status"]; ok {
		t.Error("Status header should not be in response headers")
	}
}

func TestParseHTTPResponse_LFOnly(t *testing.T) {
	// PHP-FPM sometimes uses \n instead of \r\n
	stdout := []byte("Content-Type: text/html\n\nbody")
	resp, err := parseHTTPResponse(stdout, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if ct := resp.Headers["Content-Type"]; len(ct) != 1 || ct[0] != "text/html" {
		t.Errorf("Content-Type = %v, want [text/html]", ct)
	}
	if string(resp.Body) != "body" {
		t.Errorf("body = %q, want %q", resp.Body, "body")
	}
}

func TestParseHTTPResponse_EmptyStdout(t *testing.T) {
	resp, err := parseHTTPResponse(nil, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp.StatusCode != 200 {
		t.Errorf("status = %d, want 200", resp.StatusCode)
	}
	if len(resp.Body) != 0 {
		t.Errorf("body = %q, want empty", resp.Body)
	}
}

func TestParseHTTPResponse_Stderr(t *testing.T) {
	stdout := []byte("Content-Type: text/html\r\n\r\nOK")
	stderr := []byte("PHP Warning: something")
	resp, err := parseHTTPResponse(stdout, stderr)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if string(resp.Stderr) != "PHP Warning: something" {
		t.Errorf("stderr = %q", resp.Stderr)
	}
}

func TestParseHTTPResponse_StatusCaseInsensitive(t *testing.T) {
	// textproto canonicalizes "status" to "Status"
	stdout := []byte("status: 301 Moved\r\n\r\n")
	resp, err := parseHTTPResponse(stdout, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp.StatusCode != 301 {
		t.Errorf("status = %d, want 301", resp.StatusCode)
	}
}

func TestParseHTTPResponse_MultipleHeaders(t *testing.T) {
	stdout := []byte("Set-Cookie: a=1\r\nSet-Cookie: b=2\r\n\r\n")
	resp, err := parseHTTPResponse(stdout, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	cookies := resp.Headers["Set-Cookie"]
	if len(cookies) != 2 {
		t.Fatalf("got %d Set-Cookie headers, want 2", len(cookies))
	}
	if cookies[0] != "a=1" || cookies[1] != "b=2" {
		t.Errorf("cookies = %v", cookies)
	}
}

func TestParseHTTPResponse_NoHeaders_BodyOnly(t *testing.T) {
	// Raw output with no header separator — treated as body.
	stdout := []byte("raw binary output without headers")
	resp, err := parseHTTPResponse(stdout, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(resp.Body) == 0 {
		t.Error("expected non-empty body for header-less output")
	}
}

func TestParseHTTPResponse_HeaderNoTrailingNewline(t *testing.T) {
	// Edge: headers end at EOF with no blank line separator.
	stdout := []byte("Content-Type: text/plain")
	resp, err := parseHTTPResponse(stdout, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// textproto may parse this as a header or as body depending on implementation.
	// Either way it should not panic or error.
	_ = resp
}

// TestWriteStreamFromReader verifies chunked writing from a reader.
func TestWriteStreamFromReader(t *testing.T) {
	data := bytes.Repeat([]byte("A"), 100)
	reader := bytes.NewReader(data)
	var buf bytes.Buffer

	if err := writeStreamFromReader(&buf, TypeStdin, 1, reader); err != nil {
		t.Fatalf("writeStreamFromReader error: %v", err)
	}

	// Read back the records and verify content.
	r := bytes.NewReader(buf.Bytes())
	var collected []byte
	for {
		rec, err := ReadRecord(r)
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatalf("ReadRecord error: %v", err)
		}
		collected = append(collected, rec.Content...)
	}

	if !bytes.Equal(collected, data) {
		t.Errorf("got %d bytes, want %d", len(collected), len(data))
	}
}

// TestReadResponse_StdoutCap verifies the maxResponseBody cap.
func TestReadResponse_StdoutCap(t *testing.T) {
	// Build a stream that exceeds maxResponseBody.
	var buf bytes.Buffer

	// Write a chunk that is within limits.
	chunk := bytes.Repeat([]byte("X"), maxContentSize)
	recordCount := (maxResponseBody / maxContentSize) + 2 // enough to exceed

	for range recordCount {
		if err := WriteRecord(&buf, TypeStdout, 1, chunk); err != nil {
			t.Fatalf("WriteRecord error: %v", err)
		}
	}
	// Write EndRequest.
	if err := WriteRecord(&buf, TypeEndRequest, 1, make([]byte, 8)); err != nil {
		t.Fatalf("WriteRecord error: %v", err)
	}

	client := &Client{cfg: ClientConfig{}}
	_, err := client.readResponse(fakeConn{Reader: &buf}, 1)
	if err == nil {
		t.Fatal("expected error for exceeding maxResponseBody")
	}
	if !bytes.Contains([]byte(err.Error()), []byte("exceeds")) {
		t.Errorf("unexpected error: %v", err)
	}
}

// fakeConn wraps a reader to satisfy net.Conn for testing readResponse.
type fakeConn struct {
	io.Reader
}

func (f fakeConn) Write(b []byte) (int, error)        { return 0, nil }
func (f fakeConn) Close() error                        { return nil }
func (f fakeConn) LocalAddr() net.Addr                 { return &net.TCPAddr{} }
func (f fakeConn) RemoteAddr() net.Addr                { return &net.TCPAddr{} }
func (f fakeConn) SetDeadline(_ time.Time) error       { return nil }
func (f fakeConn) SetReadDeadline(_ time.Time) error   { return nil }
func (f fakeConn) SetWriteDeadline(_ time.Time) error  { return nil }

func TestReadResponse_ProtocolStatusRefused(t *testing.T) {
	var buf bytes.Buffer

	// Write some stdout.
	if err := WriteRecord(&buf, TypeStdout, 1, []byte("Content-Type: text/html\r\n\r\nOK")); err != nil {
		t.Fatal(err)
	}

	// Write EndRequest with protocolStatus = OVERLOADED (2).
	endContent := make([]byte, 8)
	endContent[4] = StatusOverloaded
	if err := WriteRecord(&buf, TypeEndRequest, 1, endContent); err != nil {
		t.Fatal(err)
	}

	client := &Client{cfg: ClientConfig{}}
	_, err := client.readResponse(fakeConn{Reader: &buf}, 1)
	if err == nil {
		t.Fatal("expected error for non-zero protocol status")
	}
	if !bytes.Contains([]byte(err.Error()), []byte("refused")) {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestReadResponse_ProtocolStatusComplete(t *testing.T) {
	var buf bytes.Buffer

	if err := WriteRecord(&buf, TypeStdout, 1, []byte("Content-Type: text/html\r\n\r\nOK")); err != nil {
		t.Fatal(err)
	}

	// Write EndRequest with protocolStatus = REQUEST_COMPLETE (0).
	endContent := make([]byte, 8)
	endContent[4] = StatusRequestComplete
	if err := WriteRecord(&buf, TypeEndRequest, 1, endContent); err != nil {
		t.Fatal(err)
	}

	client := &Client{cfg: ClientConfig{}}
	resp, err := client.readResponse(fakeConn{Reader: &buf}, 1)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp.StatusCode != 200 {
		t.Errorf("status = %d, want 200", resp.StatusCode)
	}
	if string(resp.Body) != "OK" {
		t.Errorf("body = %q, want %q", resp.Body, "OK")
	}
}
