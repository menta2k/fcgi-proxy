package fcgi

import (
	"bytes"
	"io"
	"net"
	"strings"
	"testing"
	"time"
)

// mockFCGIServer reads a FastCGI request and responds with the given headers and body.
func mockFCGIServer(t *testing.T, ln net.Listener, responseHeaders, responseBody string) {
	t.Helper()
	conn, err := ln.Accept()
	if err != nil {
		return
	}
	defer conn.Close()

	// Read all records until we get an empty Stdin record (end of request).
	for {
		rec, err := ReadRecord(conn)
		if err != nil {
			t.Logf("mock server read error: %v", err)
			return
		}
		// Empty stdin record signals end of request.
		if rec.Header.Type == TypeStdin && len(rec.Content) == 0 {
			break
		}
	}

	// Write response.
	stdout := responseHeaders + "\r\n\r\n" + responseBody
	if err := writeStream(conn, TypeStdout, 1, []byte(stdout)); err != nil {
		t.Logf("mock server write stdout error: %v", err)
		return
	}
	if err := WriteRecord(conn, TypeStdout, 1, nil); err != nil {
		t.Logf("mock server write empty stdout error: %v", err)
		return
	}

	// Write EndRequest with StatusRequestComplete.
	endContent := make([]byte, 8)
	endContent[4] = StatusRequestComplete
	if err := WriteRecord(conn, TypeEndRequest, 1, endContent); err != nil {
		t.Logf("mock server write end error: %v", err)
		return
	}
}

func TestClient_Do_Integration(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen error: %v", err)
	}
	defer ln.Close()

	go mockFCGIServer(t, ln, "Content-Type: text/html\r\nStatus: 200 OK", "<h1>Hello</h1>")

	client := NewClient(ClientConfig{
		Network:      "tcp",
		Address:      ln.Addr().String(),
		DialTimeout:  2 * time.Second,
		ReadTimeout:  2 * time.Second,
		WriteTimeout: 2 * time.Second,
	})

	resp, err := client.Do(Request{
		Params: map[string]string{
			"REQUEST_METHOD":  "GET",
			"SCRIPT_FILENAME": "/var/www/html/index.php",
			"QUERY_STRING":    "",
		},
		Stdin: nil,
	})
	if err != nil {
		t.Fatalf("Do error: %v", err)
	}

	if resp.StatusCode != 200 {
		t.Errorf("status = %d, want 200", resp.StatusCode)
	}
	if ct := resp.Headers["Content-Type"]; len(ct) != 1 || ct[0] != "text/html" {
		t.Errorf("Content-Type = %v, want [text/html]", ct)
	}
	if string(resp.Body) != "<h1>Hello</h1>" {
		t.Errorf("body = %q, want %q", resp.Body, "<h1>Hello</h1>")
	}
}

func TestClient_Do_WithStdin(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen error: %v", err)
	}
	defer ln.Close()

	go mockFCGIServer(t, ln, "Content-Type: application/json\r\nStatus: 201 Created", `{"id":1}`)

	client := NewClient(ClientConfig{
		Network:      "tcp",
		Address:      ln.Addr().String(),
		DialTimeout:  2 * time.Second,
		ReadTimeout:  2 * time.Second,
		WriteTimeout: 2 * time.Second,
	})

	body := strings.NewReader(`{"name":"test"}`)
	resp, err := client.Do(Request{
		Params: map[string]string{
			"REQUEST_METHOD": "POST",
			"CONTENT_TYPE":   "application/json",
			"CONTENT_LENGTH": "15",
		},
		Stdin: body,
	})
	if err != nil {
		t.Fatalf("Do error: %v", err)
	}

	if resp.StatusCode != 201 {
		t.Errorf("status = %d, want 201", resp.StatusCode)
	}
	if string(resp.Body) != `{"id":1}` {
		t.Errorf("body = %q", resp.Body)
	}
}

func TestClient_Do_ConnectionRefused(t *testing.T) {
	client := NewClient(ClientConfig{
		Network:      "tcp",
		Address:      "127.0.0.1:1", // unlikely to be listening
		DialTimeout:  500 * time.Millisecond,
		ReadTimeout:  time.Second,
		WriteTimeout: time.Second,
	})

	_, err := client.Do(Request{Params: map[string]string{}})
	if err == nil {
		t.Fatal("expected connection error")
	}
	if !strings.Contains(err.Error(), "connect") {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestWriteRequest_RoundTrip(t *testing.T) {
	var buf bytes.Buffer
	client := &Client{cfg: ClientConfig{}}

	req := Request{
		Params: map[string]string{
			"REQUEST_METHOD":  "GET",
			"SCRIPT_FILENAME": "/index.php",
		},
		Stdin: strings.NewReader("body data"),
	}

	if err := client.writeRequest(fakeConnWriter{Writer: &buf}, 1, req); err != nil {
		t.Fatalf("writeRequest error: %v", err)
	}

	// Decode all records written and verify structure.
	reader := bytes.NewReader(buf.Bytes())
	var types []uint8
	for {
		rec, err := ReadRecord(reader)
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatalf("ReadRecord error: %v", err)
		}
		types = append(types, rec.Header.Type)
	}

	// Expected sequence: BeginRequest, Params, Params(empty), Stdin, Stdin(empty)
	// Stdin may be split into multiple records depending on chunk size.
	if len(types) < 5 {
		t.Fatalf("expected at least 5 records, got %d: %v", len(types), types)
	}
	if types[0] != TypeBeginRequest {
		t.Errorf("first record type = %d, want BeginRequest(%d)", types[0], TypeBeginRequest)
	}
	if types[1] != TypeParams {
		t.Errorf("second record type = %d, want Params(%d)", types[1], TypeParams)
	}
	// Last record should be empty Stdin.
	if types[len(types)-1] != TypeStdin {
		t.Errorf("last record type = %d, want Stdin(%d)", types[len(types)-1], TypeStdin)
	}
}

func TestWriteStream(t *testing.T) {
	var buf bytes.Buffer

	data := bytes.Repeat([]byte("X"), 100)
	if err := writeStream(&buf, TypeParams, 1, data); err != nil {
		t.Fatalf("writeStream error: %v", err)
	}

	// Read back and collect content.
	reader := bytes.NewReader(buf.Bytes())
	var collected []byte
	for {
		rec, err := ReadRecord(reader)
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

func TestWriteStream_LargeData(t *testing.T) {
	var buf bytes.Buffer

	// Data larger than one record.
	data := bytes.Repeat([]byte("Y"), maxContentSize+500)
	if err := writeStream(&buf, TypeStdout, 1, data); err != nil {
		t.Fatalf("writeStream error: %v", err)
	}

	reader := bytes.NewReader(buf.Bytes())
	var collected []byte
	recordCount := 0
	for {
		rec, err := ReadRecord(reader)
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatalf("ReadRecord error: %v", err)
		}
		collected = append(collected, rec.Content...)
		recordCount++
	}

	if recordCount < 2 {
		t.Errorf("expected at least 2 records for data > maxContentSize, got %d", recordCount)
	}
	if !bytes.Equal(collected, data) {
		t.Errorf("got %d bytes, want %d", len(collected), len(data))
	}
}

func TestWriteStream_Empty(t *testing.T) {
	var buf bytes.Buffer
	if err := writeStream(&buf, TypeParams, 1, nil); err != nil {
		t.Fatalf("writeStream error: %v", err)
	}
	if buf.Len() != 0 {
		t.Errorf("expected no output for empty data, got %d bytes", buf.Len())
	}
}

func TestClient_Close(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	go mockFCGIServer(t, ln, "Content-Type: text/html\r\nStatus: 200 OK", "ok")

	client := NewClient(ClientConfig{
		Network:      "tcp",
		Address:      ln.Addr().String(),
		DialTimeout:  2 * time.Second,
		ReadTimeout:  2 * time.Second,
		WriteTimeout: 2 * time.Second,
	})

	// Do a request to populate the pool.
	_, err = client.Do(Request{Params: map[string]string{"REQUEST_METHOD": "GET"}})
	if err != nil {
		t.Fatalf("Do error: %v", err)
	}

	// Close should not panic.
	client.Close()

	// Double close should not panic.
	client.Close()
}

func TestClient_Do_WriteError(t *testing.T) {
	// Connect to a server that immediately closes the connection.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		conn.Close() // immediately close
	}()
	defer ln.Close()

	client := NewClient(ClientConfig{
		Network:      "tcp",
		Address:      ln.Addr().String(),
		DialTimeout:  2 * time.Second,
		ReadTimeout:  2 * time.Second,
		WriteTimeout: 2 * time.Second,
	})
	defer client.Close()

	_, err = client.Do(Request{Params: map[string]string{"REQUEST_METHOD": "GET"}})
	if err == nil {
		t.Fatal("expected error when server closes connection immediately")
	}
}

func TestNewClient(t *testing.T) {
	cfg := ClientConfig{
		Network:      "tcp",
		Address:      "127.0.0.1:9000",
		DialTimeout:  5 * time.Second,
		ReadTimeout:  30 * time.Second,
		WriteTimeout: 30 * time.Second,
	}
	client := NewClient(cfg)
	if client.cfg.Address != "127.0.0.1:9000" {
		t.Errorf("address = %q", client.cfg.Address)
	}
}

// fakeConnWriter wraps a writer to satisfy net.Conn for writeRequest tests.
type fakeConnWriter struct {
	io.Writer
}

func (f fakeConnWriter) Read(b []byte) (int, error)         { return 0, io.EOF }
func (f fakeConnWriter) Close() error                        { return nil }
func (f fakeConnWriter) LocalAddr() net.Addr                 { return &net.TCPAddr{} }
func (f fakeConnWriter) RemoteAddr() net.Addr                { return &net.TCPAddr{} }
func (f fakeConnWriter) SetDeadline(_ time.Time) error       { return nil }
func (f fakeConnWriter) SetReadDeadline(_ time.Time) error   { return nil }
func (f fakeConnWriter) SetWriteDeadline(_ time.Time) error  { return nil }
