package fcgi

import (
	"bytes"
	"io"
	"net"
	"testing"
	"time"
)

func BenchmarkEncodeParams(b *testing.B) {
	params := map[string]string{
		"GATEWAY_INTERFACE": "FastCGI/1.0",
		"SERVER_PROTOCOL":   "HTTP/1.1",
		"SERVER_SOFTWARE":   "fcgi-proxy",
		"REQUEST_METHOD":    "GET",
		"REQUEST_URI":       "/index.php?foo=bar&baz=qux",
		"SCRIPT_NAME":       "/index.php",
		"SCRIPT_FILENAME":   "/var/www/html/index.php",
		"PATH_INFO":         "",
		"QUERY_STRING":      "foo=bar&baz=qux",
		"DOCUMENT_ROOT":     "/var/www/html",
		"DOCUMENT_URI":      "/index.php",
		"SERVER_NAME":       "example.com",
		"SERVER_PORT":       "8080",
		"REMOTE_ADDR":       "192.168.1.100",
		"REMOTE_PORT":       "54321",
		"HTTP_HOST":         "example.com",
		"HTTP_ACCEPT":       "text/html",
		"HTTP_USER_AGENT":   "Mozilla/5.0",
	}

	b.ReportAllocs()
	for b.Loop() {
		EncodeParams(params)
	}
}

func BenchmarkWriteRecord(b *testing.B) {
	content := bytes.Repeat([]byte("X"), 1024)
	var buf bytes.Buffer

	b.ReportAllocs()
	for b.Loop() {
		buf.Reset()
		WriteRecord(&buf, TypeStdout, 1, content)
	}
}

func BenchmarkReadRecord(b *testing.B) {
	// Build a record to read.
	content := bytes.Repeat([]byte("X"), 1024)
	var recBuf bytes.Buffer
	WriteRecord(&recBuf, TypeStdout, 1, content)
	data := recBuf.Bytes()

	b.ReportAllocs()
	for b.Loop() {
		reader := bytes.NewReader(data)
		ReadRecord(reader)
	}
}

func BenchmarkWriteStreamFromReader(b *testing.B) {
	data := bytes.Repeat([]byte("A"), 8192)
	var buf bytes.Buffer

	b.ReportAllocs()
	for b.Loop() {
		buf.Reset()
		writeStreamFromReader(&buf, TypeStdin, 1, bytes.NewReader(data))
	}
}

func BenchmarkParseHTTPResponse(b *testing.B) {
	stdout := []byte("Content-Type: text/html\r\nX-Custom: value\r\nSet-Cookie: a=1\r\nSet-Cookie: b=2\r\n\r\n<html><body>Hello World</body></html>")
	stderr := []byte("PHP Notice: test")

	b.ReportAllocs()
	for b.Loop() {
		parseHTTPResponse(stdout, stderr)
	}
}

func BenchmarkReadResponse(b *testing.B) {
	// Build a complete FastCGI response stream.
	var stream bytes.Buffer
	stdout := []byte("Content-Type: text/html\r\n\r\n<html>OK</html>")
	WriteRecord(&stream, TypeStdout, 1, stdout)
	WriteRecord(&stream, TypeStdout, 1, nil)
	endContent := make([]byte, 8)
	WriteRecord(&stream, TypeEndRequest, 1, endContent)
	data := stream.Bytes()

	client := &Client{cfg: ClientConfig{}}
	br := bytes.NewReader(data)
	conn := &fakeReaderConn{Reader: br}

	b.ReportAllocs()
	for b.Loop() {
		br.Reset(data)
		client.readResponse(conn, 1)
	}
}

// fakeReaderConn satisfies net.Conn for benchmarks.
type fakeReaderConn struct {
	*bytes.Reader
}

func (f *fakeReaderConn) Write(b []byte) (int, error)         { return 0, io.EOF }
func (f *fakeReaderConn) Close() error                         { return nil }
func (f *fakeReaderConn) LocalAddr() net.Addr                  { return &net.TCPAddr{} }
func (f *fakeReaderConn) RemoteAddr() net.Addr                 { return &net.TCPAddr{} }
func (f *fakeReaderConn) SetDeadline(_ time.Time) error        { return nil }
func (f *fakeReaderConn) SetReadDeadline(_ time.Time) error    { return nil }
func (f *fakeReaderConn) SetWriteDeadline(_ time.Time) error   { return nil }
