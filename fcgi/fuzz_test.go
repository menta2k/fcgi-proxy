package fcgi

import (
	"bytes"
	"testing"
)

func FuzzDecodeParams(f *testing.F) {
	// Seed with valid encoded params.
	params := map[string]string{"KEY": "value", "SCRIPT_FILENAME": "/var/www/html/index.php"}
	f.Add(EncodeParams(params))
	f.Add([]byte{})
	f.Add([]byte{5, 3, 'H', 'E', 'L', 'L', 'O', 'a', 'b', 'c'})

	f.Fuzz(func(t *testing.T, data []byte) {
		// Should never panic.
		DecodeParams(data)
	})
}

func FuzzReadRecord(f *testing.F) {
	// Seed with a valid record.
	var buf bytes.Buffer
	WriteRecord(&buf, TypeStdout, 1, []byte("hello"))
	f.Add(buf.Bytes())
	f.Add([]byte{1, 6, 0, 1, 0, 0, 0, 0}) // empty stdout record

	f.Fuzz(func(t *testing.T, data []byte) {
		// Should never panic.
		ReadRecord(bytes.NewReader(data))
	})
}

func FuzzParseHTTPResponse(f *testing.F) {
	f.Add([]byte("Content-Type: text/html\r\n\r\n<html>body</html>"), []byte(""))
	f.Add([]byte("Status: 404 Not Found\r\n\r\nNot Found"), []byte("warning"))
	f.Add([]byte(""), []byte(""))
	f.Add([]byte("raw body without headers"), []byte(""))

	f.Fuzz(func(t *testing.T, stdout, stderr []byte) {
		// Should never panic.
		parseHTTPResponse(stdout, stderr)
	})
}
