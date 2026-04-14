package fcgi

import (
	"bytes"
	"testing"
)

func TestWriteReadRecord(t *testing.T) {
	tests := []struct {
		name      string
		recType   uint8
		requestID uint16
		content   []byte
	}{
		{
			name:      "empty content",
			recType:   TypeParams,
			requestID: 1,
			content:   nil,
		},
		{
			name:      "small content",
			recType:   TypeStdout,
			requestID: 1,
			content:   []byte("Hello, World!"),
		},
		{
			name:      "content aligned to 8 bytes",
			recType:   TypeStdin,
			requestID: 42,
			content:   []byte("12345678"),
		},
		{
			name:      "content needing padding",
			recType:   TypeStderr,
			requestID: 100,
			content:   []byte("abc"),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var buf bytes.Buffer
			if err := WriteRecord(&buf, tt.recType, tt.requestID, tt.content); err != nil {
				t.Fatalf("WriteRecord error: %v", err)
			}

			rec, err := ReadRecord(&buf)
			if err != nil {
				t.Fatalf("ReadRecord error: %v", err)
			}

			if rec.Header.Type != tt.recType {
				t.Errorf("type = %d, want %d", rec.Header.Type, tt.recType)
			}
			if rec.Header.RequestID != tt.requestID {
				t.Errorf("requestID = %d, want %d", rec.Header.RequestID, tt.requestID)
			}
			if !bytes.Equal(rec.Content, tt.content) {
				t.Errorf("content = %q, want %q", rec.Content, tt.content)
			}
		})
	}
}

func TestWriteBeginRequest(t *testing.T) {
	var buf bytes.Buffer
	if err := WriteBeginRequest(&buf, 1, RoleResponder, false); err != nil {
		t.Fatalf("WriteBeginRequest error: %v", err)
	}

	rec, err := ReadRecord(&buf)
	if err != nil {
		t.Fatalf("ReadRecord error: %v", err)
	}

	if rec.Header.Type != TypeBeginRequest {
		t.Errorf("type = %d, want %d", rec.Header.Type, TypeBeginRequest)
	}
	if rec.Header.RequestID != 1 {
		t.Errorf("requestID = %d, want 1", rec.Header.RequestID)
	}
}

func TestReadRecord_InvalidVersion(t *testing.T) {
	// Version 2 (invalid)
	data := []byte{2, TypeStdout, 0, 1, 0, 0, 0, 0}
	_, err := ReadRecord(bytes.NewReader(data))
	if err != ErrInvalidHeader {
		t.Errorf("got error %v, want ErrInvalidHeader", err)
	}
}

func TestReadRecord_Truncated(t *testing.T) {
	// Only 4 bytes — too short for a header
	data := []byte{1, TypeStdout, 0, 1}
	_, err := ReadRecord(bytes.NewReader(data))
	if err == nil {
		t.Fatal("expected error for truncated header")
	}
}

func TestWriteRecord_ContentTooLong(t *testing.T) {
	var buf bytes.Buffer
	bigContent := make([]byte, maxContentSize+1)
	err := WriteRecord(&buf, TypeStdout, 1, bigContent)
	if err != ErrContentTooLong {
		t.Errorf("got error %v, want ErrContentTooLong", err)
	}
}

func TestWriteRecord_NilContent(t *testing.T) {
	var buf bytes.Buffer
	if err := WriteRecord(&buf, TypeParams, 1, nil); err != nil {
		t.Fatalf("error: %v", err)
	}
	rec, err := ReadRecord(&buf)
	if err != nil {
		t.Fatalf("ReadRecord error: %v", err)
	}
	if len(rec.Content) != 0 {
		t.Errorf("content = %q, want empty", rec.Content)
	}
}

func TestWriteBeginRequest_KeepConn(t *testing.T) {
	var buf bytes.Buffer
	if err := WriteBeginRequest(&buf, 1, RoleResponder, true); err != nil {
		t.Fatalf("error: %v", err)
	}
	rec, err := ReadRecord(&buf)
	if err != nil {
		t.Fatalf("ReadRecord error: %v", err)
	}
	if rec.Header.Type != TypeBeginRequest {
		t.Errorf("type = %d, want %d", rec.Header.Type, TypeBeginRequest)
	}
	// keepConn flag is byte 2 of the content
	if rec.Content[2] != 1 {
		t.Errorf("keepConn flag = %d, want 1", rec.Content[2])
	}
}

func TestReadRecord_TruncatedContent(t *testing.T) {
	// Valid header claiming 10 bytes of content, but only 3 bytes follow.
	data := []byte{1, TypeStdout, 0, 1, 0, 10, 0, 0, 'a', 'b', 'c'}
	_, err := ReadRecord(bytes.NewReader(data))
	if err == nil {
		t.Fatal("expected error for truncated content")
	}
}
