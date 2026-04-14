package fcgi

import (
	"testing"
)

func TestEncodeDecodeParams(t *testing.T) {
	tests := []struct {
		name   string
		params map[string]string
	}{
		{
			name:   "empty",
			params: map[string]string{},
		},
		{
			name:   "single short param",
			params: map[string]string{"KEY": "val"},
		},
		{
			name: "multiple params",
			params: map[string]string{
				"SCRIPT_FILENAME": "/var/www/html/index.php",
				"REQUEST_METHOD":  "GET",
				"QUERY_STRING":    "foo=bar&baz=qux",
			},
		},
		{
			name: "long value exceeding 127 bytes",
			params: map[string]string{
				"LONG": string(make([]byte, 200)),
			},
		},
		{
			name: "long key exceeding 127 bytes",
			params: map[string]string{
				string(make([]byte, 200)): "val",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			encoded := EncodeParams(tt.params)
			decoded, err := DecodeParams(encoded)
			if err != nil {
				t.Fatalf("DecodeParams error: %v", err)
			}
			if len(decoded) != len(tt.params) {
				t.Fatalf("got %d params, want %d", len(decoded), len(tt.params))
			}
			for k, v := range tt.params {
				if decoded[k] != v {
					t.Errorf("param %q = %q, want %q", k, decoded[k], v)
				}
			}
		})
	}
}

func TestDecodeParams_Malformed(t *testing.T) {
	tests := []struct {
		name string
		data []byte
	}{
		{
			name: "truncated at key length",
			data: []byte{0x80}, // high bit set but only 1 byte
		},
		{
			name: "truncated at value length",
			data: []byte{5, 0x80, 0x00}, // key len=5, then truncated 4-byte val length
		},
		{
			name: "key length exceeds data",
			data: []byte{10, 0}, // key len=10, val len=0, but no data follows
		},
		{
			name: "value length exceeds data",
			data: []byte{1, 10, 'K'}, // key len=1, val len=10, key='K', but no val data
		},
		{
			name: "empty data with high bit",
			data: []byte{0x80, 0x00, 0x00, 0x01, 0x00}, // key len=1, then truncated
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := DecodeParams(tt.data)
			if err == nil {
				t.Fatal("expected error for malformed data, got nil")
			}
		})
	}
}

func TestDecodeParams_Empty(t *testing.T) {
	params, err := DecodeParams(nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(params) != 0 {
		t.Fatalf("expected empty map, got %d entries", len(params))
	}
}
