package fcgi

import (
	"encoding/binary"
	"errors"
	"fmt"
)

var (
	ErrParamsTruncated = errors.New("fcgi: params data truncated")
)

// EncodeParams encodes key-value pairs into FastCGI params format.
func EncodeParams(params map[string]string) []byte {
	// Estimate total size to avoid repeated append-growth allocations.
	// Each param needs: key-length (1-4) + value-length (1-4) + key + value.
	estimated := 0
	for k, v := range params {
		estimated += 4 + 4 + len(k) + len(v) // worst case: 4-byte lengths
	}
	buf := make([]byte, 0, estimated)
	for k, v := range params {
		buf = appendParamLength(buf, len(k))
		buf = appendParamLength(buf, len(v))
		buf = append(buf, k...)
		buf = append(buf, v...)
	}
	return buf
}

func appendParamLength(buf []byte, length int) []byte {
	if length < 128 {
		return append(buf, byte(length))
	}
	var b [4]byte
	binary.BigEndian.PutUint32(b[:], uint32(length)|0x80000000)
	return append(buf, b[:]...)
}

// DecodeParams decodes FastCGI params from the given data.
// Returns an error on malformed input instead of panicking.
func DecodeParams(data []byte) (map[string]string, error) {
	params := make(map[string]string)
	for len(data) > 0 {
		keyLen, n, err := readParamLength(data)
		if err != nil {
			return nil, fmt.Errorf("fcgi: decode key length: %w", err)
		}
		data = data[n:]

		valLen, n, err := readParamLength(data)
		if err != nil {
			return nil, fmt.Errorf("fcgi: decode value length: %w", err)
		}
		data = data[n:]

		if len(data) < keyLen+valLen {
			return nil, fmt.Errorf("%w: need %d bytes for key+value, have %d", ErrParamsTruncated, keyLen+valLen, len(data))
		}

		key := string(data[:keyLen])
		data = data[keyLen:]
		val := string(data[:valLen])
		data = data[valLen:]

		params[key] = val
	}
	return params, nil
}

func readParamLength(data []byte) (int, int, error) {
	if len(data) == 0 {
		return 0, 0, ErrParamsTruncated
	}
	if data[0]>>7 == 0 {
		return int(data[0]), 1, nil
	}
	if len(data) < 4 {
		return 0, 0, fmt.Errorf("%w: need 4 bytes for extended length, have %d", ErrParamsTruncated, len(data))
	}
	return int(binary.BigEndian.Uint32(data[:4]) & 0x7fffffff), 4, nil
}
