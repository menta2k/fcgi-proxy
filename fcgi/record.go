package fcgi

import (
	"bytes"
	"encoding/binary"
	"errors"
	"io"
)

// FastCGI record types.
const (
	TypeBeginRequest    uint8 = 1
	TypeAbortRequest    uint8 = 2
	TypeEndRequest      uint8 = 3
	TypeParams          uint8 = 4
	TypeStdin           uint8 = 5
	TypeStdout          uint8 = 6
	TypeStderr          uint8 = 7
	TypeData            uint8 = 8
	TypeGetValues       uint8 = 9
	TypeGetValuesResult uint8 = 10
	TypeUnknownType     uint8 = 11
)

// FastCGI roles.
const (
	RoleResponder  uint16 = 1
	RoleAuthorizer uint16 = 2
	RoleFilter     uint16 = 3
)

// Protocol status values.
const (
	StatusRequestComplete uint8 = 0
	StatusCantMPXConn     uint8 = 1
	StatusOverloaded      uint8 = 2
	StatusUnknownRole     uint8 = 3
)

const (
	headerSize      = 8
	maxContentSize  = 65535
	recordAlignment = 8
	version         = 1
)

var (
	ErrInvalidHeader  = errors.New("fcgi: invalid record header")
	ErrContentTooLong = errors.New("fcgi: content exceeds maximum size")
)

// Header represents a FastCGI record header.
type Header struct {
	Version       uint8
	Type          uint8
	RequestID     uint16
	ContentLength uint16
	PaddingLength uint8
}

// Record represents a single FastCGI record.
type Record struct {
	Header  Header
	Content []byte
}

// ReadRecord reads a single FastCGI record from the reader.
// The returned Content slice is a copy owned by the caller.
func ReadRecord(r io.Reader) (Record, error) {
	h, err := readHeader(r)
	if err != nil {
		return Record{}, err
	}

	totalLen := int(h.ContentLength) + int(h.PaddingLength)
	if totalLen == 0 {
		return Record{Header: h}, nil
	}

	// Use pooled buffer to read content+padding, then copy only the content out.
	poolBuf := recordBufPool.Get().(*[]byte)
	readBuf := (*poolBuf)[:totalLen]

	if _, err := io.ReadFull(r, readBuf); err != nil {
		recordBufPool.Put(poolBuf)
		return Record{}, err
	}

	content := make([]byte, h.ContentLength)
	copy(content, readBuf[:h.ContentLength])
	recordBufPool.Put(poolBuf)

	return Record{
		Header:  h,
		Content: content,
	}, nil
}

// ReadRecordInto reads a FastCGI record and appends stdout/stderr content
// directly into the provided buffer, eliminating intermediate copies.
// Returns the header and the number of content bytes appended.
// For non-stdout/stderr records, content is returned in the Record.Content field.
func ReadRecordInto(r io.Reader, stdout, stderr *bytes.Buffer, maxStdout, maxStderr int) (Record, error) {
	h, err := readHeader(r)
	if err != nil {
		return Record{}, err
	}

	totalLen := int(h.ContentLength) + int(h.PaddingLength)
	if totalLen == 0 {
		return Record{Header: h}, nil
	}

	// For stdout/stderr, read directly into the target buffer to avoid copies.
	if h.Type == TypeStdout || h.Type == TypeStderr {
		var target *bytes.Buffer
		var maxSize int
		if h.Type == TypeStdout {
			target = stdout
			maxSize = maxStdout
		} else {
			target = stderr
			maxSize = maxStderr
		}

		contentLen := int(h.ContentLength)

		if target.Len()+contentLen > maxSize {
			// Would exceed cap — skip by reading into pool buffer and discarding.
			poolBuf := recordBufPool.Get().(*[]byte)
			_, err := io.ReadFull(r, (*poolBuf)[:totalLen])
			recordBufPool.Put(poolBuf)
			if err != nil {
				return Record{}, err
			}
			if h.Type == TypeStdout {
				return Record{}, errors.New("fcgi: response body exceeds size limit")
			}
			// Stderr overflow is silently truncated.
			return Record{Header: h}, nil
		}

		// Grow the buffer, read content directly into its tail.
		target.Grow(contentLen)
		buf := target.AvailableBuffer()[:contentLen]
		if _, err := io.ReadFull(r, buf); err != nil {
			return Record{}, err
		}
		target.Write(buf)

		// Discard padding.
		paddingLen := int(h.PaddingLength)
		if paddingLen > 0 {
			var padBuf [recordAlignment - 1]byte
			if _, err := io.ReadFull(r, padBuf[:paddingLen]); err != nil {
				return Record{}, err
			}
		}

		return Record{Header: h}, nil
	}

	// For other record types (BeginRequest, EndRequest, Params, etc.),
	// read content normally.
	poolBuf := recordBufPool.Get().(*[]byte)
	readBuf := (*poolBuf)[:totalLen]

	if _, err := io.ReadFull(r, readBuf); err != nil {
		recordBufPool.Put(poolBuf)
		return Record{}, err
	}

	content := make([]byte, h.ContentLength)
	copy(content, readBuf[:h.ContentLength])
	recordBufPool.Put(poolBuf)

	return Record{Header: h, Content: content}, nil
}

func readHeader(r io.Reader) (Header, error) {
	var buf [headerSize]byte
	if _, err := io.ReadFull(r, buf[:]); err != nil {
		return Header{}, err
	}

	h := Header{
		Version:       buf[0],
		Type:          buf[1],
		RequestID:     binary.BigEndian.Uint16(buf[2:4]),
		ContentLength: binary.BigEndian.Uint16(buf[4:6]),
		PaddingLength: buf[6],
	}

	if h.Version != version {
		return Header{}, ErrInvalidHeader
	}

	return h, nil
}

// WriteRecord writes a FastCGI record to the writer.
func WriteRecord(w io.Writer, recType uint8, requestID uint16, content []byte) error {
	contentLen := len(content)
	if contentLen > maxContentSize {
		return ErrContentTooLong
	}

	paddingLen := (recordAlignment - contentLen%recordAlignment) % recordAlignment

	var buf [headerSize]byte
	buf[0] = version
	buf[1] = recType
	binary.BigEndian.PutUint16(buf[2:4], requestID)
	binary.BigEndian.PutUint16(buf[4:6], uint16(contentLen))
	buf[6] = uint8(paddingLen)

	if _, err := w.Write(buf[:]); err != nil {
		return err
	}
	if contentLen > 0 {
		if _, err := w.Write(content); err != nil {
			return err
		}
	}
	if paddingLen > 0 {
		var padding [recordAlignment - 1]byte
		if _, err := w.Write(padding[:paddingLen]); err != nil {
			return err
		}
	}
	return nil
}

// WriteBeginRequest writes a BeginRequest record.
func WriteBeginRequest(w io.Writer, requestID uint16, role uint16, keepConn bool) error {
	var content [8]byte
	binary.BigEndian.PutUint16(content[0:2], role)
	if keepConn {
		content[2] = 1
	}
	return WriteRecord(w, TypeBeginRequest, requestID, content[:])
}
