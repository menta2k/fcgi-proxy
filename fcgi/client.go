package fcgi

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"io"
	"net"
	"net/textproto"
	"strconv"
	"time"
)

const (
	maxResponseBody   = 128 * 1024 * 1024 // 128 MB cap on stdout accumulation
	maxResponseStderr = 64 * 1024          // 64 KB cap on stderr accumulation
)

// Response holds the parsed FastCGI response.
type Response struct {
	StatusCode int
	Headers    map[string][]string
	Body       []byte
	Stderr     []byte
}

// ClientConfig holds connection parameters for the FastCGI client.
type ClientConfig struct {
	Network      string
	Address      string
	DialTimeout  time.Duration
	ReadTimeout  time.Duration
	WriteTimeout time.Duration
}

// Client is a FastCGI client that communicates with an upstream server.
// Each call to Do opens a new connection to the upstream. The Client is
// safe for concurrent use — it holds only immutable configuration.
type Client struct {
	cfg ClientConfig
}

// NewClient creates a new FastCGI client.
func NewClient(cfg ClientConfig) *Client {
	return &Client{cfg: cfg}
}

// Request represents a FastCGI request to send upstream.
type Request struct {
	Params map[string]string
	Stdin  io.Reader
}

// Do sends a FastCGI request and returns the response.
func (c *Client) Do(req Request) (Response, error) {
	conn, err := net.DialTimeout(c.cfg.Network, c.cfg.Address, c.cfg.DialTimeout)
	if err != nil {
		return Response{}, fmt.Errorf("fcgi: connect: %w", err)
	}
	defer conn.Close()

	const requestID uint16 = 1

	if err := conn.SetWriteDeadline(time.Now().Add(c.cfg.WriteTimeout)); err != nil {
		return Response{}, fmt.Errorf("fcgi: set write deadline: %w", err)
	}

	if err := c.writeRequest(conn, requestID, req); err != nil {
		return Response{}, fmt.Errorf("fcgi: write request: %w", err)
	}

	if err := conn.SetReadDeadline(time.Now().Add(c.cfg.ReadTimeout)); err != nil {
		return Response{}, fmt.Errorf("fcgi: set read deadline: %w", err)
	}

	resp, err := c.readResponse(conn, requestID)
	if err != nil {
		// Best-effort abort so the upstream can clean up gracefully.
		// Reset deadline since the read deadline may have already expired.
		_ = conn.SetDeadline(time.Now().Add(time.Second))
		_ = WriteRecord(conn, TypeAbortRequest, requestID, nil)
		return Response{}, fmt.Errorf("fcgi: read response: %w", err)
	}

	return resp, nil
}

func (c *Client) writeRequest(conn net.Conn, requestID uint16, req Request) error {
	// Pool the bufio.Writer to avoid allocating 4 KB per request.
	w := bufioWriterPool.Get().(*bufio.Writer)
	w.Reset(conn)
	defer bufioWriterPool.Put(w)

	if err := WriteBeginRequest(w, requestID, RoleResponder, false); err != nil {
		return err
	}

	params := EncodeParams(req.Params)
	if err := writeStream(w, TypeParams, requestID, params); err != nil {
		return err
	}
	if err := WriteRecord(w, TypeParams, requestID, nil); err != nil {
		return err
	}

	if req.Stdin != nil {
		if err := writeStreamFromReader(w, TypeStdin, requestID, req.Stdin); err != nil {
			return err
		}
	}
	if err := WriteRecord(w, TypeStdin, requestID, nil); err != nil {
		return err
	}

	return w.Flush()
}

// writeStream writes a byte slice as one or more records, splitting at maxContentSize.
func writeStream(w io.Writer, recType uint8, requestID uint16, data []byte) error {
	for len(data) > 0 {
		chunk := data
		if len(chunk) > maxContentSize {
			chunk = data[:maxContentSize]
		}
		if err := WriteRecord(w, recType, requestID, chunk); err != nil {
			return err
		}
		data = data[len(chunk):]
	}
	return nil
}

// writeStreamFromReader streams data from a reader as FastCGI records.
// Uses a pooled buffer to avoid allocating 64 KB per request.
func writeStreamFromReader(w io.Writer, recType uint8, requestID uint16, r io.Reader) error {
	poolBuf := stdinBufPool.Get().(*[]byte)
	buf := *poolBuf
	defer stdinBufPool.Put(poolBuf)

	for {
		n, err := r.Read(buf)
		if n > 0 {
			if writeErr := WriteRecord(w, recType, requestID, buf[:n]); writeErr != nil {
				return writeErr
			}
		}
		if err == io.EOF {
			return nil
		}
		if err != nil {
			return err
		}
	}
}

func (c *Client) readResponse(conn net.Conn, requestID uint16) (Response, error) {
	// Pool stdout and stderr buffers.
	// Discard oversized buffers to prevent the pool from retaining
	// the high-water mark of the largest response ever seen.
	const maxPooledBufCap = 1 * 1024 * 1024 // 1 MB

	stdout := stdoutBufPool.Get().(*bytes.Buffer)
	stdout.Reset()
	defer func() {
		if stdout.Cap() > maxPooledBufCap {
			stdoutBufPool.Put(new(bytes.Buffer))
		} else {
			stdoutBufPool.Put(stdout)
		}
	}()

	stderr := stderrBufPool.Get().(*bytes.Buffer)
	stderr.Reset()
	defer func() {
		if stderr.Cap() > maxPooledBufCap {
			stderrBufPool.Put(new(bytes.Buffer))
		} else {
			stderrBufPool.Put(stderr)
		}
	}()

	for {
		rec, err := ReadRecord(conn)
		if err != nil {
			return Response{}, err
		}

		if rec.Header.RequestID != requestID {
			continue
		}

		switch rec.Header.Type {
		case TypeStdout:
			if stdout.Len()+len(rec.Content) > maxResponseBody {
				return Response{}, fmt.Errorf("fcgi: response body exceeds %d bytes", maxResponseBody)
			}
			stdout.Write(rec.Content)
		case TypeStderr:
			if stderr.Len()+len(rec.Content) <= maxResponseStderr {
				stderr.Write(rec.Content)
			}
		case TypeEndRequest:
			if len(rec.Content) >= 5 && rec.Content[4] != StatusRequestComplete {
				return Response{}, fmt.Errorf("fcgi: upstream refused request (protocol status %d)", rec.Content[4])
			}
			// Copy stdout/stderr bytes out before returning buffers to pool.
			stdoutBytes := make([]byte, stdout.Len())
			copy(stdoutBytes, stdout.Bytes())
			stderrBytes := make([]byte, stderr.Len())
			copy(stderrBytes, stderr.Bytes())
			return parseHTTPResponse(stdoutBytes, stderrBytes)
		}
	}
}

// parseHTTPResponse parses the CGI/FastCGI response (headers + body).
// Uses net/textproto.Reader for robust MIME header parsing that handles
// both \r\n and \n line endings, continuation lines, and EOF correctly.
func parseHTTPResponse(stdout, stderr []byte) (Response, error) {
	resp := Response{
		StatusCode: 200,
		Headers:    make(map[string][]string, 8),
		Stderr:     stderr,
	}

	if len(stdout) == 0 {
		return resp, nil
	}

	// Pool the bufio.Reader.
	reader := bufioReaderPool.Get().(*bufio.Reader)
	reader.Reset(bytes.NewReader(stdout))
	defer bufioReaderPool.Put(reader)

	tp := textproto.NewReader(reader)

	mimeHeader, err := tp.ReadMIMEHeader()
	if err != nil && !errors.Is(err, io.EOF) {
		resp.Body = stdout
		return resp, nil
	}

	// Extract Status pseudo-header.
	if status := mimeHeader.Get("Status"); status != "" {
		if len(status) >= 3 {
			if code, parseErr := strconv.Atoi(status[:3]); parseErr == nil && code >= 100 && code < 600 {
				resp.StatusCode = code
			}
		}
		mimeHeader.Del("Status")
	}

	// Use the textproto.MIMEHeader directly as our header map to avoid copying.
	// Safe: textproto allocates its own strings from the wire bytes — the map and
	// its []string values are fully independent of the pooled bufio.Reader.
	resp.Headers = map[string][]string(mimeHeader)

	// Everything after the header block is the body.
	body, readErr := io.ReadAll(reader)
	if readErr != nil {
		return Response{}, fmt.Errorf("fcgi: read body: %w", readErr)
	}
	resp.Body = body

	return resp, nil
}
