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
	Pool         PoolConfig
}

// Client is a FastCGI client that communicates with an upstream server.
// It maintains a connection pool for reuse across requests.
// Safe for concurrent use.
type Client struct {
	cfg  ClientConfig
	pool *ConnPool
}

// NewClient creates a new FastCGI client with a connection pool.
func NewClient(cfg ClientConfig) *Client {
	return &Client{
		cfg:  cfg,
		pool: NewConnPool(cfg.Network, cfg.Address, cfg.DialTimeout, cfg.Pool),
	}
}

// Close shuts down the client and its connection pool.
func (c *Client) Close() {
	c.pool.Close()
}

// Request represents a FastCGI request to send upstream.
type Request struct {
	Params map[string]string
	Stdin  io.Reader
}

// Do sends a FastCGI request and returns the response.
// Connections are reused from the pool when available.
func (c *Client) Do(req Request) (Response, error) {
	conn, err := c.pool.Get()
	if err != nil {
		return Response{}, fmt.Errorf("fcgi: connect: %w", err)
	}

	const requestID uint16 = 1

	if err := conn.SetWriteDeadline(time.Now().Add(c.cfg.WriteTimeout)); err != nil {
		conn.Close()
		return Response{}, fmt.Errorf("fcgi: set write deadline: %w", err)
	}

	if err := c.writeRequest(conn, requestID, req); err != nil {
		conn.Close()
		return Response{}, fmt.Errorf("fcgi: write request: %w", err)
	}

	if err := conn.SetReadDeadline(time.Now().Add(c.cfg.ReadTimeout)); err != nil {
		conn.Close()
		return Response{}, fmt.Errorf("fcgi: set read deadline: %w", err)
	}

	resp, err := c.readResponse(conn, requestID)
	if err != nil {
		// Best-effort abort so the upstream can clean up gracefully.
		_ = conn.SetDeadline(time.Now().Add(time.Second))
		_ = WriteRecord(conn, TypeAbortRequest, requestID, nil)
		conn.Close()
		return Response{}, fmt.Errorf("fcgi: read response: %w", err)
	}

	// Success — return the connection to the pool for reuse.
	c.pool.Put(conn)

	return resp, nil
}

func (c *Client) writeRequest(conn net.Conn, requestID uint16, req Request) error {
	w := bufioWriterPool.Get().(*bufio.Writer)
	w.Reset(conn)
	defer bufioWriterPool.Put(w)

	// keepConn=true tells PHP-FPM to keep the connection open after this request.
	if err := WriteBeginRequest(w, requestID, RoleResponder, true); err != nil {
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
	const maxPooledBufCap = 1 * 1024 * 1024

	stdout := stdoutBufPool.Get().(*bytes.Buffer)
	stdout.Reset()
	stderr := stderrBufPool.Get().(*bytes.Buffer)
	stderr.Reset()

	// returnBufs puts both buffers back to the pool, discarding oversized ones.
	returnBufs := func() {
		if stdout.Cap() > maxPooledBufCap {
			stdoutBufPool.Put(new(bytes.Buffer))
		} else {
			stdoutBufPool.Put(stdout)
		}
		if stderr.Cap() > maxPooledBufCap {
			stderrBufPool.Put(new(bytes.Buffer))
		} else {
			stderrBufPool.Put(stderr)
		}
	}

	for {
		// ReadRecordInto appends stdout/stderr content directly into the buffers,
		// eliminating the per-record content copy.
		rec, err := ReadRecordInto(conn, stdout, stderr, maxResponseBody, maxResponseStderr)
		if err != nil {
			returnBufs()
			return Response{}, err
		}

		if rec.Header.RequestID != requestID {
			continue
		}

		if rec.Header.Type == TypeEndRequest {
			if len(rec.Content) >= 5 && rec.Content[4] != StatusRequestComplete {
				returnBufs()
				return Response{}, fmt.Errorf("fcgi: upstream refused request (protocol status %d)", rec.Content[4])
			}

			// Parse directly from the buffer bytes. parseHTTPResponse does not
			// retain references to the input slices (it copies via textproto),
			// so we can return the buffers to the pool after parsing.
			resp, parseErr := parseHTTPResponse(stdout.Bytes(), stderr.Bytes())
			returnBufs()
			return resp, parseErr
		}
	}
}

// parseHTTPResponse parses the CGI/FastCGI response (headers + body).
func parseHTTPResponse(stdout, stderr []byte) (Response, error) {
	resp := Response{
		StatusCode: 200,
		Headers:    make(map[string][]string, 8),
		Stderr:     stderr,
	}

	if len(stdout) == 0 {
		return resp, nil
	}

	reader := bufioReaderPool.Get().(*bufio.Reader)
	reader.Reset(bytes.NewReader(stdout))
	defer bufioReaderPool.Put(reader)

	tp := textproto.NewReader(reader)

	mimeHeader, err := tp.ReadMIMEHeader()
	if err != nil && !errors.Is(err, io.EOF) {
		resp.Body = stdout
		return resp, nil
	}

	if status := mimeHeader.Get("Status"); status != "" {
		if len(status) >= 3 {
			if code, parseErr := strconv.Atoi(status[:3]); parseErr == nil && code >= 100 && code < 600 {
				resp.StatusCode = code
			}
		}
		mimeHeader.Del("Status")
	}

	// Safe: textproto allocates its own strings from the wire bytes — the map and
	// its []string values are fully independent of the pooled bufio.Reader.
	resp.Headers = map[string][]string(mimeHeader)

	body, readErr := io.ReadAll(reader)
	if readErr != nil {
		return Response{}, fmt.Errorf("fcgi: read body: %w", readErr)
	}
	resp.Body = body

	return resp, nil
}
