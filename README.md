# fcgi-proxy

A high-performance reverse proxy that sits in front of FastCGI servers like PHP-FPM. Built with [fasthttp](https://github.com/valyala/fasthttp) for minimal overhead and optimized for low memory allocations per request.

## Features

- FastCGI protocol implemented from scratch (no `net/http` dependency in the hot path)
- Robust CGI parameter construction (SERVER_NAME, REMOTE_ADDR, PATH_INFO, etc.)
- **Location cache** — proxy specific paths to external HTTP servers with in-memory caching
- **Configurable response headers** — inject security headers (HSTS, X-Frame-Options, etc.) into every response
- **Memory-optimized** — `sync.Pool` for hot-path buffers, zero-allocation header processing, pre-sized maps
- Path traversal prevention with `filepath.Rel` boundary checks
- httpoxy (CVE-2016-5385) protection
- SSRF guard on location cache upstreams (blocks private/loopback/metadata IPs)
- Hop-by-hop header filtering (case-insensitive)
- CGI environment key validation (single-pass byte-level filter)
- Null byte rejection in URI path and query string
- Authoritative `X-Forwarded-For` / `X-Real-IP` injection (client-supplied values stripped)
- Configurable timeouts, body size limits, and concurrency caps
- Health check endpoint at `/healthz`
- Graceful shutdown on SIGINT/SIGTERM

## Quick Start

```bash
# Build
go build -o fcgi-proxy .

# Run with defaults (listens on :8080, upstream at 127.0.0.1:9000)
./fcgi-proxy

# Run with a config file
cp config.example.json config.json
./fcgi-proxy -config config.json

# Run with CLI overrides
./fcgi-proxy -listen :9090 -address 127.0.0.1:9001 -document-root /srv/www
```

## Docker

The image runs as `nobody` (non-root) with a read-only root filesystem.

```bash
# Build
docker build -t fcgi-proxy .

# Run (mount your config)
docker run -d \
  -p 8080:8080 \
  -v ./config.json:/etc/fcgi-proxy/config.json:ro \
  fcgi-proxy

# Run with CLI flags
docker run -d \
  -p 8080:8080 \
  fcgi-proxy \
  -listen :8080 \
  -network tcp \
  -address php-fpm:9000 \
  -document-root /var/www/html
```

### Docker Compose with PHP-FPM

```yaml
services:
  proxy:
    build: .
    ports:
      - "8080:8080"
    command:
      - -listen
      - ":8080"
      - -network
      - tcp
      - -address
      - php-fpm:9000
      - -document-root
      - /var/www/html
    depends_on:
      - php-fpm

  php-fpm:
    image: php:8.3-fpm
    volumes:
      - ./www:/var/www/html
```

## Helm Chart

An example Helm chart with PHP-FPM + fcgi-proxy as a sidecar is included in `deploy/helm/fcgi-proxy-example/`.

```bash
# Install
helm install my-app deploy/helm/fcgi-proxy-example/

# With custom values
helm install my-app deploy/helm/fcgi-proxy-example/ \
  --set replicaCount=3 \
  --set proxy.port=8090 \
  --set config.listen=":8090"

# Port-forward to test
kubectl port-forward svc/my-app-fcgi-proxy-example 8080:80
curl http://localhost:8080/
```

The Helm deployment includes `securityContext` with `runAsNonRoot`, `readOnlyRootFilesystem`, and `drop: ALL` capabilities.

## Configuration

Configuration is loaded from a JSON file (default: `config.json`). CLI flags override file values. If the file does not exist, built-in defaults are used.

Copy `config.example.json` to `config.json` and edit as needed.

### Options

| Option | JSON key | CLI flag | Default | Description |
|--------|----------|----------|---------|-------------|
| Listen address | `listen` | `-listen` | `:8080` | `host:port` to bind the HTTP server |
| Network | `network` | `-network` | `tcp` | FastCGI upstream network: `tcp`, `tcp4`, `tcp6`, `unix` |
| Address | `address` | `-address` | `127.0.0.1:9000` | FastCGI upstream address (TCP `host:port` or Unix socket path) |
| Document root | `document_root` | `-document-root` | `/var/www/html` | Absolute path to the PHP document root on the upstream |
| Index file | `index` | - | `index.php` | Default script for non-`.php` URIs (front-controller pattern) |
| Dial timeout | `dial_timeout` | - | `5s` | Timeout for connecting to the upstream |
| Read timeout | `read_timeout` | - | `30s` | Timeout for reading the upstream response; also HTTP server read timeout |
| Write timeout | `write_timeout` | - | `30s` | Timeout for writing to the upstream; also HTTP server write timeout |
| Max body size | `max_body_size` | - | `10485760` (10 MB) | Maximum request body in bytes (1 to 268435456) |
| Max concurrency | `max_concurrency` | - | `1024` | Maximum simultaneous connections (1 to 65535) |
| Response headers | `response_headers` | - | `{}` | Map of headers added to every response (see below) |
| Locations | `locations` | - | `[]` | External proxy locations with caching (see below) |

### Response Headers

Add custom headers to every proxied response. Uses `Set` semantics (overrides any same-named upstream header).

```json
{
  "response_headers": {
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Strict-Transport-Security": "max-age=31536000; includeSubDomains"
  }
}
```

Header names must contain only alphanumeric characters and hyphens. Values must not contain CR, LF, or null bytes. These are validated at startup.

Note: response headers are **not** applied to `/healthz` responses (health checks go to load balancers, not browsers).

### Location Cache

Proxy specific paths to external HTTP/HTTPS servers and cache the response. This is useful for serving static content from a CDN or external asset server without routing through PHP-FPM.

```json
{
  "locations": [
    {
      "path": "/apple-app-site-association",
      "upstream": "https://assets.example.com/universal-links/apple-app-site-association",
      "cache_ttl": "1h"
    },
    {
      "path": "/.well-known/assetlinks.json",
      "upstream": "https://assets.example.com/android/assetlinks.json",
      "cache_ttl": "1h"
    }
  ]
}
```

| Field | Required | Default | Description |
|-------|----------|---------|-------------|
| `path` | yes | - | Exact path to match (must start with `/`) |
| `upstream` | yes | - | External URL to fetch from (`http://` or `https://`) |
| `cache_ttl` | no | `5m` | How long to cache a successful (200) response. Go duration format. |

**Behavior:**

- Only `200 OK` responses are cached. Non-200 responses are not stored and result in `502 Bad Gateway` to the client.
- Concurrent requests for the same path are deduplicated (singleflight) — only one upstream fetch runs at a time.
- When the upstream is unreachable, a previously cached 200 response is served as a stale fallback (up to 24 hours old). Stale entries older than 24 hours are evicted from memory.
- Each cached response body is capped at 10 MB.
- Responses include an `X-Cache: HIT` or `X-Cache: MISS` header.
- Maximum 100 locations can be configured.

**Security:**

- SSRF protection: the proxy blocks connections to private (RFC 1918), loopback, link-local, and cloud metadata (169.254.169.254) addresses. Hostnames are resolved and all IPs are checked before connecting.
- Redirects are limited to 5 hops per request, and the SSRF guard applies at the TCP dial layer so redirects to internal addresses are also blocked.
- Upstream URLs must not contain credentials (`user:pass@host` is rejected at config validation).
- Error messages in logs have credentials stripped from URLs.

### Timeout format

Timeouts use Go duration strings: `100ms`, `5s`, `1m30s`, `1h`, etc. All timeouts must be between `100ms` and `5m`. Cache TTLs have no upper bound (use `0` to disable caching and always fetch).

### Validation

At startup, the proxy validates:
- `listen` is a valid `host:port`
- `network` is one of `tcp`, `tcp4`, `tcp6`, `unix`
- `address` is not empty
- `document_root` is an absolute path
- `index` is a plain filename (no `/`, `\`, or null bytes)
- All timeouts are valid durations within bounds
- `max_body_size` is between 1 and 256 MB
- `max_concurrency` is between 1 and 65535
- `response_headers` keys are alphanumeric/hyphens; values have no CR/LF/null
- `locations` paths start with `/`; upstreams are `http://` or `https://` without credentials; TTLs are non-negative; maximum 100 locations

Invalid configuration causes the proxy to exit with a clear error message.

## Health Check

`GET /healthz` returns `200 OK` with body `ok` without touching the FastCGI upstream or the location cache. Use this for load balancer and Kubernetes liveness/readiness probes.

## Performance

The proxy is optimized for minimal memory allocations per request:

- **Pooled buffers** — `bufio.Writer`, `bufio.Reader`, `bytes.Buffer` (stdout/stderr), record content buffers, and stdin streaming buffers are all reused via `sync.Pool`
- **Oversized buffer eviction** — pooled `bytes.Buffer` instances larger than 1 MB are discarded instead of returned to the pool, preventing the pool from permanently holding the high-water mark of the largest response
- **Zero-allocation header processing** — blocked-header checks and CGI env key construction use fixed-size stack buffers with no heap allocations
- **Pre-sized maps** — CGI params map pre-allocated to 28 entries; response headers map pre-allocated to 8 entries
- **Pre-estimated encoding buffer** — `EncodeParams` estimates total byte count upfront, reducing append-growth from ~5 allocations to 1
- **Direct MIMEHeader reuse** — `textproto.MIMEHeader` is cast directly to `map[string][]string` instead of copied

### Benchmark results (AMD Ryzen 5 7600X)

| Operation | ns/op | B/op | allocs/op |
|-----------|-------|------|-----------|
| EncodeParams (18 keys) | 418 | 576 | 1 |
| WriteRecord (1 KB) | 21 | 8 | 1 |
| ReadRecord (1 KB) | 257 | 1091 | 3 |
| WriteStreamFromReader (8 KB) | 163 | 56 | 2 |
| ParseHTTPResponse | 699 | 1136 | 12 |
| ReadResponse (full round-trip) | 621 | 1196 | 13 |
| BuildEnvKey | 16 | 0 | 0 |
| IsBlockedHeader | 13 | 0 | 0 |

Run benchmarks:

```bash
go test -bench=. -benchmem ./fcgi/ ./proxy/
```

## CGI Parameters

The proxy sets the following CGI environment variables for each request:

| Parameter | Source |
|-----------|--------|
| `GATEWAY_INTERFACE` | `FastCGI/1.0` |
| `SERVER_PROTOCOL` | Actual request protocol (`HTTP/1.0` or `HTTP/1.1`) |
| `SERVER_SOFTWARE` | `fcgi-proxy` |
| `SERVER_NAME` | `Host` header (port stripped, null bytes rejected) |
| `SERVER_PORT` | Derived from listen address |
| `REQUEST_METHOD` | From the HTTP request |
| `REQUEST_URI` | Full request URI including query string |
| `SCRIPT_NAME` | Resolved PHP script path |
| `SCRIPT_FILENAME` | Absolute path: `document_root` + `script_name` |
| `PATH_INFO` | Extra path after `.php` (cleaned of `..` sequences) |
| `QUERY_STRING` | From the URI |
| `DOCUMENT_ROOT` | From configuration |
| `DOCUMENT_URI` | `SCRIPT_NAME` + `PATH_INFO` |
| `REMOTE_ADDR` | Client IP (IPv6 brackets stripped) |
| `REMOTE_PORT` | Client port |
| `CONTENT_TYPE` | From `Content-Type` header |
| `CONTENT_LENGTH` | From actual body length (not the header value) |
| `HTTPS` | `on` if the connection is TLS |
| `HTTP_*` | All client headers (except blocked ones) |
| `HTTP_X_FORWARDED_FOR` | Authoritative client IP (client-supplied value stripped) |
| `HTTP_X_REAL_IP` | Authoritative client IP (client-supplied value stripped) |

### Blocked client headers

The following client headers are stripped before forwarding to prevent spoofing:

- `Proxy` (httpoxy CVE-2016-5385)
- `X-Forwarded-For` (replaced with authoritative value)
- `X-Real-IP` (replaced with authoritative value)
- `Connection`, `Transfer-Encoding`, `Trailer` (hop-by-hop)
- `Content-Type`, `Content-Length` (set explicitly from actual values)

## Script Resolution

The proxy resolves PHP scripts using a front-controller pattern compatible with Laravel, Symfony, WordPress, and similar frameworks:

| Request URI | SCRIPT_NAME | PATH_INFO |
|-------------|-------------|-----------|
| `/index.php` | `/index.php` | |
| `/index.php/api/users` | `/index.php` | `/api/users` |
| `/` | `/index.php` | |
| `/admin/` | `/admin/index.php` | |
| `/api/users` | `/index.php` | `/api/users` |
| `/admin/dashboard.php` | `/admin/dashboard.php` | |

Extension matching is case-insensitive (`.php`, `.PHP`, `.Php` all work).

## Security

The proxy implements multiple layers of defense:

- **Path traversal**: `filepath.Clean` + `filepath.Rel` boundary check ensures `SCRIPT_FILENAME` never escapes the document root
- **Null byte injection**: Requests with null bytes in URI path or query string are rejected with 400
- **httpoxy**: The `Proxy` header is unconditionally stripped
- **Header injection**: CGI env keys are validated via single-pass byte-level filter (alphanumeric + hyphen only, must contain at least one letter, max 251 chars); response header keys/values are validated at config load
- **IP spoofing**: Client-supplied `X-Forwarded-For`/`X-Real-IP` are stripped; authoritative values injected from the actual TCP connection
- **SSRF**: Location cache upstreams are blocked from connecting to private, loopback, link-local, and cloud metadata addresses; DNS resolution is checked; redirects limited to 5 hops per request
- **Hop-by-hop leaking**: `Connection`, `Transfer-Encoding`, `Keep-Alive`, `TE`, `Trailer`, `Upgrade`, `Proxy-Authenticate`, `Proxy-Authorization` are filtered from upstream responses (case-insensitive)
- **Error isolation**: Internal errors are logged server-side; clients receive only generic `502 Bad Gateway`; upstream URLs in logs have credentials stripped
- **Host header sanitization**: Null bytes and control characters in the `Host` header are rejected
- **Server identity**: The `Server` response header is suppressed
- **Body limits**: Configurable `max_body_size` (up to 256 MB); FastCGI upstream response capped at 128 MB; location cache upstream capped at 10 MB
- **Timeout enforcement**: All network operations have bounded deadlines (100ms to 5m)
- **Concurrency cap**: Configurable `max_concurrency` (up to 65535)
- **FastCGI protocol**: EndRequest `protocolStatus` is checked; non-complete statuses return 502
- **Cache safety**: Only 200 responses are cached; stale fallback limited to 24 hours with automatic eviction; singleflight prevents cache stampede
- **Memory safety**: Pooled buffers are capped at 1 MB before returning to pool; oversized buffers are discarded to prevent high-water-mark retention
- **Container security**: Dockerfile runs as `nobody`; Helm chart sets `runAsNonRoot`, `readOnlyRootFilesystem`, `allowPrivilegeEscalation: false`, `drop: ALL`

## Testing

```bash
go test -race -cover ./...
```

The test suite includes:
- Unit tests for FastCGI protocol encoding/decoding, params, records
- Config validation tests (all fields, edge cases, error paths)
- Location cache tests (fetch, cache hit, TTL expiry, stale fallback, stale eviction, singleflight dedup, SSRF guard, non-200 rejection)
- Integration tests with a mock FastCGI server (full HTTP-to-FastCGI round-trip, header filtering, body forwarding, health check, response headers, null byte rejection)
- Path traversal attack tests
- Benchmarks for all hot-path operations

## License

MIT
