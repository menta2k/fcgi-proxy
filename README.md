# fcgi-proxy

[![CI](https://github.com/menta2k/fcgi-proxy/actions/workflows/ci.yml/badge.svg)](https://github.com/menta2k/fcgi-proxy/actions/workflows/ci.yml)
[![Release](https://github.com/menta2k/fcgi-proxy/actions/workflows/release.yml/badge.svg)](https://github.com/menta2k/fcgi-proxy/actions/workflows/release.yml)
[![GitHub release (latest SemVer)](https://img.shields.io/github/v/release/menta2k/fcgi-proxy?logo=github&sort=semver)](https://github.com/menta2k/fcgi-proxy/releases/latest)
[![Go Report Card](https://goreportcard.com/badge/github.com/menta2k/fcgi-proxy)](https://goreportcard.com/report/github.com/menta2k/fcgi-proxy)
[![codecov](https://codecov.io/gh/menta2k/fcgi-proxy/branch/main/graph/badge.svg)](https://codecov.io/gh/menta2k/fcgi-proxy)
![GitHub go.mod Go version](https://img.shields.io/github/go-mod/go-version/menta2k/fcgi-proxy?logo=go)
[![License](https://img.shields.io/badge/License-MIT-blue.svg)](https://opensource.org/licenses/MIT)
[![OpenSSF Scorecard](https://api.securityscorecards.dev/projects/github.com/menta2k/fcgi-proxy/badge)](https://scorecard.dev/viewer/?uri=github.com/menta2k/fcgi-proxy)
[![OpenSSF Best Practices](https://www.bestpractices.dev/projects/12549/badge)](https://www.bestpractices.dev/projects/12549)
[![Project Status: Active](https://www.repostatus.org/badges/latest/active.svg)](https://www.repostatus.org/#active)

A high-performance reverse proxy that sits in front of FastCGI servers like PHP-FPM. Built with [fasthttp](https://github.com/valyala/fasthttp) for minimal overhead and optimized for low memory allocations per request.

## Features

- FastCGI protocol implemented from scratch (no `net/http` dependency in the hot path)
- Robust CGI parameter construction (SERVER_NAME, REMOTE_ADDR, PATH_INFO, etc.)
- **Location cache** — proxy specific paths to external HTTP servers with in-memory caching
- **Static responses** — inline `return` bodies for paths like `/robots.txt` (nginx `location { return 200 '...'; }` equivalent), served with zero upstream calls and zero hot-path allocations
- **Authentication** — HTTP Digest (RFC 7616) or Basic (RFC 7617), with an HMAC-keyed bcrypt cache for Basic. Per-location bypass. See [Authentication](#authentication).
- **Configurable response headers** — inject security headers (HSTS, X-Frame-Options, etc.) into every response
- **Configurable CORS** — RFC-compliant origin allowlist, preflight handling, credentials, zero-allocation hot path. See [CORS](#cors).
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
| Pool max idle | `pool_max_idle` | - | `32` | Maximum idle connections kept in the FastCGI connection pool (1 to 1024) |
| Pool idle timeout | `pool_idle_timeout` | - | `30s` | How long an idle connection can sit unused before being closed (1s to 5m) |
| Response headers | `response_headers` | - | `{}` | Map of headers added to every response (see below) |
| Locations | `locations` | - | `[]` | External proxy locations with caching (see below) |
| CORS | `cors` | - | `{"enabled": false}` | Cross-Origin Resource Sharing config (see [CORS](#cors)) |
| Authentication | `auth` | - | `{"enabled": false}` | HTTP Digest or Basic authentication (see [Authentication](#authentication)) |

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

### CORS

Cross-Origin Resource Sharing handled at the proxy, independently of what the backend would do. When enabled, the proxy short-circuits preflight (`OPTIONS`) requests locally and injects the appropriate `Access-Control-*` headers on simple responses. When disabled, the proxy is transparent and the backend can handle CORS itself.

```json
{
  "cors": {
    "enabled": true,
    "allowed_origins": ["https://app.example.com", "app://localhost"],
    "allowed_methods": ["GET", "POST", "PUT", "DELETE", "OPTIONS"],
    "allowed_headers": ["Content-Type", "Authorization"],
    "exposed_headers": ["X-Request-Id"],
    "allow_credentials": false,
    "max_age": "10m"
  }
}
```

| Field | Required | Default | Description |
|-------|----------|---------|-------------|
| `enabled` | yes | `false` | Master switch. When `false`, the block is ignored and CORS is not applied. |
| `allowed_origins` | yes (when enabled) | — | Exact-match allowlist. Supports `http://`, `https://`, `app://` (Cordova/hybrid mobile) schemes, the literal `"null"` (sandboxed iframes / `file://`), and the wildcard `"*"`. Scheme/host compared case-insensitively per RFC 6454. |
| `allowed_methods` | no | `[]` | Echoed in preflight `Access-Control-Allow-Methods`. Methods are normalized to upper case. Must be valid HTTP methods (`GET`, `HEAD`, `POST`, `PUT`, `PATCH`, `DELETE`, `OPTIONS`). |
| `allowed_headers` | no | `[]` | Echoed in preflight `Access-Control-Allow-Headers`. When unset, the proxy echoes the value of the client's `Access-Control-Request-Headers` after validation (rs/cors default). Entries are header-name-validated (alphanumeric + hyphen) or `"*"`. |
| `exposed_headers` | no | `[]` | Sent as `Access-Control-Expose-Headers` on simple responses. Validated like `allowed_headers`. |
| `allow_credentials` | no | `false` | When `true`, the response includes `Access-Control-Allow-Credentials: true`. Cannot be combined with `"*"` in `allowed_origins` or with `"null"` (both rejected at config load). |
| `max_age` | no | — | Preflight cache duration. Pre-formatted at parse time; range `0` to `24h`. Omit or set to `0` to omit the header. |

**Behavior details:**

- **Preflight** (`OPTIONS` with `Access-Control-Request-Method` header) is answered by the proxy with `204 No Content` — the FastCGI backend is never consulted.
- **Origin-allowed simple requests** get `Access-Control-Allow-Origin: <origin>` (exact echo) or `*` in wildcard-no-credentials mode; credentialed responses always echo the specific origin.
- **`Vary: Origin`** is emitted on every CORS-sensitive response, including rejected preflights (403) and simple requests from disallowed origins, to prevent shared-cache poisoning.
- **Origin scheme validation**: `http://`, `https://`, `app://`, or literal `"null"`. Anything else is rejected at parse time.
- **Port validation**: hostnames with a `:port` suffix require a decimal port in `1..65535`. Malformed entries like `app://loc:alhost` are rejected.
- **Case-insensitive origin matching**: browsers normalize origins to lowercase; the proxy lowercases the configured allowlist at parse time and does a zero-allocation fast path for already-lowercase request origins.
- **Bypass paths**: `/healthz` and configured `locations` (both static-return and cached-upstream entries) are not CORS-gated. If you need CORS on those paths, handle it upstream.

**Security hardening (already in place):**

- `Access-Control-Request-Headers` is validated for CR/LF/NUL before being echoed back, preventing response-splitting attacks.
- When CORS is enabled, `Origin`, `Access-Control-Request-Method`, and `Access-Control-Request-Headers` are stripped from the CGI environment forwarded to PHP-FPM — the proxy is the single CORS authority.
- `response_headers` entries starting with `Access-Control-` are rejected at config load when CORS is enabled (no silent override).
- `allow_credentials: true` combined with `"*"` or `"null"` origins is rejected at parse time (classic CORS footguns).
- The fasthttp request parser strips CR/LF from header values before the CORS middleware sees them; the NUL check is defense in depth.

**Benchmark** (AMD Ryzen 5 7600X, isolated middleware work):

| Path | ns/op | B/op | allocs/op |
|------|------:|-----:|----------:|
| Preflight (allowed origin) | 401 | 0 | 0 |
| Simple cross-origin request | 181 | 0 | 0 |
| CORS disabled (fast-path return) | 2.6 | 0 | 0 |
| Origin case-fold (slow path) | 16.8 | 0 | 0 |

### Authentication

HTTP authentication applied at the proxy, in front of the FastCGI backend. Two schemes are supported: **Digest** (RFC 7616) and **Basic** (RFC 7617). Exactly one scheme is active at a time.

```json
{
  "auth": {
    "enabled": true,
    "type": "digest",
    "realm": "fcgi-proxy",
    "algorithm": "SHA-256",
    "nonce_lifetime": "5m",
    "users": [
      { "username": "alice", "ha1": "<64-hex for SHA-256, 32-hex for MD5>" }
    ]
  }
}
```

| Field | Required | Default | Description |
|-------|----------|---------|-------------|
| `enabled` | yes | `false` | Master switch. When `false`, the block is ignored. |
| `type` | no | `digest` | `digest` or `basic`. |
| `realm` | yes (when enabled) | — | Sent in the `WWW-Authenticate` challenge. Must not contain `CR`, `LF`, NUL, or double-quote. |
| `algorithm` | digest only | `SHA-256` | `SHA-256` (recommended) or `MD5` (legacy, for old clients). |
| `nonce_lifetime` | digest only | `5m` | How long a server-issued nonce stays valid. `30s` to `24h`. |
| `users` | yes (when enabled) | — | Inline user database. Maximum 1000 entries. See per-scheme fields below. |
| `password_cache` | basic only | enabled with defaults | bcrypt result cache (see below). |

**Bypass paths** (not gated by auth):

- `/healthz` — load-balancer probes stay reachable.
- CORS preflight (`OPTIONS` with `Access-Control-Request-Method`) — browsers strip the `Authorization` header from preflights, so gating them would break every CORS-using client. The CORS middleware handles preflights before the auth gate.
- Configured `locations` — both `return` (inline static) and cached-upstream entries. If a path is in your `locations`, it serves without auth.

Everything else — the FastCGI backend, script resolution, the entire `index.php` front-controller — requires valid credentials.

#### Digest

Credentials are stored as **HA1 hex** (`H(username:realm:password)`), never plaintext. Compute with:

```bash
# SHA-256 (default)
printf '%s' 'alice:fcgi-proxy:s3cret' | sha256sum

# MD5 (legacy)
printf '%s' 'alice:fcgi-proxy:s3cret' | md5sum
```

| User field | Description |
|------------|-------------|
| `username` | Must not contain `:`, `CR`, `LF`, NUL, or double-quote. |
| `ha1` | Lowercase hex of `H(username:realm:password)`. 64 chars for `SHA-256`, 32 for `MD5`. |

**Nonce design:** stateless, HMAC-signed. The proxy does not keep a nonce store; nonces are self-verifying base64 of `timestamp || 16 random bytes || HMAC-SHA-256(secret, timestamp||random)[:16]`. On process restart, the HMAC secret is regenerated — clients present the old (now-invalid) nonce, the server responds with `stale=true`, and compliant clients re-auth silently without reprompting.

**Hardening in place:**

- `qop=auth` is required; the RFC 2069 qop-absent fallback is rejected to prevent downgrade.
- Client-supplied `algorithm=` parameter must match the configured algorithm, preventing hash-function downgrade.
- Client-supplied `uri=` must match the actual request target (RFC 7616 §3.4) — prevents replay of a captured `Authorization` header against a different URI within the nonce lifetime.
- Unknown-username responses run a dummy HMAC pass to equalize response time with wrong-password responses — no user enumeration via timing.
- Response compare uses `crypto/subtle.ConstantTimeCompare`; realm compare uses the same.
- Header parser tolerates `key ="value"` (trailing whitespace) and unescapes `\"` in quoted values.

**Trade-off:** no `nc` (nonce-count) tracking — a captured valid `Authorization` header can be replayed within the nonce lifetime. Deploy over TLS, and consider a short `nonce_lifetime` (e.g. `30s`) for high-value endpoints on plain HTTP.

#### Basic

Credentials are stored as **bcrypt hashes**. Generate with `htpasswd`:

```bash
# Cost 10 (default for htpasswd -B)
htpasswd -B -n alice

# Explicit cost (12 recommended for sensitive endpoints)
htpasswd -B -C 12 -n alice
```

| User field | Description |
|------------|-------------|
| `username` | Must not contain `:`, `CR`, `LF`, NUL, or double-quote. |
| `password_hash` | bcrypt hash starting with `$2a$`, `$2b$`, or `$2y$`. Plaintext is rejected at config load. |

Config example:

```json
{
  "auth": {
    "enabled": true,
    "type": "basic",
    "realm": "fcgi-proxy",
    "users": [
      { "username": "alice", "password_hash": "$2b$10$..." }
    ],
    "password_cache": {
      "enabled": true,
      "ttl": "1m",
      "max_entries": 10000
    }
  }
}
```

**Hardening in place:**

- Unknown-username path runs a dummy bcrypt compare **at the same cost as the slowest configured hash** — determined at parse time. No user enumeration via timing.
- Plaintext passwords are rejected at config load (prefix check: must start with `$2a$`, `$2b$`, or `$2y$`).
- Empty passwords are allowed if the stored hash matches, per RFC 7617.
- Passwords containing `:` work correctly (split on the first `:` only).
- Base64 decode uses a 512-byte stack buffer; oversized `Authorization` headers are rejected without spilling to heap.

##### Password cache

bcrypt verification at cost 10 takes ~50 ms. Without a cache, a single authenticated request caps a CPU core at ~10–20 RPS — a 1000× throughput regression vs the unauthenticated case. The proxy includes a Caddy-style in-memory cache to avoid re-running bcrypt on every request.

| Field | Default | Description |
|-------|---------|-------------|
| `password_cache.enabled` | `true` | Set to `false` to disable the cache and pay the full bcrypt cost on every request. |
| `password_cache.ttl` | `1m` | How long a successful auth stays cached. Range `1s` to `1h`. |
| `password_cache.max_entries` | `10000` | Upper bound on cached entries. Range `1` to `1,000,000`. |

**Design:**

- Cache **only successful** authentications. Failures and unknown users always run bcrypt, so the cache cannot accelerate brute-force attacks.
- Keys are HMAC-SHA-256(secret, `stored_hash || 0x00 || password`) with a per-cache 32-byte random secret. Binding to the stored hash means rotating a password automatically orphans prior entries. The HMAC secret makes a partial memory dump (map bytes only) useless for offline password cracking.
- Eviction is lazy: on `set` at capacity, expired entries are dropped first, then — if still full — half the map is bulk-dropped (map iteration order as pseudo-random eviction). No background goroutines.
- Hot path: atomic-counter RLock + map lookup + `time.Now()` compare. Zero allocations, 12 ns/op.
- HMAC derivation also zero-allocation via pre-computed inner/outer pads and stack-buffered SHA-256.

**Performance (AMD Ryzen 5 7600X, `bcrypt.MinCost`):**

| Path | ns/op | allocs/op |
|------|------:|----------:|
| Cache hit (Authorization → success) | 643 | 8 |
| Cache miss (bcrypt MinCost verify) | 673,020 | 19 |
| Cache hit isolated (`check` only) | 12 | 0 |
| HMAC key derivation isolated | 217 | 0 |

Speedup: **1046×** at `MinCost`, scaling linearly with bcrypt cost. At operator cost 10 (~50 ms bcrypt), the speedup approaches **~77,000×**.

**Operator note on password rotation:** the cache is rebuilt when the process restarts (new HMAC secret, empty map). Editing `config.json` in place without restarting the process will keep cached credentials valid for up to `password_cache.ttl` (default 1 minute). For immediate rotation, send `SIGTERM` and start the proxy again.

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
- `pool_max_idle` is between 1 and 1024
- `pool_idle_timeout` is between 1s and 5m
- `response_headers` keys are alphanumeric/hyphens; values have no CR/LF/null
- `locations` paths start with `/`; upstreams are `http://` or `https://` without credentials; TTLs are non-negative; maximum 100 locations; each entry is either `upstream`- or `return`-shaped (never both)
- `cors` origins have `http://`/`https://`/`app://` schemes with valid host[:port]; `allow_credentials` + `"*"` or `"null"` rejected; `max_age` ≤ 24h; `response_headers` cannot contain `Access-Control-*` keys while CORS is enabled
- `auth` realm is non-empty and free of CR/LF/NUL/quote; digest users supply HA1 matching the algorithm hash size; basic users supply bcrypt-prefixed password hashes; `password_cache` applies only to Basic

Invalid configuration causes the proxy to exit with a clear error message.

## Health Check

`GET /healthz` returns `200 OK` with body `ok` without touching the FastCGI upstream or the location cache. Use this for load balancer and Kubernetes liveness/readiness probes.

## Performance

### Connection pooling

The proxy maintains a pool of reusable TCP/Unix connections to PHP-FPM, eliminating the TCP handshake overhead on every request:

- **LIFO ordering** — most recently used connection returned first (most likely alive)
- **No liveness probe** — dead connections are detected on write and discarded (eliminates 3 syscalls per reuse)
- **`keepConn=true`** — tells PHP-FPM to keep connections open after each request
- **Background eviction** — idle connections are cleaned up automatically
- **Configurable** — `pool_max_idle` (default 32) and `pool_idle_timeout` (default 30s)

For best results, set `pool_max_idle` to match or exceed your PHP-FPM `pm.max_children`.

### Memory optimizations

- **Pooled buffers** — `bufio.Writer`, `bufio.Reader`, `bytes.Buffer` (stdout/stderr), record content buffers, and stdin streaming buffers are all reused via `sync.Pool`
- **Direct buffer writes** — `ReadRecordInto` appends FastCGI stdout/stderr content directly into the response buffer, eliminating per-record intermediate copies
- **Oversized buffer eviction** — pooled `bytes.Buffer` instances larger than 1 MB are discarded instead of returned to the pool, preventing high-water-mark retention
- **Zero-allocation header processing** — blocked-header checks and CGI env key construction use fixed-size stack buffers with no heap allocations
- **Pre-sized maps** — CGI params map pre-allocated to 28 entries; response headers map pre-allocated to 8 entries
- **Pre-estimated encoding buffer** — `EncodeParams` estimates total byte count upfront, reducing append-growth from ~5 allocations to 1
- **Direct MIMEHeader reuse** — `textproto.MIMEHeader` is cast directly to `map[string][]string` instead of copied

### Micro-benchmark results (AMD Ryzen 5 7600X)

| Operation | ns/op | B/op | allocs/op |
|-----------|-------|------|-----------|
| EncodeParams (18 keys) | 425 | 576 | 1 |
| WriteRecord (1 KB) | 23 | 8 | 1 |
| ReadRecord (1 KB) | 274 | 1093 | 3 |
| WriteStreamFromReader (8 KB) | 169 | 56 | 2 |
| ParseHTTPResponse | 706 | 1136 | 12 |
| ReadResponse (full round-trip) | 615 | 1110 | 12 |
| BuildEnvKey | 16 | 0 | 0 |
| IsBlockedHeader | 13 | 0 | 0 |

### fcgi-proxy vs nginx — comparative benchmark

Both proxying to the same PHP-FPM backend (50 children, `pm = static`), 10-second test duration.

**Throughput (requests in 10s):**

| Test | fcgi-proxy | nginx | Diff |
|------|-----------|-------|------|
| Minimal JSON (GET, 50c) | **254,297** | 168,320 | **+51%** |
| Front-controller (GET /, 50c) | **257,313** | 161,263 | **+60%** |
| Heavy workload (GET, 10KB resp, 50c) | **147,693** | 126,056 | **+17%** |
| POST with body (50c) | **246,976** | 161,365 | **+53%** |
| Health check (50c) | **913,235** | 888,454 | **+3%** |
| High concurrency (GET, 200c) | **259,729** | 152,274 | **+71%** |

**Latency p50 (ms):**

| Test | fcgi-proxy | nginx |
|------|-----------|-------|
| Minimal JSON | **0.6** | 1.5 |
| Front-controller | **0.9** | 1.8 |
| Heavy workload | **2.2** | 3.5 |
| POST with body | **0.9** | 1.9 |
| Health check | 0.5 | 0.5 |
| High concurrency (200c) | **1.7** | 12.5 |

### Running the comparative benchmark

A full benchmark suite is included in `benchmark/` that runs fcgi-proxy and nginx side-by-side against the same PHP-FPM backend. It tests 6 scenarios: minimal JSON, front-controller routing, heavy workload (~10 KB response), POST with body, health check, and high concurrency (200 connections).

**Requirements:** Docker, Docker Compose, [hey](https://github.com/rakyll/hey) (`go install github.com/rakyll/hey@latest`)

```bash
cd benchmark

# Start PHP-FPM (50 children), fcgi-proxy, and nginx
docker compose up -d

# Run all tests (default: 10s duration, 50 concurrency)
./run.sh

# Custom duration and concurrency
./run.sh 30s 100

# Clean up
docker compose down
```

The benchmark stack:
- `php-fpm` — PHP 8.3 FPM Alpine with `pm.max_children = 50`
- `fcgi-proxy` — built from source, listening on port 8081
- `nginx` — nginx 1.27 Alpine with equivalent FastCGI config, listening on port 8082
- Both proxies connect to the same PHP-FPM container over TCP

**Included PHP test scripts:**
- `www/index.php` — minimal JSON response (~60 bytes)
- `www/heavy.php` — 100 users with md5 hashes (~10 KB response)
- `www/echo.php` — echoes POST body metadata

### Running micro-benchmarks

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
