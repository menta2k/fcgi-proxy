# Security Policy

## Supported Versions

| Version | Supported          |
|---------|--------------------|
| latest  | :white_check_mark: |

## Reporting a Vulnerability

If you discover a security vulnerability in fcgi-proxy, please report it responsibly.

**Do not open a public GitHub issue for security vulnerabilities.**

Instead, please report vulnerabilities via [GitHub Security Advisories](https://github.com/menta2k/fcgi-proxy/security/advisories/new).

You will receive a response within 48 hours. If the issue is confirmed, a fix will be released as soon as possible.

## Security Measures

This project implements multiple layers of defense:

- Path traversal prevention
- httpoxy (CVE-2016-5385) protection
- SSRF guard on external upstreams
- CGI environment key validation
- Null byte rejection
- Hop-by-hop header filtering
- Error isolation (no internal details leaked to clients)
- Bounded timeouts, body sizes, and concurrency
- Connection pool with idle eviction

See the [README](README.md#security) for full details.
