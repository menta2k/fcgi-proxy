#!/usr/bin/env bash
set -euo pipefail

# Comparative benchmark: fcgi-proxy vs nginx, both proxying to the same PHP-FPM.
#
# Requirements: hey (go install github.com/rakyll/hey@latest)
# Usage: cd benchmark && ./run.sh [duration] [concurrency]

DURATION="${1:-10s}"
CONCURRENCY="${2:-50}"
FCGI_PROXY="http://127.0.0.1:8081"
NGINX="http://127.0.0.1:8082"

RED='\033[0;31m'
GREEN='\033[0;32m'
CYAN='\033[0;36m'
BOLD='\033[1m'
RESET='\033[0m'

command -v hey >/dev/null 2>&1 || {
    echo "hey not found. Install with: go install github.com/rakyll/hey@latest"
    exit 1
}

header() {
    echo ""
    echo -e "${BOLD}${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${RESET}"
    echo -e "${BOLD}  $1${RESET}"
    echo -e "${BOLD}${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${RESET}"
}

run_bench() {
    local label="$1"
    local url="$2"
    local method="${3:-GET}"
    local body_file="${4:-}"

    echo -e "\n${GREEN}>>> ${label}${RESET}"
    echo -e "    URL: ${url}"
    echo -e "    Duration: ${DURATION}, Concurrency: ${CONCURRENCY}\n"

    if [ "$method" = "POST" ] && [ -n "$body_file" ]; then
        hey -z "$DURATION" -c "$CONCURRENCY" -m POST \
            -T "application/json" \
            -D "$body_file" \
            "$url" 2>&1 | tail -20
    else
        hey -z "$DURATION" -c "$CONCURRENCY" "$url" 2>&1 | tail -20
    fi
}

# Verify both services are up.
echo "Checking services..."
for url in "$FCGI_PROXY/healthz" "$NGINX/healthz"; do
    if ! curl -sf "$url" > /dev/null 2>&1; then
        echo "ERROR: $url is not responding. Run: docker compose up -d"
        exit 1
    fi
done
echo "Both services are up."

# Create a POST body for the echo test.
POST_BODY=$(mktemp)
echo '{"key":"value","numbers":[1,2,3,4,5]}' > "$POST_BODY"
trap "rm -f $POST_BODY" EXIT

# ─── Test 1: Minimal JSON response (GET /index.php) ───────────────────────────

header "Test 1: Minimal JSON response (GET /index.php)"
run_bench "fcgi-proxy" "$FCGI_PROXY/index.php"
run_bench "nginx"      "$NGINX/index.php"

# ─── Test 2: Front-controller routing (GET /) ─────────────────────────────────

header "Test 2: Front-controller routing (GET /)"
run_bench "fcgi-proxy" "$FCGI_PROXY/"
run_bench "nginx"      "$NGINX/"

# ─── Test 3: Heavy PHP workload (GET /heavy.php) ──────────────────────────────

header "Test 3: Heavy PHP workload (GET /heavy.php)"
run_bench "fcgi-proxy" "$FCGI_PROXY/heavy.php"
run_bench "nginx"      "$NGINX/heavy.php"

# ─── Test 4: POST with body (POST /echo.php) ─────────────────────────────────

header "Test 4: POST with JSON body (POST /echo.php)"
run_bench "fcgi-proxy" "$FCGI_PROXY/echo.php" POST "$POST_BODY"
run_bench "nginx"      "$NGINX/echo.php"      POST "$POST_BODY"

# ─── Test 5: Health check (GET /healthz) ──────────────────────────────────────

header "Test 5: Health check endpoint (GET /healthz) — proxy only, no PHP-FPM"
run_bench "fcgi-proxy" "$FCGI_PROXY/healthz"
run_bench "nginx"      "$NGINX/healthz"

# ─── Test 6: High concurrency (GET /index.php, 200 concurrent) ───────────────

header "Test 6: High concurrency (GET /index.php, 200 concurrent)"
echo -e "\n${GREEN}>>> fcgi-proxy${RESET}"
hey -z "$DURATION" -c 200 "$FCGI_PROXY/index.php" 2>&1 | tail -20
echo -e "\n${GREEN}>>> nginx${RESET}"
hey -z "$DURATION" -c 200 "$NGINX/index.php" 2>&1 | tail -20

header "Done"
echo ""
echo "Configuration:"
echo "  Duration per test: $DURATION"
echo "  Default concurrency: $CONCURRENCY"
echo "  fcgi-proxy: $FCGI_PROXY"
echo "  nginx: $NGINX"
echo "  PHP-FPM: shared backend (php:8.3-fpm-alpine)"
echo ""
