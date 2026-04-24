package proxy

import (
	"net"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/menta2k/fcgi-proxy/config"
	"github.com/valyala/fasthttp"
	"github.com/valyala/fasthttp/fasthttputil"
)

// mustCIDR parses a CIDR string or fails the test. Keeps table-driven tests
// terse without swallowing malformed test fixtures.
func mustCIDR(t *testing.T, s string) *net.IPNet {
	t.Helper()
	_, n, err := net.ParseCIDR(s)
	if err != nil {
		t.Fatalf("bad CIDR %q: %v", s, err)
	}
	return n
}

// drainProxyHarness spins up a real TCP HTTP listener on 127.0.0.1 so the
// drain endpoint's loopback IP guard sees a real loopback remote — the
// in-memory listener would surface 0.0.0.0 and fail the guard.
type drainProxyHarness struct {
	proxyAddr     string
	upstreamConns *atomic.Int32
	shutdown      func()
}

func startDrainProxy(t *testing.T, trustedCIDRs []*net.IPNet, drainEnabled bool) *drainProxyHarness {
	t.Helper()

	// Upstream PHP-FPM stand-in always returns 200 on the status probe.
	upstream, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	var conns atomic.Int32
	go statusPageServer(t, upstream, &conns, func(conn net.Conn, _ int32) {
		readStdinEnd(t, conn)
		writeStatus200(conn)
	})

	cfg := Config{
		Network:      "tcp",
		Address:      upstream.Addr().String(),
		DocumentRoot: "/var/www/html",
		Index:        "index.php",
		ListenPort:   "8080",
		DialTimeout:  2 * time.Second,
		ReadTimeout:  2 * time.Second,
		WriteTimeout: 2 * time.Second,
		Readiness: config.ParsedReadiness{
			Enabled:           true,
			StatusPath:        "/status",
			Timeout:           500 * time.Millisecond,
			DrainEnabled:      drainEnabled,
			DrainTrustedCIDRs: trustedCIDRs,
		},
	}

	// Real TCP listener gives the handler a real loopback RemoteAddr.
	proxy, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		upstream.Close()
		t.Fatal(err)
	}
	server := &fasthttp.Server{Handler: Handler(cfg)}
	go func() { _ = server.Serve(proxy) }()

	return &drainProxyHarness{
		proxyAddr:     proxy.Addr().String(),
		upstreamConns: &conns,
		shutdown: func() {
			_ = server.Shutdown()
			proxy.Close()
			upstream.Close()
		},
	}
}

// doTCP issues a real TCP request against the proxy so ctx.RemoteIP()
// surfaces the loopback address the IP guard expects to see.
func doTCP(t *testing.T, addr, method, uri string) (int, string, string) {
	t.Helper()
	req := fasthttp.AcquireRequest()
	resp := fasthttp.AcquireResponse()
	defer fasthttp.ReleaseRequest(req)
	defer fasthttp.ReleaseResponse(resp)

	req.SetRequestURI("http://" + addr + uri)
	req.Header.SetMethod(method)

	if err := fasthttp.Do(req, resp); err != nil {
		t.Fatalf("request %s %s: %v", method, uri, err)
	}
	return resp.StatusCode(), string(resp.Body()), string(resp.Header.Peek("Connection"))
}

// TestHealthzFail_TriggersDrain verifies the end-to-end drain sequence.
func TestHealthzFail_TriggersDrain(t *testing.T) {
	h := startDrainProxy(t, []*net.IPNet{mustCIDR(t, "127.0.0.0/8"), mustCIDR(t, "::1/128")}, true)
	defer h.shutdown()

	// Pre-drain: /readyz probes upstream successfully.
	status, body, connHdr := doTCP(t, h.proxyAddr, "GET", "/readyz")
	if status != 200 {
		t.Errorf("pre-drain /readyz status = %d, want 200", status)
	}
	if body != "ready" {
		t.Errorf("pre-drain /readyz body = %q, want ready", body)
	}
	if strings.EqualFold(connHdr, "close") {
		t.Errorf("pre-drain Connection must not be close, got %q", connHdr)
	}
	pre := h.upstreamConns.Load()
	if pre < 1 {
		t.Errorf("pre-drain /readyz must have probed upstream")
	}

	// Trigger drain from loopback — allowed.
	status, body, _ = doTCP(t, h.proxyAddr, "GET", "/healthz/fail")
	if status != 200 {
		t.Errorf("/healthz/fail status = %d, want 200", status)
	}
	if body != "draining" {
		t.Errorf("/healthz/fail body = %q, want draining", body)
	}

	// Post-drain: /readyz flips to 503 and skips upstream probe.
	status, body, connHdr = doTCP(t, h.proxyAddr, "GET", "/readyz")
	if status != 503 {
		t.Errorf("post-drain /readyz status = %d, want 503", status)
	}
	if body != "draining" {
		t.Errorf("post-drain /readyz body = %q, want draining", body)
	}
	if !strings.EqualFold(connHdr, "close") {
		t.Errorf("post-drain /readyz Connection = %q, want close", connHdr)
	}
	if got := h.upstreamConns.Load(); got != pre {
		t.Errorf("post-drain /readyz must not probe upstream, saw %d extra", got-pre)
	}

	// /healthz stays 200 so k8s liveness doesn't restart us mid-drain.
	status, body, connHdr = doTCP(t, h.proxyAddr, "GET", "/healthz")
	if status != 200 {
		t.Errorf("post-drain /healthz status = %d, want 200", status)
	}
	if body != "ok" {
		t.Errorf("post-drain /healthz body = %q, want ok", body)
	}
	if !strings.EqualFold(connHdr, "close") {
		t.Errorf("post-drain /healthz Connection = %q, want close", connHdr)
	}

	// /healthz/drain-status reports draining.
	status, body, _ = doTCP(t, h.proxyAddr, "GET", "/healthz/drain-status")
	if status != 200 {
		t.Errorf("/healthz/drain-status status = %d, want 200", status)
	}
	if body != "draining" {
		t.Errorf("/healthz/drain-status body = %q, want draining", body)
	}
}

// TestHealthzFail_Idempotent verifies repeated calls don't error.
func TestHealthzFail_Idempotent(t *testing.T) {
	h := startDrainProxy(t, []*net.IPNet{mustCIDR(t, "127.0.0.0/8")}, true)
	defer h.shutdown()

	for i := range 3 {
		status, body, _ := doTCP(t, h.proxyAddr, "GET", "/healthz/fail")
		if status != 200 {
			t.Errorf("call %d status = %d, want 200", i, status)
		}
		if body != "draining" {
			t.Errorf("call %d body = %q, want draining", i, body)
		}
	}
}

// TestHealthzFail_AcceptsPOST verifies POST is accepted.
func TestHealthzFail_AcceptsPOST(t *testing.T) {
	h := startDrainProxy(t, []*net.IPNet{mustCIDR(t, "127.0.0.0/8")}, true)
	defer h.shutdown()

	status, body, _ := doTCP(t, h.proxyAddr, "POST", "/healthz/fail")
	if status != 200 {
		t.Errorf("POST /healthz/fail status = %d, want 200", status)
	}
	if body != "draining" {
		t.Errorf("POST /healthz/fail body = %q, want draining", body)
	}
}

// TestDrainDisabled_ReturnsNotFound verifies drain endpoints 404 when off.
func TestDrainDisabled_ReturnsNotFound(t *testing.T) {
	h := startDrainProxy(t, nil, false)
	defer h.shutdown()

	status, body, _ := doTCP(t, h.proxyAddr, "GET", "/healthz/fail")
	if status != 404 {
		t.Errorf("/healthz/fail status = %d, want 404 when drain disabled", status)
	}
	if !strings.Contains(body, "not enabled") {
		t.Errorf("/healthz/fail body = %q, want mention of 'not enabled'", body)
	}

	status, body, _ = doTCP(t, h.proxyAddr, "GET", "/healthz/drain-status")
	if status != 200 {
		t.Errorf("drain-status status = %d, want 200", status)
	}
	if body != "live" {
		t.Errorf("drain-status body = %q, want live", body)
	}
}

// TestDrainStatus_LiveBeforeFail verifies drain-status is "live" until fired.
func TestDrainStatus_LiveBeforeFail(t *testing.T) {
	h := startDrainProxy(t, []*net.IPNet{mustCIDR(t, "127.0.0.0/8")}, true)
	defer h.shutdown()

	status, body, _ := doTCP(t, h.proxyAddr, "GET", "/healthz/drain-status")
	if status != 200 {
		t.Errorf("drain-status status = %d, want 200", status)
	}
	if body != "live" {
		t.Errorf("drain-status body = %q, want live", body)
	}
}

// TestDrainState_MarkDrainingOnce verifies markDraining is single-shot.
func TestDrainState_MarkDrainingOnce(t *testing.T) {
	var d drainState
	if !d.markDraining() {
		t.Error("first markDraining must return true")
	}
	if d.markDraining() {
		t.Error("second markDraining must return false")
	}
	if !d.isDraining() {
		t.Error("isDraining must be true after mark")
	}
}

// TestDrainState_ZeroValue verifies the zero value is not draining.
func TestDrainState_ZeroValue(t *testing.T) {
	var d drainState
	if d.isDraining() {
		t.Error("zero-value drainState must report isDraining=false")
	}
}

// TestHealthzFail_NonLoopbackForbidden verifies the IP guard. An in-memory
// listener surfaces 0.0.0.0 as the remote IP, which matches neither
// 127.0.0.0/8 nor ::1/128, so the guard must return 403.
func TestHealthzFail_NonLoopbackForbidden(t *testing.T) {
	cfg := Config{
		Network:      "tcp",
		Address:      "127.0.0.1:9000",
		DocumentRoot: "/var/www/html",
		Index:        "index.php",
		ListenPort:   "8080",
		DialTimeout:  time.Second,
		ReadTimeout:  time.Second,
		WriteTimeout: time.Second,
		Readiness: config.ParsedReadiness{
			Enabled:           true,
			StatusPath:        "/status",
			Timeout:           500 * time.Millisecond,
			DrainEnabled:      true,
			DrainTrustedCIDRs: []*net.IPNet{mustCIDR(t, "127.0.0.0/8"), mustCIDR(t, "::1/128")},
		},
	}
	inmem := fasthttputil.NewInmemoryListener()
	defer inmem.Close()
	server := &fasthttp.Server{Handler: Handler(cfg)}
	go func() { _ = server.Serve(inmem) }()

	client := &fasthttp.HostClient{
		Dial: func(addr string) (net.Conn, error) { return inmem.Dial() },
	}
	req := fasthttp.AcquireRequest()
	resp := fasthttp.AcquireResponse()
	defer fasthttp.ReleaseRequest(req)
	defer fasthttp.ReleaseResponse(resp)
	req.SetRequestURI("http://test/healthz/fail")
	req.Header.SetMethod("GET")
	if err := client.Do(req, resp); err != nil {
		t.Fatalf("request error: %v", err)
	}
	if resp.StatusCode() != 403 {
		t.Errorf("status = %d, want 403 for non-loopback remote", resp.StatusCode())
	}
	if !strings.Contains(string(resp.Body()), "forbidden") {
		t.Errorf("body = %q, want mention of forbidden", resp.Body())
	}
}

// TestHealthzFail_EmptyCIDRsOptOut verifies an explicit empty CIDR list
// disables the IP guard — operators who need to accept drain triggers from
// anywhere can opt out without rebuilding the proxy.
func TestHealthzFail_EmptyCIDRsOptOut(t *testing.T) {
	cfg := Config{
		Network:      "tcp",
		Address:      "127.0.0.1:9000",
		DocumentRoot: "/var/www/html",
		Index:        "index.php",
		ListenPort:   "8080",
		DialTimeout:  time.Second,
		ReadTimeout:  time.Second,
		WriteTimeout: time.Second,
		Readiness: config.ParsedReadiness{
			Enabled:           true,
			StatusPath:        "/status",
			Timeout:           500 * time.Millisecond,
			DrainEnabled:      true,
			DrainTrustedCIDRs: []*net.IPNet{}, // explicit opt-out
		},
	}
	inmem := fasthttputil.NewInmemoryListener()
	defer inmem.Close()
	server := &fasthttp.Server{Handler: Handler(cfg)}
	go func() { _ = server.Serve(inmem) }()

	client := &fasthttp.HostClient{
		Dial: func(addr string) (net.Conn, error) { return inmem.Dial() },
	}
	req := fasthttp.AcquireRequest()
	resp := fasthttp.AcquireResponse()
	defer fasthttp.ReleaseRequest(req)
	defer fasthttp.ReleaseResponse(resp)
	req.SetRequestURI("http://test/healthz/fail")
	req.Header.SetMethod("GET")
	if err := client.Do(req, resp); err != nil {
		t.Fatalf("request error: %v", err)
	}
	if resp.StatusCode() != 200 {
		t.Errorf("status = %d, want 200 when CIDRs opted out", resp.StatusCode())
	}
	if string(resp.Body()) != "draining" {
		t.Errorf("body = %q, want draining", resp.Body())
	}
}

// TestIsTrustedRemote_TableCases locks down the CIDR match logic at the
// unit level so future config changes can't accidentally flip semantics.
func TestIsTrustedRemote_TableCases(t *testing.T) {
	loop4 := mustCIDR(t, "127.0.0.0/8")
	loop6 := mustCIDR(t, "::1/128")
	pod := mustCIDR(t, "10.0.0.0/8")

	cases := []struct {
		name    string
		cidrs   []*net.IPNet
		ip      string
		trusted bool
	}{
		{"loopback_v4_in_default", []*net.IPNet{loop4, loop6}, "127.0.0.1", true},
		{"loopback_v6_in_default", []*net.IPNet{loop4, loop6}, "::1", true},
		{"public_ip_rejected", []*net.IPNet{loop4, loop6}, "8.8.8.8", false},
		{"pod_ip_rejected_by_default", []*net.IPNet{loop4, loop6}, "10.0.5.7", false},
		{"pod_ip_allowed_when_added", []*net.IPNet{loop4, pod}, "10.0.5.7", true},
		{"empty_list_allows_all", []*net.IPNet{}, "8.8.8.8", true},
		{"nil_list_allows_all", nil, "8.8.8.8", true},
		{"zero_addr_rejected_by_default", []*net.IPNet{loop4, loop6}, "0.0.0.0", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			d := &drainState{trustedCIDRs: tc.cidrs}
			got := d.isTrustedRemote(net.ParseIP(tc.ip))
			if got != tc.trusted {
				t.Errorf("isTrustedRemote(%s) with %d cidrs = %v, want %v", tc.ip, len(tc.cidrs), got, tc.trusted)
			}
		})
	}
}
