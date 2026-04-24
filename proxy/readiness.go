package proxy

import (
	"errors"
	"fmt"
	"log"
	"time"

	"github.com/menta2k/fcgi-proxy/fcgi"
	"github.com/valyala/fasthttp"
)

// readinessProber drives the /readyz endpoint by issuing lightweight
// FastCGI requests against PHP-FPM's built-in status path. It owns its
// own fcgi.Client so probe-level timeouts stay independent of the main
// request path (which typically runs with much longer read/write deadlines).
type readinessProber struct {
	client     *fcgi.Client
	statusPath string
	docRoot    string
	listenPort string
	// retryBackoff is the delay between the first failed attempt and
	// the retry. Kept as a field so tests can set it to zero.
	retryBackoff time.Duration
}

// newReadinessProber constructs a prober with a dedicated short-timeout
// FastCGI client. Returns nil when readiness is disabled.
func newReadinessProber(cfg Config) *readinessProber {
	if !cfg.Readiness.Enabled {
		return nil
	}
	client := fcgi.NewClient(fcgi.ClientConfig{
		Network:      cfg.Network,
		Address:      cfg.Address,
		DialTimeout:  cfg.Readiness.Timeout,
		ReadTimeout:  cfg.Readiness.Timeout,
		WriteTimeout: cfg.Readiness.Timeout,
		// Tiny pool: probes are infrequent (k8s default cadence 10s) and
		// keeping a large idle pool here would just waste sockets.
		Pool: fcgi.PoolConfig{MaxIdle: 2, IdleTimeout: 30 * time.Second},
	})
	return &readinessProber{
		client:       client,
		statusPath:   cfg.Readiness.StatusPath,
		docRoot:      cfg.DocumentRoot,
		listenPort:   cfg.ListenPort,
		retryBackoff: 100 * time.Millisecond,
	}
}

// probe sends a single status-page request and retries once on failure.
//
// The retry covers the case where PHP-FPM is mid-restart: the first
// attempt hits a fresh dial into a not-yet-ready worker, and the second
// attempt — after a brief pause — catches the restarted master. Stale
// pooled connections are already retried inside fcgi.Client.Do, so this
// layer only needs the one extra attempt.
func (r *readinessProber) probe() error {
	req := fcgi.Request{Params: r.buildParams()}

	resp, err := r.client.Do(req)
	if err == nil && isProbeSuccess(resp.StatusCode) {
		return nil
	}
	firstErr := probeError(resp, err)

	time.Sleep(r.retryBackoff)

	resp, err = r.client.Do(req)
	if err == nil && isProbeSuccess(resp.StatusCode) {
		return nil
	}
	return fmt.Errorf("probe failed after retry: first=%v, second=%v", firstErr, probeError(resp, err))
}

func (r *readinessProber) close() {
	if r.client != nil {
		r.client.Close()
	}
}

// buildParams constructs the minimal CGI params needed for PHP-FPM to
// route the request to its built-in status handler. Setting
// SCRIPT_FILENAME and SCRIPT_NAME to the configured status_path makes
// PHP-FPM intercept without touching any PHP file on disk.
func (r *readinessProber) buildParams() map[string]string {
	return map[string]string{
		"GATEWAY_INTERFACE": "FastCGI/1.0",
		"SERVER_PROTOCOL":   "HTTP/1.1",
		"SERVER_SOFTWARE":   "fcgi-proxy",
		"REQUEST_METHOD":    "GET",
		"REQUEST_URI":       r.statusPath,
		"SCRIPT_NAME":       r.statusPath,
		"SCRIPT_FILENAME":   r.statusPath,
		"PATH_INFO":         "",
		"QUERY_STRING":      "",
		"DOCUMENT_ROOT":     r.docRoot,
		"DOCUMENT_URI":      r.statusPath,
		"SERVER_NAME":       "readyz",
		"SERVER_PORT":       r.listenPort,
		"REMOTE_ADDR":       "127.0.0.1",
		"REMOTE_PORT":       "0",
	}
}

func isProbeSuccess(status int) bool {
	return status >= 200 && status < 300
}

// probeError normalises a probe outcome into a single error describing
// why it was unsuccessful. Returns nil only when the probe both returned
// no transport error and a successful HTTP status.
func probeError(resp fcgi.Response, err error) error {
	if err != nil {
		return err
	}
	if isProbeSuccess(resp.StatusCode) {
		return nil
	}
	return fmt.Errorf("upstream status %d", resp.StatusCode)
}

// handleReadiness answers /readyz. The PHP-FPM status body is drained and
// never echoed — the endpoint is meant for k8s probes and must not leak
// worker-pool internals to arbitrary callers.
//
// When drain is non-nil and marked, the handler short-circuits to 503
// without probing upstream. The pod is going away: PHP-FPM's state is
// irrelevant, and skipping the probe avoids flagging the upstream as
// unhealthy for a reason that's actually us.
func handleReadiness(ctx *fasthttp.RequestCtx, prober *readinessProber, drain *drainState) {
	ctx.SetContentType("text/plain")

	if drain != nil && drain.isDraining() {
		ctx.SetStatusCode(fasthttp.StatusServiceUnavailable)
		ctx.SetBodyString("draining")
		return
	}

	if prober == nil {
		// Readiness disabled: fall back to a liveness-style OK so a
		// misconfigured probe still marks the pod ready.
		ctx.SetStatusCode(fasthttp.StatusOK)
		ctx.SetBodyString("ready")
		return
	}

	if err := prober.probe(); err != nil {
		log.Printf("readiness probe failed: %v", truncateErr(err, 200))
		ctx.SetStatusCode(fasthttp.StatusServiceUnavailable)
		ctx.SetBodyString("not ready")
		return
	}

	ctx.SetStatusCode(fasthttp.StatusOK)
	ctx.SetBodyString("ready")
}

// truncateErr caps the printed error message so a noisy upstream cannot
// flood the proxy log through /readyz probes.
func truncateErr(err error, max int) error {
	if err == nil {
		return nil
	}
	msg := err.Error()
	if len(msg) <= max {
		return err
	}
	return errors.New(msg[:max] + "…")
}
