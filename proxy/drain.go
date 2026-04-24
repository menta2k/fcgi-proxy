package proxy

import (
	"net"
	"sync/atomic"

	"github.com/valyala/fasthttp"
)

// drainState tracks whether the proxy is draining in preparation for pod
// termination. A single atomic.Bool is enough: the transition is one-way
// (live → draining) and never reversed within a process lifetime. The zero
// value is safe to use (drained=false).
//
// trustedCIDRs restricts which remote IPs may flip the flag via
// /healthz/fail. A non-empty list enforces the allowlist; nil or an empty
// slice disables the check (operator opt-out). DefaultConfig populates
// this with loopback so the common case is safe without any opt-in.
type drainState struct {
	draining     atomic.Bool
	trustedCIDRs []*net.IPNet
}

// markDraining transitions to the draining state. Returns true on the first
// call so the caller can log/emit metrics once, and false on repeat calls.
func (d *drainState) markDraining() bool {
	return d.draining.CompareAndSwap(false, true)
}

// isDraining reports whether the proxy has entered the drain sequence.
func (d *drainState) isDraining() bool {
	return d.draining.Load()
}

// handleDrainFail marks the proxy as draining. Accepts GET and POST so a
// k8s preStop hook can use either curl default or an explicit --request POST.
// The endpoint is idempotent: subsequent calls return 200 "draining" without
// side effects.
//
// Security: the remote IP must match drain.trustedCIDRs (default loopback
// only). Non-loopback callers get 403 so an accidentally-exposed ingress
// cannot take the pod out of rotation. Operators who coordinate drain from
// a sibling pod can extend drain_trusted_cidrs; operators who explicitly
// configure [] opt out of the check entirely.
func handleDrainFail(ctx *fasthttp.RequestCtx, drain *drainState) {
	ctx.SetContentType("text/plain")
	if drain == nil {
		// Drain disabled — return 404 so operators don't assume the
		// endpoint succeeded when it was never wired up.
		ctx.SetStatusCode(fasthttp.StatusNotFound)
		ctx.SetBodyString("drain not enabled")
		return
	}
	if !drain.isTrustedRemote(ctx.RemoteIP()) {
		ctx.SetStatusCode(fasthttp.StatusForbidden)
		ctx.SetBodyString("forbidden")
		return
	}
	drain.markDraining()
	ctx.SetStatusCode(fasthttp.StatusOK)
	ctx.SetBodyString("draining")
}

// isTrustedRemote reports whether ip is allowed to trigger a drain. An
// empty or nil trustedCIDRs means the operator opted out of the check
// (explicit drain_trusted_cidrs: []); a non-empty list enforces the
// allowlist. DefaultConfig pre-populates loopback so the safe default
// applies without requiring the user to set anything.
func (d *drainState) isTrustedRemote(ip net.IP) bool {
	if len(d.trustedCIDRs) == 0 {
		return true
	}
	for _, n := range d.trustedCIDRs {
		if n.Contains(ip) {
			return true
		}
	}
	return false
}

// handleDrainStatus reports the current drain state as plain text so
// operators can confirm the pod received /healthz/fail.
func handleDrainStatus(ctx *fasthttp.RequestCtx, drain *drainState) {
	ctx.SetContentType("text/plain")
	if drain == nil {
		ctx.SetStatusCode(fasthttp.StatusOK)
		ctx.SetBodyString("live")
		return
	}
	ctx.SetStatusCode(fasthttp.StatusOK)
	if drain.isDraining() {
		ctx.SetBodyString("draining")
		return
	}
	ctx.SetBodyString("live")
}
