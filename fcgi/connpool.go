package fcgi

import (
	"net"
	"sync"
	"sync/atomic"
	"time"
)

// PoolConfig holds connection pool parameters.
type PoolConfig struct {
	// MaxIdle is the maximum number of idle connections kept in the pool.
	MaxIdle int
	// IdleTimeout is how long an idle connection can sit unused before being closed.
	IdleTimeout time.Duration
}

// DefaultPoolConfig returns sensible pool defaults.
func DefaultPoolConfig() PoolConfig {
	return PoolConfig{
		MaxIdle:     32,
		IdleTimeout: 30 * time.Second,
	}
}

type pooledConn struct {
	net.Conn
	idleSince time.Time
}

// ConnPool manages a pool of reusable TCP/Unix connections to a FastCGI upstream.
type ConnPool struct {
	network     string
	address     string
	dialTimeout time.Duration
	maxIdle     int
	idleTimeout time.Duration

	mu     sync.Mutex
	idle   []pooledConn
	closed atomic.Bool

	stopEvict chan struct{}
}

// NewConnPool creates a connection pool with background eviction of idle connections.
func NewConnPool(network, address string, dialTimeout time.Duration, cfg PoolConfig) *ConnPool {
	if cfg.MaxIdle <= 0 {
		cfg.MaxIdle = 32
	}
	if cfg.IdleTimeout <= 0 {
		cfg.IdleTimeout = 30 * time.Second
	}

	p := &ConnPool{
		network:     network,
		address:     address,
		dialTimeout: dialTimeout,
		maxIdle:     cfg.MaxIdle,
		idleTimeout: cfg.IdleTimeout,
		idle:        make([]pooledConn, 0, cfg.MaxIdle),
		stopEvict:   make(chan struct{}),
	}

	go p.evictLoop()
	return p
}

// Get returns a connection from the pool or dials a new one.
// No liveness probe is performed — dead connections are detected on the
// first write/read and discarded by the caller. This eliminates 3 syscalls
// per reuse (SetReadDeadline + Read + SetReadDeadline).
func (p *ConnPool) Get() (net.Conn, error) {
	p.mu.Lock()
	for len(p.idle) > 0 {
		// Pop from the end (LIFO — most recently used, most likely alive).
		n := len(p.idle) - 1
		pc := p.idle[n]
		p.idle[n] = pooledConn{} // clear reference for GC
		p.idle = p.idle[:n]
		p.mu.Unlock()

		// Discard connections that have been idle too long.
		if time.Since(pc.idleSince) > p.idleTimeout {
			pc.Conn.Close()
			p.mu.Lock()
			continue
		}

		return pc.Conn, nil
	}
	p.mu.Unlock()

	return net.DialTimeout(p.network, p.address, p.dialTimeout)
}

// Put returns a connection to the pool for reuse.
// If the pool is full or closed, the connection is closed.
func (p *ConnPool) Put(conn net.Conn) {
	if p.closed.Load() {
		conn.Close()
		return
	}

	// Clear any deadlines left over from the request.
	_ = conn.SetDeadline(time.Time{})

	p.mu.Lock()
	if len(p.idle) >= p.maxIdle {
		p.mu.Unlock()
		conn.Close()
		return
	}
	p.idle = append(p.idle, pooledConn{
		Conn:      conn,
		idleSince: time.Now(),
	})
	p.mu.Unlock()
}

// Close shuts down the pool and closes all idle connections.
func (p *ConnPool) Close() {
	if !p.closed.CompareAndSwap(false, true) {
		return
	}
	close(p.stopEvict)

	p.mu.Lock()
	idle := p.idle
	p.idle = nil
	p.mu.Unlock()

	for _, pc := range idle {
		pc.Conn.Close()
	}
}

// evictLoop periodically removes connections that have been idle too long.
func (p *ConnPool) evictLoop() {
	ticker := time.NewTicker(p.idleTimeout / 2)
	defer ticker.Stop()

	for {
		select {
		case <-p.stopEvict:
			return
		case <-ticker.C:
			p.evictExpired()
		}
	}
}

func (p *ConnPool) evictExpired() {
	now := time.Now()
	p.mu.Lock()
	alive := p.idle[:0]
	var toClose []pooledConn
	for _, pc := range p.idle {
		if now.Sub(pc.idleSince) > p.idleTimeout {
			toClose = append(toClose, pc)
		} else {
			alive = append(alive, pc)
		}
	}
	p.idle = alive
	p.mu.Unlock()

	for _, pc := range toClose {
		pc.Conn.Close()
	}
}

// Stats returns the current number of idle connections (for monitoring/testing).
func (p *ConnPool) Stats() int {
	p.mu.Lock()
	n := len(p.idle)
	p.mu.Unlock()
	return n
}
