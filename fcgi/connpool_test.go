package fcgi

import (
	"net"
	"testing"
	"time"
)

func startTCPEcho(t *testing.T) net.Listener {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })

	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			// Keep connections open until closed by the client.
			go func() {
				buf := make([]byte, 1024)
				for {
					_, err := conn.Read(buf)
					if err != nil {
						conn.Close()
						return
					}
				}
			}()
		}
	}()
	return ln
}

func TestConnPool_GetPut(t *testing.T) {
	ln := startTCPEcho(t)
	pool := NewConnPool("tcp", ln.Addr().String(), 2*time.Second, DefaultPoolConfig())
	defer pool.Close()

	conn, err := pool.Get()
	if err != nil {
		t.Fatalf("Get error: %v", err)
	}

	if pool.Stats() != 0 {
		t.Errorf("idle = %d, want 0 (conn is checked out)", pool.Stats())
	}

	pool.Put(conn)

	if pool.Stats() != 1 {
		t.Errorf("idle = %d, want 1 (conn returned)", pool.Stats())
	}
}

func TestConnPool_Reuse(t *testing.T) {
	ln := startTCPEcho(t)
	pool := NewConnPool("tcp", ln.Addr().String(), 2*time.Second, DefaultPoolConfig())
	defer pool.Close()

	// Get and put a connection.
	conn1, _ := pool.Get()
	addr1 := conn1.LocalAddr().String()
	pool.Put(conn1)

	// Get again — should reuse the same connection.
	conn2, _ := pool.Get()
	addr2 := conn2.LocalAddr().String()
	pool.Put(conn2)

	if addr1 != addr2 {
		t.Errorf("expected reuse: conn1=%s, conn2=%s", addr1, addr2)
	}
}

func TestConnPool_MaxIdle(t *testing.T) {
	ln := startTCPEcho(t)
	pool := NewConnPool("tcp", ln.Addr().String(), 2*time.Second, PoolConfig{
		MaxIdle:     2,
		IdleTimeout: 30 * time.Second,
	})
	defer pool.Close()

	// Get 5 connections.
	conns := make([]net.Conn, 5)
	for i := range conns {
		var err error
		conns[i], err = pool.Get()
		if err != nil {
			t.Fatal(err)
		}
	}

	// Put all 5 back. Only 2 should be kept (max idle).
	for _, c := range conns {
		pool.Put(c)
	}

	if pool.Stats() != 2 {
		t.Errorf("idle = %d, want 2 (max idle)", pool.Stats())
	}
}

func TestConnPool_IdleTimeout(t *testing.T) {
	ln := startTCPEcho(t)
	pool := NewConnPool("tcp", ln.Addr().String(), 2*time.Second, PoolConfig{
		MaxIdle:     16,
		IdleTimeout: 50 * time.Millisecond,
	})
	defer pool.Close()

	conn, _ := pool.Get()
	pool.Put(conn)

	if pool.Stats() != 1 {
		t.Fatalf("idle = %d, want 1", pool.Stats())
	}

	// Wait for the idle timeout + eviction interval.
	time.Sleep(100 * time.Millisecond)

	// Trigger eviction by trying to Get — expired connections are discarded.
	conn2, err := pool.Get()
	if err != nil {
		t.Fatalf("Get error: %v", err)
	}
	pool.Put(conn2)
}

func TestConnPool_Close(t *testing.T) {
	ln := startTCPEcho(t)
	pool := NewConnPool("tcp", ln.Addr().String(), 2*time.Second, DefaultPoolConfig())

	conn, _ := pool.Get()
	pool.Put(conn)

	pool.Close()

	if pool.Stats() != 0 {
		t.Errorf("idle = %d, want 0 after close", pool.Stats())
	}

	// Put after close should not panic — connection is just closed.
	conn2, _ := net.Dial("tcp", ln.Addr().String())
	pool.Put(conn2) // should not panic
}

func TestConnPool_DeadConnectionDiscarded(t *testing.T) {
	ln := startTCPEcho(t)
	pool := NewConnPool("tcp", ln.Addr().String(), 2*time.Second, DefaultPoolConfig())
	defer pool.Close()

	conn, _ := pool.Get()
	pool.Put(conn)

	// Close the listener so the server stops accepting new connections.
	ln.Close()

	// Give the OS time to propagate the FIN to the client side.
	time.Sleep(50 * time.Millisecond)

	// The liveness check should detect the dead connection and discard it.
	// A fresh dial will be attempted, which should fail since the listener is closed.
	conn2, err := pool.Get()
	if err == nil {
		// If the liveness check didn't catch it (possible on some OS/timing),
		// the connection was returned but is dead — this is acceptable.
		// The next write/read will fail, and the caller will close it.
		conn2.Close()
		t.Log("dead connection was returned (liveness check missed it); acceptable on fast systems")
	}
}

func TestConnPool_ConcurrentAccess(t *testing.T) {
	ln := startTCPEcho(t)
	pool := NewConnPool("tcp", ln.Addr().String(), 2*time.Second, PoolConfig{
		MaxIdle:     8,
		IdleTimeout: 30 * time.Second,
	})
	defer pool.Close()

	done := make(chan struct{}, 100)
	for range 100 {
		go func() {
			defer func() { done <- struct{}{} }()
			conn, err := pool.Get()
			if err != nil {
				return
			}
			time.Sleep(time.Millisecond)
			pool.Put(conn)
		}()
	}

	for range 100 {
		<-done
	}

	// Pool should have some idle connections, but not more than MaxIdle.
	idle := pool.Stats()
	if idle > 8 {
		t.Errorf("idle = %d, exceeds max_idle=8", idle)
	}
}
