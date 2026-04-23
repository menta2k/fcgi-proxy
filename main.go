package main

import (
	"flag"
	"log"
	"net"
	"net/http"
	_ "net/http/pprof" // registers /debug/pprof/* on http.DefaultServeMux
	"os"
	"os/signal"
	"runtime"
	"syscall"
	"time"

	"github.com/menta2k/fcgi-proxy/config"
	"github.com/menta2k/fcgi-proxy/fcgi"
	"github.com/menta2k/fcgi-proxy/proxy"
	"github.com/menta2k/fcgi-proxy/proxy/locationcache"
	"github.com/valyala/fasthttp"
)

func main() {
	configPath := flag.String("config", "config.json", "path to configuration file")
	listen := flag.String("listen", "", "listen address (overrides config)")
	network := flag.String("network", "", "fcgi network: tcp or unix (overrides config)")
	address := flag.String("address", "", "fcgi upstream address (overrides config)")
	docRoot := flag.String("document-root", "", "document root (overrides config)")
	pprofAddr := flag.String("pprof", "", "enable pprof profiling on this address (e.g., 127.0.0.1:6060). DO NOT expose publicly — bind to loopback only")
	flag.Parse()

	if *pprofAddr != "" {
		startPprof(*pprofAddr)
	} else {
		// Even though net/http/pprof is imported (to make -pprof opt-in without
		// a rebuild), disable heap-allocation sampling when no pprof server is
		// running. Importing the package flips runtime.MemProfileRate from 0
		// to 512 KiB and adds a small per-allocation branch cost; turning it
		// back off restores true zero data collection and shaves a measurable
		// 10-15% off nanosecond-scale middleware benchmarks.
		runtime.MemProfileRate = 0
	}

	cfg, err := config.Load(*configPath)
	if err != nil {
		log.Fatalf("Failed to load config: %v", err)
	}

	if *listen != "" {
		cfg.Listen = *listen
	}
	if *network != "" {
		cfg.Network = *network
	}
	if *address != "" {
		cfg.Address = *address
	}
	if *docRoot != "" {
		cfg.DocumentRoot = *docRoot
	}

	parsed, err := config.Parse(cfg)
	if err != nil {
		log.Fatalf("Invalid config: %v", err)
	}

	listenPort := derivePort(parsed.Listen)

	// Partition parsed locations: upstream-cached entries feed locationcache,
	// static-return entries feed the static dispatch map.
	var locations []locationcache.Location
	var staticLocations map[string]proxy.StaticResponse
	for _, loc := range parsed.Locations {
		if loc.Return != nil {
			if staticLocations == nil {
				staticLocations = make(map[string]proxy.StaticResponse, len(parsed.Locations))
			}
			staticLocations[loc.Path] = proxy.StaticResponse{
				Status:      loc.Return.Status,
				Body:        loc.Return.Body,
				ContentType: loc.Return.ContentType,
			}
			continue
		}
		locations = append(locations, locationcache.Location{
			Path:     loc.Path,
			Upstream: loc.Upstream,
			TTL:      loc.CacheTTL,
		})
	}

	handler := proxy.Handler(proxy.Config{
		Network:         parsed.Network,
		Address:         parsed.Address,
		DocumentRoot:    parsed.DocumentRoot,
		Index:           parsed.Index,
		ListenPort:      listenPort,
		DialTimeout:     parsed.DialTimeout,
		ReadTimeout:     parsed.ReadTimeout,
		WriteTimeout:    parsed.WriteTimeout,
		ResponseHeaders: parsed.ResponseHeaders,
		Locations:       locations,
		StaticLocations: staticLocations,
		CORS:            parsed.CORS,
		Auth:            parsed.Auth,
		Pool: fcgi.PoolConfig{
			MaxIdle:     parsed.PoolMaxIdle,
			IdleTimeout: parsed.PoolIdleTimeout,
		},
	})

	server := &fasthttp.Server{
		Handler:            handler,
		Name:               "", // Suppress Server header to avoid disclosing proxy identity.
		MaxRequestBodySize: parsed.MaxBodySize,
		Concurrency:        parsed.MaxConcurrency,
		ReadTimeout:        parsed.ReadTimeout,
		WriteTimeout:       parsed.WriteTimeout,
	}

	go func() {
		log.Printf("Starting fcgi-proxy on %s -> %s://%s", parsed.Listen, parsed.Network, parsed.Address)
		if err := server.ListenAndServe(parsed.Listen); err != nil {
			log.Fatalf("Server error: %v", err)
		}
	}()

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	<-sig

	log.Println("Shutting down...")
	if err := server.Shutdown(); err != nil {
		log.Printf("Shutdown error: %v", err)
	}
}

// startPprof brings up the Go runtime profiler on a dedicated HTTP server.
// Bind to a loopback address — the pprof handlers leak internal state and
// allow remote callers to trigger long profiling runs that stall the process.
func startPprof(addr string) {
	srv := &http.Server{
		Addr:         addr,
		Handler:      http.DefaultServeMux,
		ReadTimeout:  30 * time.Second,
		WriteTimeout: 60 * time.Second,
	}
	go func() {
		log.Printf("pprof listening on %s (http://%s/debug/pprof/)", addr, addr)
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Printf("pprof server error: %v", err)
		}
	}()
}

// derivePort extracts the port from a listen address like ":8080" or "0.0.0.0:9090".
// Uses net.SplitHostPort for correct IPv6 handling.
func derivePort(listen string) string {
	_, port, err := net.SplitHostPort(listen)
	if err != nil {
		log.Printf("Warning: could not parse listen port from %q, defaulting to 80", listen)
		return "80"
	}
	return port
}
