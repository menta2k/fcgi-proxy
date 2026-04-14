package main

import (
	"flag"
	"log"
	"net"
	"os"
	"os/signal"
	"syscall"

	"github.com/sko/fcgi-proxy/config"
	"github.com/sko/fcgi-proxy/proxy"
	"github.com/sko/fcgi-proxy/proxy/locationcache"
	"github.com/valyala/fasthttp"
)

func main() {
	configPath := flag.String("config", "config.json", "path to configuration file")
	listen := flag.String("listen", "", "listen address (overrides config)")
	network := flag.String("network", "", "fcgi network: tcp or unix (overrides config)")
	address := flag.String("address", "", "fcgi upstream address (overrides config)")
	docRoot := flag.String("document-root", "", "document root (overrides config)")
	flag.Parse()

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

	// Convert parsed locations to locationcache.Location entries.
	var locations []locationcache.Location
	for _, loc := range parsed.Locations {
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
