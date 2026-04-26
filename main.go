package main

import (
	"flag"
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
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"github.com/valyala/fasthttp"
)

func main() {
	setupLogger()

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
		log.Fatal().Err(err).Str("path", *configPath).Msg("failed to load config")
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
		log.Fatal().Err(err).Msg("invalid config")
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
		Readiness:       parsed.Readiness,
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
		Logger:             fasthttpLogAdapter{},
	}

	go func() {
		log.Info().
			Str("listen", parsed.Listen).
			Str("network", parsed.Network).
			Str("address", parsed.Address).
			Msg("starting fcgi-proxy")
		if err := server.ListenAndServe(parsed.Listen); err != nil {
			log.Fatal().Err(err).Msg("server error")
		}
	}()

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	<-sig

	log.Info().Msg("shutting down")
	if err := server.Shutdown(); err != nil {
		log.Error().Err(err).Msg("shutdown error")
	}
}

// setupLogger configures zerolog to emit JSON shaped for Google Cloud Logging.
// The agent on GKE auto-parses jsonPayload fields, so renaming `level` to
// `severity` (with uppercase values) and `time` to `timestamp` makes log
// records show up with proper severity in Logs Explorer instead of every
// line being tagged ERROR because it was on stderr.
func setupLogger() {
	zerolog.TimestampFieldName = "timestamp"
	zerolog.LevelFieldName = "severity"
	zerolog.MessageFieldName = "message"
	zerolog.ErrorFieldName = "error"
	zerolog.TimeFieldFormat = time.RFC3339Nano
	zerolog.LevelTraceValue = "DEBUG"
	zerolog.LevelDebugValue = "DEBUG"
	zerolog.LevelInfoValue = "INFO"
	zerolog.LevelWarnValue = "WARNING"
	zerolog.LevelErrorValue = "ERROR"
	zerolog.LevelFatalValue = "CRITICAL"
	zerolog.LevelPanicValue = "ALERT"
	log.Logger = zerolog.New(os.Stdout).With().Timestamp().Logger()
}

// fasthttpLogAdapter routes fasthttp's internal Printf calls into zerolog so
// server-level errors (e.g. timeouts, malformed requests) carry the same
// severity tagging as application logs. fasthttp logs are nearly all error
// or warning class, so mapping them to ERROR is safe — the alternative
// (stdlib log on stderr) loses severity entirely under GCP.
type fasthttpLogAdapter struct{}

func (fasthttpLogAdapter) Printf(format string, args ...any) {
	log.Error().Msgf(format, args...)
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
		log.Info().Str("addr", addr).Msg("pprof listening")
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Error().Err(err).Msg("pprof server error")
		}
	}()
}

// derivePort extracts the port from a listen address like ":8080" or "0.0.0.0:9090".
// Uses net.SplitHostPort for correct IPv6 handling.
func derivePort(listen string) string {
	_, port, err := net.SplitHostPort(listen)
	if err != nil {
		log.Warn().Str("listen", listen).Msg("could not parse listen port, defaulting to 80")
		return "80"
	}
	return port
}
