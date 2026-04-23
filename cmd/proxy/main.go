package main

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/njm2360/i-filter-imitation/internal/cert"
	"github.com/njm2360/i-filter-imitation/internal/logger"
	"github.com/njm2360/i-filter-imitation/internal/proxy"
	"github.com/njm2360/i-filter-imitation/internal/scan"
	"github.com/redis/go-redis/v9"
)

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	listenAddr := envOr("LISTEN_ADDR", ":8080")
	caCertPath := envOr("CA_CERT", "ca.crt")
	caKeyPath := envOr("CA_KEY", "ca.key")
	redisURL := envOr("REDIS_URL", "redis://localhost:6379")
	syslogNet := envOr("SYSLOG_NET", "udp")
	syslogAddr := envOr("SYSLOG_ADDR", "")
	blockListPath := envOr("BLOCK_LIST", "")
	pacFilePath := envOr("PAC_FILE", "")

	ca, err := cert.LoadOrCreate(caCertPath, caKeyPath)
	if err != nil {
		slog.Error("failed to load CA", "err", err)
		os.Exit(1)
	}

	opt, err := redis.ParseURL(redisURL)
	if err != nil {
		slog.Error("invalid REDIS_URL", "err", err)
		os.Exit(1)
	}
	rdb := redis.NewClient(opt)

	bl, err := proxy.LoadBlocklist(blockListPath)
	if err != nil {
		slog.Error("failed to load blocklist", "err", err)
		os.Exit(1)
	}

	var mgr *scan.Manager
	if clamdAddr := envOr("CLAMD_ADDR", ""); clamdAddr != "" {
		network, address, err := parseClamdAddr(clamdAddr)
		if err != nil {
			slog.Error("invalid CLAMD_ADDR", "err", err)
			os.Exit(1)
		}
		maxMB, _ := strconv.ParseInt(envOr("SCAN_MAX_SIZE_MB", "100"), 10, 64)
		ttlMin, _ := strconv.ParseInt(envOr("SCAN_TTL_MINUTES", "60"), 10, 64)
		tempDir := envOr("SCAN_TEMP_DIR", "/tmp/log-proxy-scan")
		if err := os.MkdirAll(tempDir, 0o700); err != nil {
			slog.Error("failed to create scan temp dir", "err", err)
			os.Exit(1)
		}
		urlTTLMin, _ := strconv.ParseInt(envOr("SCAN_CACHE_URL_TTL_MINUTES", "60"), 10, 64)
		hashTTLHrs, _ := strconv.ParseInt(envOr("SCAN_CACHE_HASH_TTL_HOURS", "24"), 10, 64)
		maxEntries, _ := strconv.ParseInt(envOr("SCAN_CACHE_MAX_ENTRIES", "10000"), 10, 64)
		resultCache := scan.NewResultCache(
			time.Duration(urlTTLMin)*time.Minute,
			time.Duration(hashTTLHrs)*time.Hour,
			maxEntries,
			rdb,
		)
		resultCache.StartCleanup(ctx)

		clamd := scan.NewClamdClient(network, address, 30*time.Second)
		mgr = scan.NewManager(tempDir, time.Duration(ttlMin)*time.Minute, maxMB<<20, clamd, resultCache)
		mgr.StartCleanup(ctx)
		slog.Info("scan enabled", "clamd", clamdAddr, "max_mb", maxMB)
	}

	var pacContent []byte
	if pacFilePath != "" {
		pacContent, err = os.ReadFile(pacFilePath)
		if err != nil {
			slog.Error("failed to read PAC_FILE", "err", err)
			os.Exit(1)
		}
		slog.Info("PAC file loaded", "path", pacFilePath)
	}

	cache := cert.NewCache(ctx, ca, rdb)
	var sender *logger.Sender
	if syslogAddr != "" {
		sender = logger.NewSender(syslogNet, syslogAddr, 1000)
		defer sender.Close()
		slog.Info("syslog enabled", "addr", syslogAddr)
	}

	srv := &http.Server{
		Addr:    listenAddr,
		Handler: proxy.NewServer(cache, sender, bl, mgr, pacContent),
	}

	go func() {
		slog.Info("proxy listening", "addr", listenAddr, "syslog", syslogAddr)
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			slog.Error("server error", "err", err)
			os.Exit(1)
		}
	}()

	<-ctx.Done()
	stop() // release signal resources

	slog.Info("shutting down")
	shutCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	srv.Shutdown(shutCtx) //nolint:errcheck
}

func envOr(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

// parseClamdAddr parses "unix:///path" → ("unix", "/path")
// or "tcp://host:port" → ("tcp", "host:port").
func parseClamdAddr(addr string) (network, address string, err error) {
	switch {
	case strings.HasPrefix(addr, "unix://"):
		return "unix", strings.TrimPrefix(addr, "unix://"), nil
	case strings.HasPrefix(addr, "tcp://"):
		return "tcp", strings.TrimPrefix(addr, "tcp://"), nil
	default:
		return "", "", fmt.Errorf("CLAMD_ADDR must start with unix:// or tcp://; got %q", addr)
	}
}
