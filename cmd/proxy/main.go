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
	listenAddr := envOr("LISTEN_ADDR", ":8080")
	proxyAddr := envOr("PROXY_ADDR", deriveProxyAddr(listenAddr))
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
		clamd := scan.NewClamdClient(network, address, 30*time.Second)
		mgr = scan.NewManager(tempDir, time.Duration(ttlMin)*time.Minute, maxMB<<20, clamd)
		mgr.StartCleanup()
		slog.Info("scan enabled", "clamd", clamdAddr, "max_mb", maxMB, "proxy_addr", proxyAddr)
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

	cache := cert.NewCache(ca, rdb)
	var sender *logger.Sender
	if syslogAddr != "" {
		sender = logger.NewSender(syslogNet, syslogAddr, 1000)
		defer sender.Close()
		slog.Info("syslog enabled", "addr", syslogAddr)
	}

	srv := &http.Server{
		Addr:    listenAddr,
		Handler: proxy.NewServer(cache, sender, bl, mgr, proxyAddr, pacContent),
	}

	go func() {
		slog.Info("proxy listening", "addr", listenAddr, "syslog", syslogAddr)
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			slog.Error("server error", "err", err)
			os.Exit(1)
		}
	}()

	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit

	slog.Info("shutting down")
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	srv.Shutdown(ctx)
}

func envOr(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

// deriveProxyAddr builds a default proxy address from the listen address.
// ":8080" → "http://localhost:8080"
func deriveProxyAddr(listenAddr string) string {
	if strings.HasPrefix(listenAddr, ":") {
		return "http://localhost" + listenAddr
	}
	return "http://" + listenAddr
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
