package proxy

import (
	"context"
	"encoding/json"
	"log/slog"
	"time"

	"github.com/njm2360/i-filter-imitation/internal/scan"
	"github.com/redis/go-redis/v9"
)

const (
	scanConfigRedisKey = "scan:config"
	scanConfigPubSubCh = "scan:config:changed"
)

// StartScanConfigSync seeds the scan Manager config from Redis and subscribes
// to scan:config:changed. On each notification it reloads the config atomically.
// Runs until ctx is cancelled.
func (s *Server) StartScanConfigSync(ctx context.Context, rdb *redis.Client, mgr *scan.Manager) {
	if mgr == nil {
		return
	}

	load := func() {
		data, err := rdb.Get(ctx, scanConfigRedisKey).Bytes()
		if err != nil {
			if err != redis.Nil {
				slog.Warn("scan config: Redis GET failed", "err", err)
			}
			return
		}
		var cfg scan.ScanConfig
		if err := json.Unmarshal(data, &cfg); err != nil {
			slog.Warn("scan config: JSON unmarshal failed", "err", err)
			return
		}
		mgr.SetConfig(&cfg)
		slog.Info("scan config reloaded", "enabled", cfg.Enabled, "max_size_mb", cfg.MaxSizeMB, "rules", len(cfg.Rules))
	}

	load()

	go func() {
		const maxBackoff = 30 * time.Second
		backoff := time.Second
		for {
			sub := rdb.Subscribe(ctx, scanConfigPubSubCh)
			disconnected := s.runScanConfigSubLoop(ctx, sub, load)
			sub.Close()
			if !disconnected {
				return
			}
			slog.Warn("scan config: pub/sub disconnected, reconnecting", "backoff", backoff)
			select {
			case <-ctx.Done():
				return
			case <-time.After(backoff):
			}
			load()
			if backoff < maxBackoff {
				backoff *= 2
			}
		}
	}()
}

// runScanConfigSubLoop drains the subscription channel until ctx is cancelled
// or the channel closes. Returns true if the channel closed (disconnected).
func (s *Server) runScanConfigSubLoop(ctx context.Context, sub *redis.PubSub, load func()) bool {
	ch := sub.Channel()
	for {
		select {
		case <-ctx.Done():
			return false
		case _, ok := <-ch:
			if !ok {
				return true
			}
			load()
		}
	}
}
