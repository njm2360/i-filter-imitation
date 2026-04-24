package proxy

import (
	"context"
	"log/slog"
	"time"

	"github.com/redis/go-redis/v9"
)

const (
	blocklistRedisKey = "blocklist:domains"
	blocklistPubSubCh = "blocklist:changed"
)

// StartBlocklistSync seeds the in-memory blocklist from the Redis Set and
// subscribes to blocklist:changed. On each notification it re-fetches
// SMEMBERS and atomically swaps the live Blocklist. Runs until ctx is cancelled.
func (s *Server) StartBlocklistSync(ctx context.Context, rdb *redis.Client) {
	load := func() {
		members, err := rdb.SMembers(ctx, blocklistRedisKey).Result()
		if err != nil {
			slog.Warn("blocklist: SMEMBERS failed", "err", err)
			return
		}
		s.blocklist.Store(NewBlocklist(members))
		slog.Info("blocklist reloaded", "count", len(members))
	}

	load()

	go func() {
		const maxBackoff = 30 * time.Second
		backoff := time.Second
		for {
			sub := rdb.Subscribe(ctx, blocklistPubSubCh)
			disconnected := s.runBlocklistSubLoop(ctx, sub, load)
			sub.Close()
			if !disconnected {
				return
			}
			slog.Warn("blocklist: pub/sub disconnected, reconnecting", "backoff", backoff)
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

// runBlocklistSubLoop drains the subscription channel until ctx is cancelled
// or the channel closes. Returns true if the channel closed (disconnected).
func (s *Server) runBlocklistSubLoop(ctx context.Context, sub *redis.PubSub, load func()) bool {
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
