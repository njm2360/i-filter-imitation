package scan

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"log/slog"
	"sync"
	"sync/atomic"
	"time"

	"github.com/redis/go-redis/v9"
)

const (
	redisPrefixURL  = "scan:url:"
	redisPrefixHash = "scan:hash:"
)

// cachedScanEntry is the Redis payload.
type cachedScanEntry struct {
	Status     ScanStatus `json:"status"`
	ThreatName string     `json:"threat_name,omitempty"`
}

// cacheEntry is the in-memory entry.
type cacheEntry struct {
	status     ScanStatus
	threatName string
	expiresAt  time.Time
}

// ResultCache holds scan results keyed by URL and file content hash.
// All methods are safe for concurrent use.
type ResultCache struct {
	byURL     sync.Map    // sha256Hex(rawURL)    → *cacheEntry
	byHash    sync.Map    // hex(sha256(content)) → *cacheEntry
	urlCount  atomic.Int64
	hashCount atomic.Int64

	urlTTL     time.Duration
	hashTTL    time.Duration
	maxEntries int64

	rdb *redis.Client // nil = in-memory only
}

// NewResultCache creates a ResultCache. rdb may be nil to disable Redis.
func NewResultCache(urlTTL, hashTTL time.Duration, maxEntries int64, rdb *redis.Client) *ResultCache {
	return &ResultCache{
		urlTTL:     urlTTL,
		hashTTL:    hashTTL,
		maxEntries: maxEntries,
		rdb:        rdb,
	}
}

func sha256Hex(s string) string {
	h := sha256.Sum256([]byte(s))
	return fmt.Sprintf("%x", h)
}

// GetByURL looks up a cached scan result for the given URL.
func (c *ResultCache) GetByURL(ctx context.Context, rawURL string) (ScanStatus, string, bool) {
	return c.get(ctx, &c.byURL, &c.urlCount, sha256Hex(rawURL), redisPrefixURL, c.urlTTL)
}

// GetByHash looks up a cached scan result for the given file content hash.
func (c *ResultCache) GetByHash(ctx context.Context, contentHash []byte) (ScanStatus, string, bool) {
	return c.get(ctx, &c.byHash, &c.hashCount, fmt.Sprintf("%x", contentHash), redisPrefixHash, c.hashTTL)
}

func (c *ResultCache) get(ctx context.Context, m *sync.Map, counter *atomic.Int64, key, redisPrefix string, ttl time.Duration) (ScanStatus, string, bool) {
	if v, ok := m.Load(key); ok {
		e := v.(*cacheEntry)
		if time.Now().Before(e.expiresAt) {
			return e.status, e.threatName, true
		}
		m.Delete(key)
		counter.Add(-1)
	}

	if c.rdb != nil {
		val, err := c.rdb.Get(ctx, redisPrefix+key).Bytes()
		if err == nil {
			var payload cachedScanEntry
			if json.Unmarshal(val, &payload) == nil {
				c.storeMem(m, counter, key, payload.Status, payload.ThreatName, ttl)
				return payload.Status, payload.ThreatName, true
			}
		} else if err != redis.Nil {
			slog.Warn("scan cache redis get error", "err", err)
		}
	}
	return 0, "", false
}

// Store saves a scan result for the given URL and content hash.
// Only StatusClean and StatusInfected are cached; other statuses are ignored.
func (c *ResultCache) Store(ctx context.Context, rawURL string, contentHash []byte, status ScanStatus, threatName string) {
	if status != StatusClean && status != StatusInfected {
		return
	}

	urlKey := sha256Hex(rawURL)
	hashKey := fmt.Sprintf("%x", contentHash)
	payload, _ := json.Marshal(cachedScanEntry{Status: status, ThreatName: threatName})

	c.storeMem(&c.byURL, &c.urlCount, urlKey, status, threatName, c.urlTTL)
	c.storeMem(&c.byHash, &c.hashCount, hashKey, status, threatName, c.hashTTL)

	if c.rdb != nil {
		if err := c.rdb.Set(ctx, redisPrefixURL+urlKey, payload, c.urlTTL).Err(); err != nil {
			slog.Warn("scan cache redis set error", "key", "url", "err", err)
		}
		if err := c.rdb.Set(ctx, redisPrefixHash+hashKey, payload, c.hashTTL).Err(); err != nil {
			slog.Warn("scan cache redis set error", "key", "hash", "err", err)
		}
	}
}

func (c *ResultCache) storeMem(m *sync.Map, counter *atomic.Int64, key string, status ScanStatus, threatName string, ttl time.Duration) {
	if counter.Load() >= c.maxEntries {
		return
	}
	if _, loaded := m.LoadOrStore(key, &cacheEntry{
		status:     status,
		threatName: threatName,
		expiresAt:  time.Now().Add(ttl),
	}); !loaded {
		counter.Add(1)
	}
}

// StartCleanup launches a background goroutine that evicts expired entries every 15 minutes.
func (c *ResultCache) StartCleanup(ctx context.Context) {
	go func() {
		ticker := time.NewTicker(15 * time.Minute)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				c.evict(&c.byURL, &c.urlCount)
				c.evict(&c.byHash, &c.hashCount)
			}
		}
	}()
}

func (c *ResultCache) evict(m *sync.Map, counter *atomic.Int64) {
	now := time.Now()
	m.Range(func(k, v any) bool {
		if v.(*cacheEntry).expiresAt.Before(now) {
			m.Delete(k)
			counter.Add(-1)
		}
		return true
	})
}

// mergeResults returns the more restrictive of two scan results.
// StatusInfected takes precedence; the threat name comes from whichever result is infected.
func mergeResults(aStatus ScanStatus, aThreat string, bStatus ScanStatus, bThreat string) (ScanStatus, string) {
	if aStatus == StatusInfected {
		return StatusInfected, aThreat
	}
	if bStatus == StatusInfected {
		return StatusInfected, bThreat
	}
	return aStatus, aThreat
}
