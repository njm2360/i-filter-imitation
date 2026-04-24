package api

import (
	"context"
	"errors"
	"fmt"
	"log/slog"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/redis/go-redis/v9"
)

const migration = `
CREATE TABLE IF NOT EXISTS blocklist_entries (
    id         BIGSERIAL    PRIMARY KEY,
    domain     TEXT         NOT NULL UNIQUE,
    enabled    BOOLEAN      NOT NULL DEFAULT TRUE,
    comment    TEXT         NOT NULL DEFAULT '',
    created_by TEXT         NOT NULL DEFAULT '',
    created_at TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
    updated_by TEXT         NOT NULL DEFAULT '',
    updated_at TIMESTAMPTZ  NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS blocklist_audit_log (
    id          BIGSERIAL    PRIMARY KEY,
    domain      TEXT         NOT NULL,
    action      TEXT         NOT NULL,
    actor       TEXT         NOT NULL DEFAULT '',
    comment     TEXT         NOT NULL DEFAULT '',
    occurred_at TIMESTAMPTZ  NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS scan_settings (
    key        TEXT         PRIMARY KEY,
    value      TEXT         NOT NULL,
    updated_by TEXT         NOT NULL DEFAULT '',
    updated_at TIMESTAMPTZ  NOT NULL DEFAULT NOW()
);

INSERT INTO scan_settings (key, value) VALUES
    ('enabled',    'true'),
    ('max_size_mb','500')
ON CONFLICT DO NOTHING;

CREATE TABLE IF NOT EXISTS scan_mime_types (
    id         BIGSERIAL    PRIMARY KEY,
    pattern    TEXT         NOT NULL UNIQUE,
    is_prefix  BOOLEAN      NOT NULL DEFAULT FALSE,
    enabled    BOOLEAN      NOT NULL DEFAULT TRUE,
    note       TEXT         NOT NULL DEFAULT '',
    updated_by TEXT         NOT NULL DEFAULT '',
    updated_at TIMESTAMPTZ  NOT NULL DEFAULT NOW()
);

INSERT INTO scan_mime_types (pattern, is_prefix) VALUES
    ('application/zip',                                                              false),
    ('application/x-zip-compressed',                                                 false),
    ('application/vnd.rar',                                                          false),
    ('application/x-7z-compressed',                                                  false),
    ('application/x-tar',                                                            false),
    ('application/gzip',                                                             false),
    ('application/x-bzip2',                                                          false),
    ('application/x-xz',                                                             false),
    ('application/x-lzma',                                                           false),
    ('application/x-lzip',                                                           false),
    ('application/x-zstd',                                                           false),
    ('application/x-cab',                                                            false),
    ('application/vnd.ms-cab-compressed',                                            false),
    ('application/x-iso9660-image',                                                  false),
    ('application/x-apple-diskimage',                                                false),
    ('application/octet-stream',                                                     false),
    ('binary/octet-stream',                                                          false),
    ('application/x-msdownload',                                                     false),
    ('application/x-dosexec',                                                        false),
    ('application/x-executable',                                                     false),
    ('application/x-msi',                                                            false),
    ('application/x-ms-installer',                                                   false),
    ('application/vnd.microsoft.portable-executable',                                false),
    ('application/pdf',                                                              false),
    ('application/rtf',                                                              false),
    ('text/rtf',                                                                     false),
    ('application/msword',                                                           false),
    ('application/vnd.ms-excel',                                                     false),
    ('application/vnd.ms-powerpoint',                                                false),
    ('application/vnd.ms-office',                                                    false),
    ('application/vnd.openxmlformats-officedocument.wordprocessingml.document',      false),
    ('application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',            false),
    ('application/vnd.openxmlformats-officedocument.presentationml.presentation',    false),
    ('application/java-archive',                                                     false),
    ('application/x-java-archive',                                                   false),
    ('application/vnd.android.package-archive',                                      false),
    ('message/rfc822',                                                               false),
    ('application/vnd.ms-outlook',                                                   false),
    ('application/x-*',                                                              true)
ON CONFLICT DO NOTHING;`

var (
	ErrDuplicate = errors.New("domain already exists")
	ErrNotFound  = errors.New("domain not found")
)

// Store wraps a PostgreSQL connection pool and a Redis client.
type Store struct {
	pool *pgxpool.Pool
	rdb  *redis.Client
}

// NewStore connects to PostgreSQL, runs schema migration, syncs existing
// entries to Redis, and returns a ready Store.
func NewStore(ctx context.Context, pgURL string, rdb *redis.Client) (*Store, error) {
	pool, err := pgxpool.New(ctx, pgURL)
	if err != nil {
		return nil, fmt.Errorf("pgxpool.New: %w", err)
	}
	if err := pool.Ping(ctx); err != nil {
		pool.Close()
		return nil, fmt.Errorf("pg ping: %w", err)
	}
	if _, err := pool.Exec(ctx, migration); err != nil {
		pool.Close()
		return nil, fmt.Errorf("migration: %w", err)
	}

	s := &Store{pool: pool, rdb: rdb}
	if err := s.syncToRedis(ctx); err != nil {
		slog.Warn("initial blocklist Redis sync failed (non-fatal)", "err", err)
	}
	if err := s.syncScanConfigToRedis(ctx); err != nil {
		slog.Warn("initial scan config Redis sync failed (non-fatal)", "err", err)
	}
	return s, nil
}

func (s *Store) Close() { s.pool.Close() }

func nullableString(s string) *string {
	if s == "" {
		return nil
	}
	return &s
}
