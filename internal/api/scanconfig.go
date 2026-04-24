package api

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"strconv"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/njm2360/i-filter-imitation/internal/scan"
)

const (
	scanConfigRedisKey = "scan:config"
	scanConfigPubSubCh = "scan:config:changed"
)

// MimeTypeEntry is one row from scan_mime_types.
type MimeTypeEntry struct {
	ID        int64     `json:"id"`
	Pattern   string    `json:"pattern"`
	IsPrefix  bool      `json:"is_prefix"`
	Enabled   bool      `json:"enabled"`
	Note      string    `json:"note"`
	UpdatedBy string    `json:"updated_by"`
	UpdatedAt time.Time `json:"updated_at"`
}

// ScanSettingEntry is one row from scan_settings.
type ScanSettingEntry struct {
	Key       string    `json:"key"`
	Value     string    `json:"value"`
	UpdatedBy string    `json:"updated_by"`
	UpdatedAt time.Time `json:"updated_at"`
}

// buildScanConfig constructs a ScanConfig from the current PG state.
func (s *Store) buildScanConfig(ctx context.Context) (*scan.ScanConfig, error) {
	rows, err := s.pool.Query(ctx, "SELECT key, value FROM scan_settings")
	if err != nil {
		return nil, err
	}
	settings := map[string]string{}
	for rows.Next() {
		var k, v string
		if err := rows.Scan(&k, &v); err != nil {
			rows.Close()
			return nil, err
		}
		settings[k] = v
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, err
	}

	enabled := settings["enabled"] != "false"
	maxSizeMB, _ := strconv.ParseInt(settings["max_size_mb"], 10, 64)
	if maxSizeMB <= 0 {
		maxSizeMB = 500
	}

	mrows, err := s.pool.Query(ctx,
		"SELECT pattern, is_prefix, enabled FROM scan_mime_types ORDER BY id")
	if err != nil {
		return nil, err
	}
	defer mrows.Close()

	var rules []scan.MimeRule
	for mrows.Next() {
		var r scan.MimeRule
		if err := mrows.Scan(&r.Pattern, &r.IsPrefix, &r.Enabled); err != nil {
			return nil, err
		}
		rules = append(rules, r)
	}
	if err := mrows.Err(); err != nil {
		return nil, err
	}

	return &scan.ScanConfig{Enabled: enabled, MaxSizeMB: maxSizeMB, Rules: rules}, nil
}

// syncScanConfigToRedis writes the current scan config to Redis and notifies subscribers.
func (s *Store) syncScanConfigToRedis(ctx context.Context) error {
	cfg, err := s.buildScanConfig(ctx)
	if err != nil {
		return err
	}
	data, err := json.Marshal(cfg)
	if err != nil {
		return err
	}
	if err := s.rdb.Set(ctx, scanConfigRedisKey, data, 0).Err(); err != nil {
		return fmt.Errorf("redis SET scan:config: %w", err)
	}
	s.rdb.Publish(ctx, scanConfigPubSubCh, "sync") //nolint:errcheck
	slog.Info("scan config synced to Redis", "enabled", cfg.Enabled, "max_mb", cfg.MaxSizeMB, "rules", len(cfg.Rules))
	return nil
}

// GetScanSettings returns all rows from scan_settings.
func (s *Store) GetScanSettings(ctx context.Context) ([]ScanSettingEntry, error) {
	rows, err := s.pool.Query(ctx,
		"SELECT key, value, updated_by, updated_at FROM scan_settings ORDER BY key")
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []ScanSettingEntry
	for rows.Next() {
		var e ScanSettingEntry
		if err := rows.Scan(&e.Key, &e.Value, &e.UpdatedBy, &e.UpdatedAt); err != nil {
			return nil, err
		}
		out = append(out, e)
	}
	return out, rows.Err()
}

// UpdateScanSetting updates one scan_settings row and re-syncs Redis.
func (s *Store) UpdateScanSetting(ctx context.Context, key, value, actor string) error {
	tag, err := s.pool.Exec(ctx, `
		UPDATE scan_settings
		SET value = $2, updated_by = $3, updated_at = NOW()
		WHERE key = $1`, key, value, actor)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return s.syncScanConfigToRedis(ctx)
}

// ListMimeTypes returns rows from scan_mime_types, optionally filtered and sorted.
func (s *Store) ListMimeTypes(ctx context.Context, enabledOnly bool, lq ListQuery) ([]MimeTypeEntry, error) {
	sortCol := map[string]string{
		"id":         "id",
		"pattern":    "pattern",
		"updated_at": "updated_at",
	}[lq.Sort]
	if sortCol == "" {
		sortCol = "id"
	}

	var args []any
	where := ""
	if enabledOnly && lq.Q != "" {
		args = append(args, "%"+lq.Q+"%")
		where = " WHERE enabled = TRUE AND pattern ILIKE $1"
	} else if enabledOnly {
		where = " WHERE enabled = TRUE"
	} else if lq.Q != "" {
		args = append(args, "%"+lq.Q+"%")
		where = " WHERE pattern ILIKE $1"
	}

	q := `SELECT id, pattern, is_prefix, enabled, note, updated_by, updated_at
	      FROM scan_mime_types` + where +
		" ORDER BY " + sortCol + " " + lq.order()

	rows, err := s.pool.Query(ctx, q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []MimeTypeEntry
	for rows.Next() {
		var e MimeTypeEntry
		if err := rows.Scan(&e.ID, &e.Pattern, &e.IsPrefix, &e.Enabled,
			&e.Note, &e.UpdatedBy, &e.UpdatedAt); err != nil {
			return nil, err
		}
		out = append(out, e)
	}
	return out, rows.Err()
}

// UpdateMimeType toggles enabled/note on a scan_mime_types row and re-syncs Redis.
func (s *Store) UpdateMimeType(ctx context.Context, pattern string, enabled *bool, note, actor string) (MimeTypeEntry, error) {
	var e MimeTypeEntry
	err := s.pool.QueryRow(ctx, `
		UPDATE scan_mime_types
		SET
		    enabled    = COALESCE($2, enabled),
		    note       = COALESCE($3, note),
		    updated_by = $4,
		    updated_at = NOW()
		WHERE pattern = $1
		RETURNING id, pattern, is_prefix, enabled, note, updated_by, updated_at`,
		pattern, enabled, nullableString(note), actor,
	).Scan(&e.ID, &e.Pattern, &e.IsPrefix, &e.Enabled,
		&e.Note, &e.UpdatedBy, &e.UpdatedAt)
	if err != nil {
		if pgx.ErrNoRows == err {
			return MimeTypeEntry{}, ErrNotFound
		}
		return MimeTypeEntry{}, err
	}
	return e, s.syncScanConfigToRedis(ctx)
}
