package api

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/jackc/pgx/v5"
)

const (
	redisSetKey   = "blocklist:domains"
	redisPubSubCh = "blocklist:changed"
)

// Entry is a blocklist record returned by the API.
type Entry struct {
	ID        int64     `json:"id"`
	Domain    string    `json:"domain"`
	Enabled   bool      `json:"enabled"`
	Comment   string    `json:"comment"`
	CreatedBy string    `json:"created_by"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedBy string    `json:"updated_by"`
	UpdatedAt time.Time `json:"updated_at"`
}

// AuditEntry is one row from blocklist_audit_log.
type AuditEntry struct {
	ID         int64     `json:"id"`
	Domain     string    `json:"domain"`
	Action     string    `json:"action"`
	Actor      string    `json:"actor"`
	Comment    string    `json:"comment"`
	OccurredAt time.Time `json:"occurred_at"`
}

// UpdateRequest carries the fields that can be changed via PATCH.
type UpdateRequest struct {
	Enabled *bool
	Comment *string
	Actor   string
}

// syncToRedis rebuilds the Redis set from PG (enabled entries only).
func (s *Store) syncToRedis(ctx context.Context) error {
	rows, err := s.pool.Query(ctx,
		"SELECT domain FROM blocklist_entries WHERE enabled = TRUE")
	if err != nil {
		return err
	}
	defer rows.Close()

	var members []any
	for rows.Next() {
		var d string
		if err := rows.Scan(&d); err != nil {
			return err
		}
		members = append(members, d)
	}
	if err := rows.Err(); err != nil {
		return err
	}

	pipe := s.rdb.Pipeline()
	pipe.Del(ctx, redisSetKey)
	if len(members) > 0 {
		pipe.SAdd(ctx, redisSetKey, members...)
	}
	if _, err := pipe.Exec(ctx); err != nil {
		return fmt.Errorf("redis sync pipeline: %w", err)
	}
	s.rdb.Publish(ctx, redisPubSubCh, "sync") //nolint:errcheck
	slog.Info("blocklist synced to Redis", "count", len(members))
	return nil
}

func (s *Store) publishChange(ctx context.Context, msg string) {
	if err := s.rdb.Publish(ctx, redisPubSubCh, msg).Err(); err != nil {
		slog.Warn("blocklist: Redis PUBLISH failed", "err", err)
	}
}

// List returns a paginated result with optional keyword filter and sort.
func (s *Store) List(ctx context.Context, enabledOnly bool, lq ListQuery) (PagedResult[Entry], error) {
	sortCol := map[string]string{
		"domain":     "domain",
		"created_at": "created_at",
		"updated_at": "updated_at",
	}[lq.Sort]
	if sortCol == "" {
		sortCol = "created_at"
	}

	var args []any
	where := ""
	if enabledOnly && lq.Q != "" {
		args = append(args, "%"+lq.Q+"%")
		where = " WHERE enabled = TRUE AND (domain ILIKE $1 OR comment ILIKE $1)"
	} else if enabledOnly {
		where = " WHERE enabled = TRUE"
	} else if lq.Q != "" {
		args = append(args, "%"+lq.Q+"%")
		where = " WHERE domain ILIKE $1 OR comment ILIKE $1"
	}

	limit := lq.clampedLimit()
	limitIdx := len(args) + 1
	offsetIdx := limitIdx + 1
	args = append(args, limit, lq.offset())

	q := fmt.Sprintf(
		`SELECT id, domain, enabled, comment, created_by, created_at, updated_by, updated_at,
		        COUNT(*) OVER() AS total
		 FROM blocklist_entries%s
		 ORDER BY %s %s
		 LIMIT $%d OFFSET $%d`,
		where, sortCol, lq.order(), limitIdx, offsetIdx,
	)

	rows, err := s.pool.Query(ctx, q, args...)
	if err != nil {
		return PagedResult[Entry]{}, err
	}
	defer rows.Close()

	result := PagedResult[Entry]{Page: lq.page(), Limit: limit, Items: []Entry{}}
	for rows.Next() {
		var e Entry
		if err := rows.Scan(&e.ID, &e.Domain, &e.Enabled, &e.Comment,
			&e.CreatedBy, &e.CreatedAt, &e.UpdatedBy, &e.UpdatedAt, &result.Total); err != nil {
			return PagedResult[Entry]{}, err
		}
		result.Items = append(result.Items, e)
	}
	return result, rows.Err()
}

// Add inserts a new domain. Returns ErrDuplicate if it already exists.
func (s *Store) Add(ctx context.Context, domain, comment, actor string) (Entry, error) {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return Entry{}, err
	}
	defer tx.Rollback(ctx) //nolint:errcheck

	var e Entry
	err = tx.QueryRow(ctx, `
		INSERT INTO blocklist_entries (domain, comment, created_by, updated_by)
		VALUES ($1, $2, $3, $3)
		ON CONFLICT DO NOTHING
		RETURNING id, domain, enabled, comment, created_by, created_at, updated_by, updated_at`,
		domain, comment, actor,
	).Scan(&e.ID, &e.Domain, &e.Enabled, &e.Comment,
		&e.CreatedBy, &e.CreatedAt, &e.UpdatedBy, &e.UpdatedAt)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return Entry{}, ErrDuplicate
		}
		return Entry{}, err
	}

	if _, err := tx.Exec(ctx, `
		INSERT INTO blocklist_audit_log (domain, action, actor, comment)
		VALUES ($1, 'add', $2, $3)`, domain, actor, comment); err != nil {
		return Entry{}, err
	}

	if err := tx.Commit(ctx); err != nil {
		return Entry{}, err
	}

	pipe := s.rdb.Pipeline()
	pipe.SAdd(ctx, redisSetKey, domain)
	pipe.Publish(ctx, redisPubSubCh, "add:"+domain)
	if _, err := pipe.Exec(ctx); err != nil {
		slog.Warn("blocklist: Redis SADD/PUBLISH failed", "domain", domain, "err", err)
	}

	return e, nil
}

// Update modifies enabled/comment on an existing entry.
func (s *Store) Update(ctx context.Context, domain string, req UpdateRequest) (Entry, error) {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return Entry{}, err
	}
	defer tx.Rollback(ctx) //nolint:errcheck

	var e Entry
	err = tx.QueryRow(ctx, `
		UPDATE blocklist_entries
		SET
		    enabled    = COALESCE($2, enabled),
		    comment    = COALESCE($3, comment),
		    updated_by = $4,
		    updated_at = NOW()
		WHERE domain = $1
		RETURNING id, domain, enabled, comment, created_by, created_at, updated_by, updated_at`,
		domain, req.Enabled, req.Comment, req.Actor,
	).Scan(&e.ID, &e.Domain, &e.Enabled, &e.Comment,
		&e.CreatedBy, &e.CreatedAt, &e.UpdatedBy, &e.UpdatedAt)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return Entry{}, ErrNotFound
		}
		return Entry{}, err
	}

	action := "update"
	if req.Enabled != nil {
		if *req.Enabled {
			action = "enable"
		} else {
			action = "disable"
		}
	}
	comment := ""
	if req.Comment != nil {
		comment = *req.Comment
	}
	if _, err := tx.Exec(ctx, `
		INSERT INTO blocklist_audit_log (domain, action, actor, comment)
		VALUES ($1, $2, $3, $4)`, domain, action, req.Actor, comment); err != nil {
		return Entry{}, err
	}

	if err := tx.Commit(ctx); err != nil {
		return Entry{}, err
	}

	if req.Enabled != nil {
		pipe := s.rdb.Pipeline()
		if *req.Enabled {
			pipe.SAdd(ctx, redisSetKey, domain)
		} else {
			pipe.SRem(ctx, redisSetKey, domain)
		}
		pipe.Publish(ctx, redisPubSubCh, action+":"+domain)
		if _, err := pipe.Exec(ctx); err != nil {
			slog.Warn("blocklist: Redis update failed", "domain", domain, "err", err)
		}
	}

	return e, nil
}

// Remove deletes an entry. Returns ErrNotFound if absent.
func (s *Store) Remove(ctx context.Context, domain, actor, comment string) error {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx) //nolint:errcheck

	tag, err := tx.Exec(ctx,
		"DELETE FROM blocklist_entries WHERE domain = $1", domain)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}

	if _, err := tx.Exec(ctx, `
		INSERT INTO blocklist_audit_log (domain, action, actor, comment)
		VALUES ($1, 'remove', $2, $3)`, domain, actor, comment); err != nil {
		return err
	}

	if err := tx.Commit(ctx); err != nil {
		return err
	}

	pipe := s.rdb.Pipeline()
	pipe.SRem(ctx, redisSetKey, domain)
	pipe.Publish(ctx, redisPubSubCh, "remove:"+domain)
	if _, err := pipe.Exec(ctx); err != nil {
		slog.Warn("blocklist: Redis SREM/PUBLISH failed", "domain", domain, "err", err)
	}

	return nil
}

// AuditLog returns paginated change history for a domain, newest first.
func (s *Store) AuditLog(ctx context.Context, domain string, lq ListQuery) (PagedResult[AuditEntry], error) {
	limit := lq.clampedLimit()
	rows, err := s.pool.Query(ctx, `
		SELECT id, domain, action, actor, comment, occurred_at,
		       COUNT(*) OVER() AS total
		FROM blocklist_audit_log
		WHERE domain = $1
		ORDER BY occurred_at DESC
		LIMIT $2 OFFSET $3`, domain, limit, lq.offset())
	if err != nil {
		return PagedResult[AuditEntry]{}, err
	}
	defer rows.Close()

	result := PagedResult[AuditEntry]{Page: lq.page(), Limit: limit, Items: []AuditEntry{}}
	for rows.Next() {
		var e AuditEntry
		if err := rows.Scan(&e.ID, &e.Domain, &e.Action, &e.Actor,
			&e.Comment, &e.OccurredAt, &result.Total); err != nil {
			return PagedResult[AuditEntry]{}, err
		}
		result.Items = append(result.Items, e)
	}
	return result, rows.Err()
}
