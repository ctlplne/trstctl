// SPDX-License-Identifier: BUSL-1.1

package store

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"time"

	"github.com/jackc/pgx/v5"

	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/events"
)

// APITokenRevocationCommand is independent, first-writer command authority.
// Pending rows carry the exact event until publication and projection agree;
// completed rows retain only opaque IDs to keep bearer admission terminal.
type APITokenRevocationCommand struct {
	TenantID string
	TokenID  string
	Event    events.Event
	Status   string
}

func scanAPITokenRevocationCommand(row pgx.Row) (APITokenRevocationCommand, error) {
	var c APITokenRevocationCommand
	var actor, payload []byte
	var digest *string
	err := row.Scan(&c.TenantID, &c.TokenID, &c.Event.ID, &c.Event.Time,
		&actor, &payload, &digest, &c.Status)
	if err != nil {
		return c, err
	}
	c.Event.TenantID = c.TenantID
	c.Event.Type = "api_token.revoked"
	c.Event.SchemaVersion = events.DefaultSchemaVersion
	c.Event.Data = payload
	if len(actor) != 0 {
		var a events.Actor
		if err := json.Unmarshal(actor, &a); err != nil {
			return c, fmt.Errorf("store: decode API-token revocation actor: %w", err)
		}
		c.Event.Actor = &a
	}
	if c.Status == "pending" {
		if digest == nil || crypto.SHA256Hex(payload) != *digest || len(payload) == 0 {
			return c, errors.New("store: API-token revocation command payload drifted")
		}
	} else if c.Status != "completed" {
		return c, errors.New("store: unsupported API-token revocation command state")
	}
	return c, nil
}

// #nosec G101 -- SQL column names for an opaque command fence, not a credential.
const apiTokenRevocationCommandColumns = `tenant_id::text, token_id::text,
    event_id::text, event_time, event_actor, event_payload, payload_sha256, status`

// ClaimAPITokenRevocationCommand commits a denial before any event append. The
// command row lock precedes the target row lock on every recovery/replay path.
// It deliberately has no FK to api_tokens: rebuild truncates read models.
func (s *Store) ClaimAPITokenRevocationCommand(ctx context.Context, candidate APITokenRevocationCommand) (APITokenRevocationCommand, bool, error) {
	var canonical APITokenRevocationCommand
	var created bool
	if candidate.TenantID == "" || candidate.TokenID == "" || candidate.Event.ID == "" ||
		candidate.Event.Time.IsZero() || candidate.Event.Type != "api_token.revoked" ||
		candidate.Event.TenantID != candidate.TenantID || len(candidate.Event.Data) == 0 ||
		candidate.Event.SchemaVersion != events.DefaultSchemaVersion ||
		!candidate.Event.Time.Equal(candidate.Event.Time.UTC().Truncate(time.Microsecond)) {
		return canonical, false, errors.New("store: incomplete API-token revocation command")
	}
	var actor []byte
	if candidate.Event.Actor != nil {
		var err error
		actor, err = json.Marshal(candidate.Event.Actor)
		if err != nil {
			return canonical, false, err
		}
	}
	err := s.WithPrivacyRecoveryBarrier(ctx, candidate.TenantID,
		"API-token revocation command privacy barrier", func(barrierCtx context.Context) error {
			return s.WithTenant(barrierCtx, candidate.TenantID, func(tx pgx.Tx) error {
				// Serialize both unique identities before ON CONFLICT. The token-ID
				// arbiter covers competing revokes; the event-ID lock also protects a
				// malformed/reused producer identity from the second unique index.
				if err := lockUpsertArbiterTx(barrierCtx, tx,
					"api_token_revocation_commands", candidate.TenantID, candidate.TokenID); err != nil {
					return err
				}
				if err := lockUpsertArbiterTx(barrierCtx, tx,
					"api_token_revocation_commands:event", candidate.TenantID, candidate.Event.ID); err != nil {
					return err
				}
				// Recovery and tail replay lock a pending command before api_tokens.
				// A retry must do the same, including when it will later discover that
				// the token was revoked, or the two transactions form an ABBA cycle.
				var existingTokenID string
				err := tx.QueryRow(barrierCtx,
					`SELECT token_id::text FROM api_token_revocation_commands
					 WHERE tenant_id = $1 AND token_id = $2 FOR UPDATE`,
					candidate.TenantID, candidate.TokenID).Scan(&existingTokenID)
				if err != nil && !errors.Is(err, pgx.ErrNoRows) {
					return err
				}
				var revokedAt *time.Time
				if err := tx.QueryRow(barrierCtx,
					`SELECT revoked_at FROM api_tokens WHERE tenant_id = $1 AND id = $2 FOR UPDATE`,
					candidate.TenantID, candidate.TokenID).Scan(&revokedAt); err != nil {
					return err
				}
				if revokedAt != nil {
					return ErrIdempotencyConflict
				}
				var eventAlreadyClaimed bool
				if err := tx.QueryRow(barrierCtx,
					`SELECT EXISTS (SELECT 1 FROM api_token_revocation_commands
				 WHERE tenant_id = $1 AND event_id = $2 AND token_id <> $3)`,
					candidate.TenantID, candidate.Event.ID, candidate.TokenID).Scan(&eventAlreadyClaimed); err != nil {
					return err
				}
				if eventAlreadyClaimed {
					return ErrIdempotencyConflict
				}
				err = tx.QueryRow(barrierCtx,
					`INSERT INTO api_token_revocation_commands
				 (tenant_id, token_id, event_id, event_time, event_actor, event_payload, payload_sha256)
				 VALUES ($1, $2, $3, $4, $5, $6, $7)
				 ON CONFLICT (tenant_id, token_id) DO NOTHING
				 RETURNING token_id::text`,
					candidate.TenantID, candidate.TokenID, candidate.Event.ID, candidate.Event.Time,
					actor, candidate.Event.Data, crypto.SHA256Hex(candidate.Event.Data)).Scan(new(string))
				if err != nil && !errors.Is(err, pgx.ErrNoRows) {
					return err
				}
				created = err == nil
				canonical, err = scanAPITokenRevocationCommand(tx.QueryRow(barrierCtx,
					`SELECT `+apiTokenRevocationCommandColumns+` FROM api_token_revocation_commands
				 WHERE tenant_id = $1 AND token_id = $2 FOR UPDATE`,
					candidate.TenantID, candidate.TokenID))
				if err != nil {
					return err
				}
				if !created && canonical.Status == "pending" &&
					(!bytes.Equal(canonical.Event.Data, candidate.Event.Data) ||
						!reflect.DeepEqual(canonical.Event.Actor, candidate.Event.Actor)) {
					return ErrIdempotencyConflict
				}
				return nil
			})
		})
	return canonical, created, err
}

// LockAPITokenRevocationCommandTx serializes recovery and first projection.
func (s *Store) LockAPITokenRevocationCommandTx(ctx context.Context, tx pgx.Tx, tenantID, tokenID string) (APITokenRevocationCommand, error) {
	return scanAPITokenRevocationCommand(tx.QueryRow(ctx,
		`SELECT `+apiTokenRevocationCommandColumns+` FROM api_token_revocation_commands
		 WHERE tenant_id = $1 AND token_id = $2 FOR UPDATE`, tenantID, tokenID))
}

// CompleteAPITokenRevocationCommandTx verifies that the projection consumed
// the exact first command and atomically replaces transient PII with a terminal
// denial tombstone. Legacy events with no command retain their old behavior.
func (s *Store) CompleteAPITokenRevocationCommandTx(ctx context.Context, tx pgx.Tx, tenantID, tokenID string, event events.Event) error {
	c, err := s.LockAPITokenRevocationCommandTx(ctx, tx, tenantID, tokenID)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil
	}
	if err != nil {
		return err
	}
	if c.Event.ID != event.ID {
		return errors.New("store: API-token revocation event conflicts with first command")
	}
	if c.Status == "completed" {
		return nil
	}
	if !c.Event.Time.Equal(event.Time) || !bytes.Equal(c.Event.Data, event.Data) ||
		!reflect.DeepEqual(c.Event.Actor, event.Actor) || c.Event.Type != event.Type ||
		c.Event.SchemaVersion != event.SchemaVersion {
		return errors.New("store: API-token revocation event differs from durable first command")
	}
	_, err = tx.Exec(ctx,
		`UPDATE api_token_revocation_commands
		 SET status = 'completed', event_actor = NULL, event_payload = NULL,
		     payload_sha256 = NULL, updated_at = now()
		 WHERE tenant_id = $1 AND token_id = $2 AND event_id = $3`,
		tenantID, tokenID, event.ID)
	return err
}

// ListPendingAPITokenRevocations is tenant-scoped and bounded for one recovery
// pass. Callers repeat passes rather than loading an unbounded command backlog.
func (s *Store) ListPendingAPITokenRevocations(ctx context.Context, tenantID string, limit int) ([]APITokenRevocationCommand, error) {
	if limit <= 0 || limit > 100 {
		limit = 100
	}
	var out []APITokenRevocationCommand
	err := s.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx,
			`SELECT `+apiTokenRevocationCommandColumns+` FROM api_token_revocation_commands
			 WHERE tenant_id = $1 AND status = 'pending'
			 ORDER BY created_at, token_id LIMIT $2`, tenantID, limit)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			c, err := scanAPITokenRevocationCommand(rows)
			if err != nil {
				return err
			}
			out = append(out, c)
		}
		return rows.Err()
	})
	return out, err
}
