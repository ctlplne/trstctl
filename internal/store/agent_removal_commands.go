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

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/events"
)

// AgentRemovalCommand is independent admission authority. A pending command
// carries one exact source event; a completed row remains a terminal denial.
type AgentRemovalCommand struct {
	TenantID    string
	AgentID     string
	Kind        string
	Serial      string
	Fingerprint string
	Event       events.Event
	Status      string
}

const agentRemovalCommandColumns = `tenant_id::text, agent_id::text, kind,
    serial, fingerprint, event_id::text, event_time, event_actor,
    event_payload, payload_sha256, status`

func scanAgentRemovalCommand(row pgx.Row) (AgentRemovalCommand, error) {
	var c AgentRemovalCommand
	var actor, payload []byte
	var digest *string
	if err := row.Scan(&c.TenantID, &c.AgentID, &c.Kind, &c.Serial,
		&c.Fingerprint, &c.Event.ID, &c.Event.Time, &actor, &payload,
		&digest, &c.Status); err != nil {
		return c, err
	}
	c.Event.TenantID = c.TenantID
	c.Event.SchemaVersion = events.DefaultSchemaVersion
	c.Event.Data = payload
	switch c.Kind {
	case "offboard":
		c.Event.Type = "agent.offboarded"
	case "cert":
		c.Event.Type = "agent.cert.revoked"
	default:
		return c, errors.New("store: unsupported agent removal command kind")
	}
	if len(actor) > 0 {
		var a events.Actor
		if err := json.Unmarshal(actor, &a); err != nil {
			return c, fmt.Errorf("store: decode agent removal actor: %w", err)
		}
		c.Event.Actor = &a
	}
	switch c.Status {
	case "pending":
		if digest == nil || len(payload) == 0 || crypto.SHA256Hex(payload) != *digest {
			return c, errors.New("store: agent removal command payload drifted")
		}
	case "completed":
		if len(payload) != 0 || len(actor) != 0 || digest != nil {
			return c, errors.New("store: completed agent removal command retained payload")
		}
	default:
		return c, errors.New("store: unsupported agent removal command state")
	}
	return c, nil
}

func (s *Store) ClaimAgentRemovalCommand(ctx context.Context, candidate AgentRemovalCommand) (AgentRemovalCommand, bool, error) {
	var canonical AgentRemovalCommand
	var created bool
	if candidate.TenantID == "" || candidate.AgentID == "" || candidate.Event.ID == "" ||
		candidate.Event.TenantID != candidate.TenantID || candidate.Event.Time.IsZero() ||
		len(candidate.Event.Data) == 0 || candidate.Event.SchemaVersion != events.DefaultSchemaVersion ||
		!candidate.Event.Time.Equal(candidate.Event.Time.UTC().Truncate(time.Microsecond)) ||
		(candidate.Kind == "offboard" && (candidate.Serial != "" || candidate.Fingerprint != "" || candidate.Event.Type != "agent.offboarded")) ||
		(candidate.Kind == "cert" && (candidate.Serial == "" && candidate.Fingerprint == "" || candidate.Event.Type != "agent.cert.revoked")) ||
		(candidate.Kind != "offboard" && candidate.Kind != "cert") {
		return canonical, false, errors.New("store: incomplete agent removal command")
	}
	if _, err := uuid.Parse(candidate.AgentID); err != nil {
		return canonical, false, errors.New("store: agent removal requires a UUID agent id")
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
		"agent removal command privacy barrier", func(barrierCtx context.Context) error {
			return s.WithTenant(barrierCtx, candidate.TenantID, func(tx pgx.Tx) error {
				if err := lockUpsertArbiterTx(barrierCtx, tx,
					"agent_removal_commands", candidate.TenantID, candidate.AgentID); err != nil {
					return err
				}
				if err := lockUpsertArbiterTx(barrierCtx, tx,
					"agent_removal_commands:event", candidate.TenantID, candidate.Event.ID); err != nil {
					return err
				}
				var other bool
				if err := tx.QueryRow(barrierCtx, `SELECT EXISTS (
					SELECT 1 FROM agent_removal_commands WHERE tenant_id=$1 AND event_id=$2
					AND (agent_id<>$3 OR kind<>$4 OR serial<>$5 OR fingerprint<>$6))`,
					candidate.TenantID, candidate.Event.ID, candidate.AgentID, candidate.Kind,
					candidate.Serial, candidate.Fingerprint).Scan(&other); err != nil {
					return err
				}
				if other {
					return ErrIdempotencyConflict
				}
				err := tx.QueryRow(barrierCtx, `INSERT INTO agent_removal_commands
					(tenant_id, agent_id, kind, serial, fingerprint, event_id,
					 event_time, event_actor, event_payload, payload_sha256)
					VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)
					ON CONFLICT (tenant_id, agent_id, kind, serial, fingerprint) DO NOTHING
					RETURNING agent_id::text`, candidate.TenantID, candidate.AgentID,
					candidate.Kind, candidate.Serial, candidate.Fingerprint, candidate.Event.ID,
					candidate.Event.Time, actor, candidate.Event.Data,
					crypto.SHA256Hex(candidate.Event.Data)).Scan(new(string))
				if err != nil && !errors.Is(err, pgx.ErrNoRows) {
					return err
				}
				created = err == nil
				canonical, err = scanAgentRemovalCommand(tx.QueryRow(barrierCtx,
					`SELECT `+agentRemovalCommandColumns+` FROM agent_removal_commands
					 WHERE tenant_id=$1 AND agent_id=$2 AND kind=$3 AND serial=$4 AND fingerprint=$5 FOR UPDATE`,
					candidate.TenantID, candidate.AgentID, candidate.Kind,
					candidate.Serial, candidate.Fingerprint))
				return err
			})
		})
	return canonical, created, err
}

func (s *Store) LockAgentRemovalCommandTx(ctx context.Context, tx pgx.Tx, tenantID, eventID string) (AgentRemovalCommand, error) {
	return scanAgentRemovalCommand(tx.QueryRow(ctx,
		`SELECT `+agentRemovalCommandColumns+` FROM agent_removal_commands
		 WHERE tenant_id=$1 AND event_id=$2 FOR UPDATE`, tenantID, eventID))
}

// LockAgentRemovalEventTx establishes command-before-read-model lock order for
// tail replay, recovery and rebuild. Historical source events have no command.
func (s *Store) LockAgentRemovalEventTx(ctx context.Context, tx pgx.Tx, event events.Event) error {
	if _, err := uuid.Parse(event.ID); err != nil {
		return nil
	}
	c, err := s.LockAgentRemovalCommandTx(ctx, tx, event.TenantID, event.ID)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil
	}
	if err != nil {
		return err
	}
	if c.Event.Type != event.Type {
		return errors.New("store: agent removal event has wrong command kind")
	}
	return nil
}

func (s *Store) CompleteAgentRemovalCommandTx(ctx context.Context, tx pgx.Tx, event events.Event) error {
	if _, err := uuid.Parse(event.ID); err != nil {
		return nil // Historical events can have opaque identities.
	}
	c, err := s.LockAgentRemovalCommandTx(ctx, tx, event.TenantID, event.ID)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil
	}
	if err != nil {
		return err
	}
	if c.Status == "completed" {
		return nil
	}
	if !c.Event.Time.Equal(event.Time) || !bytes.Equal(c.Event.Data, event.Data) ||
		!reflect.DeepEqual(c.Event.Actor, event.Actor) || c.Event.Type != event.Type ||
		c.Event.SchemaVersion != event.SchemaVersion ||
		event.Sequence == 0 || event.Sequence > 1<<63-1 {
		return errors.New("store: agent removal event differs from durable first command")
	}
	_, err = tx.Exec(ctx, `UPDATE agent_removal_commands
		 SET status='completed', event_actor=NULL, event_payload=NULL,
		     payload_sha256=NULL, updated_at=now()
		 WHERE tenant_id=$1 AND event_id=$2`, event.TenantID, event.ID)
	return err
}

func (s *Store) ListPendingAgentRemovals(ctx context.Context, tenantID string, limit int) ([]AgentRemovalCommand, error) {
	if limit <= 0 || limit > 100 {
		limit = 100
	}
	var out []AgentRemovalCommand
	err := s.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `SELECT `+agentRemovalCommandColumns+` FROM agent_removal_commands
		 WHERE tenant_id=$1 AND status='pending' ORDER BY updated_at, agent_id, kind LIMIT $2`, tenantID, limit)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			c, err := scanAgentRemovalCommand(rows)
			if err != nil {
				return err
			}
			out = append(out, c)
		}
		return rows.Err()
	})
	return out, err
}
