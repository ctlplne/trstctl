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

// MachineAuthMethodCommand is the latest independently committed admission
// fence for one tenant and configured method. A pending command retains the
// exact first event; a completed one retains only opaque identity and posture.
type MachineAuthMethodCommand struct {
	TenantID       string
	MethodName     string
	TargetDisabled bool
	Event          events.Event
	Status         string
}

var ErrMachineAuthMethodDisabled = errors.New("store: machine-auth method is disabled")

const machineAuthMethodCommandColumns = `tenant_id::text, method_name,
    target_disabled, event_id::text, event_time, event_actor, event_payload,
    payload_sha256, status`

func scanMachineAuthMethodCommand(row pgx.Row) (MachineAuthMethodCommand, error) {
	var c MachineAuthMethodCommand
	var actor, payload []byte
	var digest *string
	if err := row.Scan(&c.TenantID, &c.MethodName, &c.TargetDisabled,
		&c.Event.ID, &c.Event.Time, &actor, &payload, &digest, &c.Status); err != nil {
		return c, err
	}
	c.Event.TenantID = c.TenantID
	c.Event.SchemaVersion = events.DefaultSchemaVersion
	if c.TargetDisabled {
		c.Event.Type = "secrets.auth_method.disabled"
	} else {
		c.Event.Type = "secrets.auth_method.enabled"
	}
	c.Event.Data = payload
	if len(actor) != 0 {
		var a events.Actor
		if err := json.Unmarshal(actor, &a); err != nil {
			return c, fmt.Errorf("store: decode machine-auth command actor: %w", err)
		}
		c.Event.Actor = &a
	}
	switch c.Status {
	case "pending":
		if digest == nil || len(payload) == 0 || crypto.SHA256Hex(payload) != *digest {
			return c, errors.New("store: machine-auth command payload drifted")
		}
	case "completed":
		if len(payload) != 0 || len(actor) != 0 || digest != nil {
			return c, errors.New("store: completed machine-auth command retained payload")
		}
	default:
		return c, errors.New("store: unsupported machine-auth command state")
	}
	return c, nil
}

// ClaimMachineAuthMethodCommand serializes commands for the exact method. A
// pending opposite action cannot overtake the first event. A repeated action
// reconciles its canonical first writer rather than inventing another event.
func (s *Store) ClaimMachineAuthMethodCommand(ctx context.Context, candidate MachineAuthMethodCommand) (MachineAuthMethodCommand, bool, error) {
	var canonical MachineAuthMethodCommand
	var created bool
	wantType := "secrets.auth_method.enabled"
	if candidate.TargetDisabled {
		wantType = "secrets.auth_method.disabled"
	}
	if candidate.TenantID == "" || candidate.MethodName == "" || candidate.Event.ID == "" ||
		candidate.Event.Time.IsZero() || candidate.Event.Type != wantType ||
		candidate.Event.TenantID != candidate.TenantID || len(candidate.Event.Data) == 0 ||
		candidate.Event.SchemaVersion != events.DefaultSchemaVersion ||
		!candidate.Event.Time.Equal(candidate.Event.Time.UTC().Truncate(time.Microsecond)) {
		return canonical, false, errors.New("store: incomplete machine-auth command")
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
		"machine-auth method command privacy barrier", func(barrierCtx context.Context) error {
			return s.WithTenant(barrierCtx, candidate.TenantID, func(tx pgx.Tx) error {
				if err := lockUpsertArbiterTx(barrierCtx, tx,
					"machine_auth_method_commands", candidate.TenantID, candidate.MethodName); err != nil {
					return err
				}
				if err := lockUpsertArbiterTx(barrierCtx, tx,
					"machine_auth_method_commands:event", candidate.TenantID, candidate.Event.ID); err != nil {
					return err
				}
				var err error
				canonical, err = scanMachineAuthMethodCommand(tx.QueryRow(barrierCtx,
					`SELECT `+machineAuthMethodCommandColumns+` FROM machine_auth_method_commands
					 WHERE tenant_id = $1 AND method_name = $2 FOR UPDATE`,
					candidate.TenantID, candidate.MethodName))
				if err != nil && !errors.Is(err, pgx.ErrNoRows) {
					return err
				}
				if err == nil {
					if canonical.Status == "pending" {
						if canonical.TargetDisabled != candidate.TargetDisabled {
							return ErrIdempotencyConflict
						}
						return nil
					}
					if canonical.TargetDisabled == candidate.TargetDisabled {
						return nil
					}
					_, err = tx.Exec(barrierCtx,
						`UPDATE machine_auth_method_commands
						 SET target_disabled = $3, event_id = $4, event_time = $5,
						     event_actor = $6, event_payload = $7, payload_sha256 = $8,
						     status = 'pending', updated_at = now()
						 WHERE tenant_id = $1 AND method_name = $2`,
						candidate.TenantID, candidate.MethodName, candidate.TargetDisabled,
						candidate.Event.ID, candidate.Event.Time, actor, candidate.Event.Data,
						crypto.SHA256Hex(candidate.Event.Data))
					if err != nil {
						return err
					}
					created = true
				} else {
					_, err = tx.Exec(barrierCtx,
						`INSERT INTO machine_auth_method_commands
						 (tenant_id, method_name, target_disabled, event_id, event_time,
						  event_actor, event_payload, payload_sha256)
						 VALUES ($1, $2, $3, $4, $5, $6, $7, $8)`,
						candidate.TenantID, candidate.MethodName, candidate.TargetDisabled,
						candidate.Event.ID, candidate.Event.Time, actor, candidate.Event.Data,
						crypto.SHA256Hex(candidate.Event.Data))
					if err != nil {
						return err
					}
					created = true
				}
				canonical, err = scanMachineAuthMethodCommand(tx.QueryRow(barrierCtx,
					`SELECT `+machineAuthMethodCommandColumns+` FROM machine_auth_method_commands
					 WHERE tenant_id = $1 AND method_name = $2 FOR UPDATE`,
					candidate.TenantID, candidate.MethodName))
				return err
			})
		})
	return canonical, created, err
}

func (s *Store) LockMachineAuthMethodCommandTx(ctx context.Context, tx pgx.Tx, tenantID, name string) (MachineAuthMethodCommand, error) {
	return scanMachineAuthMethodCommand(tx.QueryRow(ctx,
		`SELECT `+machineAuthMethodCommandColumns+` FROM machine_auth_method_commands
		 WHERE tenant_id = $1 AND method_name = $2 FOR UPDATE`, tenantID, name))
}

// CompleteMachineAuthMethodCommandTx keeps the denial fence and strips actor
// bytes only when the exact first event and projection commit together.
func (s *Store) CompleteMachineAuthMethodCommandTx(ctx context.Context, tx pgx.Tx, tenantID, name string, event events.Event) error {
	c, err := s.LockMachineAuthMethodCommandTx(ctx, tx, tenantID, name)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil // Historical event without an operational command.
	}
	if err != nil {
		return err
	}
	if c.Event.ID != event.ID {
		// Historical events are legal during a full rebuild. The read model
		// orders them by source sequence; only the exact current command may
		// clear the independent admission fence.
		return nil
	}
	if c.Status == "completed" {
		return nil
	}
	if !c.Event.Time.Equal(event.Time) || !bytes.Equal(c.Event.Data, event.Data) ||
		!reflect.DeepEqual(c.Event.Actor, event.Actor) || c.Event.Type != event.Type ||
		c.Event.SchemaVersion != event.SchemaVersion {
		return errors.New("store: machine-auth event differs from durable first command")
	}
	_, err = tx.Exec(ctx,
		`UPDATE machine_auth_method_commands
		 SET status = 'completed', event_actor = NULL, event_payload = NULL,
		     payload_sha256 = NULL, updated_at = now()
		 WHERE tenant_id = $1 AND method_name = $2 AND event_id = $3`,
		tenantID, name, event.ID)
	return err
}

func (s *Store) ListPendingMachineAuthMethodCommands(ctx context.Context, tenantID string, limit int) ([]MachineAuthMethodCommand, error) {
	if limit <= 0 || limit > 100 {
		limit = 100
	}
	var out []MachineAuthMethodCommand
	err := s.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx,
			`SELECT `+machineAuthMethodCommandColumns+` FROM machine_auth_method_commands
			 WHERE tenant_id = $1 AND status = 'pending'
			 ORDER BY updated_at, method_name LIMIT $2`, tenantID, limit)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			c, err := scanMachineAuthMethodCommand(rows)
			if err != nil {
				return err
			}
			out = append(out, c)
		}
		return rows.Err()
	})
	return out, err
}

// WithMachineAuthMethodAdmission serializes the final bearer-mint decision
// with a disable claim across replicas. Credential verification runs before
// this short lock. If login wins, its session event appends before disable can
// claim; its read-model projection happens after release. If disable wins, the
// login receives a generic denial. The callback must not acquire a second
// request-pool connection while this transaction is open.
func (s *Store) WithMachineAuthMethodAdmission(ctx context.Context, tenantID, name string, issue func() error) error {
	if tenantID == "" || name == "" || issue == nil {
		return errors.New("store: incomplete machine-auth admission")
	}
	return s.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		if err := lockUpsertArbiterTx(ctx, tx, "machine_auth_method_commands", tenantID, name); err != nil {
			return err
		}
		var disabled bool
		var status string
		err := tx.QueryRow(ctx,
			`SELECT target_disabled, status FROM machine_auth_method_commands
			 WHERE tenant_id = $1 AND method_name = $2`, tenantID, name).Scan(&disabled, &status)
		if err != nil && !errors.Is(err, pgx.ErrNoRows) {
			return err
		}
		if err == nil {
			if status != "pending" && status != "completed" {
				return errors.New("store: invalid machine-auth method command state")
			}
			if status == "pending" || disabled {
				return ErrMachineAuthMethodDisabled
			}
		} else {
			// Pre-command legacy overlays retain their original admission rule.
			if err := tx.QueryRow(ctx,
				`SELECT EXISTS (SELECT 1 FROM machine_auth_method_overrides
				 WHERE tenant_id = $1 AND method_name = $2 AND disabled)`,
				tenantID, name).Scan(&disabled); err != nil {
				return err
			}
			if disabled {
				return ErrMachineAuthMethodDisabled
			}
		}
		return issue()
	})
}
