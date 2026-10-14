// SPDX-License-Identifier: BUSL-1.1

package store

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"reflect"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/events"
)

// WorkloadAttesterTrustCommand is the latest independently committed posture
// for one tenant/source. Pending commands retain the first event for recovery;
// completed commands keep only opaque binding and source-order evidence.
type WorkloadAttesterTrustCommand struct {
	SourceID       string
	BindingSHA256  string
	RequestBinding string
	TargetDisabled bool
	Event          events.Event
	Status         string
}

// WorkloadAttesterTrustReceipt is the immutable result of one projected source
// event. Snapshot contains public trust metadata, never a proof or private key.
type WorkloadAttesterTrustReceipt struct {
	TenantID, EventID, SourceID, EventType string
	RequestBinding, BindingSHA256          string
	Snapshot                               json.RawMessage
	ProjectedSequence                      int64
}

func scanWorkloadAttesterTrustReceipt(row pgx.Row) (WorkloadAttesterTrustReceipt, error) {
	var receipt WorkloadAttesterTrustReceipt
	err := row.Scan(&receipt.TenantID, &receipt.EventID, &receipt.SourceID,
		&receipt.EventType, &receipt.RequestBinding, &receipt.BindingSHA256,
		&receipt.Snapshot, &receipt.ProjectedSequence)
	return receipt, err
}

// WorkloadAttesterTrustReceiptByEventID is bounded by the tenant/event key.
func (s *Store) WorkloadAttesterTrustReceiptByEventID(ctx context.Context, tenantID, eventID string) (WorkloadAttesterTrustReceipt, error) {
	var receipt WorkloadAttesterTrustReceipt
	err := s.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		var err error
		receipt, err = scanWorkloadAttesterTrustReceipt(tx.QueryRow(ctx,
			`SELECT tenant_id::text,event_id::text,source_id::text,event_type,request_binding,
			        binding_sha256,response_snapshot,projected_sequence
			   FROM workload_attester_trust_receipts WHERE tenant_id=$1 AND event_id=$2`,
			tenantID, eventID))
		return err
	})
	return receipt, err
}

const workloadAttesterTrustCommandColumns = `tenant_id::text,source_id::text,
	event_id::text,event_type,event_time,event_actor,event_payload,payload_sha256,
	binding_sha256,request_binding,target_disabled,status,projected_sequence`

func scanWorkloadAttesterTrustCommand(row pgx.Row) (WorkloadAttesterTrustCommand, error) {
	var command WorkloadAttesterTrustCommand
	var actor, payload []byte
	var digest *string
	var sequence *int64
	if err := row.Scan(&command.Event.TenantID, &command.SourceID,
		&command.Event.ID, &command.Event.Type, &command.Event.Time,
		&actor, &payload, &digest, &command.BindingSHA256, &command.RequestBinding,
		&command.TargetDisabled, &command.Status, &sequence); err != nil {
		return command, err
	}
	command.Event.SchemaVersion = events.DefaultSchemaVersion
	command.Event.Data = payload
	if len(actor) != 0 {
		var a events.Actor
		if err := json.Unmarshal(actor, &a); err != nil {
			return command, fmt.Errorf("store: decode attester trust command actor: %w", err)
		}
		command.Event.Actor = &a
	}
	switch command.Status {
	case "pending":
		if digest == nil || sequence != nil || len(payload) == 0 || crypto.SHA256Hex(payload) != *digest {
			return command, errors.New("store: pending attester trust command payload drifted")
		}
	case "completed":
		if digest != nil || sequence == nil || *sequence <= 0 || len(payload) != 0 || len(actor) != 0 {
			return command, errors.New("store: completed attester trust command retained payload")
		}
		command.Event.Sequence = uint64(*sequence)
	default:
		return command, errors.New("store: invalid attester trust command status")
	}
	return command, nil
}

func validWorkloadAttesterTrustCommandType(eventType string) bool {
	switch eventType {
	case "workload.attester_trust_source.upserted", "workload.attester_trust_source.rotated",
		"workload.attester_trust_source.revoked", "workload.attester_trust_source.deleted":
		return true
	default:
		return false
	}
}

// ClaimWorkloadAttesterTrustCommand denies an old proof before the broker
// append. A different pending command cannot replace its first writer.
func (s *Store) ClaimWorkloadAttesterTrustCommand(ctx context.Context, candidate WorkloadAttesterTrustCommand) (WorkloadAttesterTrustCommand, error) {
	var canonical WorkloadAttesterTrustCommand
	if candidate.Event.TenantID == "" || candidate.SourceID == "" || candidate.Event.ID == "" ||
		!validWorkloadAttesterTrustCommandType(candidate.Event.Type) ||
		candidate.Event.SchemaVersion != events.DefaultSchemaVersion ||
		candidate.Event.Time.IsZero() ||
		!candidate.Event.Time.Equal(candidate.Event.Time.UTC().Truncate(time.Microsecond)) ||
		len(candidate.Event.Data) == 0 || len(candidate.BindingSHA256) != 64 ||
		len(candidate.RequestBinding) != 64 {
		return canonical, errors.New("store: incomplete attester trust command")
	}
	for _, id := range []string{candidate.Event.TenantID, candidate.SourceID, candidate.Event.ID} {
		parsed, err := uuid.Parse(id)
		if err != nil || parsed.String() != id {
			return canonical, errors.New("store: attester trust command needs canonical UUIDs")
		}
	}
	var coordinates struct {
		ID      string `json:"id"`
		Enabled bool   `json:"enabled"`
	}
	if err := json.Unmarshal(candidate.Event.Data, &coordinates); err != nil || coordinates.ID != candidate.SourceID {
		return canonical, errors.New("store: attester trust command source differs from payload")
	}
	switch candidate.Event.Type {
	case "workload.attester_trust_source.revoked", "workload.attester_trust_source.deleted":
		if !candidate.TargetDisabled {
			return canonical, errors.New("store: terminal attester trust command must deny admission")
		}
	case "workload.attester_trust_source.rotated":
		if candidate.TargetDisabled {
			return canonical, errors.New("store: rotated attester trust command has invalid target posture")
		}
	case "workload.attester_trust_source.upserted":
		if candidate.TargetDisabled == coordinates.Enabled {
			return canonical, errors.New("store: attester trust command posture differs from payload")
		}
	}
	var actor []byte
	if candidate.Event.Actor != nil {
		var err error
		actor, err = json.Marshal(candidate.Event.Actor)
		if err != nil {
			return canonical, err
		}
	}
	err := s.WithPrivacyRecoveryBarrier(ctx, candidate.Event.TenantID,
		"attester trust command privacy barrier", func(barrierCtx context.Context) error {
			return s.WithTenant(barrierCtx, candidate.Event.TenantID, func(tx pgx.Tx) error {
				if err := lockUpsertArbiterTx(barrierCtx, tx,
					"workload_attester_trust_commands", candidate.Event.TenantID, candidate.SourceID); err != nil {
					return err
				}
				if receipt, receiptErr := scanWorkloadAttesterTrustReceipt(tx.QueryRow(barrierCtx,
					`SELECT tenant_id::text,event_id::text,source_id::text,event_type,request_binding,
					        binding_sha256,response_snapshot,projected_sequence
					   FROM workload_attester_trust_receipts WHERE tenant_id=$1 AND event_id=$2`,
					candidate.Event.TenantID, candidate.Event.ID)); receiptErr == nil {
					if receipt.SourceID != candidate.SourceID || receipt.EventType != candidate.Event.Type ||
						receipt.RequestBinding != candidate.RequestBinding || receipt.BindingSHA256 != candidate.BindingSHA256 {
						return ErrIdempotencyConflict
					}
					return ErrIdempotencyConflict // Completed work must replay its saved response, never re-claim.
				} else if !errors.Is(receiptErr, pgx.ErrNoRows) {
					return receiptErr
				}
				var err error
				canonical, err = scanWorkloadAttesterTrustCommand(tx.QueryRow(barrierCtx,
					`SELECT `+workloadAttesterTrustCommandColumns+` FROM workload_attester_trust_commands
					 WHERE tenant_id=$1 AND source_id=$2 FOR UPDATE`, candidate.Event.TenantID, candidate.SourceID))
				if err != nil && !errors.Is(err, pgx.ErrNoRows) {
					return err
				}
				if err == nil {
					if canonical.Event.ID == candidate.Event.ID {
						if canonical.BindingSHA256 != candidate.BindingSHA256 ||
							canonical.RequestBinding != candidate.RequestBinding ||
							canonical.Event.Type != candidate.Event.Type ||
							canonical.TargetDisabled != candidate.TargetDisabled ||
							(canonical.Status == "pending" && (!bytes.Equal(canonical.Event.Data, candidate.Event.Data) ||
								!reflect.DeepEqual(canonical.Event.Actor, candidate.Event.Actor))) {
							return ErrIdempotencyConflict
						}
						return nil
					}
					if canonical.Status == "pending" {
						return ErrIdempotencyConflict
					}
					_, err = tx.Exec(barrierCtx, `UPDATE workload_attester_trust_commands SET
						event_id=$3,event_type=$4,event_time=$5,event_actor=$6,event_payload=$7,
						payload_sha256=$8,binding_sha256=$9,request_binding=$10,target_disabled=$11,
						status='pending',projected_sequence=NULL,updated_at=now()
						WHERE tenant_id=$1 AND source_id=$2`, candidate.Event.TenantID, candidate.SourceID,
						candidate.Event.ID, candidate.Event.Type, candidate.Event.Time, actor,
						candidate.Event.Data, crypto.SHA256Hex(candidate.Event.Data),
						candidate.BindingSHA256, candidate.RequestBinding, candidate.TargetDisabled)
				} else {
					_, err = tx.Exec(barrierCtx, `INSERT INTO workload_attester_trust_commands
						(tenant_id,source_id,event_id,event_type,event_time,event_actor,event_payload,
						payload_sha256,binding_sha256,request_binding,target_disabled)
						VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)`, candidate.Event.TenantID,
						candidate.SourceID, candidate.Event.ID, candidate.Event.Type,
						candidate.Event.Time, actor, candidate.Event.Data,
						crypto.SHA256Hex(candidate.Event.Data), candidate.BindingSHA256, candidate.RequestBinding,
						candidate.TargetDisabled)
				}
				if err != nil {
					return err
				}
				canonical = candidate
				canonical.Status = "pending"
				return nil
			})
		})
	return canonical, err
}

// CompleteWorkloadAttesterTrustCommandTx atomically binds the independent
// authority to the exact source event that built the read model.
func (s *Store) CompleteWorkloadAttesterTrustCommandTx(ctx context.Context, tx pgx.Tx, sourceID string, event events.Event) error {
	if event.Sequence == 0 || event.Sequence > math.MaxInt64 {
		return errors.New("store: attester trust command needs a bounded source sequence")
	}
	command, err := scanWorkloadAttesterTrustCommand(tx.QueryRow(ctx,
		`SELECT `+workloadAttesterTrustCommandColumns+` FROM workload_attester_trust_commands
		 WHERE tenant_id=$1 AND source_id=$2 FOR UPDATE`, event.TenantID, sourceID))
	if errors.Is(err, pgx.ErrNoRows) {
		return nil // Historical event predates the independent command receiver.
	}
	if err != nil {
		return err
	}
	if command.Event.ID != event.ID {
		return nil // An older event cannot clear a newer command during replay.
	}
	if command.Status == "completed" {
		if command.Event.Sequence != event.Sequence {
			return errors.New("store: attester trust completion sequence drifted")
		}
		return nil
	}
	if command.Event.Type != event.Type || command.Event.SchemaVersion != event.SchemaVersion ||
		!command.Event.Time.Equal(event.Time) || !bytes.Equal(command.Event.Data, event.Data) ||
		!reflect.DeepEqual(command.Event.Actor, event.Actor) {
		return errors.New("store: attester trust event differs from first command")
	}
	var snapshot []byte
	if event.Type != "workload.attester_trust_source.deleted" {
		var source WorkloadAttesterTrustSource
		if err := scanWorkloadAttesterTrustSource(tx.QueryRow(ctx,
			`SELECT id::text,tenant_id::text,name,method,issuer,audience,jwks,
			        root_certs_pem,expected_nonce_base64,enabled,revoked_at,revoked_reason,
			        rotation_version,last_rotated_at,created_at,updated_at
			   FROM workload_attester_trust_sources WHERE tenant_id=$1 AND id=$2`,
			event.TenantID, sourceID), &source); err != nil {
			return err
		}
		snapshot, err = json.Marshal(source)
		if err != nil {
			return err
		}
	}
	if _, err := tx.Exec(ctx, `INSERT INTO workload_attester_trust_receipts
		(tenant_id,event_id,source_id,event_type,request_binding,binding_sha256,response_snapshot,projected_sequence)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8)`, event.TenantID, event.ID, sourceID,
		event.Type, command.RequestBinding, command.BindingSHA256, snapshot, int64(event.Sequence)); err != nil {
		return err
	}
	_, err = tx.Exec(ctx, `UPDATE workload_attester_trust_commands SET status='completed',
		event_actor=NULL,event_payload=NULL,payload_sha256=NULL,
		projected_sequence=$3,updated_at=now()
		WHERE tenant_id=$1 AND source_id=$2 AND event_id=$4 AND status='pending'`,
		event.TenantID, sourceID, int64(event.Sequence), event.ID)
	return err
}

func (s *Store) WorkloadAttesterTrustCommand(ctx context.Context, tenantID, sourceID string) (WorkloadAttesterTrustCommand, error) {
	var command WorkloadAttesterTrustCommand
	err := s.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		var err error
		command, err = scanWorkloadAttesterTrustCommand(tx.QueryRow(ctx,
			`SELECT `+workloadAttesterTrustCommandColumns+` FROM workload_attester_trust_commands
			 WHERE tenant_id=$1 AND source_id=$2`, tenantID, sourceID))
		return err
	})
	return command, err
}

// PendingWorkloadAttesterTrustKeysSystem returns only opaque keys. The caller
// enters tenant RLS before reading any recoverable event bytes.
func (s *Store) PendingWorkloadAttesterTrustKeysSystem(ctx context.Context, afterTenant, afterSource string, limit int) ([][2]string, error) {
	if afterTenant == "" {
		afterTenant = "00000000-0000-0000-0000-000000000000"
	}
	if afterSource == "" {
		afterSource = "00000000-0000-0000-0000-000000000000"
	}
	if limit <= 0 || limit > 100 {
		limit = 100
	}
	//trstctl:system-query — startup inventory exposes only tenant/source IDs, not command payloads.
	rows, err := s.SystemPool().Query(ctx, `SELECT tenant_id::text,source_id::text FROM workload_attester_trust_commands
		WHERE status='pending' AND (tenant_id,source_id) > ($1::uuid,$2::uuid)
		ORDER BY tenant_id,source_id LIMIT $3`, afterTenant, afterSource, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var keys [][2]string
	for rows.Next() {
		var key [2]string
		if err := rows.Scan(&key[0], &key[1]); err != nil {
			return nil, err
		}
		keys = append(keys, key)
	}
	return keys, rows.Err()
}
