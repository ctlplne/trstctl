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

// CACeremonyEffectCommand is a PostgreSQL first-writer fence, not a projection.
// Only a pending command retains the exact event bytes needed after an
// ambiguous broker append. Completion scrubs those bytes in the same SQL
// transaction that accounts for the dependency.
type CACeremonyEffectCommand struct {
	TenantID      string
	CeremonyID    string
	KeyID         string
	CertificateID string
	Event         events.Event
	Status        string
}

const caCeremonyEffectColumns = `tenant_id::text,ceremony_id::text,key_id::text,certificate_id::text,event_id,event_time,event_schema_version,
	event_actor,actor_sha256,event_payload,payload_sha256,status`

func scanCACeremonyEffectCommand(row pgx.Row) (CACeremonyEffectCommand, error) {
	var command CACeremonyEffectCommand
	var actorBytes, payload []byte
	var actorDigest, payloadDigest string
	if err := row.Scan(&command.TenantID, &command.CeremonyID, &command.KeyID, &command.CertificateID, &command.Event.ID,
		&command.Event.Time, &command.Event.SchemaVersion, &actorBytes, &actorDigest, &payload,
		&payloadDigest, &command.Status); err != nil {
		return command, err
	}
	command.Event.TenantID = command.TenantID
	command.Event.Type = "dependency.released"
	command.Event.Data = payload
	switch command.Status {
	case "pending":
		if crypto.SHA256Hex(actorBytes) != actorDigest || crypto.SHA256Hex(payload) != payloadDigest {
			return command, errors.New("store: CA ceremony effect command bytes drifted")
		}
		var actor events.Actor
		if err := json.Unmarshal(actorBytes, &actor); err != nil {
			return command, err
		}
		command.Event.Actor = &actor
	case "completed":
		if len(actorBytes) != 0 || len(payload) != 0 {
			return command, errors.New("store: completed CA ceremony effect retained transient material")
		}
	default:
		return command, errors.New("store: unsupported CA ceremony effect command state")
	}
	return command, nil
}

// ReserveCACeremonyEffectCommandTx runs after the caller locks and validates
// the exact ceremony and dependent in this transaction. A primary-key conflict
// is a competing first writer and must never replace an event payload.
func (s *Store) ReserveCACeremonyEffectCommandTx(ctx context.Context, tx pgx.Tx, command CACeremonyEffectCommand) error {
	ev := command.Event
	if command.TenantID == "" || command.CeremonyID == "" || command.KeyID == "" || command.CertificateID == "" || ev.ID == "" ||
		ev.TenantID != command.TenantID || ev.Type != "dependency.released" ||
		(ev.SchemaVersion != 2 && ev.SchemaVersion != 3) || ev.Time.IsZero() || ev.Actor == nil || len(ev.Data) == 0 ||
		!ev.Time.Equal(ev.Time.UTC().Truncate(time.Microsecond)) {
		return errors.New("store: incomplete CA ceremony effect command")
	}
	var identity struct {
		TenantID   string `json:"tenant_id"`
		KeyID      string `json:"key_id"`
		CeremonyID string `json:"ceremony_id"`
		Dependent  struct {
			Class string `json:"class"`
			ID    string `json:"id"`
		} `json:"dependent"`
	}
	if err := json.Unmarshal(ev.Data, &identity); err != nil {
		return err
	}
	if identity.TenantID != command.TenantID || identity.KeyID != command.KeyID ||
		identity.CeremonyID != command.CeremonyID || identity.Dependent.Class != "credential" ||
		identity.Dependent.ID != command.CertificateID {
		return errors.New("store: CA ceremony effect coordinates differ from immutable event")
	}
	actor, err := json.Marshal(ev.Actor)
	if err != nil {
		return err
	}
	_, err = tx.Exec(ctx, `INSERT INTO ca_ceremony_effect_commands
		(tenant_id,ceremony_id,key_id,certificate_id,operation,event_id,event_time,event_schema_version,event_actor,actor_sha256,event_payload,payload_sha256)
		VALUES ($1,$2,$3,$4,'release_managed_ca_leaf',$5,$6,$7,$8,$9,$10,$11)`,
		command.TenantID, command.CeremonyID, command.KeyID, command.CertificateID, ev.ID, ev.Time,
		ev.SchemaVersion, actor, crypto.SHA256Hex(actor), ev.Data, crypto.SHA256Hex(ev.Data))
	return err
}

func (s *Store) GetCACeremonyEffectCommand(ctx context.Context, tenantID, ceremonyID string) (CACeremonyEffectCommand, error) {
	var command CACeremonyEffectCommand
	err := s.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		var queryErr error
		command, queryErr = scanCACeremonyEffectCommand(tx.QueryRow(ctx,
			`SELECT `+caCeremonyEffectColumns+` FROM ca_ceremony_effect_commands
			 WHERE tenant_id=$1 AND ceremony_id=$2`, tenantID, ceremonyID))
		return queryErr
	})
	return command, err
}

// A preview must not advertise a second release while an independent
// first-writer claim for this exact CA leaf is pending or completed.
func (s *Store) CACeremonyEffectClaimedForDependent(ctx context.Context, tenantID, keyID, certificateID string) (bool, error) {
	var claimed bool
	err := s.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM ca_ceremony_effect_commands
			WHERE tenant_id=$1 AND key_id=$2 AND certificate_id=$3)`,
			tenantID, keyID, certificateID).Scan(&claimed)
	})
	return claimed, err
}

func (s *Store) LockCACeremonyEffectCommandTx(ctx context.Context, tx pgx.Tx, tenantID, ceremonyID string) (CACeremonyEffectCommand, error) {
	return scanCACeremonyEffectCommand(tx.QueryRow(ctx,
		`SELECT `+caCeremonyEffectColumns+` FROM ca_ceremony_effect_commands
		 WHERE tenant_id=$1 AND ceremony_id=$2 FOR UPDATE`, tenantID, ceremonyID))
}

func (s *Store) ListPendingCACeremonyEffects(ctx context.Context, tenantID string, limit int) ([]CACeremonyEffectCommand, error) {
	if limit <= 0 || limit > 100 {
		limit = 100
	}
	var out []CACeremonyEffectCommand
	err := s.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `SELECT `+caCeremonyEffectColumns+` FROM ca_ceremony_effect_commands
			WHERE tenant_id=$1 AND status='pending' ORDER BY created_at,ceremony_id LIMIT $2`, tenantID, limit)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			command, err := scanCACeremonyEffectCommand(rows)
			if err != nil {
				return err
			}
			out = append(out, command)
		}
		return rows.Err()
	})
	return out, err
}

// CACeremonyEffectCommandExistsTx is the shared pre-append fence consulted by
// approval, cancellation and execution. A pending effect claim survives an
// event append/SQL rollback and must be reconciled before any other decision.
func (s *Store) CACeremonyEffectCommandExistsTx(ctx context.Context, tx pgx.Tx, tenantID, ceremonyID string) (bool, error) {
	var exists bool
	err := tx.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM ca_ceremony_effect_commands
		WHERE tenant_id=$1 AND ceremony_id=$2)`, tenantID, ceremonyID).Scan(&exists)
	return exists, err
}

// CompleteCACeremonyEffectCommandTx accepts only the exact retained event
// reserved before append. The command is not a second source of authority; its
// status is a crash-recovery receipt derived from that immutable event.
func (s *Store) CompleteCACeremonyEffectCommandTx(ctx context.Context, tx pgx.Tx, tenantID, ceremonyID string, ev events.Event) error {
	var eventID, actorDigest, digest, status string
	var actorBytes []byte
	var eventTime time.Time
	var eventSchemaVersion int
	var payload []byte
	if err := tx.QueryRow(ctx, `SELECT event_id,event_time,event_schema_version,event_actor,actor_sha256,event_payload,payload_sha256,status
		FROM ca_ceremony_effect_commands WHERE tenant_id=$1 AND ceremony_id=$2 FOR UPDATE`, tenantID, ceremonyID).
		Scan(&eventID, &eventTime, &eventSchemaVersion, &actorBytes, &actorDigest, &payload, &digest, &status); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			// Event-only rebuild runs before independent PostgreSQL receivers
			// are restored. The immutable release and approvals are authority;
			// this row only bridges the live append/projection crash gap.
			return nil
		}
		return err
	}
	if ev.Actor == nil {
		return errors.New("store: ceremony effect event has no actor")
	}
	eventActor, err := json.Marshal(ev.Actor)
	if err != nil {
		return err
	}
	if ev.ID != eventID || ev.TenantID != tenantID || ev.Type != "dependency.released" || ev.SchemaVersion != eventSchemaVersion ||
		!ev.Time.Equal(eventTime) || crypto.SHA256Hex(eventActor) != actorDigest ||
		crypto.SHA256Hex(ev.Data) != digest ||
		(status != "pending" && status != "completed") {
		return fmt.Errorf("store: ceremony effect event conflicts with durable first-writer command %s", ceremonyID)
	}
	if status == "pending" {
		var actor events.Actor
		if err := json.Unmarshal(actorBytes, &actor); err != nil {
			return err
		}
		if !reflect.DeepEqual(*ev.Actor, actor) || !bytes.Equal(ev.Data, payload) ||
			crypto.SHA256Hex(actorBytes) != actorDigest || crypto.SHA256Hex(payload) != digest {
			return errors.New("store: ceremony effect pending payload conflicts with retained event")
		}
	} else if len(actorBytes) != 0 || len(payload) != 0 {
		return errors.New("store: completed ceremony effect retains transient payload")
	}
	_, err = tx.Exec(ctx, `UPDATE ca_ceremony_effect_commands
		SET status='completed',event_actor=NULL,event_payload=NULL
		WHERE tenant_id=$1 AND ceremony_id=$2`, tenantID, ceremonyID)
	return err
}
