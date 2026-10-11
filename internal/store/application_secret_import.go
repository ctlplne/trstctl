// SPDX-License-Identifier: BUSL-1.1

package store

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"time"

	"github.com/jackc/pgx/v5"

	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/privacy"
)

// ApplicationSecretImportBatch is a ciphertext-only command, committed before
// publishing its single batch event. Name fences keep concurrent single-secret
// and batch writers behind this command until its projection commits.
type ApplicationSecretImportBatch struct {
	TenantID       string
	EventID        string
	TenantEpoch    string
	RequestBinding string
	Payload        []byte
	PayloadDigest  string
	Actor          *events.Actor
	EventTime      time.Time
	Names          []string
}

type ApplicationSecretImportItem struct {
	Name      string    `json:"name"`
	Version   int       `json:"version"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

type ApplicationSecretImportReceipt struct {
	TenantID       string
	EventID        string
	SemanticDigest string
	RequestBinding string
	Items          []ApplicationSecretImportItem
	AppliedAt      time.Time
}

type ApplicationSecretImportSealedItem struct {
	Name   string
	Sealed []byte
}

func validateApplicationSecretImportBatch(batch ApplicationSecretImportBatch) error {
	if batch.TenantID == "" || batch.EventID == "" || batch.TenantEpoch == "" ||
		len(batch.RequestBinding) != 64 || batch.Actor == nil || batch.Actor.Subject == "" ||
		batch.EventTime.IsZero() || len(batch.Payload) == 0 || len(batch.Names) == 0 ||
		len(batch.Names) > 100 {
		return errors.New("store: application-secret import command is incomplete")
	}
	if !slices.IsSorted(batch.Names) {
		return errors.New("store: application-secret import names must be sorted")
	}
	for index, name := range batch.Names {
		if name == "" || len(name) > 512 || index > 0 && batch.Names[index-1] == name {
			return errors.New("store: application-secret import names must be unique and bounded")
		}
	}
	return nil
}

// ClaimApplicationSecretImportBatch reserves every name in one tenant
// transaction. It acquires the same advisory lock as a single-secret command
// claim, in lexical order. A collision therefore publishes no partial event.
func (s *Store) ClaimApplicationSecretImportBatch(ctx context.Context, batch ApplicationSecretImportBatch) (ApplicationSecretImportBatch, error) {
	// PostgreSQL TIMESTAMPTZ retains microseconds. Use its exact precision for
	// the event as well, so a fresh projection and a crash replay compare equal.
	batch.EventTime = batch.EventTime.UTC().Truncate(time.Microsecond)
	if err := validateApplicationSecretImportBatch(batch); err != nil {
		return ApplicationSecretImportBatch{}, err
	}
	batch.PayloadDigest = crypto.SHA256Hex(batch.Payload)
	var canonical ApplicationSecretImportBatch
	err := s.WithApplicationSecretMutationPrivacyBarrier(ctx, batch.TenantID, func(barrierCtx context.Context) error {
		var err error
		canonical, err = s.claimApplicationSecretImportBatchUnbarriered(barrierCtx, batch)
		return err
	})
	return canonical, err
}

// RunApplicationSecretImportCommand holds the privacy generation lock across
// reservation, broker append and projection. The callback gets only the
// canonical stored ciphertext command and runs after its name fences commit.
func (s *Store) RunApplicationSecretImportCommand(
	ctx context.Context, batch ApplicationSecretImportBatch,
	fn func(context.Context, ApplicationSecretImportBatch) error,
) error {
	batch.EventTime = batch.EventTime.UTC().Truncate(time.Microsecond)
	if err := validateApplicationSecretImportBatch(batch); err != nil {
		return err
	}
	batch.PayloadDigest = crypto.SHA256Hex(batch.Payload)
	return s.WithApplicationSecretMutationPrivacyBarrier(ctx, batch.TenantID,
		func(barrierCtx context.Context) error {
			canonical, err := s.claimApplicationSecretImportBatchUnbarriered(barrierCtx, batch)
			if err != nil {
				return err
			}
			return fn(barrierCtx, canonical)
		})
}

func (s *Store) claimApplicationSecretImportBatchUnbarriered(
	ctx context.Context, batch ApplicationSecretImportBatch,
) (ApplicationSecretImportBatch, error) {
	var canonical ApplicationSecretImportBatch
	err := s.WithTenant(ctx, batch.TenantID, func(tx pgx.Tx) error {
		var err error
		canonical, err = getApplicationSecretImportBatchTx(ctx, tx, batch.TenantID, batch.EventID)
		if err == nil {
			if canonical.RequestBinding != batch.RequestBinding || canonical.PayloadDigest != batch.PayloadDigest ||
				!slices.Equal(canonical.Names, batch.Names) {
				return ErrIdempotencyConflict
			}
			return nil
		}
		if !errors.Is(err, pgx.ErrNoRows) {
			return err
		}
		if err := s.ValidateApplicationSecretTenantEpochTx(ctx, tx, batch.TenantID, batch.TenantEpoch); err != nil {
			return err
		}
		for _, name := range batch.Names {
			if err := lockApplicationSecretImportNameTx(ctx, tx, batch.TenantID, name); err != nil {
				return err
			}
		}
		for _, name := range batch.Names {
			var occupied bool
			if err := tx.QueryRow(ctx, `
						SELECT EXISTS (SELECT 1 FROM secret_store WHERE tenant_id = $1 AND name = $2)
						    OR EXISTS (SELECT 1 FROM application_secret_mutation_fences WHERE tenant_id = $1 AND secret_name = $2)
						    OR EXISTS (SELECT 1 FROM application_secret_import_name_fences WHERE tenant_id = $1 AND secret_name = $2)`,
				batch.TenantID, name).Scan(&occupied); err != nil {
				return err
			}
			if occupied {
				return fmt.Errorf("%w: application-secret import name %s is already reserved or exists", ErrIdempotencyConflict, name)
			}
		}
		actor, err := json.Marshal(batch.Actor)
		if err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `
				INSERT INTO application_secret_import_batches
				    (tenant_id, event_id, tenant_epoch, request_binding, payload_sha256,
				     command_payload, actor, actor_subject_ref, event_time)
				VALUES ($1, $2, $3, $4, $5, $6, $7::jsonb, $8, $9)`,
			batch.TenantID, batch.EventID, batch.TenantEpoch, batch.RequestBinding,
			batch.PayloadDigest, batch.Payload, string(actor),
			privacy.SubjectRef(batch.TenantID, batch.Actor.Subject), batch.EventTime.UTC()); err != nil {
			return err
		}
		for _, name := range batch.Names {
			if _, err := tx.Exec(ctx, `
					INSERT INTO application_secret_import_name_fences (tenant_id, secret_name, event_id)
					VALUES ($1, $2, $3)`, batch.TenantID, name, batch.EventID); err != nil {
				return err
			}
		}
		canonical = batch
		return nil
	})
	return canonical, err
}

func lockApplicationSecretImportNameTx(ctx context.Context, tx pgx.Tx, tenantID, name string) error {
	_, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtextextended($1, 0))`,
		applicationSecretMutationLockKey(tenantID, name))
	return err
}

func getApplicationSecretImportBatchTx(ctx context.Context, tx pgx.Tx, tenantID, eventID string) (ApplicationSecretImportBatch, error) {
	var batch ApplicationSecretImportBatch
	var actor []byte
	err := tx.QueryRow(ctx, `
		SELECT tenant_id::text, event_id::text, tenant_epoch::text, request_binding,
		       payload_sha256, command_payload, actor, event_time
		  FROM application_secret_import_batches
		 WHERE tenant_id = $1 AND event_id = $2`, tenantID, eventID).
		Scan(&batch.TenantID, &batch.EventID, &batch.TenantEpoch, &batch.RequestBinding,
			&batch.PayloadDigest, &batch.Payload, &actor, &batch.EventTime)
	if err != nil {
		return batch, err
	}
	if err := json.Unmarshal(actor, &batch.Actor); err != nil {
		return ApplicationSecretImportBatch{}, err
	}
	rows, err := tx.Query(ctx, `
		SELECT secret_name FROM application_secret_import_name_fences
		 WHERE tenant_id = $1 AND event_id = $2 ORDER BY secret_name`, tenantID, eventID)
	if err != nil {
		return ApplicationSecretImportBatch{}, err
	}
	defer rows.Close()
	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err != nil {
			return ApplicationSecretImportBatch{}, err
		}
		batch.Names = append(batch.Names, name)
	}
	return batch, rows.Err()
}

func (s *Store) GetApplicationSecretImportBatch(
	ctx context.Context, tenantID, eventID string,
) (ApplicationSecretImportBatch, error) {
	var batch ApplicationSecretImportBatch
	err := s.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		var err error
		batch, err = getApplicationSecretImportBatchTx(ctx, tx, tenantID, eventID)
		return err
	})
	return batch, err
}

func (s *Store) GetApplicationSecretImportReceipt(ctx context.Context, tenantID, eventID string) (ApplicationSecretImportReceipt, error) {
	var receipt ApplicationSecretImportReceipt
	var items []byte
	err := s.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `
			SELECT tenant_id::text, event_id::text, semantic_sha256, request_binding, items, applied_at
			  FROM application_secret_import_receipts
			 WHERE tenant_id = $1 AND event_id = $2`, tenantID, eventID).
			Scan(&receipt.TenantID, &receipt.EventID, &receipt.SemanticDigest,
				&receipt.RequestBinding, &items, &receipt.AppliedAt)
	})
	if err == nil {
		err = json.Unmarshal(items, &receipt.Items)
	}
	return receipt, err
}

// ListApplicationSecretImportBatchesPage reads only outstanding commands. It
// never replays the event log to find recovery work and bounds each worker pass.
func (s *Store) ListApplicationSecretImportBatchesPage(
	ctx context.Context, tenantID, afterEventID string, limit int,
) ([]ApplicationSecretImportBatch, error) {
	if limit <= 0 || limit > 100 {
		return nil, errors.New("store: application-secret import recovery page limit must be 1..100")
	}
	var out []ApplicationSecretImportBatch
	err := s.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `
			SELECT event_id::text FROM application_secret_import_batches
			 WHERE tenant_id = $1 AND (NULLIF($2, '') IS NULL OR event_id > NULLIF($2, '')::uuid)
			 ORDER BY event_id LIMIT $3`, tenantID, afterEventID, limit)
		if err != nil {
			return err
		}
		var ids []string
		for rows.Next() {
			var id string
			if err := rows.Scan(&id); err != nil {
				rows.Close()
				return err
			}
			ids = append(ids, id)
		}
		rowErr := rows.Err()
		rows.Close()
		if rowErr != nil {
			return rowErr
		}
		for _, id := range ids {
			batch, err := getApplicationSecretImportBatchTx(ctx, tx, tenantID, id)
			if err != nil {
				return err
			}
			out = append(out, batch)
		}
		return nil
	})
	return out, err
}

// ApplyApplicationSecretImportTx materializes one immutable batch. Every name,
// version row, receipt and reservation release shares this one SQL transaction.
// If a later item collides, PostgreSQL rolls the earlier inserts back.
func (s *Store) ApplyApplicationSecretImportTx(
	ctx context.Context, tx pgx.Tx, batch ApplicationSecretImportBatch,
	semanticDigest string, items []ApplicationSecretImportSealedItem, privacyPruned bool,
) error {
	if err := validateApplicationSecretImportBatch(batch); err != nil {
		return err
	}
	if len(semanticDigest) != 64 || len(items) != len(batch.Names) ||
		crypto.SHA256Hex(batch.Payload) != batch.PayloadDigest {
		return errors.New("store: application-secret import projection binding is incomplete")
	}
	for index, item := range items {
		if item.Name != batch.Names[index] || len(item.Sealed) == 0 {
			return errors.New("store: application-secret import projection items differ from name fences")
		}
	}
	if err := s.ValidateApplicationSecretTenantEpochTx(ctx, tx, batch.TenantID, batch.TenantEpoch); err != nil {
		return err
	}
	for _, name := range batch.Names {
		if err := lockApplicationSecretImportNameTx(ctx, tx, batch.TenantID, name); err != nil {
			return err
		}
	}
	var priorDigest, priorBinding string
	err := tx.QueryRow(ctx, `
		SELECT semantic_sha256, request_binding FROM application_secret_import_receipts
		 WHERE tenant_id = $1 AND event_id = $2 FOR UPDATE`, batch.TenantID, batch.EventID).
		Scan(&priorDigest, &priorBinding)
	if err == nil {
		if priorBinding != batch.RequestBinding || !privacyPruned && priorDigest != semanticDigest {
			return ErrIdempotencyConflict
		}
		return nil
	}
	if !errors.Is(err, pgx.ErrNoRows) {
		return err
	}
	if !privacyPruned {
		canonical, err := getApplicationSecretImportBatchTx(ctx, tx, batch.TenantID, batch.EventID)
		if err != nil {
			return err
		}
		if canonical.TenantEpoch != batch.TenantEpoch || canonical.RequestBinding != batch.RequestBinding ||
			canonical.PayloadDigest != batch.PayloadDigest || !slices.Equal(canonical.Names, batch.Names) ||
			!canonical.EventTime.Equal(batch.EventTime.UTC().Truncate(time.Microsecond)) {
			return ErrIdempotencyConflict
		}
	}
	result := make([]ApplicationSecretImportItem, 0, len(items))
	for _, item := range items {
		var rec ApplicationSecretImportItem
		err := tx.QueryRow(ctx, `
			INSERT INTO secret_store (tenant_id, name, sealed, version, created_at, updated_at)
			VALUES ($1, $2, $3, 1, $4, $4)
			ON CONFLICT (tenant_id, name) DO NOTHING
			RETURNING name, version, created_at, updated_at`,
			batch.TenantID, item.Name, item.Sealed, batch.EventTime.UTC()).
			Scan(&rec.Name, &rec.Version, &rec.CreatedAt, &rec.UpdatedAt)
		if errors.Is(err, pgx.ErrNoRows) {
			return fmt.Errorf("%w: application-secret import name %s changed after reservation", ErrIdempotencyConflict, item.Name)
		}
		if err != nil {
			return err
		}
		if err := insertSecretVersion(ctx, tx, batch.TenantID, item.Name, 1,
			item.Sealed, batch.EventTime, nil); err != nil {
			return err
		}
		result = append(result, rec)
	}
	encoded, err := json.Marshal(result)
	if err != nil {
		return err
	}
	if _, err := tx.Exec(ctx, `
		INSERT INTO application_secret_import_receipts
		    (tenant_id, event_id, semantic_sha256, request_binding, items, applied_at)
		VALUES ($1, $2, $3, $4, $5::jsonb, $6)`, batch.TenantID, batch.EventID,
		semanticDigest, batch.RequestBinding, string(encoded), batch.EventTime.UTC()); err != nil {
		return err
	}
	_, err = tx.Exec(ctx, `DELETE FROM application_secret_import_batches
		WHERE tenant_id = $1 AND event_id = $2`, batch.TenantID, batch.EventID)
	return err
}
