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
	"trstctl.com/trstctl/internal/privacy"
)

// Versioned batches (A236): an environment promotion or a folder restore writes
// new versions of several secrets as one command. They reuse the batch-import
// reservation — a row in application_secret_import_batches carrying its
// operation, plus one import name fence per secret — so a single-secret
// command or another batch cannot change a reserved name between the plan and
// the projection, and a crash after the reservation is completed from the
// stored ciphertext command.
const (
	ApplicationSecretBatchImport    = "import"
	ApplicationSecretBatchPromotion = "promotion"
	ApplicationSecretBatchRestore   = "restore"
	// ApplicationSecretBatchMigration writes a migration's staged, reissued or
	// rolled-back versions (A243).
	ApplicationSecretBatchMigration = "migration"
)

// ErrApplicationSecretBatchStale is a versioned batch whose plan no longer
// matches a secret: its version moved after the plan was made.
var ErrApplicationSecretBatchStale = errors.New("store: a secret changed after the plan was made")

// ApplicationSecretVersionFence is the version a batch item expects when the
// batch is reserved: 0 for a name that must not exist yet.
type ApplicationSecretVersionFence struct {
	Name            string
	ExpectedVersion int
}

// ApplicationSecretVersionItem is one projected item of a versioned batch.
type ApplicationSecretVersionItem struct {
	Name            string
	ExpectedVersion int
	ResultVersion   int
	Sealed          []byte
	// RecoveredFrom is the restored version (restore only).
	RecoveredFrom *int
}

func validApplicationSecretBatchOperation(operation string) bool {
	return operation == ApplicationSecretBatchPromotion || operation == ApplicationSecretBatchRestore ||
		operation == ApplicationSecretBatchMigration
}

// RunApplicationSecretVersionBatchCommand reserves every name of a versioned
// batch at its expected version and runs fn (append and project) under the
// same privacy barrier as a batch import. A name that is reserved by another
// command fails with ErrApplicationSecretMutationInFlight; one whose version
// moved fails with ErrApplicationSecretBatchStale. Either way nothing is
// reserved or published.
func (s *Store) RunApplicationSecretVersionBatchCommand(
	ctx context.Context, batch ApplicationSecretImportBatch, fences []ApplicationSecretVersionFence,
	fn func(context.Context, ApplicationSecretImportBatch) error,
) error {
	batch.EventTime = batch.EventTime.UTC().Truncate(time.Microsecond)
	if err := validateApplicationSecretImportBatch(batch); err != nil {
		return err
	}
	if !validApplicationSecretBatchOperation(batch.Operation) || len(fences) != len(batch.Names) {
		return errors.New("store: versioned secret batch is incomplete")
	}
	for index, fence := range fences {
		if fence.Name != batch.Names[index] || fence.ExpectedVersion < 0 {
			return errors.New("store: versioned secret batch fences differ from its names")
		}
	}
	batch.PayloadDigest = crypto.SHA256Hex(batch.Payload)
	return s.WithApplicationSecretMutationPrivacyBarrier(ctx, batch.TenantID,
		func(barrierCtx context.Context) error {
			canonical, err := s.claimApplicationSecretVersionBatchUnbarriered(barrierCtx, batch, fences)
			if err != nil {
				return err
			}
			return fn(barrierCtx, canonical)
		})
}

func (s *Store) claimApplicationSecretVersionBatchUnbarriered(
	ctx context.Context, batch ApplicationSecretImportBatch, fences []ApplicationSecretVersionFence,
) (ApplicationSecretImportBatch, error) {
	var canonical ApplicationSecretImportBatch
	err := s.WithTenant(ctx, batch.TenantID, func(tx pgx.Tx) error {
		var err error
		canonical, err = getApplicationSecretImportBatchTx(ctx, tx, batch.TenantID, batch.EventID)
		if err == nil {
			if canonical.Operation != batch.Operation || canonical.RequestBinding != batch.RequestBinding ||
				canonical.PayloadDigest != batch.PayloadDigest || !slices.Equal(canonical.Names, batch.Names) {
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
		for _, fence := range fences {
			var reserved bool
			if err := tx.QueryRow(ctx, `
				SELECT EXISTS (SELECT 1 FROM application_secret_mutation_fences WHERE tenant_id = $1 AND secret_name = $2)
				    OR EXISTS (SELECT 1 FROM application_secret_import_name_fences WHERE tenant_id = $1 AND secret_name = $2)`,
				batch.TenantID, fence.Name).Scan(&reserved); err != nil {
				return err
			}
			if reserved {
				return fmt.Errorf("%w: %s is being changed by another command", ErrApplicationSecretMutationInFlight, fence.Name)
			}
			version := 0
			err := tx.QueryRow(ctx, `SELECT version FROM secret_store WHERE tenant_id = $1 AND name = $2`,
				batch.TenantID, fence.Name).Scan(&version)
			if err != nil && !errors.Is(err, pgx.ErrNoRows) {
				return err
			}
			if version != fence.ExpectedVersion {
				return fmt.Errorf("%w: %s", ErrApplicationSecretBatchStale, fence.Name)
			}
		}
		actor, err := json.Marshal(batch.Actor)
		if err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `
			INSERT INTO application_secret_import_batches
			    (tenant_id, event_id, tenant_epoch, request_binding, payload_sha256,
			     command_payload, actor, actor_subject_ref, event_time, operation)
			VALUES ($1, $2, $3, $4, $5, $6, $7::jsonb, $8, $9, $10)`,
			batch.TenantID, batch.EventID, batch.TenantEpoch, batch.RequestBinding,
			batch.PayloadDigest, batch.Payload, string(actor),
			privacy.SubjectRef(batch.TenantID, batch.Actor.Subject), batch.EventTime.UTC(), batch.Operation); err != nil {
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

// ApplyApplicationSecretVersionBatchTx materializes one versioned batch: every
// new version, the receipt and the reservation release share this one SQL
// transaction. An item whose version moved fails the whole batch, so PostgreSQL
// rolls the earlier items back; the reservation makes that impossible outside
// a corrupted log.
func (s *Store) ApplyApplicationSecretVersionBatchTx(
	ctx context.Context, tx pgx.Tx, batch ApplicationSecretImportBatch,
	semanticDigest string, items []ApplicationSecretVersionItem, privacyPruned bool,
) error {
	if err := validateApplicationSecretImportBatch(batch); err != nil {
		return err
	}
	if !validApplicationSecretBatchOperation(batch.Operation) || len(semanticDigest) != 64 ||
		len(items) != len(batch.Names) || crypto.SHA256Hex(batch.Payload) != batch.PayloadDigest {
		return errors.New("store: versioned secret batch projection binding is incomplete")
	}
	for index, item := range items {
		if item.Name != batch.Names[index] || len(item.Sealed) == 0 || item.ExpectedVersion < 0 ||
			item.ResultVersion != item.ExpectedVersion+1 {
			return errors.New("store: versioned secret batch items differ from their fences")
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
		if canonical.Operation != batch.Operation || canonical.TenantEpoch != batch.TenantEpoch ||
			canonical.RequestBinding != batch.RequestBinding || canonical.PayloadDigest != batch.PayloadDigest ||
			!slices.Equal(canonical.Names, batch.Names) ||
			!canonical.EventTime.Equal(batch.EventTime.UTC().Truncate(time.Microsecond)) {
			return ErrIdempotencyConflict
		}
	}
	at := batch.EventTime.UTC()
	result := make([]ApplicationSecretImportItem, 0, len(items))
	for _, item := range items {
		var rec ApplicationSecretImportItem
		if item.ExpectedVersion == 0 {
			err = tx.QueryRow(ctx, `
				INSERT INTO secret_store (tenant_id, name, sealed, version, created_at, updated_at)
				VALUES ($1, $2, $3, 1, $4, $4)
				ON CONFLICT (tenant_id, name) DO NOTHING
				RETURNING name, version, created_at, updated_at`,
				batch.TenantID, item.Name, item.Sealed, at).
				Scan(&rec.Name, &rec.Version, &rec.CreatedAt, &rec.UpdatedAt)
		} else {
			err = tx.QueryRow(ctx, `
				UPDATE secret_store SET sealed = $3, version = $4, updated_at = $5
				 WHERE tenant_id = $1 AND name = $2 AND version = $6
				RETURNING name, version, created_at, updated_at`,
				batch.TenantID, item.Name, item.Sealed, item.ResultVersion, at, item.ExpectedVersion).
				Scan(&rec.Name, &rec.Version, &rec.CreatedAt, &rec.UpdatedAt)
		}
		if errors.Is(err, pgx.ErrNoRows) {
			return fmt.Errorf("%w: %s", ErrApplicationSecretBatchStale, item.Name)
		}
		if err != nil {
			return err
		}
		if err := insertSecretVersion(ctx, tx, batch.TenantID, item.Name, item.ResultVersion,
			item.Sealed, at, item.RecoveredFrom); err != nil {
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
		semanticDigest, batch.RequestBinding, string(encoded), at); err != nil {
		return err
	}
	_, err = tx.Exec(ctx, `DELETE FROM application_secret_import_batches
		WHERE tenant_id = $1 AND event_id = $2`, batch.TenantID, batch.EventID)
	return err
}

// Credential states a restore or promotion refuses (A236): a version whose
// credential its provider no longer accepts.
const (
	SecretCredentialRetired  = "retired"  // a rotation retired it at its provider
	SecretCredentialRetiring = "retiring" // a rotation is retiring it
	SecretCredentialRevoked  = "revoked"  // a rotation rolled it back and revoked it
	SecretCredentialExpired  = "expired"  // a dynamic lease that has expired
)

// SecretCredentialState says whether a secret version holds a credential its
// provider retired, revoked or let expire, from the rotation commands that
// produced or replaced it. "" means nothing is known against it.
type SecretCredentialState struct {
	State     string
	CommandID string
	At        time.Time
}

// SecretVersionCredentialState returns the credential state of one version.
func (s *Store) SecretVersionCredentialState(ctx context.Context, tenantID, name string, version int, now time.Time) (SecretCredentialState, error) {
	var out SecretCredentialState
	err := s.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		var id, phase string
		var at time.Time
		err := tx.QueryRow(ctx, `
			SELECT id::text, phase, updated_at FROM secret_static_rotation_commands
			 WHERE tenant_id = $1 AND secret_key = $2
			   AND ((expected_version = $3 AND phase IN ('completed', 'retire_pending'))
			     OR (result_version = $3 AND phase = 'rolled_back'))
			 ORDER BY updated_at DESC, id LIMIT 1`, tenantID, name, version).Scan(&id, &phase, &at)
		switch {
		case err == nil:
			out = SecretCredentialState{State: SecretCredentialRetired, CommandID: id, At: at}
			switch phase {
			case SecretStaticRotationRetirePending:
				out.State = SecretCredentialRetiring
			case SecretStaticRotationRolledBack:
				out.State = SecretCredentialRevoked
			}
			return nil
		case !errors.Is(err, pgx.ErrNoRows):
			return err
		}
		err = tx.QueryRow(ctx, `
			SELECT id::text, new_expires_at FROM secret_static_rotation_commands
			 WHERE tenant_id = $1 AND secret_key = $2 AND result_version = $3
			   AND ttl_seconds > 0 AND new_expires_at IS NOT NULL AND new_expires_at <= $4
			 ORDER BY new_expires_at DESC, id LIMIT 1`, tenantID, name, version, now.UTC()).Scan(&id, &at)
		if err == nil {
			out = SecretCredentialState{State: SecretCredentialExpired, CommandID: id, At: at}
			return nil
		}
		if errors.Is(err, pgx.ErrNoRows) {
			return nil
		}
		return err
	})
	return out, err
}
