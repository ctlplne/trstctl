// SPDX-License-Identifier: BUSL-1.1

package backup

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"strconv"
	"time"
	"trstctl.com/trstctl/internal/crypto/secret"
	"trstctl.com/trstctl/internal/store"

	"github.com/google/uuid"

	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/eventprotect"
)

// The production provider resolves opt-in and key identity from the retained
// source at the authenticated paired cut. A missing custodian must refuse an
// active tenant instead of reporting that protection is disabled.
type PostgresStateProtection interface {
	ProtectPostgresRow(context.Context, eventprotect.Context, json.RawMessage) (eventprotect.Envelope, bool, error)
	OpenPostgresRow(context.Context, eventprotect.Context, eventprotect.Envelope) (json.RawMessage, bool, error)
}

// PostgresStateProtectionFactory opens current custody only after the complete
// artifact and its declared owners have verified. Cleanup runs after row opening
// on success and failure; no private key handle enters SQL restore.
type PostgresStateProtectionFactory func(context.Context, PostgresStateSummary) (PostgresStateProtection, func(), error)

type protectedPostgresArtifact struct {
	ID               string
	CreatedAt        time.Time
	EventCutSequence uint64
}

type protectedPostgresRecord struct {
	Table           string                   `json:"table"`
	Ordinal         uint64                   `json:"ordinal"`
	TenantID        string                   `json:"tenant_id"`
	StorageTenantID string                   `json:"storage_tenant_id,omitempty"`
	ErasureRow      json.RawMessage          `json:"erasure_row,omitempty"`
	Checkpoint      *AuditCheckpointBoundary `json:"audit_checkpoint,omitempty"`
	Row             json.RawMessage          `json:"row,omitempty"`
	Protection      *eventprotect.Envelope   `json:"protection,omitempty"`
}

func postgresRowPolicyDigest() string {
	return crypto.SHA256Hex([]byte("trstctl.postgres-state-sensitive-row.v2"))
}

func postgresRowContext(artifact protectedPostgresArtifact, row protectedPostgresRecord) (eventprotect.Context, error) {
	identity, err := uuid.Parse(artifact.ID)
	tenant, tenantErr := uuid.Parse(row.TenantID)
	if err != nil || identity.Version() != 4 || identity.String() != artifact.ID || artifact.CreatedAt.IsZero() ||
		tenantErr != nil || tenant == uuid.Nil || tenant.String() != row.TenantID || row.Ordinal == 0 {
		return eventprotect.Context{}, errors.New("backup: invalid protected postgres row identity")
	}
	if _, err := quoteBackupTable(row.Table); err != nil {
		return eventprotect.Context{}, err
	}
	metadata, err := json.Marshal(struct {
		StorageTenantID string                   `json:"storage_tenant_id"`
		ErasureRow      json.RawMessage          `json:"erasure_row,omitempty"`
		Checkpoint      *AuditCheckpointBoundary `json:"audit_checkpoint,omitempty"`
	}{postgresStorageTenant(row), row.ErasureRow, row.Checkpoint})
	if err != nil {
		return eventprotect.Context{}, err
	}
	return eventprotect.Context{Scope: eventprotect.ScopePostgresRow, ID: artifact.ID + ":" + strconv.FormatUint(artifact.EventCutSequence, 10) + ":" + strconv.FormatUint(row.Ordinal, 10) + ":" + crypto.SHA256Hex(metadata), Type: row.Table, TenantID: row.TenantID, SchemaVersion: 2, Time: artifact.CreatedAt}, nil
}

func validateProtectedPostgresRecord(artifact protectedPostgresArtifact, row protectedPostgresRecord) (eventprotect.Context, error) {
	context, err := postgresRowContext(artifact, row)
	if err != nil {
		return eventprotect.Context{}, err
	}
	if err := validatePostgresPublicRecovery(row); err != nil {
		return eventprotect.Context{}, err
	}
	if row.Protection != nil {
		if len(row.Row) != 0 {
			return eventprotect.Context{}, errors.New("backup: protected postgres row also contains plaintext")
		}
		if err := eventprotect.ValidateEnvelope(context, postgresRowPolicyDigest(), *row.Protection); err != nil {
			return eventprotect.Context{}, err
		}
	} else if len(row.Row) == 0 || !json.Valid(row.Row) {
		return eventprotect.Context{}, errors.New("backup: postgres row has no valid representation")
	}
	return context, nil
}

// Invoke only AFTER authenticating the COMPLETE artifact header/rows/trailer.
// A structural envelope check alone must never reach this provider callback.
func openAuthenticatedPostgresRecord(ctx context.Context, artifact protectedPostgresArtifact, row protectedPostgresRecord, provider PostgresStateProtection) (json.RawMessage, bool, error) {
	context, err := validateProtectedPostgresRecord(artifact, row)
	if err != nil {
		return nil, false, err
	}
	if row.Protection == nil {
		if err := validateOpenedPostgresRow(row, row.Row); err != nil {
			return nil, false, err
		}
		return row.Row, false, nil
	}
	if provider == nil {
		return nil, false, errors.New("backup: protected postgres row requires current independent custody")
	}
	opened, erased, err := provider.OpenPostgresRow(ctx, context, *row.Protection)
	if err != nil {
		secret.Wipe(opened)
		return nil, false, err
	}
	if erased {
		if len(opened) != 0 {
			secret.Wipe(opened)
			return nil, false, errors.New("backup: erased postgres row returned readable data")
		}
		// A verified caller may retain only the authenticated closed denial tombstone.
		return bytes.Clone(row.ErasureRow), true, nil
	}
	if err := validateOpenedPostgresRow(row, opened); err != nil {
		secret.Wipe(opened)
		return nil, false, err
	}
	return opened, false, nil
}

func postgresStorageTenant(row protectedPostgresRecord) string {
	if row.StorageTenantID != "" {
		return row.StorageTenantID
	}
	return row.TenantID
}
func decodeClosedPostgresMetadata(raw []byte, target any) error {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return err
	}
	if err := decoder.Decode(new(any)); err != io.EOF {
		return errors.New("backup: recovery metadata has trailing input")
	}
	return nil
}
func validatePostgresPublicRecovery(row protectedPostgresRecord) error {
	storage, err := uuid.Parse(postgresStorageTenant(row))
	if err != nil || storage.String() != postgresStorageTenant(row) {
		return errors.New("backup: invalid postgres storage tenant")
	}
	if row.Table == "audit_checkpoints" {
		if row.Checkpoint == nil || row.Checkpoint.BoundarySeq == 0 || row.Checkpoint.RecordCount <= 0 {
			return errors.New("backup: missing public audit checkpoint boundary")
		}
		mapped, err := store.AuditCheckpointRLSID(row.Checkpoint.TenantID)
		if err != nil || mapped != storage.String() {
			return errors.New("backup: checkpoint source scope does not match storage tenant")
		}
	} else if row.Checkpoint != nil {
		return errors.New("backup: checkpoint metadata on another table")
	}
	if row.Table != "ca_signer_handle_claims" {
		if row.TenantID != storage.String() || len(row.ErasureRow) != 0 {
			return errors.New("backup: unexpected postgres owner or erasure replacement")
		}
		return nil
	}
	if storage.String() != "00000000-0000-0000-0000-000000000003" || len(row.ErasureRow) == 0 {
		return errors.New("backup: signer claim lost its denial tombstone")
	}
	var tombstone struct {
		TenantID        string    `json:"tenant_id"`
		HandleSHA256    string    `json:"handle_sha256"`
		State           string    `json:"state"`
		CreatedAt       time.Time `json:"created_at"`
		OwnerTenantID   *string   `json:"owner_tenant_id"`
		OwnerCeremonyID *string   `json:"owner_ceremony_id"`
	}
	if err := decodeClosedPostgresMetadata(row.ErasureRow, &tombstone); err != nil {
		return err
	}
	if tombstone.TenantID != storage.String() || tombstone.State != "retired" || tombstone.CreatedAt.IsZero() || tombstone.OwnerTenantID != nil || tombstone.OwnerCeremonyID != nil {
		return errors.New("backup: invalid signer denial tombstone")
	}
	if len(tombstone.HandleSHA256) != 64 {
		return errors.New("backup: invalid signer denial digest")
	}
	for _, b := range tombstone.HandleSHA256 {
		if (b < '0' || b > '9') && (b < 'a' || b > 'f') {
			return errors.New("backup: invalid signer denial digest")
		}
	}
	return nil
}
func validateOpenedPostgresRow(frame protectedPostgresRecord, raw json.RawMessage) error {
	var row map[string]json.RawMessage
	if err := json.Unmarshal(raw, &row); err != nil || row == nil {
		return errors.New("backup: opened postgres row is not an object")
	}
	var storage string
	if err := json.Unmarshal(row["tenant_id"], &storage); err != nil || storage != postgresStorageTenant(frame) {
		return errors.New("backup: opened postgres row changed its storage tenant")
	}
	owner := storage
	if frame.Table == "ca_signer_handle_claims" {
		if err := json.Unmarshal(row["owner_tenant_id"], &owner); err != nil || owner != frame.TenantID {
			return errors.New("backup: opened signer claim changed its private owner")
		}
		tombstone, err := postgresSignerDenialRow(row)
		if err != nil {
			return err
		}
		var got, want any
		if json.Unmarshal(frame.ErasureRow, &got) != nil || json.Unmarshal(tombstone, &want) != nil {
			return errors.New("backup: invalid signer denial metadata")
		}
		a, _ := json.Marshal(got)
		b, _ := json.Marshal(want)
		if !bytes.Equal(a, b) {
			return errors.New("backup: signer claim denial metadata differs from opened row")
		}
	}
	if owner != frame.TenantID {
		return errors.New("backup: opened postgres row changed its private owner")
	}
	if frame.Table == "audit_checkpoints" {
		boundaries, err := latestAuditCheckpointBoundaries([]json.RawMessage{raw})
		if err != nil || len(boundaries) != 1 || frame.Checkpoint == nil || boundaries[0] != *frame.Checkpoint {
			return errors.New("backup: opened audit boundary differs from authenticated metadata")
		}
	}
	return nil
}
func postgresSignerDenialRow(row map[string]json.RawMessage) (json.RawMessage, error) {
	tombstone := map[string]json.RawMessage{"state": json.RawMessage(`"retired"`), "owner_tenant_id": json.RawMessage(`null`), "owner_ceremony_id": json.RawMessage(`null`)}
	for _, name := range []string{"tenant_id", "handle_sha256", "created_at"} {
		value, ok := row[name]
		if !ok {
			return nil, errors.New("backup: incomplete signer denial identity")
		}
		tombstone[name] = value
	}
	return json.Marshal(tombstone)
}
