// SPDX-License-Identifier: BUSL-1.1

package backup

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"maps"
	"sort"

	"github.com/google/uuid"

	"trstctl.com/trstctl/internal/crypto/secret"
)

type postgresPlainRowProtection interface {
	RestorePlainPostgresRow(context.Context, int, uint64, string, json.RawMessage) (json.RawMessage, bool, error)
}

// postgresRowOwnership follows the existing storage/offboarding ownership, not
// arbitrary names in a row. Fixed deployment authority is never assigned to a
// customer's key. A signer claim's private preparation belongs to its owner,
// while the fixed partition must retain the digest denial after that owner ends.
func postgresRowOwnership(table string, raw json.RawMessage) (string, string, json.RawMessage, *AuditCheckpointBoundary, error) {
	var row map[string]json.RawMessage
	if json.Unmarshal(raw, &row) != nil || row == nil {
		return "", "", nil, nil, errors.New("backup: postgres row is not an object")
	}
	if table == "federation_peer_checkpoints" || table == "deployment_kek_domain" {
		if _, exists := row["tenant_id"]; exists {
			return "", "", nil, nil, errors.New("backup: deployment authority gained an unclassified tenant owner")
		}
		return "", "", nil, nil, nil
	}
	var storage string
	if json.Unmarshal(row["tenant_id"], &storage) != nil {
		return "", "", nil, nil, errors.New("backup: postgres row has no storage tenant")
	}
	identity, err := uuid.Parse(storage)
	if err != nil || identity.String() != storage {
		return "", "", nil, nil, errors.New("backup: postgres row storage tenant is not canonical")
	}
	if identity == uuid.Nil {
		switch table {
		case "provider_operators", "provider_roles", "provider_operator_delegations", "provider_operator_grant_episodes",
			"provider_authority_projection_receipts", "provider_authority_projection_state", "provider_tenant_templates":
			return "", storage, nil, nil, nil
		default:
			return "", "", nil, nil, errors.New("backup: unclassified zero-tenant postgres row")
		}
	}
	if table == "oidc_logout_receipts" {
		if storage != "00000000-0000-0000-0000-000000000002" {
			return "", "", nil, nil, errors.New("backup: logout denial has a foreign authority partition")
		}
		// Shared immutable callback denial is deliberately retained on customer
		// offboarding; it has no customer-scoped owner to shred independently.
		return "", storage, nil, nil, nil
	}
	if table == "ca_signer_handle_claims" {
		if storage != "00000000-0000-0000-0000-000000000003" {
			return "", "", nil, nil, errors.New("backup: signer claim has a foreign storage partition")
		}
		var state, owner string
		if json.Unmarshal(row["state"], &state) != nil {
			return "", "", nil, nil, errors.New("backup: signer claim has no state")
		}
		if state == "retired" && bytes.Equal(bytes.TrimSpace(row["owner_tenant_id"]), []byte("null")) {
			return "", storage, nil, nil, nil
		}
		if state != "claimed" || json.Unmarshal(row["owner_tenant_id"], &owner) != nil {
			return "", "", nil, nil, errors.New("backup: signer claim has no private owner")
		}
		ownerID, err := uuid.Parse(owner)
		if err != nil || ownerID == uuid.Nil || ownerID.String() != owner {
			return "", "", nil, nil, errors.New("backup: signer claim private owner is not canonical")
		}
		denial, err := postgresSignerDenialRow(row)
		return owner, storage, denial, nil, err
	}
	if table == "audit_checkpoints" {
		boundaries, err := latestAuditCheckpointBoundaries([]json.RawMessage{raw})
		if err != nil || len(boundaries) != 1 {
			return "", "", nil, nil, errors.New("backup: invalid postgres audit boundary")
		}
		return storage, storage, nil, &boundaries[0], nil
	}
	return storage, storage, nil, nil, nil
}

func postgresFrameForRow(table string, ordinal uint64, raw json.RawMessage) (protectedPostgresRecord, error) {
	owner, storage, denial, checkpoint, err := postgresRowOwnership(table, raw)
	if err != nil {
		return protectedPostgresRecord{}, err
	}
	return protectedPostgresRecord{Table: table, Ordinal: ordinal, TenantID: owner,
		StorageTenantID: storage, ErasureRow: denial, Checkpoint: checkpoint, Row: raw}, nil
}

func encodePostgresStateRow(ctx context.Context, enc *json.Encoder, header postgresStateHeader, table string, ordinal uint64, raw json.RawMessage, provider PostgresStateProtection) error {
	if header.Version == postgresStateVersion {
		return enc.Encode(postgresStateRecord{Table: table, Row: raw})
	}
	defer secret.Wipe(raw)
	frame, err := postgresFrameForRow(table, ordinal, raw)
	if err != nil {
		return fmt.Errorf("backup: classify postgres table %s: %w", table, err)
	}
	if frame.TenantID != "" {
		artifact := protectedPostgresArtifact{ID: header.ArtifactID, CreatedAt: header.CreatedAt, EventCutSequence: header.EventCutSequence}
		binding, err := postgresRowContext(artifact, frame)
		if err != nil {
			return err
		}
		if provider == nil {
			return errors.New("backup: protected postgres writer has no source policy")
		}
		envelope, protected, err := provider.ProtectPostgresRow(ctx, binding, raw)
		if err != nil {
			return err
		}
		if protected {
			frame.Row, frame.Protection = nil, &envelope
		}
		if _, err := validateProtectedPostgresRecord(artifact, frame); err != nil {
			return err
		}
	}
	return enc.Encode(frame)
}

func validateFramedPostgresState(artifact protectedPostgresArtifact, rows map[string][]json.RawMessage) error {
	identity, err := uuid.Parse(artifact.ID)
	if err != nil || identity.Version() != 4 || identity.String() != artifact.ID || artifact.CreatedAt.IsZero() {
		return errors.New("backup: invalid protected postgres artifact identity")
	}
	for table, records := range rows {
		for _, raw := range records {
			var frame protectedPostgresRecord
			if err := decodeClosedPostgresMetadata(raw, &frame); err != nil {
				return err
			}
			if frame.Table != table || frame.Ordinal == 0 {
				return errors.New("backup: protected postgres frame has inconsistent table or ordinal")
			}
			if frame.TenantID != "" {
				if _, err := validateProtectedPostgresRecord(artifact, frame); err != nil {
					return err
				}
			}
			if frame.Protection == nil {
				expected, err := postgresFrameForRow(table, frame.Ordinal, frame.Row)
				if err != nil {
					return err
				}
				if !samePostgresFrameMetadata(frame, expected) {
					return errors.New("backup: plaintext postgres row disagrees with declared recovery metadata")
				}
			} else if frame.TenantID == "" {
				return errors.New("backup: protected postgres frame has no private owner")
			}
		}
	}
	return nil
}

func samePostgresFrameMetadata(a, b protectedPostgresRecord) bool {
	a.Row, b.Row, a.Protection, b.Protection = nil, nil, nil, nil
	// An omitted storage owner has the same canonical meaning as the logical
	// tenant. The AEAD binding commits to that resolved identity as well.
	a.StorageTenantID, b.StorageTenantID = postgresStorageTenant(a), postgresStorageTenant(b)
	x, xerr := json.Marshal(a)
	y, yerr := json.Marshal(b)
	return xerr == nil && yerr == nil && bytes.Equal(x, y)
}

func framedAuditCheckpointBoundaries(records []json.RawMessage) ([]AuditCheckpointBoundary, error) {
	latest := map[string]AuditCheckpointBoundary{}
	for _, raw := range records {
		var frame protectedPostgresRecord
		if err := decodeClosedPostgresMetadata(raw, &frame); err != nil || frame.Checkpoint == nil {
			return nil, errors.New("backup: protected audit row has no authenticated source boundary")
		}
		boundary := *frame.Checkpoint
		if prior, found := latest[boundary.TenantID]; !found || boundary.BoundarySeq > prior.BoundarySeq {
			latest[boundary.TenantID] = boundary
		}
	}
	var boundaries []AuditCheckpointBoundary
	for _, boundary := range latest {
		boundaries = append(boundaries, boundary)
	}
	sort.Slice(boundaries, func(i, j int) bool { return boundaries[i].TenantID < boundaries[j].TenantID })
	return boundaries, nil
}

// readPostgresStateForRestore completes the shared artifact verifier and every
// public structural check before the first custody callback. The caller starts
// SQL only after all rows have opened and their actual owners have been checked.
func readPostgresStateForRestore(ctx context.Context, r io.Reader, key []byte, id PostgresStateIdentity) (map[string][]json.RawMessage, PostgresStateSummary, error) {
	rows, summary, err := readVerifiedPostgresState(r, key, id)
	if err != nil {
		return nil, PostgresStateSummary{}, err
	}
	if summary.artifact == nil && id.Protection == nil && id.ProtectionFactory == nil {
		return rows, summary, nil
	}
	if len(key) == 0 && len(id.TrustAnchors) == 0 {
		return nil, PostgresStateSummary{}, errors.New("backup: protected postgres restore requires an integrity key or pinned manifest verification key")
	}
	if id.Protection != nil && id.ProtectionFactory != nil {
		return nil, summary, errors.New("backup: postgres restore has two custody providers")
	}
	if summary.artifact == nil {
		for table, records := range rows {
			for _, raw := range records {
				if _, err := postgresFrameForRow(table, 0, raw); err != nil {
					return nil, summary, err
				}
			}
		}
	}
	if id.ProtectionFactory != nil {
		factorySummary := summary
		factorySummary.Tables = maps.Clone(summary.Tables)
		factorySummary.AppliedTables = maps.Clone(summary.AppliedTables)
		factorySummary.AuditCheckpoints = append([]AuditCheckpointBoundary(nil), summary.AuditCheckpoints...)
		provider, closeProvider, err := id.ProtectionFactory(ctx, factorySummary)
		if closeProvider != nil {
			defer closeProvider()
		}
		if err != nil {
			return nil, summary, err
		}
		if provider == nil {
			return nil, summary, errors.New("backup: postgres custody factory returned no provider")
		}
		id.Protection = provider
	}
	openedRows := map[string][]json.RawMessage{}
	complete := false
	defer func() {
		if !complete {
			wipePostgresRows(openedRows)
		}
	}()
	summary.AppliedTables = map[string]int{}
	for table, records := range rows {
		for _, raw := range records {
			var frame protectedPostgresRecord
			if summary.artifact == nil {
				frame, err = postgresFrameForRow(table, 0, raw)
			} else {
				err = decodeClosedPostgresMetadata(raw, &frame)
			}
			if err != nil {
				return nil, summary, err
			}
			value, erased := frame.Row, false
			if frame.Protection != nil {
				value, erased, err = openAuthenticatedPostgresRecord(ctx, *summary.artifact, frame, id.Protection)
			} else if frame.TenantID != "" {
				policy, ok := id.Protection.(postgresPlainRowProtection)
				if !ok {
					return nil, summary, errors.New("backup: plaintext postgres row requires current source policy")
				}
				version := postgresStateVersion
				if summary.artifact != nil {
					version = protectedPostgresStateVersion
				}
				value, erased, err = policy.RestorePlainPostgresRow(ctx, version, summary.EventCutSequence, frame.TenantID, frame.Row)
				if erased && err == nil {
					value = bytes.Clone(frame.ErasureRow)
				}
			}
			if err != nil {
				return nil, summary, err
			}
			if erased {
				if len(value) == 0 {
					summary.OmittedRecords++
					continue
				}
				summary.RedactedRecords++
			}
			openedRows[table] = append(openedRows[table], value)
			summary.AppliedTables[table]++
			summary.AppliedRecords++
		}
	}
	complete = true
	return openedRows, summary, nil
}

func wipePostgresRows(rows map[string][]json.RawMessage) {
	for _, records := range rows {
		for _, raw := range records {
			secret.Wipe(raw)
		}
	}
}
