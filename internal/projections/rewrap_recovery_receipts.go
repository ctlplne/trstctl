// SPDX-License-Identifier: BUSL-1.1
package projections

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5"

	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/store"
)

func recoveryEventSHA256(event events.Event) (string, error) {
	canonical, err := json.Marshal(event)
	if err != nil {
		return "", err
	}
	return crypto.SHA256Hex(canonical), nil
}

func retainedApplicationSecretMutationForProof(event events.Event) (ApplicationSecretMutation, error) {
	switch event.Type {
	case EventApplicationSecretCreated, EventApplicationSecretRotated,
		EventApplicationSecretRecovered, EventApplicationSecretDeleted,
		EventApplicationSecretUndeleted:
	default:
		return ApplicationSecretMutation{}, fmt.Errorf("%w: recovery receipt names another event type", store.ErrIdempotencyConflict)
	}
	if err := ValidateSchemaVersion(event); err != nil {
		return ApplicationSecretMutation{}, err
	}
	var mutation ApplicationSecretMutation
	switch event.SchemaVersion {
	case ApplicationSecretMutationSchemaVersion:
		if err := json.Unmarshal(event.Data, &mutation); err != nil {
			return mutation, err
		}
	case ApplicationSecretPrivacyDispositionSchemaVersion:
		var localOnly ApplicationSecretPrivacySyncErased
		if err := json.Unmarshal(event.Data, &localOnly); err != nil ||
			!localOnly.PrivacySyncAuthorityErased || localOnly.Sync != nil ||
			localOnly.PrivacyDisposition != events.ApplicationSecretPrivacyDispositionSyncErased {
			return mutation, fmt.Errorf("%w: recovery receipt names an invalid privacy command", store.ErrIdempotencyConflict)
		}
		mutation = localOnly.ApplicationSecretMutation
	default:
		return mutation, fmt.Errorf("%w: recovery receipt names an unsupported secret schema", store.ErrIdempotencyConflict)
	}
	if mutation.TenantEpoch == "" || mutation.Name == "" {
		return mutation, fmt.Errorf("%w: recovery receipt event is incomplete", store.ErrIdempotencyConflict)
	}
	return mutation, nil
}

// preverifyRewrappedMutationReceipts authenticates every v1-mismatched receipt
// while the old read model still exists. One tenant and one bounded page are
// retained at a time; only non-secret hashes enter the owner transaction.
func (p *Projector) preverifyRewrappedMutationReceipts(
	ctx context.Context, tx pgx.Tx, log *events.Log, operationID string,
	verifier func(context.Context, string, ApplicationSecretMutation) error,
) error {
	if verifier == nil {
		return errors.New("projections: recovery receipt verifier is unavailable")
	}
	tenants, err := p.store.RecoverySnapshotTenantsTx(ctx, tx, operationID)
	if err != nil {
		return err
	}
	for _, tenantID := range tenants {
		after := ""
		for {
			if err := ctx.Err(); err != nil {
				return err
			}
			page, err := p.store.ListApplicationSecretReceiptProofPageTx(ctx, tx, tenantID, after)
			if err != nil {
				return err
			}
			for _, receipt := range page {
				event, found, err := log.EventByID(ctx, receipt.EventID)
				if err != nil {
					return err
				}
				if !found || event.ID != receipt.EventID || event.TenantID != tenantID {
					return fmt.Errorf("%w: recovery receipt has no exact tenant event", store.ErrIdempotencyConflict)
				}
				mutation, err := retainedApplicationSecretMutationForProof(event)
				if err != nil {
					return err
				}
				v1, err := ApplicationSecretMutationSemanticDigest(event, mutation)
				if err != nil {
					return err
				}
				if v1 != receipt.DigestV1 {
					v2, err := ApplicationSecretMutationSemanticDigestV2(event, mutation)
					if err != nil || receipt.DigestV2 == "" || v2 != receipt.DigestV2 {
						return fmt.Errorf("%w: recovery receipt identity differs from retained event", store.ErrIdempotencyConflict)
					}
					if err := verifier(ctx, tenantID, mutation); err != nil {
						return fmt.Errorf("projections: authenticate recovery receipt event: %w", err)
					}
					eventHash, err := recoveryEventSHA256(event)
					if err != nil {
						return err
					}
					keyHash, err := p.store.RecoveryKeyStateDigestTx(ctx, tx, tenantID, operationID)
					if err != nil {
						return err
					}
					if err := p.store.InsertRecoveryPairProofTx(ctx, tx, store.RecoveryPairProof{
						TenantID: tenantID, OperationID: operationID, EventID: event.ID,
						PairKind: "mutation_receipt", RowID: receipt.EventID,
						EventSHA256: eventHash, RowSHA256: receipt.RowSHA256,
						KeyStateSHA256: keyHash,
					}); err != nil {
						return err
					}
				}
				after = receipt.EventID
			}
			if len(page) < store.ApplicationSecretRewrapReceiptPageLimit {
				break
			}
		}
	}
	return nil
}
