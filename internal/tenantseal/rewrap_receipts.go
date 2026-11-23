// SPDX-License-Identifier: BUSL-1.1
package tenantseal

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"

	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/projections"
	"trstctl.com/trstctl/internal/store"
)

// backfillMutationReceipts authenticates every retained mutation container
// against the current permitted tenant key before a wrapper change. A legacy
// v1-only receipt must still match its exact source event; an already-v2 row
// matches v2 and leaves its historical v1 bytes untouched.
func backfillMutationReceipts(ctx context.Context, st *store.Store, log *events.Log, access Access, tenantID string) error {
	if st == nil || log == nil || access == nil || tenantID == "" {
		return errors.New("tenantseal: application-secret receipt backfill is not configured")
	}
	after := ""
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		page, err := st.ListApplicationSecretRewrapReceiptsPage(ctx, tenantID, after)
		if err != nil {
			return fmt.Errorf("tenantseal: page application-secret receipts: %w", err)
		}
		for _, receipt := range page {
			event, found, err := log.EventByID(ctx, receipt.EventID)
			if err != nil {
				return err
			}
			if !found || event.ID != receipt.EventID || event.TenantID != tenantID {
				return fmt.Errorf("%w: retained application-secret receipt has no exact tenant event", store.ErrIdempotencyConflict)
			}
			mutation, err := retainedApplicationSecretMutation(event)
			if err != nil {
				return err
			}
			v1, err := projections.ApplicationSecretMutationSemanticDigest(event, mutation)
			if err != nil {
				return err
			}
			v2, err := projections.ApplicationSecretMutationSemanticDigestV2(event, mutation)
			if err != nil {
				return err
			}
			if receipt.DigestV2 == "" {
				if v1 != receipt.DigestV1 {
					return fmt.Errorf("%w: v1-only application-secret receipt differs from retained event", store.ErrIdempotencyConflict)
				}
			} else if v2 != receipt.DigestV2 {
				return fmt.Errorf("%w: v2 application-secret receipt differs from retained event", store.ErrIdempotencyConflict)
			}
			if err := AuthenticateApplicationSecretMutationContainers(ctx, access, tenantID, mutation); err != nil {
				return fmt.Errorf("tenantseal: authenticate application-secret receipt event: %w", err)
			}
			if receipt.DigestV2 == "" {
				if err := st.BackfillApplicationSecretReceiptV2(ctx, tenantID, receipt.EventID, receipt.DigestV1, v2); err != nil {
					return err
				}
			}
			after = receipt.EventID
		}
		if len(page) < store.ApplicationSecretRewrapReceiptPageLimit {
			return nil
		}
	}
}

func retainedApplicationSecretMutation(event events.Event) (projections.ApplicationSecretMutation, error) {
	switch event.Type {
	case projections.EventApplicationSecretCreated,
		projections.EventApplicationSecretRotated,
		projections.EventApplicationSecretRecovered,
		projections.EventApplicationSecretDeleted,
		projections.EventApplicationSecretUndeleted:
	default:
		return projections.ApplicationSecretMutation{}, fmt.Errorf("%w: receipt event type is not an application-secret mutation", store.ErrIdempotencyConflict)
	}
	var mutation projections.ApplicationSecretMutation
	switch event.SchemaVersion {
	case projections.ApplicationSecretMutationSchemaVersion:
		if err := json.Unmarshal(event.Data, &mutation); err != nil {
			return mutation, err
		}
	case projections.ApplicationSecretPrivacyDispositionSchemaVersion:
		var erased projections.ApplicationSecretPrivacySyncErased
		if err := json.Unmarshal(event.Data, &erased); err != nil || !erased.PrivacySyncAuthorityErased || erased.Sync != nil {
			return mutation, fmt.Errorf("%w: privacy-disposition mutation is not a local-only command", store.ErrIdempotencyConflict)
		}
		mutation = erased.ApplicationSecretMutation
	default:
		return mutation, fmt.Errorf("%w: application-secret receipt event schema is unsupported", store.ErrIdempotencyConflict)
	}
	if mutation.Name == "" || mutation.TenantEpoch == "" {
		return mutation, fmt.Errorf("%w: application-secret receipt event is incomplete", store.ErrIdempotencyConflict)
	}
	return mutation, nil
}

// AuthenticateApplicationSecretMutationContainers opens every sealed field in
// one tenant lease. It accepts neither a digest nor an event ID as proof that
// the current ciphertext still authenticates under the exact field AAD.
func AuthenticateApplicationSecretMutationContainers(ctx context.Context, access Access, tenantID string, mutation projections.ApplicationSecretMutation) error {
	return access.WithTenant(ctx, tenantID, func(cipher Cipher) error {
		verifier, ok := cipher.(interface {
			VerifyRewrapPair(before, after, aad []byte) (bool, error)
		})
		if !ok {
			return ErrRewrapVerificationUnavailable
		}
		authenticate := func(container, aad []byte) error {
			same, err := verifier.VerifyRewrapPair(container, container, aad)
			if err != nil {
				return err
			}
			if !same {
				return store.ErrIdempotencyConflict
			}
			return nil
		}
		if len(mutation.Sealed) != 0 {
			if err := authenticate(mutation.Sealed, []byte(tenantID+"/secret-store/"+mutation.Name)); err != nil {
				return err
			}
		}
		if mutation.Sync != nil {
			sync := mutation.Sync
			if sync.ID == "" || sync.Target == "" || sync.RemoteKey == "" || len(sync.Sealed) == 0 {
				return store.ErrIdempotencyConflict
			}
			return authenticate(sync.Sealed, []byte(tenantID+"/secret-sync/"+sync.Target+"/"+sync.ID+"/"+sync.RemoteKey))
		}
		return nil
	})
}
