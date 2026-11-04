// SPDX-License-Identifier: BUSL-1.1

package orchestrator

import (
	"context"
	"encoding/json"
	"strings"

	"trstctl.com/trstctl/internal/crypto/secret"
	"trstctl.com/trstctl/internal/projections"
	"trstctl.com/trstctl/internal/store"
)

// Agent access bundles (A251). A run's credential is an API token whose subject
// carries BundleRunSubjectPrefix: the API honors such a token only through its
// run's live grants, so a token whose run was never recorded, or whose grants
// were removed, does nothing.

// BundleRunSubjectPrefix marks a run's API token; the rest is the principal.
const BundleRunSubjectPrefix = "bundle-run:"

// BundleRunPrincipal is the principal a run token acts as, and whether the
// subject is a run's at all.
func BundleRunPrincipal(subject string) (string, bool) {
	principal, ok := strings.CutPrefix(subject, BundleRunSubjectPrefix)
	return principal, ok && principal != ""
}

func (o *Orchestrator) emitAccessBundleEvent(ctx context.Context, tenantID, eventType string, payload any) error {
	data, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	_, err = o.emit(ctx, eventType, tenantID, data)
	return err
}

// SaveAccessBundle records a bundle at its next revision.
func (o *Orchestrator) SaveAccessBundle(ctx context.Context, tenantID string, saved projections.AccessBundleSaved) error {
	return o.emitAccessBundleEvent(ctx, tenantID, projections.EventAccessBundleSaved, saved)
}

// DeleteAccessBundle deletes a bundle; its grants and runs give nothing from
// the next request on.
func (o *Orchestrator) DeleteAccessBundle(ctx context.Context, tenantID string, deleted projections.AccessBundleDeleted) error {
	return o.emitAccessBundleEvent(ctx, tenantID, projections.EventAccessBundleDeleted, deleted)
}

// GrantAccessBundle gives a bundle to a user or a machine.
func (o *Orchestrator) GrantAccessBundle(ctx context.Context, tenantID string, granted projections.AccessBundleGranted) error {
	return o.emitAccessBundleEvent(ctx, tenantID, projections.EventAccessBundleGranted, granted)
}

// UngrantAccessBundle removes one grant.
func (o *Orchestrator) UngrantAccessBundle(ctx context.Context, tenantID string, ungranted projections.AccessBundleUngranted) error {
	return o.emitAccessBundleEvent(ctx, tenantID, projections.EventAccessBundleUngranted, ungranted)
}

// IssueAccessBundleRun mints a run's credential under run.GrantIDs and records
// the run (run.ID is ignored: the run takes its token's ID). The token is
// returned once; its creation event holds only its hash.
func (o *Orchestrator) IssueAccessBundleRun(ctx context.Context, tenantID string, run projections.AccessBundleRunIssued) (store.APITokenRecord, []byte, error) {
	expiresAt := run.ExpiresAt
	rec, raw, err := o.CreateAPIToken(ctx, tenantID, BundleRunSubjectPrefix+run.Principal, run.Permissions, &expiresAt)
	if err != nil {
		return store.APITokenRecord{}, nil, err
	}
	run.ID = rec.ID
	if err := o.emitAccessBundleEvent(ctx, tenantID, projections.EventAccessBundleRunIssued, run); err != nil {
		// Without its run the token is honored nowhere; retire it anyway.
		secret.Wipe(raw)
		_ = o.RevokeAPIToken(context.WithoutCancel(ctx), tenantID, rec.ID, "access bundle run was not recorded")
		return store.APITokenRecord{}, nil, err
	}
	return rec, raw, nil
}

// RevokeAccessBundleRun retires a run's token and records the revocation.
func (o *Orchestrator) RevokeAccessBundleRun(ctx context.Context, tenantID, runID, revokedBy string) error {
	if err := o.RevokeAPIToken(ctx, tenantID, runID, "access bundle run revoked"); err != nil {
		return err
	}
	return o.emitAccessBundleEvent(ctx, tenantID, projections.EventAccessBundleRunRevoked,
		projections.AccessBundleRunRevoked{ID: runID, RevokedBy: revokedBy})
}
