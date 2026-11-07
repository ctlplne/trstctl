// SPDX-License-Identifier: BUSL-1.1
package projections

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"github.com/jackc/pgx/v5"
	"reflect"
	"time"
	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/privacy"
	"trstctl.com/trstctl/internal/servicedependents"
	"trstctl.com/trstctl/internal/store"
)

// ServiceReconcileSemanticDigest freezes every effect and command coordinate.
// Human spelling/text is checked separately against the exact permitted privacy
// transform; it cannot change the native intent or claim another approval.
func ServiceReconcileSemanticDigest(e events.Event, v ServiceDependentRotationQueued) (string, error) {
	if err := ValidateServiceDependentRotationSource(e, v); err != nil {
		return "", err
	}
	if v.Approval == nil || (schemaVersionOf(e) != ServiceDependentReconcileSchemaVersion && schemaVersionOf(e) != ServiceDependentManifestSchemaVersion) || e.Time.IsZero() || !e.Time.Equal(e.Time.UTC().Truncate(time.Microsecond)) {
		return "", errors.New("dependent reconcile: incomplete PostgreSQL-exact first command")
	}
	digest, err := v.Intent.Digest()
	if err != nil {
		return "", err
	}
	raw, err := json.Marshal(struct {
		ID             string                     `json:"id"`
		TenantID       string                     `json:"tenant_id"`
		Type           string                     `json:"type"`
		Version        int                        `json:"version"`
		Time           time.Time                  `json:"time"`
		At             time.Time                  `json:"at"`
		IntentDigest   string                     `json:"intent_digest"`
		Child          SecretStaticRotationQueued `json:"child"`
		ApprovalID     string                     `json:"approval_id"`
		ApprovalDigest string                     `json:"approval_digest"`
	}{e.ID, e.TenantID, e.Type, schemaVersionOf(e), e.Time.UTC(), v.At, digest, v.Child, v.Approval.RequestID, v.Approval.IntentDigest})
	if err != nil {
		return "", err
	}
	return crypto.SHA256Hex(append([]byte("trstctl.service-dependent.reconcile-first-command.v1\x00"), raw...)), nil
}
func (p *Projector) resolveServiceReconcileFenceUseTx(ctx context.Context, tx pgx.Tx, e events.Event, v *ServiceDependentRotationQueued) (string, error) {
	semantic, err := ServiceReconcileSemanticDigest(e, *v)
	if err != nil {
		return "", err
	}
	fence, use, rewritten, err := p.store.LockApprovedTargetFenceTx(ctx, tx, e.TenantID, store.ApprovedTargetServiceReconciliation, servicedependents.ReconcileCommandKey(e.TenantID, v.Intent.Plan.SecretName))
	if errors.Is(err, pgx.ErrNoRows) {
		return semantic, nil
	}
	if err != nil {
		return "", err
	}
	if semantic != fence.SemanticDigest || fence.EventID != e.ID || fence.EventType != e.Type || fence.SchemaVersion != schemaVersionOf(e) || !fence.EventTime.Equal(e.Time) {
		return "", store.ErrIdempotencyConflict
	}
	if !rewritten {
		if !bytes.Equal(e.Data, fence.Payload) || !reflect.DeepEqual(e.Actor, fence.Actor) {
			return "", store.ErrIdempotencyConflict
		}
		return semantic, nil
	}
	var original ServiceDependentRotationQueued
	if json.Unmarshal(fence.Payload, &original) != nil || original.Approval == nil || v.Approval == nil {
		return "", store.ErrApprovalDrifted
	}
	if err := store.ValidateApprovedTargetActorPrivacyRewrite(e.TenantID, fence.Actor, use.Requester, e.Actor, original.Approval.Requester); err != nil {
		return "", err
	}
	if err := store.ValidateApprovedTargetPrivacyRewrite(e.TenantID, *original.Approval, use, *v.Approval); err != nil {
		return "", err
	}
	if v.Actor != original.Actor && (!privacy.IsPlaceholder(use.Requester) || original.Actor != original.Approval.Requester || v.Actor != use.Requester) {
		return "", store.ErrIdempotencyConflict
	}
	v.Approval = &use
	return semantic, nil
}
