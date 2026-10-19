// SPDX-License-Identifier: BUSL-1.1

package reprotect

import (
	"context"
	"encoding/json"

	"trstctl.com/trstctl/internal/decommission/depstate"
	"trstctl.com/trstctl/internal/events"
	corestore "trstctl.com/trstctl/internal/store"
)

// RecordVerifiedHostCompletion accounts for the old CA dependency only after
// the signed served-leaf cutover has changed the tenant's certificate and
// identity read models. Both records use durable first-writer event IDs, so a
// crash between them leaves the same job safe to retry.
func RecordVerifiedHostCompletion(ctx context.Context, st *corestore.Store, log *events.Log,
	tenantID string, cut corestore.CertificateReprotectionCutover) error {
	if st == nil || log == nil || tenantID == "" || cut.JobID == "" {
		return ErrExecutorUnavailable
	}
	plan, found, err := NewCredentialPlanLedger(log, st).Load(ctx, tenantID, cut.JobID)
	if err != nil {
		return err
	}
	if !found || plan.Job.TenantID != tenantID || plan.Job.Dependent.ID != cut.OldCertificateID ||
		plan.Job.KeyID != cut.OldAuthorityID || plan.IdentityID != cut.IdentityID ||
		plan.TargetID != cut.TargetID || plan.SuccessorAuthorityID != cut.NewAuthorityID ||
		plan.PredecessorFingerprint != cut.OldFingerprint {
		return ErrCompletionConflict
	}
	old, err := st.GetCertificate(ctx, tenantID, cut.OldCertificateID)
	if err != nil {
		return err
	}
	newCert, err := st.GetCertificate(ctx, tenantID, cut.NewCertificateID)
	if err != nil {
		return err
	}
	identity, err := st.GetIdentity(ctx, tenantID, cut.IdentityID)
	if err != nil {
		return err
	}
	var attributes struct {
		IssuingAuthorityID string `json:"issuing_authority_id"`
	}
	if json.Unmarshal(identity.Attributes, &attributes) != nil || old.Status != "superseded" ||
		old.Fingerprint != cut.OldFingerprint || newCert.Status != "active" ||
		newCert.Fingerprint != cut.NewFingerprint || newCert.ReplacesID == nil ||
		*newCert.ReplacesID != cut.OldCertificateID || attributes.IssuingAuthorityID != cut.NewAuthorityID {
		return ErrCompletionConflict
	}
	link := CredentialSupersession{TenantID: tenantID, JobID: cut.JobID,
		IdempotencyKey: plan.Job.IdempotencyKey, OldCredentialID: cut.OldCertificateID,
		NewCredentialID: cut.NewCertificateID, SuccessorKeyID: cut.NewAuthorityID}
	if err := (eventCredentialSupersessionRecorder{log: log, store: st}).RecordCredentialSupersession(ctx, link); err != nil {
		return err
	}
	_, err = NewCompletionRecorder(eventSink{log: log, store: st}).RecordCompletionEvidence(ctx,
		plan.Job, CompletionEvidence{SuccessorKeyID: cut.NewAuthorityID,
			CredentialSupersession: &depstate.CredentialSupersessionV1{
				OldCredentialID: cut.OldCertificateID, NewCredentialID: cut.NewCertificateID,
			}},
	)
	return err
}
