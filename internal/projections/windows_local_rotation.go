// SPDX-License-Identifier: BUSL-1.1
package projections

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"github.com/jackc/pgx/v5"
	"slices"
	"time"
	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/store"
)

const EventWindowsLocalRotationObserved = "pam.windows_local_accounts.rotation_observed"

type WindowsLocalRotationObserved = store.WindowsLocalRotationObservation

func (p *Projector) applyWindowsLocalRotationTx(ctx context.Context, tx pgx.Tx, e events.Event) (bool, error) {
	if e.Type != EventWindowsLocalRotationObserved {
		return false, nil
	}
	var v WindowsLocalRotationObserved
	if err := decode(e, &v); err != nil {
		return true, err
	}
	if err := validateServiceDependentReceipt(v.JobID, v.Attempt, v.ReceiptStatement, v.ReceiptSignature, v.SignerFingerprint, v.At); err != nil {
		return true, err
	}
	raw, err := json.Marshal(v.Report)
	if err != nil || crypto.SHA256Hex(raw) != v.EvidenceDigest {
		return true, errors.New("native local rotation evidence digest differs")
	}
	return true, p.store.ApplyWindowsLocalRotationObservedTx(ctx, tx, e.TenantID, e.ID, v)
}
func addWindowsLocalRotationPrivacyPolicies(p map[privacyEventPolicyKey]events.PrivacyEventPolicy) {
	exact := events.PrivacyFieldOpaqueExact
	p[privacyEventPolicyKey{EventWindowsLocalRotationObserved, 1}] = privacyRules(privacyRule("/job_id", exact), privacyRule("/attempt", exact), privacyRule("/report", exact), privacyRule("/evidence_digest", exact), privacyRule("/receipt_statement", exact), privacyRule("/receipt_signature_base64", exact), privacyRule("/signer_fingerprint", exact), privacyRule("/at", exact))
}
func addWindowsLocalRotationPrivacyShapes(p map[privacyEventPolicyKey]events.PrivacyPayloadShape) {
	p[privacyEventPolicyKey{EventWindowsLocalRotationObserved, 1}] = privacyPayloadShape[WindowsLocalRotationObserved]()
}

// CanonicalWindowsLocalRotation reopens retained source for every native claim,
// credential release and publication proof. Cache rows never grant authority.
func CanonicalWindowsLocalRotation(ctx context.Context, s *store.Store, log *events.Log, tenantID, id string) (store.WindowsLocalRotation, store.SecretStaticRotationCommand, error) {
	var cmd store.SecretStaticRotationCommand
	v, err := s.GetWindowsLocalRotation(ctx, tenantID, id)
	if err != nil {
		return v, cmd, err
	}
	fail := errors.New("native local rotation differs from retained source")
	if log == nil {
		return v, cmd, fail
	}
	cmd, err = s.GetSecretStaticRotationCommand(ctx, tenantID, id)
	if err != nil {
		return v, cmd, err
	}
	epoch, err := s.ApplicationSecretTenantEpoch(ctx, tenantID)
	if err != nil {
		return v, cmd, err
	}
	if epoch != cmd.TenantEpoch {
		return v, cmd, fail
	}
	queued, found, err := log.EventByID(ctx, id)
	if err != nil {
		return v, cmd, err
	}
	var q SecretStaticRotationQueued
	if !found || queued.TenantID != tenantID || queued.Type != EventSecretStaticRotationQueued || queued.SchemaVersion != 1 || json.Unmarshal(queued.Data, &q) != nil || q.ID != id || q.TenantEpoch != cmd.TenantEpoch || q.Provider != cmd.Provider || q.Key != cmd.Key || q.OldRef != cmd.OldRef || q.ExpectedVersion != cmd.ExpectedVersion || q.ProviderBinding != cmd.ProviderBinding || q.RequestBinding != cmd.RequestBinding || !q.SinglePhaseAcknowledged || q.DependentChangeID != "" || q.CloudChangeID != "" || q.TTLSeconds != 0 || cmd.TTLSeconds != 0 || q.ScheduleID != cmd.ScheduleID || q.IdempotencyKeyDigest != cmd.IdempotencyKeyDigest || !slices.Equal(q.Consumers, cmd.Consumers) || q.RetireAfterSeconds != cmd.RetireAfterSeconds || q.RetireApprovedBy != cmd.RetireApprovedBy || !cmd.SinglePhaseAcknowledged {
		return v, cmd, fail
	}
	prepared, found, err := log.EventByID(ctx, v.PreparedEventID)
	if err != nil {
		return v, cmd, err
	}
	var p SecretStaticRotationAdvanced
	if !found || prepared.TenantID != tenantID || prepared.Type != EventSecretStaticRotationAdvanced || prepared.SchemaVersion != 2 || prepared.Sequence <= queued.Sequence || json.Unmarshal(prepared.Data, &p) != nil || p.ID != id || p.TenantEpoch != cmd.TenantEpoch || p.FromPhase != store.SecretStaticRotationQueued || p.Phase != store.SecretStaticRotationPrepared || p.WindowsLocalIntent == nil || *p.WindowsLocalIntent != v.Intent || v.Intent.TenantID != tenantID || v.Intent.RotationID != id || !prepared.Time.Equal(v.PreparedAt) || !bytes.Equal(p.SealedPreparation, cmd.SealedPreparation) || !bytes.Equal(p.SealedOld, cmd.SealedOld) {
		return v, cmd, fail
	}
	if v.ObservedEventID == "" {
		if v.Observation != nil {
			return v, cmd, fail
		}
		return v, cmd, nil
	}
	observed, found, err := log.EventByID(ctx, v.ObservedEventID)
	if err != nil {
		return v, cmd, err
	}
	var o WindowsLocalRotationObserved
	if !found || observed.TenantID != tenantID || observed.Type != EventWindowsLocalRotationObserved || observed.SchemaVersion != 1 || observed.Sequence <= prepared.Sequence || json.Unmarshal(observed.Data, &o) != nil || o.Report.Validate(v.Intent) != nil || v.Observation == nil {
		return v, cmd, fail
	}
	a, _ := json.Marshal(o)
	b, _ := json.Marshal(v.Observation)
	raw, _ := json.Marshal(o.Report)
	if !bytes.Equal(a, b) || crypto.SHA256Hex(raw) != o.EvidenceDigest || validateServiceDependentReceipt(o.JobID, o.Attempt, o.ReceiptStatement, o.ReceiptSignature, o.SignerFingerprint, o.At) != nil {
		return v, cmd, fail
	}
	return v, cmd, nil
}

// Native proof timestamps are historical when a host replays a completed journal
// generation. The signed receipt time, not the old native observation, is current.
func ValidWindowsLocalRotationObservationTime(native, prepared, received time.Time) bool {
	return !native.Before(prepared.Add(-5*time.Minute)) && !native.After(received.Add(5*time.Minute))
}
