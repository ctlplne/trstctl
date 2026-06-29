package orchestrator

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"trstctl.com/trstctl/internal/approval"
	"trstctl.com/trstctl/internal/auth"
	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/privacy"
	"trstctl.com/trstctl/internal/projections"
	"trstctl.com/trstctl/internal/store"
)

// This file holds the served domain commands (AN-2). Each records the mutation
// as an event (the source of truth), then projects it into the read model
// through the projector — the sole read-model writer. The served API delegates
// to these instead of writing the read tables directly, so a rebuild from the
// log reproduces every change and the audit trail is complete.

const (
	eventProfileEditApprovalRequested = "profile.edit_approval.requested"
	eventProfileEditApprovalApproved  = "profile.edit_approval.approved"
	eventProfileEditApprovalRefused   = "profile.edit_approval.refused"
	EventAuthzDecision                = "authz.decision"
	DestinationConnectorRightSize     = "connector.right_size"
)

type approvalProfileEditRequest struct {
	Request approval.Request `json:"request"`
	Name    string           `json:"name"`
	Spec    json.RawMessage  `json:"spec"`
}

// AuthzDecision records the governed authorization decision for a sensitive
// served mutation that has request-body-specific authorization inputs.
type AuthzDecision struct {
	Actor      string   `json:"actor"`
	Permission string   `json:"permission"`
	Resource   string   `json:"resource"`
	Target     string   `json:"target"`
	Decision   string   `json:"decision"`
	Reason     string   `json:"reason,omitempty"`
	Roles      []string `json:"roles,omitempty"`
}

// ProfileApprovalRequirement is the profile-bound approval gate for an identity
// issuance transition.
type ProfileApprovalRequirement struct {
	ProfileName      string
	RequiresApproval bool
}

// ProfileEditPendingError reports that a profile create/edit is parked in the
// dual-control approval queue instead of being projected.
type ProfileEditPendingError struct {
	Request approval.Request
}

func (e *ProfileEditPendingError) Error() string {
	return fmt.Sprintf("orchestrator: profile edit %s requires approval request %s", e.Request.Resource, e.Request.ID)
}

// emit appends a domain event to the log and projects it into the read model,
// returning the stored event (with its assigned ID, time, and sequence). The
// append is the source of truth; the projection is the same logic a rebuild
// uses, so live state and a replayed state agree.
func (o *Orchestrator) emit(ctx context.Context, eventType, tenantID string, payload []byte) (events.Event, error) {
	return o.emitVersioned(ctx, eventType, tenantID, 0, payload)
}

func (o *Orchestrator) emitVersioned(ctx context.Context, eventType, tenantID string, schemaVersion int, payload []byte) (events.Event, error) {
	ev, err := o.log.Append(ctx, events.Event{
		Type: eventType, TenantID: tenantID, SchemaVersion: schemaVersion, Data: payload,
	})
	if err != nil {
		return events.Event{}, err
	}
	if err := o.proj.Apply(ctx, ev); err != nil {
		return events.Event{}, err
	}
	return ev, nil
}

// RecordAuthzDecision appends an immutable authorization decision event. It does
// not project into a read model; the event log is the audit evidence.
func (o *Orchestrator) RecordAuthzDecision(ctx context.Context, tenantID string, decision AuthzDecision) error {
	payload, err := json.Marshal(decision)
	if err != nil {
		return err
	}
	_, err = o.emit(ctx, EventAuthzDecision, tenantID, payload)
	return err
}

// CreateProfile records a new certificate-profile version as a full-spec
// profile.created/profile.updated event, then projects that event into the active
// certificate_profiles read model. The event is the source of truth (AN-2): a rebuild
// from the log restores every version and active-state transition.
func (o *Orchestrator) CreateProfile(ctx context.Context, tenantID, name string, spec json.RawMessage) (store.ProfileRecord, error) {
	gated, err := o.profileEditRequiresApproval(ctx, tenantID, name, spec)
	if err != nil {
		return store.ProfileRecord{}, err
	}
	if gated {
		req, err := o.requestProfileEditApproval(ctx, tenantID, name, spec)
		if err != nil {
			return store.ProfileRecord{}, err
		}
		return store.ProfileRecord{}, &ProfileEditPendingError{Request: req}
	}
	return o.createProfileVersion(ctx, tenantID, name, spec)
}

func (o *Orchestrator) createProfileVersion(ctx context.Context, tenantID, name string, spec json.RawMessage) (store.ProfileRecord, error) {
	actor := ""
	if a, ok := events.ActorFromContext(ctx); ok {
		actor = a.Subject
	}
	var rec store.ProfileRecord
	err := o.store.WithProjectionLock(ctx, func(ctx context.Context) error {
		version, err := o.store.NextProfileVersion(ctx, tenantID, name)
		if err != nil {
			return err
		}
		rec = store.ProfileRecord{
			ID: uuid.NewString(), TenantID: tenantID, Name: name, Version: version,
			Spec: append(json.RawMessage(nil), spec...), Active: true, CreatedBy: actor,
		}
		evType := projections.EventProfileCreated
		if rec.Version > 1 {
			evType = projections.EventProfileUpdated
		}
		payload, err := json.Marshal(projections.ProfileVersioned{
			ID: rec.ID, Name: rec.Name, Version: rec.Version, Spec: rec.Spec,
			Active: rec.Active, CreatedBy: rec.CreatedBy,
		})
		if err != nil {
			return err
		}
		ev, err := o.emitVersioned(ctx, evType, tenantID, projections.ProfileEventSchemaVersion, payload)
		if err != nil {
			return err
		}
		rec.CreatedAt = ev.Time
		return nil
	})
	if err != nil {
		return store.ProfileRecord{}, err
	}
	return rec, nil
}

// ProfileApprovalRequirement resolves the active certificate profile bound to an
// identity and reports whether it requires dual-control issuance approval.
func (o *Orchestrator) ProfileApprovalRequirement(ctx context.Context, tenantID, identityID string) (ProfileApprovalRequirement, error) {
	identity, err := o.store.GetIdentity(ctx, tenantID, identityID)
	if err != nil {
		return ProfileApprovalRequirement{}, err
	}
	profileName, err := profileNameFromIdentityAttributes(identity.Attributes)
	if err != nil {
		return ProfileApprovalRequirement{}, err
	}
	if profileName == "" {
		return ProfileApprovalRequirement{}, nil
	}
	rec, err := o.store.GetActiveProfile(ctx, tenantID, profileName)
	if err != nil {
		return ProfileApprovalRequirement{}, err
	}
	requires, err := profileSpecRequiresApproval(rec.Spec)
	if err != nil {
		return ProfileApprovalRequirement{}, err
	}
	return ProfileApprovalRequirement{ProfileName: profileName, RequiresApproval: requires}, nil
}

func profileNameFromIdentityAttributes(attrs json.RawMessage) (string, error) {
	if len(attrs) == 0 {
		return "", nil
	}
	var probe struct {
		ProfileName string `json:"profile_name"`
		Profile     string `json:"profile"`
	}
	if err := json.Unmarshal(attrs, &probe); err != nil {
		return "", fmt.Errorf("orchestrator: decode identity profile binding: %w", err)
	}
	if name := strings.TrimSpace(probe.ProfileName); name != "" {
		return name, nil
	}
	return strings.TrimSpace(probe.Profile), nil
}

func (o *Orchestrator) profileEditRequiresApproval(ctx context.Context, tenantID, name string, spec json.RawMessage) (bool, error) {
	proposed, err := profileSpecRequiresApproval(spec)
	if err != nil {
		return false, err
	}
	active, err := o.store.GetActiveProfile(ctx, tenantID, name)
	if err != nil {
		if store.IsNotFound(err) {
			return proposed, nil
		}
		return false, err
	}
	current, err := profileSpecRequiresApproval(active.Spec)
	if err != nil {
		return false, err
	}
	return current || proposed, nil
}

func profileSpecRequiresApproval(spec json.RawMessage) (bool, error) {
	var probe struct {
		RequiresApproval bool `json:"requires_approval"`
	}
	if err := json.Unmarshal(spec, &probe); err != nil {
		return false, fmt.Errorf("orchestrator: decode profile approval policy: %w", err)
	}
	return probe.RequiresApproval, nil
}

func (o *Orchestrator) requestProfileEditApproval(ctx context.Context, tenantID, name string, spec json.RawMessage) (approval.Request, error) {
	actor, ok := events.ActorFromContext(ctx)
	if !ok || actor.Subject == "" {
		return approval.Request{}, fmt.Errorf("orchestrator: profile edit approval requires an authenticated requester")
	}
	now := time.Now().UTC()
	req := approval.Request{
		ID: uuid.NewString(), TenantID: tenantID, Kind: approval.KindProfileEdit,
		Resource: "profile:" + name, Requester: actor.Subject, RequiredApprovals: 1,
		State: approval.StateAwaitingApproval, Payload: append(json.RawMessage(nil), spec...),
		CreatedAt: now, ExpiresAt: now.Add(24 * time.Hour),
	}
	entry := approvalProfileEditRequest{
		Request: req,
		Name:    name,
		Spec:    append(json.RawMessage(nil), spec...),
	}
	payload, err := json.Marshal(entry)
	if err != nil {
		return approval.Request{}, err
	}
	if _, err := o.emit(ctx, eventProfileEditApprovalRequested, tenantID, payload); err != nil {
		return approval.Request{}, err
	}
	o.profileEditMu.Lock()
	o.profileEditApprovals[profileEditApprovalKey(tenantID, req.ID)] = entry
	o.profileEditMu.Unlock()
	return req, nil
}

// ApproveProfileEdit records a non-requester approval and applies the queued
// profile spec when quorum is reached.
func (o *Orchestrator) ApproveProfileEdit(ctx context.Context, tenantID, requestID, approver string) (approval.Request, error) {
	if approver == "" {
		if actor, ok := events.ActorFromContext(ctx); ok {
			approver = actor.Subject
		}
	}
	if approver == "" {
		return approval.Request{}, fmt.Errorf("orchestrator: profile edit approval requires an authenticated approver")
	}
	key := profileEditApprovalKey(tenantID, requestID)

	o.profileEditMu.Lock()
	entry, ok := o.profileEditApprovals[key]
	o.profileEditMu.Unlock()
	if !ok {
		return approval.Request{}, fmt.Errorf("orchestrator: unknown profile edit approval request %q", requestID)
	}
	if entry.Request.State == approval.StateIssued || entry.Request.State == approval.StateDenied {
		return entry.Request, nil
	}
	if approver == entry.Request.Requester {
		payload, _ := json.Marshal(map[string]string{
			"id":       entry.Request.ID,
			"approver": approver,
			"reason":   "self-approval",
		})
		if _, err := o.emit(ctx, eventProfileEditApprovalRefused, tenantID, payload); err != nil {
			return approval.Request{}, err
		}
		return entry.Request, fmt.Errorf("orchestrator: requester cannot approve own profile edit (dual control)")
	}
	for _, a := range entry.Request.Approvals {
		if a.Approver == approver && a.Decision == "approve" {
			return entry.Request, nil
		}
	}
	now := time.Now().UTC()
	entry.Request.Approvals = append(entry.Request.Approvals, approval.Approval{
		Approver: approver,
		Decision: "approve",
		At:       now,
	})
	approvedPayload, err := json.Marshal(map[string]any{
		"id":        entry.Request.ID,
		"approver":  approver,
		"requester": entry.Request.Requester,
		"resource":  entry.Request.Resource,
	})
	if err != nil {
		return approval.Request{}, err
	}
	if _, err := o.emit(ctx, eventProfileEditApprovalApproved, tenantID, approvedPayload); err != nil {
		return approval.Request{}, err
	}
	entry.Request.State = approval.StateApproved
	rec, err := o.createProfileVersion(ctx, tenantID, entry.Name, entry.Spec)
	if err != nil {
		o.profileEditMu.Lock()
		o.profileEditApprovals[key] = entry
		o.profileEditMu.Unlock()
		return entry.Request, err
	}
	entry.Request.State = approval.StateIssued
	entry.Request.CredentialID = rec.ID
	o.profileEditMu.Lock()
	o.profileEditApprovals[key] = entry
	o.profileEditMu.Unlock()
	return entry.Request, nil
}

func profileEditApprovalKey(tenantID, requestID string) string {
	return tenantID + "|" + requestID
}

// CreateOwner records an owner.created event and returns the new owner.
func (o *Orchestrator) CreateOwner(ctx context.Context, tenantID, kind, name, email string) (store.Owner, error) {
	id := uuid.NewString()
	payload, err := json.Marshal(projections.OwnerCreated{ID: id, Kind: kind, Name: name, Email: email})
	if err != nil {
		return store.Owner{}, err
	}
	ev, err := o.emit(ctx, projections.EventOwnerCreated, tenantID, payload)
	if err != nil {
		return store.Owner{}, err
	}
	return store.Owner{ID: id, TenantID: tenantID, Kind: store.OwnerKind(kind), Name: name, Email: email, CreatedAt: ev.Time}, nil
}

// EnsureOwner records an owner.created event with a caller-provided stable ID
// only when that owner is absent. It is used by served system-owned identities
// whose graph node must be deterministic across retries and rebuilds.
func (o *Orchestrator) EnsureOwner(ctx context.Context, tenantID, id string, kind store.OwnerKind, name, email string) (store.Owner, error) {
	existing, err := o.store.GetOwner(ctx, tenantID, id)
	if err == nil {
		return existing, nil
	}
	if !store.IsNotFound(err) {
		return store.Owner{}, err
	}
	payload, err := json.Marshal(projections.OwnerCreated{ID: id, Kind: string(kind), Name: name, Email: email})
	if err != nil {
		return store.Owner{}, err
	}
	ev, err := o.emit(ctx, projections.EventOwnerCreated, tenantID, payload)
	if err != nil {
		return store.Owner{}, err
	}
	return store.Owner{ID: id, TenantID: tenantID, Kind: kind, Name: name, Email: email, CreatedAt: ev.Time}, nil
}

// UpdateOwner records an owner.updated event. It returns a not-found error
// (mapped to 404) when the owner does not exist, without emitting an event — so
// a no-op never produces a spurious event.
func (o *Orchestrator) UpdateOwner(ctx context.Context, tenantID, id, kind, name, email string) error {
	if _, err := o.store.GetOwner(ctx, tenantID, id); err != nil {
		return err
	}
	payload, err := json.Marshal(projections.OwnerUpdated{ID: id, Kind: kind, Name: name, Email: email})
	if err != nil {
		return err
	}
	_, err = o.emit(ctx, projections.EventOwnerUpdated, tenantID, payload)
	return err
}

// DeleteOwner records an owner.deleted event (404 if absent, no event emitted).
func (o *Orchestrator) DeleteOwner(ctx context.Context, tenantID, id string) error {
	if _, err := o.store.GetOwner(ctx, tenantID, id); err != nil {
		return err
	}
	payload, err := json.Marshal(projections.OwnerDeleted{ID: id})
	if err != nil {
		return err
	}
	_, err = o.emit(ctx, projections.EventOwnerDeleted, tenantID, payload)
	return err
}

// ErasePrivacySubject records a subject-level erasure using only non-PII
// selectors in the event. The raw subject is used once to resolve rows, then the
// immutable event carries a tenant-bound subject_ref and stable row identifiers.
func (o *Orchestrator) ErasePrivacySubject(ctx context.Context, tenantID, subject, reason string) (store.PrivacySubjectErasure, error) {
	erasure, err := o.store.SelectPrivacySubjectErasure(ctx, tenantID, subject)
	if err != nil {
		return store.PrivacySubjectErasure{}, err
	}
	if actor, ok := events.ActorFromContext(ctx); ok {
		erasure.RequestedByRef = privacy.SubjectRef(tenantID, actor.Subject)
	}
	erasure.Reason = reason
	payload, err := json.Marshal(projections.PrivacySubjectErased{
		SubjectRef:     erasure.SubjectRef,
		RequestedByRef: erasure.RequestedByRef,
		Reason:         erasure.Reason,
		Selectors:      erasure.Selectors,
		Counts:         erasure.Counts,
	})
	if err != nil {
		return store.PrivacySubjectErasure{}, err
	}
	ev, err := o.emit(ctx, projections.EventPrivacySubjectErased, tenantID, payload)
	if err != nil {
		return store.PrivacySubjectErasure{}, err
	}
	if err := o.log.PseudonymizeSubject(ctx, tenantID, subject); err != nil {
		return store.PrivacySubjectErasure{}, err
	}
	erasure.ErasedAt = ev.Time
	return erasure, nil
}

// EnforcePrivacyRetention records one non-audit PII retention pass for a tenant.
// The event carries only cutoffs and aggregate counts; projection logic performs
// the tenant-scoped pseudonymization from those deterministic boundaries.
func (o *Orchestrator) EnforcePrivacyRetention(ctx context.Context, tenantID string, policy privacy.RetentionPolicy, now time.Time) (store.PrivacyRetentionRun, error) {
	runID := uuid.NewString()
	run, err := o.store.SelectPrivacyRetention(ctx, tenantID, runID, policy, now)
	if err != nil {
		return store.PrivacyRetentionRun{}, err
	}
	if actor, ok := events.ActorFromContext(ctx); ok {
		run.RequestedByRef = privacy.SubjectRef(tenantID, actor.Subject)
	}
	payload, err := json.Marshal(projections.PrivacyRetentionEnforced{
		RunID:          run.RunID,
		RequestedByRef: run.RequestedByRef,
		Cutoffs:        run.Cutoffs,
		Counts:         run.Counts,
	})
	if err != nil {
		return store.PrivacyRetentionRun{}, err
	}
	ev, err := o.emit(ctx, projections.EventPrivacyRetentionEnforced, tenantID, payload)
	if err != nil {
		return store.PrivacyRetentionRun{}, err
	}
	run.EnforcedAt = ev.Time
	return run, nil
}

// CreateIssuer records an issuer.created event and returns the new issuer. The
// caller is expected to have validated it (the structural issuer rules).
func (o *Orchestrator) CreateIssuer(ctx context.Context, tenantID string, in store.Issuer) (store.Issuer, error) {
	id := uuid.NewString()
	chain := in.Chain
	if chain == nil {
		chain = []string{}
	}
	payload, err := json.Marshal(projections.IssuerCreated{
		ID: id, Kind: string(in.Kind), Name: in.Name, Chain: chain, PublicKey: in.PublicKey, Internal: in.Internal,
	})
	if err != nil {
		return store.Issuer{}, err
	}
	ev, err := o.emit(ctx, projections.EventIssuerCreated, tenantID, payload)
	if err != nil {
		return store.Issuer{}, err
	}
	out := in
	out.ID, out.TenantID, out.Chain, out.CreatedAt = id, tenantID, chain, ev.Time
	return out, nil
}

// CreateIdentity records an identity.created event and returns the new identity
// in its initial lifecycle status.
func (o *Orchestrator) CreateIdentity(ctx context.Context, tenantID string, in store.Identity) (store.Identity, error) {
	id := uuid.NewString()
	payload, err := json.Marshal(projections.IdentityCreated{
		ID: id, Kind: string(in.Kind), Name: in.Name, OwnerID: in.OwnerID, IssuerID: in.IssuerID, Attributes: in.Attributes,
	})
	if err != nil {
		return store.Identity{}, err
	}
	ev, err := o.emit(ctx, projections.EventIdentityCreated, tenantID, payload)
	if err != nil {
		return store.Identity{}, err
	}
	out := in
	out.ID, out.TenantID, out.Status, out.CreatedAt = id, tenantID, string(StateRequested), ev.Time
	return out, nil
}

// UpsertDeploymentTarget records a tenant-owned connector target. The target
// config is metadata and credential references only; secret bytes stay outside
// this read model.
func (o *Orchestrator) UpsertDeploymentTarget(ctx context.Context, tenantID string, in store.DeploymentTarget) (store.DeploymentTarget, error) {
	id := strings.TrimSpace(in.ID)
	if id == "" {
		id = uuid.NewString()
	}
	payload, err := json.Marshal(projections.DeploymentTargetUpserted{
		ID: id, Name: strings.TrimSpace(in.Name), Connector: strings.TrimSpace(in.Type), Config: in.Config,
	})
	if err != nil {
		return store.DeploymentTarget{}, err
	}
	if _, err := o.emit(ctx, projections.EventDeploymentTargetUpserted, tenantID, payload); err != nil {
		return store.DeploymentTarget{}, err
	}
	return o.store.GetDeploymentTarget(ctx, tenantID, id)
}

// DeleteDeploymentTarget records the removal of a tenant-owned connector target.
func (o *Orchestrator) DeleteDeploymentTarget(ctx context.Context, tenantID, id string) error {
	id = strings.TrimSpace(id)
	if id == "" {
		return fmt.Errorf("orchestrator: deployment target id is required")
	}
	payload, err := json.Marshal(projections.DeploymentTargetDeleted{ID: id})
	if err != nil {
		return err
	}
	_, err = o.emit(ctx, projections.EventDeploymentTargetDeleted, tenantID, payload)
	return err
}

// BindIdentityDeploymentTarget records the route that lifecycle deployment uses
// to deliver an identity to a connector target.
func (o *Orchestrator) BindIdentityDeploymentTarget(ctx context.Context, tenantID, identityID string, target store.DeploymentTarget) (store.Identity, error) {
	identityID = strings.TrimSpace(identityID)
	if identityID == "" {
		return store.Identity{}, fmt.Errorf("orchestrator: identity id is required")
	}
	if target.ID == "" || target.Type == "" || target.Name == "" {
		return store.Identity{}, fmt.Errorf("orchestrator: deployment target requires id, connector, and name")
	}
	payload, err := json.Marshal(projections.IdentityConnectorTargetBound{
		IdentityID: identityID, TargetID: target.ID, Connector: target.Type, Target: target.Name, Route: deploymentRoute(target),
	})
	if err != nil {
		return store.Identity{}, err
	}
	if _, err := o.emit(ctx, projections.EventIdentityConnectorTargetBound, tenantID, payload); err != nil {
		return store.Identity{}, err
	}
	return o.store.GetIdentity(ctx, tenantID, identityID)
}

func deploymentRoute(target store.DeploymentTarget) string {
	if len(target.Config) == 0 {
		return ""
	}
	var cfg map[string]any
	if err := json.Unmarshal(target.Config, &cfg); err != nil {
		return ""
	}
	for _, key := range []string{"target", "route", "deployment_route", "endpoint", "object", "virtual_service"} {
		if raw, ok := cfg[key]; ok {
			if s, ok := raw.(string); ok && strings.TrimSpace(s) != "" {
				return strings.TrimSpace(s)
			}
		}
	}
	return ""
}

// RecordCertificate records a certificate.recorded event (keyed by fingerprint)
// and returns the canonical inventoried row — whose id and created_at are stable
// across a re-ingest of the same certificate.
func (o *Orchestrator) RecordCertificate(ctx context.Context, tenantID string, in store.Certificate) (store.Certificate, error) {
	id := uuid.NewString()
	sans := in.SANs
	if sans == nil {
		sans = []string{}
	}
	payload, err := json.Marshal(projections.CertificateRecorded{
		ID: id, CAID: in.CAID, OwnerID: in.OwnerID, Subject: in.Subject, SANs: sans, Issuer: in.Issuer, Serial: in.Serial,
		Fingerprint: in.Fingerprint, KeyAlgorithm: in.KeyAlgorithm, NotBefore: in.NotBefore, NotAfter: in.NotAfter,
		DeploymentLocation: in.DeploymentLocation, Source: in.Source,
		CertificateDER:         in.CertificateDER,
		IssuanceIdempotencyKey: in.IssuanceIdempotencyKey,
	})
	if err != nil {
		return store.Certificate{}, err
	}
	if _, err := o.emit(ctx, projections.EventCertificateRecorded, tenantID, payload); err != nil {
		return store.Certificate{}, err
	}
	return o.store.GetCertificateByFingerprint(ctx, tenantID, in.Fingerprint)
}

// RevokeCertificate records a certificate.revoked event (keyed by the cert's
// fingerprint) and projects it, so the inventoried certificate's status becomes
// revoked. The status change is driven through the projector (the sole
// read-model writer, AN-2), so it is reconstructed from the log on a Rebuild()
// rather than lost. revokedAt is supplied by the caller so a redelivery (AN-5)
// re-applies the same revocation time deterministically.
func (o *Orchestrator) RevokeCertificate(ctx context.Context, tenantID, fingerprint, serial, reason string, revokedAt time.Time) error {
	return o.RevokeCertificateForCA(ctx, tenantID, fingerprint, serial, "", reason, 0, revokedAt)
}

// RevokeCertificateForCA records a certificate.revoked event for an inventoried
// cert and, when caID is set, also lets the projector update the OCSP/CRL serial
// row from the same event. This keeps certificate inventory and responder state
// rebuildable from one source-of-truth fact (CORRECT-002 / RED-002).
func (o *Orchestrator) RevokeCertificateForCA(ctx context.Context, tenantID, fingerprint, serial, caID, reason string, reasonCode int, revokedAt time.Time) error {
	payload, err := json.Marshal(projections.CertificateRevoked{
		Fingerprint: fingerprint, CAID: caID, Serial: serial, Reason: reason, ReasonCode: reasonCode, RevokedAt: revokedAt.UTC(),
	})
	if err != nil {
		return err
	}
	_, err = o.emit(ctx, projections.EventCertificateRevoked, tenantID, payload)
	return err
}

// SupersedeCertificate records a certificate.superseded event (keyed by the
// cert's fingerprint) and projects it, so the inventoried certificate's status
// becomes superseded and renewed_at is stamped (CORRECT-002). The status change
// is driven through the projector (the sole read-model writer, AN-2), so it is
// reconstructed from the log on a Rebuild() rather than lost — the same treatment
// as RevokeCertificate. renewedAt is supplied by the caller so a redelivery (AN-5)
// re-applies the same time deterministically; supersededBySerial is the successor
// serial, recorded for the audit trail.
func (o *Orchestrator) SupersedeCertificate(ctx context.Context, tenantID, fingerprint, serial, supersededBySerial string, renewedAt time.Time) error {
	payload, err := json.Marshal(projections.CertificateSuperseded{
		Fingerprint: fingerprint, Serial: serial, SupersededBy: supersededBySerial, RenewedAt: renewedAt.UTC(),
	})
	if err != nil {
		return err
	}
	_, err = o.emit(ctx, projections.EventCertificateSuperseded, tenantID, payload)
	return err
}

// RevokeAgentCertificate records an agent.cert.revoked event. The relational
// deny-list is only a projection of this event, so a rebuild from the event log
// restores the same agent certificate rejection behavior (AN-2).
func (o *Orchestrator) RevokeAgentCertificate(ctx context.Context, tenantID, agentID, agentName, serial, fingerprint, reason string, revokedAt time.Time) error {
	agentID = strings.TrimSpace(agentID)
	agentName = strings.TrimSpace(agentName)
	serial = normalizeAgentCertSerial(serial)
	fingerprint = normalizeAgentCertFingerprint(fingerprint)
	reason = strings.TrimSpace(reason)
	if agentID == "" {
		return fmt.Errorf("orchestrator: agent certificate revocation requires an agent id")
	}
	if serial == "" && fingerprint == "" {
		return fmt.Errorf("orchestrator: agent certificate revocation requires a serial or fingerprint")
	}
	if revokedAt.IsZero() {
		revokedAt = time.Now().UTC()
	}
	payload, err := json.Marshal(projections.AgentCertRevoked{
		ID: agentID, Agent: agentName, Serial: serial, Fingerprint: fingerprint,
		Reason: reason, RevokedAt: revokedAt.UTC(),
	})
	if err != nil {
		return err
	}
	_, err = o.emit(ctx, projections.EventAgentCertRevoked, tenantID, payload)
	return err
}

func normalizeAgentCertSerial(v string) string {
	return strings.ReplaceAll(strings.ToLower(strings.TrimSpace(v)), ":", "")
}

func normalizeAgentCertFingerprint(v string) string {
	v = strings.ToLower(strings.TrimSpace(v))
	v = strings.TrimPrefix(v, "sha256:")
	return strings.ReplaceAll(v, ":", "")
}

// UpsertTenantMember records a governed tenant principal. The member row is a
// projection of tenant.member.upserted, so a rebuild restores the same admin
// inventory operators used to create RA approvers.
func (o *Orchestrator) UpsertTenantMember(ctx context.Context, tenantID string, member store.TenantMember) (store.TenantMember, error) {
	if member.Source == "" {
		member.Source = "manual"
	}
	payload, err := json.Marshal(projections.TenantMemberUpserted{
		Subject: member.Subject, DisplayName: member.DisplayName, Email: member.Email,
		Roles: member.Roles, Source: member.Source,
	})
	if err != nil {
		return store.TenantMember{}, err
	}
	ev, err := o.emit(ctx, projections.EventTenantMemberUpserted, tenantID, payload)
	if err != nil {
		return store.TenantMember{}, err
	}
	member.TenantID = tenantID
	member.Status = "active"
	member.CreatedAt = ev.Time
	member.UpdatedAt = ev.Time
	return member, nil
}

// OffboardTenantMember records member retirement and lets the projector revoke
// every active API token for that subject. revokedCount is evidence captured
// before the event is applied; replay is still deterministic because the event
// carries the subject and the projection revokes by subject.
func (o *Orchestrator) OffboardTenantMember(ctx context.Context, tenantID, subject, reason string) (store.TenantMember, int, error) {
	actor := ""
	if a, ok := events.ActorFromContext(ctx); ok {
		actor = a.Subject
	}
	revokedCount, err := o.store.CountActiveAPITokensForSubject(ctx, tenantID, subject)
	if err != nil {
		return store.TenantMember{}, 0, err
	}
	payload, err := json.Marshal(projections.TenantMemberOffboarded{
		Subject: subject, Reason: reason, OffboardedBy: actor, RevokedTokenCount: revokedCount,
	})
	if err != nil {
		return store.TenantMember{}, 0, err
	}
	ev, err := o.emit(ctx, projections.EventTenantMemberOffboarded, tenantID, payload)
	if err != nil {
		return store.TenantMember{}, 0, err
	}
	member, err := o.store.GetTenantMember(ctx, tenantID, subject)
	if err != nil {
		return store.TenantMember{}, 0, err
	}
	member.UpdatedAt = ev.Time
	return member, revokedCount, nil
}

// CreateAPIToken records a served API-token mint. The event carries only the
// hash; raw is returned exactly once to the caller and is never persisted in the
// token table or event log.
func (o *Orchestrator) CreateAPIToken(ctx context.Context, tenantID, subject string, scopes []string, expiresAt *time.Time) (store.APITokenRecord, string, error) {
	raw, hash, err := auth.GenerateAPIToken()
	if err != nil {
		return store.APITokenRecord{}, "", err
	}
	id := uuid.NewString()
	payload, err := json.Marshal(projections.APITokenCreated{
		ID: id, TokenHash: hash, Subject: subject, Scopes: scopes, ExpiresAt: expiresAt,
	})
	if err != nil {
		return store.APITokenRecord{}, "", err
	}
	ev, err := o.emit(ctx, projections.EventAPITokenCreated, tenantID, payload)
	if err != nil {
		return store.APITokenRecord{}, "", err
	}
	return store.APITokenRecord{
		ID: id, TenantID: tenantID, TokenHash: hash, Subject: subject,
		Scopes: scopes, ExpiresAt: expiresAt, CreatedAt: ev.Time,
	}, raw, nil
}

// RevokeAPIToken records explicit token retirement. An already-revoked token is
// a safe no-op so retries and duplicate offboard/manual paths do not create
// noisy events.
func (o *Orchestrator) RevokeAPIToken(ctx context.Context, tenantID, tokenID, reason string) error {
	rec, err := o.store.GetAPIToken(ctx, tenantID, tokenID)
	if err != nil {
		return err
	}
	if rec.RevokedAt != nil {
		return nil
	}
	actor := ""
	if a, ok := events.ActorFromContext(ctx); ok {
		actor = a.Subject
	}
	payload, err := json.Marshal(projections.APITokenRevoked{ID: tokenID, Reason: reason, RevokedBy: actor})
	if err != nil {
		return err
	}
	_, err = o.emit(ctx, projections.EventAPITokenRevoked, tenantID, payload)
	return err
}

// ExpireAPITokens is the leaseworker entry point for short-lived API keys. It
// finds due rows with a bounded system sweep, then revokes each through the same
// tenant-scoped event command as an explicit admin revoke.
func (o *Orchestrator) ExpireAPITokens(ctx context.Context, now time.Time, limit int) (int, error) {
	expired, err := o.store.ListExpiredAPITokens(ctx, now, limit)
	if err != nil {
		return 0, err
	}
	count := 0
	for _, rec := range expired {
		if err := o.RevokeAPIToken(ctx, rec.TenantID, rec.ID, "expired"); err != nil {
			return count, err
		}
		count++
	}
	return count, nil
}

// RecordConnectorDelivery records a connector delivery receipt as event-sourced
// evidence. It is used by served orchestration paths that need to attest to a
// queued/unrouted connector action before an external connector plugin produces a
// later worker receipt.
func (o *Orchestrator) RecordConnectorDelivery(ctx context.Context, tenantID string, r store.ConnectorDeliveryReceipt) (store.ConnectorDeliveryReceipt, error) {
	if r.ID == "" {
		r.ID = uuid.NewString()
	}
	if r.Attempts == 0 {
		r.Attempts = 1
	}
	payload, err := json.Marshal(projections.ConnectorDeliveryRecorded{
		ID: r.ID, OutboxID: r.OutboxID, IdentityID: r.IdentityID, Destination: r.Destination,
		Connector: r.Connector, Target: r.Target, Fingerprint: r.Fingerprint,
		Status: r.Status, Attempts: r.Attempts, Reason: r.Reason, Detail: r.Detail,
		RollbackRef: r.RollbackRef, IdempotencyKey: r.IdempotencyKey,
	})
	if err != nil {
		return store.ConnectorDeliveryReceipt{}, err
	}
	ev, err := o.emit(ctx, projections.EventConnectorDeliveryRecorded, tenantID, payload)
	if err != nil {
		return store.ConnectorDeliveryReceipt{}, err
	}
	r.TenantID = tenantID
	r.CreatedAt = ev.Time
	r.UpdatedAt = ev.Time
	return r, nil
}

// RecordIncidentExecution records the final served incident execution evidence
// pack. The row is a projection of this event, so rebuild/snapshot/offboarding
// all treat the incident result as event-sourced state (AN-2).
func (o *Orchestrator) RecordIncidentExecution(ctx context.Context, tenantID string, r store.IncidentExecution) (store.IncidentExecution, error) {
	if r.ID == "" {
		r.ID = uuid.NewString()
	}
	payload, err := json.Marshal(projections.IncidentExecutionRecorded{
		ID: r.ID, CompromisedIdentityID: r.CompromisedIdentityID,
		ReplacementIdentityID: r.ReplacementIdentityID, ConnectorDeliveryID: r.ConnectorDeliveryID,
		Status: r.Status, Phase: r.Phase, Reason: r.Reason, BlastRadius: r.BlastRadius,
		RevocationStatus: r.RevocationStatus, EvidenceBundleFormat: r.EvidenceBundleFormat,
		EvidenceBundle: r.EvidenceBundle, FailedTargets: r.FailedTargets, RollbackRefs: r.RollbackRefs,
		IdempotencyKey: r.IdempotencyKey, CreatedBy: r.CreatedBy,
	})
	if err != nil {
		return store.IncidentExecution{}, err
	}
	ev, err := o.emit(ctx, projections.EventIncidentExecutionRecorded, tenantID, payload)
	if err != nil {
		return store.IncidentExecution{}, err
	}
	r.TenantID = tenantID
	r.CreatedAt = ev.Time
	r.UpdatedAt = ev.Time
	return r, nil
}

// RecordRemediationPlaybookRun records the final served playbook evidence pack.
// When outboxDestination is non-empty, the same event payload is also enqueued as
// the durable external-effect intent in the projection transaction (AN-6), keyed
// by the event id so boot reconciliation can recreate a lost right-size intent
// exactly once.
func (o *Orchestrator) RecordRemediationPlaybookRun(ctx context.Context, tenantID string, r store.RemediationPlaybookRun, outboxDestination string) (store.RemediationPlaybookRun, error) {
	if r.ID == "" {
		r.ID = uuid.NewString()
	}
	payload, err := json.Marshal(projections.RemediationPlaybookRunRecorded{
		ID: r.ID, PlaybookID: r.PlaybookID, TargetIdentityID: r.TargetIdentityID,
		InventoryID: r.InventoryID, Status: r.Status, Phase: r.Phase, Action: r.Action,
		Reason: r.Reason, Connector: r.Connector, Target: r.Target, OutboxID: r.OutboxID,
		ConnectorDeliveryID: r.ConnectorDeliveryID, ScopeDelta: r.ScopeDelta,
		EvidenceRefs: r.EvidenceRefs, RollbackRefs: r.RollbackRefs,
		IdempotencyKey: r.IdempotencyKey, CreatedBy: r.CreatedBy,
	})
	if err != nil {
		return store.RemediationPlaybookRun{}, err
	}
	ev, err := o.log.Append(ctx, events.Event{Type: projections.EventRemediationPlaybookRunRecorded, TenantID: tenantID, Data: payload})
	if err != nil {
		return store.RemediationPlaybookRun{}, err
	}
	if err := o.store.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		if err := o.proj.ApplyTx(ctx, tx, ev); err != nil {
			return err
		}
		if outboxDestination == "" {
			return nil
		}
		if o.outbox == nil {
			return fmt.Errorf("orchestrator: remediation playbook outbox is not configured")
		}
		_, err := o.outbox.EnqueueIfAbsent(ctx, tx, Entry{
			TenantID:       tenantID,
			Destination:    outboxDestination,
			IdempotencyKey: ev.ID,
			Payload:        payload,
		})
		return err
	}); err != nil {
		return store.RemediationPlaybookRun{}, err
	}
	r.TenantID = tenantID
	r.CreatedAt = ev.Time
	r.UpdatedAt = ev.Time
	return r, nil
}

// RecordIncidentFleetReissuance records a compromised-issuer fleet reissuance
// evidence snapshot. The row is a projection of this event, so pause/resume,
// rollback evidence, rebuild, and snapshot restore all replay from the immutable
// log instead of mutating read state directly (AN-2).
func (o *Orchestrator) RecordIncidentFleetReissuance(ctx context.Context, tenantID string, r store.IncidentFleetReissuanceRun) (store.IncidentFleetReissuanceRun, error) {
	if r.ID == "" {
		r.ID = uuid.NewString()
	}
	batches := make([]projections.FleetReissuanceBatch, 0, len(r.Batches))
	for _, b := range r.Batches {
		batches = append(batches, projections.FleetReissuanceBatch{
			Index: b.Index, Status: b.Status, IdentityIDs: b.IdentityIDs,
			ReplacementIdentityIDs: b.ReplacementIdentityIDs, HealthGate: b.HealthGate,
		})
	}
	healthGates := make([]projections.FleetReissuanceHealthGate, 0, len(r.HealthGates))
	for _, g := range r.HealthGates {
		healthGates = append(healthGates, projections.FleetReissuanceHealthGate{Name: g.Name, Status: g.Status})
	}
	payload, err := json.Marshal(projections.IncidentFleetReissuanceRecorded{
		ID: r.ID, IssuerID: r.IssuerID, Status: r.Status, Phase: r.Phase,
		Reason: r.Reason, BatchSize: r.BatchSize, Connector: r.Connector, Target: r.Target,
		GraphImpact: r.GraphImpact, AffectedIdentityIDs: r.AffectedIdentityIDs,
		ReplacementIdentityIDs: r.ReplacementIdentityIDs, RevokedIdentityIDs: r.RevokedIdentityIDs,
		ConnectorDeliveryIDs: r.ConnectorDeliveryIDs, Batches: batches, HealthGates: healthGates,
		FailedTargets: r.FailedTargets, RollbackRefs: r.RollbackRefs,
		EvidenceBundleFormat: r.EvidenceBundleFormat, EvidenceBundle: r.EvidenceBundle,
		IdempotencyKey: r.IdempotencyKey, CreatedBy: r.CreatedBy,
	})
	if err != nil {
		return store.IncidentFleetReissuanceRun{}, err
	}
	ev, err := o.emit(ctx, projections.EventIncidentFleetReissuanceRecorded, tenantID, payload)
	if err != nil {
		return store.IncidentFleetReissuanceRun{}, err
	}
	r.TenantID = tenantID
	if r.CreatedAt.IsZero() {
		r.CreatedAt = ev.Time
	}
	r.UpdatedAt = ev.Time
	return r, nil
}

// RecordSuccessorCertificate records a certificate.recorded event for the
// successor produced by a renewal/rotation, carrying its predecessor link
// (replaces_id) in the event so the link survives a Rebuild() (CORRECT-002).
// The projector treats replaces_id as the rotation domain fact: it inserts the
// successor and supersedes the predecessor in one transaction, so a partial
// failure cannot leave both certificates active. It returns the canonical
// inventoried row. This is the event-sourced replacement for the former direct
// successor-insert write into the read table.
func (o *Orchestrator) RecordSuccessorCertificate(ctx context.Context, tenantID string, in store.Certificate, replacesID string) (store.Certificate, error) {
	id := uuid.NewString()
	sans := in.SANs
	if sans == nil {
		sans = []string{}
	}
	rep := replacesID
	payload, err := json.Marshal(projections.CertificateRecorded{
		ID: id, CAID: in.CAID, OwnerID: in.OwnerID, Subject: in.Subject, SANs: sans, Issuer: in.Issuer, Serial: in.Serial,
		Fingerprint: in.Fingerprint, KeyAlgorithm: in.KeyAlgorithm, NotBefore: in.NotBefore, NotAfter: in.NotAfter,
		DeploymentLocation: in.DeploymentLocation, Source: in.Source, ReplacesID: &rep,
		CertificateDER:         in.CertificateDER,
		IssuanceIdempotencyKey: in.IssuanceIdempotencyKey,
	})
	if err != nil {
		return store.Certificate{}, err
	}
	if _, err := o.emit(ctx, projections.EventCertificateRecorded, tenantID, payload); err != nil {
		return store.Certificate{}, err
	}
	return o.store.GetCertificateByFingerprint(ctx, tenantID, in.Fingerprint)
}
