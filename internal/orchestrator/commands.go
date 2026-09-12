// SPDX-License-Identifier: MPL-2.0

package orchestrator

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"reflect"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"trstctl.com/trstctl/internal/approval"
	"trstctl.com/trstctl/internal/auth"
	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/crypto/certinfo"
	"trstctl.com/trstctl/internal/crypto/secret"
	ephemerallib "trstctl.com/trstctl/internal/ephemeral"
	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/privacy"
	"trstctl.com/trstctl/internal/profile"
	"trstctl.com/trstctl/internal/projections"
	"trstctl.com/trstctl/internal/store"
)

var (
	connectorRightSizeIdentityNamespace = uuid.MustParse("64ad96b4-b750-5e90-b55b-baf67c779a4a")
	errPrivacyErasureEventFound         = errors.New("orchestrator: privacy erasure event found")
	// ErrProfileRestoreStale is returned when the active profile changed after
	// an operator reviewed a restore preview. The mutation fails closed instead
	// of copying an old rule over a newer decision.
	ErrProfileRestoreStale = errors.New("orchestrator: certificate profile active version changed after review")
	// ErrProfileRestoreAlreadyActive prevents recovery from manufacturing a new
	// version when the selected source is already the active rule.
	ErrProfileRestoreAlreadyActive = errors.New("orchestrator: certificate profile version is already active")
)

// ConnectorRightSizeIdentity is every stable identity derived from the tenant
// and raw Idempotency-Key. None contains the caller or command in reversible
// form; RequestBinding separately proves which authenticated command owns them.
type ConnectorRightSizeIdentity struct {
	OperationID          string
	DeliveryID           string
	RequestedEventID     string
	OutboxIdempotencyKey string
	TerminalEventID      string
}

// ConnectorRightSizeIdentityFor gives retries, reconciliation, and rebuild the
// same operation/event/outbox/receipt identities without a transient registry.
func ConnectorRightSizeIdentityFor(tenantID, idempotencyKey string) ConnectorRightSizeIdentity {
	derive := func(kind string) string {
		return uuid.NewSHA1(connectorRightSizeIdentityNamespace,
			[]byte(kind+"\x00"+tenantID+"\x00"+idempotencyKey)).String()
	}
	operationID := derive("operation")
	return ConnectorRightSizeIdentity{
		OperationID: operationID, DeliveryID: derive("delivery"),
		RequestedEventID:     derive("requested-event"),
		OutboxIdempotencyKey: "connector-right-size:" + operationID,
		TerminalEventID:      derive("terminal-event"),
	}
}

// PrivacySubjectErasureIdentity is the durable receiver identity for a served
// erasure. It is derived from the tenant and raw Idempotency-Key; the separately
// signed request binding proves which caller/body owns that otherwise opaque ID.
type PrivacySubjectErasureIdentity struct {
	OperationID string
	EventID     string
}

// PrivacySubjectErasureIdentityFor makes a retry address the same immutable
// privacy event without persisting the raw Idempotency-Key in the event log.
// EventID is the raw-key anchor, so changed-body reuse still finds and rejects
// the first command. OperationID also binds the canonical caller/body digest.
func PrivacySubjectErasureIdentityFor(tenantID, idempotencyKey, requestBinding string) PrivacySubjectErasureIdentity {
	derive := func(kind string, fields ...string) string {
		material := []byte("trstctl.privacy-subject-erasure-identity.v1\x00" +
			kind + "\x00" + strings.Join(fields, "\x00"))
		defer secret.Wipe(material)
		return "sha256:" + crypto.SHA256Hex(material)
	}
	return PrivacySubjectErasureIdentity{
		OperationID: derive("operation", tenantID, idempotencyKey, requestBinding),
		EventID:     derive("raw-key-event", tenantID, idempotencyKey),
	}
}

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
	// DestinationFleetReissuanceBatch is an internal, bounded worker command.
	// Exactly one command is published for the durable cursor; later batches do
	// not exist in the outbox until signed canary verification advances it.
	DestinationFleetReissuanceBatch = "incident.fleet_reissuance.batch"
)

// FleetReissuanceBatchCommand names one durable fleet execution unit. The run
// projection owns the identity lists, connector routing, and cursor, so the
// outbox body cannot substitute a different target set.
type FleetReissuanceBatchCommand struct {
	RunID      string `json:"run_id"`
	BatchIndex int    `json:"batch_index"`
}

// FleetReissuanceBatchIdempotencyKey is stable across restart reconciliation.
func FleetReissuanceBatchIdempotencyKey(runID string, batchIndex int) string {
	return fmt.Sprintf("fleet-reissuance:%s:batch:%d", runID, batchIndex)
}

type approvalProfileEditRequest struct {
	Request               approval.Request `json:"request"`
	Name                  string           `json:"name"`
	Spec                  json.RawMessage  `json:"spec"`
	RestoredFromVersion   int              `json:"restored_from_version,omitempty"`
	RestoreReason         string           `json:"restore_reason,omitempty"`
	ExpectedActiveVersion int              `json:"expected_active_version,omitempty"`
}

// ProfileRestorePlan is an effect-free receipt for copying a known-good
// historical certificate-profile spec into one new active version. Empty
// PreviewWrites and PreviewExternalEffects are explicit proof that review did
// not change state or contact another system.
type ProfileRestorePlan struct {
	Capability             string          `json:"capability"`
	Operation              string          `json:"operation"`
	Ready                  bool            `json:"ready"`
	Name                   string          `json:"name"`
	SourceVersion          int             `json:"source_version"`
	ActiveVersion          int             `json:"active_version"`
	NextVersion            int             `json:"next_version"`
	Reason                 string          `json:"reason"`
	SourceSpecDigest       string          `json:"source_spec_digest"`
	RequestFingerprint     string          `json:"request_fingerprint"`
	RequiredPermission     string          `json:"required_permission"`
	Changes                []string        `json:"changes"`
	Risks                  []string        `json:"risks"`
	VerificationSteps      []string        `json:"verification_steps"`
	PreviewWrites          []string        `json:"preview_writes"`
	PreviewExternalEffects []string        `json:"preview_external_effects"`
	SourceSpec             json.RawMessage `json:"source_spec"`
}

type profileVersionOptions struct {
	RestoredFromVersion   int
	RestoreReason         string
	ExpectedActiveVersion int
	// ApprovalRequestID is the parked dual-control request this version closes;
	// the emitted profile event carries it so the projection marks the request
	// issued, and the create is skipped when another replica already did so.
	ApprovalRequestID string
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
	ProfileName         string
	ProfileID           string
	ProfileVersion      int
	ProfileSpecDigest   string
	RequestedTTLSeconds int64
	EffectiveTTLSeconds int64
	RequiresApproval    bool
}

// DefaultIdentityIssuanceTTL is the validity the identity lifecycle command asks
// the signer to use when the API has no caller-selected TTL field. Both the
// requested and effective values are pinned into any approval authority.
const DefaultIdentityIssuanceTTL = 30 * 24 * time.Hour

// IssuanceBinding turns the resolved requirement into the immutable command
// shape that is covered by approval evidence and carried to the dispatcher.
func (r ProfileApprovalRequirement) IssuanceBinding() *store.OperationApprovalIssuanceBinding {
	return &store.OperationApprovalIssuanceBinding{
		ProfileName: r.ProfileName, ProfileID: r.ProfileID,
		ProfileVersion: r.ProfileVersion, ProfileSpecDigest: r.ProfileSpecDigest,
		RequestedTTLSeconds: r.RequestedTTLSeconds,
		EffectiveTTLSeconds: r.EffectiveTTLSeconds,
	}
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
	next := events.Event{
		Type: eventType, TenantID: tenantID, SchemaVersion: schemaVersion, Data: payload,
	}
	return o.emitPrepared(ctx, next)
}

// emitPrepared is the narrow form used by durable receivers that must supply a
// stable event ID (and, for self-erasure, an already-sanitized actor).
func (o *Orchestrator) emitPrepared(ctx context.Context, next events.Event) (events.Event, error) {
	if next.Type == projections.EventTenantRegistered {
		return events.Event{}, errors.New("orchestrator: live tenant registration requires ExecuteTenantRegistration")
	}
	if next.Type == projections.EventTenantOffboarded {
		return o.emitTenantOffboard(ctx, next)
	}
	if next.Type == projections.EventCertificateRecorded || next.Type == projections.EventEdgeIssuanceReconciled {
		return o.emitCertificateRecording(ctx, next)
	}
	certificateMetadata, err := projections.CertificateMetadataEvent(next)
	if err != nil {
		return events.Event{}, err
	}

	var ev events.Event
	err = o.store.WithTenant(ctx, next.TenantID, func(tx pgx.Tx) error {
		if certificateMetadata {
			// Admission covers the source append, not just SQL projection. A
			// recording that already owns this fence must finish before we get
			// an event sequence; otherwise it can project a later sequence and
			// make this unapplied revocation/ownership event unsafe to replay.
			if err := o.store.LockCertificateMetadataOrderTx(ctx, tx, next.TenantID); err != nil {
				return err
			}
		}
		var err error
		ev, err = o.log.Append(ctx, next)
		if err != nil {
			return err
		}
		return o.proj.ApplyTx(ctx, tx, ev)
	})
	return ev, err
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
	if err := profile.ValidateSpec(spec); err != nil {
		return store.ProfileRecord{}, err
	}
	gated, err := o.profileEditRequiresApproval(ctx, tenantID, name, spec)
	if err != nil {
		return store.ProfileRecord{}, err
	}
	if gated {
		req, err := o.requestProfileEditApproval(ctx, tenantID, name, spec, profileVersionOptions{})
		if err != nil {
			return store.ProfileRecord{}, err
		}
		return store.ProfileRecord{}, &ProfileEditPendingError{Request: req}
	}
	return o.createProfileVersion(ctx, tenantID, name, spec)
}

func (o *Orchestrator) createProfileVersion(ctx context.Context, tenantID, name string, spec json.RawMessage) (store.ProfileRecord, error) {
	return o.createProfileVersionWithOptions(ctx, tenantID, name, spec, profileVersionOptions{})
}

func (o *Orchestrator) createProfileVersionWithOptions(ctx context.Context, tenantID, name string, spec json.RawMessage, opts profileVersionOptions) (store.ProfileRecord, error) {
	actor := ""
	if a, ok := events.ActorFromContext(ctx); ok {
		actor = a.Subject
	}
	var rec store.ProfileRecord
	err := o.store.WithProjectionLock(ctx, func(ctx context.Context) error {
		if opts.ApprovalRequestID != "" {
			// Two reviewers reaching quorum at once both arrive here; the lock
			// serializes them and the second finds the request already issued.
			parked, err := o.store.GetProfileEditApproval(ctx, tenantID, opts.ApprovalRequestID)
			if err != nil {
				return err
			}
			if parked.State == "issued" && parked.ProfileID != "" {
				existing, err := o.store.GetProfileVersionByID(ctx, tenantID, parked.ProfileID)
				if err != nil {
					return err
				}
				rec = existing
				return nil
			}
		}
		if opts.ExpectedActiveVersion > 0 {
			active, err := o.store.GetActiveProfile(ctx, tenantID, name)
			if err != nil {
				return err
			}
			if active.Version != opts.ExpectedActiveVersion {
				return ErrProfileRestoreStale
			}
			if active.Version == opts.RestoredFromVersion {
				return ErrProfileRestoreAlreadyActive
			}
		}
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
			RestoredFromVersion:   opts.RestoredFromVersion,
			RestoreReason:         opts.RestoreReason,
			ExpectedActiveVersion: opts.ExpectedActiveVersion,
			ApprovalRequestID:     opts.ApprovalRequestID,
		})
		if err != nil {
			return err
		}
		ev, err := o.emitVersioned(ctx, evType, tenantID, projections.ProfileEventSchemaVersion, payload)
		if err != nil {
			return err
		}
		rec.CreatedAt = ev.Time
		// Return the projected PostgreSQL jsonb representation, not the caller's
		// byte ordering. ProfileSpecDigest is intentionally defined over the
		// stored canonical bytes so create, preview, approval, and recovery all
		// show the same digest for the same version.
		projected, err := o.store.GetProfileVersion(ctx, tenantID, name, rec.Version)
		if err != nil {
			return err
		}
		rec = projected
		return nil
	})
	if err != nil {
		return store.ProfileRecord{}, err
	}
	return rec, nil
}

// PlanProfileRestore validates and describes an exact recovery without emitting
// an event or changing a projection. The returned source spec is certificate
// policy metadata, not credential or private-key material.
func (o *Orchestrator) PlanProfileRestore(ctx context.Context, tenantID, name string, sourceVersion, expectedActiveVersion int, reason string) (ProfileRestorePlan, error) {
	name = strings.TrimSpace(name)
	reason = strings.TrimSpace(reason)
	if name == "" || sourceVersion < 1 || expectedActiveVersion < 1 || reason == "" {
		return ProfileRestorePlan{}, fmt.Errorf("orchestrator: profile name, positive source/active versions, and recovery reason are required")
	}
	source, err := o.store.GetProfileVersion(ctx, tenantID, name, sourceVersion)
	if err != nil {
		return ProfileRestorePlan{}, err
	}
	if err := profile.ValidateSpec(source.Spec); err != nil {
		return ProfileRestorePlan{}, fmt.Errorf("orchestrator: historical profile spec is invalid: %w", err)
	}
	active, err := o.store.GetActiveProfile(ctx, tenantID, name)
	if err != nil {
		return ProfileRestorePlan{}, err
	}
	if active.Version != expectedActiveVersion {
		return ProfileRestorePlan{}, ErrProfileRestoreStale
	}
	if active.Version == sourceVersion {
		return ProfileRestorePlan{}, ErrProfileRestoreAlreadyActive
	}
	nextVersion, err := o.store.NextProfileVersion(ctx, tenantID, name)
	if err != nil {
		return ProfileRestorePlan{}, err
	}
	digest := store.ProfileSpecDigest(source.Spec)
	fingerprintInput, err := json.Marshal(struct {
		Capability            string `json:"capability"`
		TenantID              string `json:"tenant_id"`
		Name                  string `json:"name"`
		SourceVersion         int    `json:"source_version"`
		ExpectedActiveVersion int    `json:"expected_active_version"`
		Reason                string `json:"reason"`
		SourceSpecDigest      string `json:"source_spec_digest"`
	}{
		Capability: "certificate_profile_recovery", TenantID: tenantID, Name: name,
		SourceVersion: sourceVersion, ExpectedActiveVersion: expectedActiveVersion,
		Reason: reason, SourceSpecDigest: digest,
	})
	if err != nil {
		return ProfileRestorePlan{}, err
	}
	return ProfileRestorePlan{
		Capability: "certificate_profile_recovery", Operation: "restore_as_new_version", Ready: true,
		Name: name, SourceVersion: sourceVersion, ActiveVersion: active.Version, NextVersion: nextVersion,
		Reason: reason, SourceSpecDigest: digest,
		RequestFingerprint: "sha256:" + crypto.SHA256Hex(fingerprintInput), RequiredPermission: "profiles:write",
		Changes:           []string{fmt.Sprintf("Create profile %s version %d from reviewed historical version %d", name, nextVersion, sourceVersion), fmt.Sprintf("Make version %d active and retain version %d as immutable history", nextVersion, active.Version)},
		Risks:             []string{"New issuance uses the restored rule after confirmation; certificates already issued keep their original profile-version evidence", "A concurrent profile change makes this receipt stale and the mutation fails closed"},
		VerificationSteps: []string{fmt.Sprintf("Confirm version %d is active and its spec digest is %s", nextVersion, digest), "Confirm prior versions remain readable and inactive", "Issue a test certificate and verify it records the restored profile version"},
		PreviewWrites:     []string{}, PreviewExternalEffects: []string{},
		SourceSpec: append(json.RawMessage(nil), source.Spec...),
	}, nil
}

// RestoreProfileVersion copies a reviewed historical spec into one new active
// event-sourced version. It never mutates or reactivates the historical row.
func (o *Orchestrator) RestoreProfileVersion(ctx context.Context, tenantID, name string, sourceVersion, expectedActiveVersion int, reason string) (store.ProfileRecord, error) {
	plan, err := o.PlanProfileRestore(ctx, tenantID, name, sourceVersion, expectedActiveVersion, reason)
	if err != nil {
		return store.ProfileRecord{}, err
	}
	opts := profileVersionOptions{
		RestoredFromVersion: plan.SourceVersion, RestoreReason: plan.Reason,
		ExpectedActiveVersion: plan.ActiveVersion,
	}
	gated, err := o.profileEditRequiresApproval(ctx, tenantID, plan.Name, plan.SourceSpec)
	if err != nil {
		return store.ProfileRecord{}, err
	}
	if gated {
		req, err := o.requestProfileEditApproval(ctx, tenantID, plan.Name, plan.SourceSpec, opts)
		if err != nil {
			return store.ProfileRecord{}, err
		}
		return store.ProfileRecord{}, &ProfileEditPendingError{Request: req}
	}
	return o.createProfileVersionWithOptions(ctx, tenantID, plan.Name, plan.SourceSpec, opts)
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
		return defaultProfileApprovalRequirement(""), nil
	}
	return o.ProfileApprovalRequirementByName(ctx, tenantID, profileName)
}

// ProfileApprovalRequirementByName resolves a configured/default profile when
// an identity has no explicit profile attribute. This keeps the policy label and
// the issuance semantics on the same exact stored revision.
func (o *Orchestrator) ProfileApprovalRequirementByName(ctx context.Context, tenantID, profileName string) (ProfileApprovalRequirement, error) {
	profileName = strings.TrimSpace(profileName)
	if profileName == "" {
		return defaultProfileApprovalRequirement(""), nil
	}
	rec, err := o.store.GetActiveProfile(ctx, tenantID, profileName)
	if err != nil {
		return ProfileApprovalRequirement{}, err
	}
	requires, err := profileSpecRequiresApproval(rec.Spec)
	if err != nil {
		return ProfileApprovalRequirement{}, err
	}
	requirement := defaultProfileApprovalRequirement(profileName)
	requirement.ProfileID = rec.ID
	requirement.ProfileVersion = rec.Version
	requirement.ProfileSpecDigest = store.ProfileSpecDigest(rec.Spec)
	requirement.RequiresApproval = requires
	var resolved profile.CertificateProfile
	if err := json.Unmarshal(rec.Spec, &resolved); err != nil {
		return ProfileApprovalRequirement{}, fmt.Errorf("orchestrator: decode profile issuance policy: %w", err)
	}
	if maxValidity := time.Duration(resolved.MaxValidity); maxValidity > 0 && maxValidity < DefaultIdentityIssuanceTTL {
		effectiveSeconds := int64(maxValidity / time.Second)
		if effectiveSeconds <= 0 {
			return ProfileApprovalRequirement{}, fmt.Errorf("orchestrator: profile %q max_validity is below one second", profileName)
		}
		requirement.EffectiveTTLSeconds = effectiveSeconds
	}
	return requirement, nil
}

func defaultProfileApprovalRequirement(profileName string) ProfileApprovalRequirement {
	seconds := int64(DefaultIdentityIssuanceTTL / time.Second)
	return ProfileApprovalRequirement{
		ProfileName: strings.TrimSpace(profileName), RequestedTTLSeconds: seconds,
		EffectiveTTLSeconds: seconds,
	}
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

func (o *Orchestrator) requestProfileEditApproval(ctx context.Context, tenantID, name string, spec json.RawMessage, opts profileVersionOptions) (approval.Request, error) {
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
		Request: req, Name: name, Spec: append(json.RawMessage(nil), spec...),
		RestoredFromVersion:   opts.RestoredFromVersion,
		RestoreReason:         opts.RestoreReason,
		ExpectedActiveVersion: opts.ExpectedActiveVersion,
	}
	payload, err := json.Marshal(entry)
	if err != nil {
		return approval.Request{}, err
	}
	// The event is the record: its inline projection parks the request in
	// profile_edit_approvals, where every replica and every restart finds it.
	if _, err := o.emit(ctx, eventProfileEditApprovalRequested, tenantID, payload); err != nil {
		return approval.Request{}, err
	}
	return req, nil
}

// ErrProfileEditApprovalUnknown reports an approval id the tenant does not own.
var ErrProfileEditApprovalUnknown = errors.New("orchestrator: unknown profile edit approval request")

// ErrProfileEditApprovalExpired reports a parked request past its 24-hour window.
var ErrProfileEditApprovalExpired = errors.New("orchestrator: profile edit approval request expired")

// ErrProfileEditSelfApproval reports the requester approving their own edit.
var ErrProfileEditSelfApproval = errors.New("orchestrator: requester cannot approve own profile edit (dual control)")

// ProfileEditApprovalState reads the served state of a parked request: the
// projected state, or "expired" when it is still awaiting approval past its
// window.
func ProfileEditApprovalState(r store.ProfileEditApproval, now time.Time) string {
	if r.State == string(approval.StateAwaitingApproval) && !now.Before(r.ExpiresAt) {
		return string(approval.StateExpired)
	}
	return r.State
}

// ListProfileEditApprovals returns the tenant's parked profile create/edit
// approval requests, oldest first, from the projection (DP2-057, OPP-R09).
func (o *Orchestrator) ListProfileEditApprovals(ctx context.Context, tenantID string) ([]store.ProfileEditApproval, error) {
	return o.store.ListProfileEditApprovals(ctx, tenantID)
}

// GetProfileEditApproval returns one parked request of the tenant.
func (o *Orchestrator) GetProfileEditApproval(ctx context.Context, tenantID, requestID string) (store.ProfileEditApproval, error) {
	r, err := o.store.GetProfileEditApproval(ctx, tenantID, requestID)
	if errors.Is(err, store.ErrProfileEditApprovalNotFound) {
		return store.ProfileEditApproval{}, ErrProfileEditApprovalUnknown
	}
	return r, err
}

// ApproveProfileEdit records a non-requester approval and applies the queued
// profile spec when quorum is reached. The decision is an event; the projection
// carries the state, so the same call on any replica, or after a restart, sees
// the same request and an identical decision is absorbed rather than doubled.
func (o *Orchestrator) ApproveProfileEdit(ctx context.Context, tenantID, requestID, approver string) (store.ProfileEditApproval, error) {
	if approver == "" {
		if actor, ok := events.ActorFromContext(ctx); ok {
			approver = actor.Subject
		}
	}
	if approver == "" {
		return store.ProfileEditApproval{}, fmt.Errorf("orchestrator: profile edit approval requires an authenticated approver")
	}
	parked, err := o.GetProfileEditApproval(ctx, tenantID, requestID)
	if err != nil {
		return store.ProfileEditApproval{}, err
	}
	now := time.Now().UTC()
	switch ProfileEditApprovalState(parked, now) {
	case string(approval.StateIssued), string(approval.StateDenied):
		return parked, nil
	case string(approval.StateExpired):
		return parked, ErrProfileEditApprovalExpired
	}
	if approver == parked.Requester {
		payload, _ := json.Marshal(map[string]string{"id": parked.ID, "approver": approver, "reason": "self-approval"})
		if _, err := o.emit(ctx, eventProfileEditApprovalRefused, tenantID, payload); err != nil {
			return store.ProfileEditApproval{}, err
		}
		return parked, ErrProfileEditSelfApproval
	}
	alreadyApproved := false
	for _, a := range parked.Approvals {
		if a.Approver == approver && a.Decision == "approve" {
			alreadyApproved = true
		}
	}
	if !alreadyApproved {
		approvedPayload, err := json.Marshal(map[string]any{
			"id": parked.ID, "approver": approver, "requester": parked.Requester, "resource": "profile:" + parked.Name,
		})
		if err != nil {
			return store.ProfileEditApproval{}, err
		}
		if _, err := o.emit(ctx, eventProfileEditApprovalApproved, tenantID, approvedPayload); err != nil {
			return store.ProfileEditApproval{}, err
		}
		parked, err = o.GetProfileEditApproval(ctx, tenantID, requestID)
		if err != nil {
			return store.ProfileEditApproval{}, err
		}
	}
	if len(parked.Approvals) < parked.RequiredApprovals {
		return parked, nil
	}
	// Quorum: apply the queued spec as the new active version. The version event
	// carries the request id, so the projection closes the request; a replica
	// that lost the race finds it issued under the projection lock and returns
	// the version the winner created.
	if _, err := o.createProfileVersionWithOptions(ctx, tenantID, parked.Name, parked.Spec, profileVersionOptions{
		RestoredFromVersion:   parked.RestoredFromVersion,
		RestoreReason:         parked.RestoreReason,
		ExpectedActiveVersion: parked.ExpectedActiveVersion,
		ApprovalRequestID:     parked.ID,
	}); err != nil {
		return parked, err
	}
	return o.GetProfileEditApproval(ctx, tenantID, requestID)
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

// ErasePrivacySubject is the one-shot internal form retained for callers that do
// not sit behind the served Idempotency-Key wall. The served API uses
// ErasePrivacySubjectBound so retries address one durable event.
func (o *Orchestrator) ErasePrivacySubject(ctx context.Context, tenantID, subject, reason string) (store.PrivacySubjectErasure, error) {
	nonce := events.NewID()
	return o.erasePrivacySubjectBound(
		ctx, tenantID, subject, reason,
		"orchestrator-one-shot:"+nonce,
		PrivacySubjectErasureIdentityFor(tenantID, nonce, "orchestrator-one-shot:"+nonce),
	)
}

// ErasePrivacySubjectBound is a crash-resumable AN-5 receiver. Its immutable
// event ID is derived from tenant + raw Idempotency-Key, while requestBinding
// proves the authenticated caller and canonical body that own that key.
func (o *Orchestrator) ErasePrivacySubjectBound(
	ctx context.Context,
	tenantID, subject, reason, idempotencyKey, requestBinding string,
) (store.PrivacySubjectErasure, error) {
	if idempotencyKey == "" || requestBinding == "" {
		return store.PrivacySubjectErasure{}, errors.New("orchestrator: bound privacy erasure requires idempotency key and request binding")
	}
	return o.erasePrivacySubjectBound(
		ctx, tenantID, subject, reason,
		requestBinding,
		PrivacySubjectErasureIdentityFor(tenantID, idempotencyKey, requestBinding),
	)
}

func (o *Orchestrator) erasePrivacySubjectBound(
	ctx context.Context,
	tenantID, subject, reason string,
	requestBinding string,
	identity PrivacySubjectErasureIdentity,
) (store.PrivacySubjectErasure, error) {
	if err := events.ValidateTenantDataRewriteOptions(o.tenantDataRewrite...); err != nil {
		return store.PrivacySubjectErasure{}, fmt.Errorf("orchestrator: privacy subject erasure proof preflight: %w", err)
	}
	if err := o.log.HistoryRewriteReady(); err != nil {
		return store.PrivacySubjectErasure{}, fmt.Errorf("orchestrator: privacy subject erasure log preflight: %w", err)
	}
	if _, err := o.RecoverPrivacySubjectErasurePreparations(ctx); err != nil {
		return store.PrivacySubjectErasure{}, fmt.Errorf(
			"orchestrator: recover unfinished privacy subject erasure before new command: %w", err,
		)
	}

	if authoritative, found, err := o.recoverPrivacyErasure(
		ctx, tenantID, subject, identity, requestBinding,
	); err != nil {
		return store.PrivacySubjectErasure{}, err
	} else if found {
		return authoritative, nil
	}

	// Keep the durable-state recheck, selector read, and deterministic append
	// inside the same deployment-wide rewrite-operation lease. A second replica
	// can neither pass the recheck nor race beyond JetStream's finite dedup window
	// before this operation projection commits.
	var (
		authoritative   store.PrivacySubjectErasure
		prepared        store.PrivacySubjectErasurePreparation
		alreadyComplete bool
	)
	err := o.log.PseudonymizeSubjectWithPreparationAndCompletion(
		ctx,
		tenantID,
		subject,
		func(preparationCtx context.Context, report events.TenantDataRewriteReport) error {
			// Another replica can finish while this caller waits for the exclusive
			// history-operation lease. Recheck inside the lease before creating any
			// new preparation; an already-projected operation needs only the no-op
			// completion path below.
			if recovered, found, err := o.recoverPrivacyErasure(
				preparationCtx, tenantID, subject, identity, requestBinding,
			); err != nil {
				return err
			} else if found {
				authoritative = recovered
				alreadyComplete = true
				return nil
			}
			requestedByRef := ""
			if actor, ok := events.ActorFromContext(preparationCtx); ok {
				requestedByRef = privacy.SubjectRef(tenantID, actor.Subject)
			}
			candidate := store.PrivacySubjectErasurePreparation{
				PrivacySubjectErasure: store.PrivacySubjectErasure{
					TenantID: tenantID, SubjectRef: privacy.SubjectRef(tenantID, subject),
					RequestedByRef: requestedByRef,
					Reason:         sanitizePrivacyErasureText(tenantID, subject, reason),
					ErasedAt:       time.Now().UTC(),
				},
				OperationID: identity.OperationID, RequestBinding: requestBinding,
				EventID:            identity.EventID,
				RewriteOperationID: report.OperationID,
				TargetGeneration:   report.TargetGeneration,
				EventActor:         sanitizedPrivacyErasureActor(preparationCtx, tenantID, subject),
			}
			var err error
			prepared, err = o.store.PreparePrivacySubjectErasureWithSchedulerResolver(
				preparationCtx, tenantID, subject, candidate,
				o.durableIdem.ResolveSecretRotationSchedulePrivacyOuter,
				func(receiptCtx context.Context, tx pgx.Tx) error {
					return o.store.RebindCertificateMetadataPrivacyReceiptsTx(receiptCtx, tx, tenantID, subject, o.log.ReplayThrough)
				})
			if err != nil {
				return fmt.Errorf("orchestrator: prepare privacy subject erasure: %w", err)
			}
			return nil
		},
		func(completionCtx context.Context) error {
			if alreadyComplete {
				return nil
			}
			completed, completionErr := o.completePreparedPrivacySubjectErasure(
				completionCtx, prepared,
			)
			authoritative = completed
			return completionErr
		},
		o.tenantDataRewrite...,
	)
	if err != nil {
		return store.PrivacySubjectErasure{}, err
	}
	return authoritative, nil
}

// RecoverPrivacySubjectErasurePreparations autonomously finishes every
// independently durable SQL preparation before snapshot restore or ordinary
// recovery publishers run. Log.Open has already recovered any signed staged
// target; this method proves that exact generation, reconstructs the canonical
// completion event entirely from non-PII preparation data, and retires the row
// atomically with projection.
func (o *Orchestrator) RecoverPrivacySubjectErasurePreparations(
	ctx context.Context,
) (int, error) {
	if o == nil || o.log == nil || o.store == nil {
		return 0, errors.New("orchestrator: privacy preparation recovery is not configured")
	}
	completed := 0
	err := o.log.WithHistoryOperation(ctx, func(operationCtx context.Context) error {
		keys, err := o.store.ListPrivacySubjectErasurePreparationKeysSystem(operationCtx)
		if err != nil {
			return fmt.Errorf("orchestrator: list privacy erasure preparations: %w", err)
		}
		for _, key := range keys {
			prepared, err := o.store.GetPrivacySubjectErasurePreparation(
				operationCtx, key.TenantID, key.OperationID,
			)
			if errors.Is(err, pgx.ErrNoRows) {
				// Another replica completed this exact marker after the system
				// inventory. The operation lock normally prevents that, but the
				// missing row is still an already-safe outcome.
				continue
			}
			if err != nil {
				return fmt.Errorf("orchestrator: load privacy erasure preparation: %w", err)
			}
			if _, err := o.completePreparedPrivacySubjectErasure(operationCtx, prepared); err != nil {
				return fmt.Errorf(
					"orchestrator: complete privacy erasure preparation %s: %w",
					prepared.OperationID, err,
				)
			}
			completed++
		}
		return nil
	})
	return completed, err
}

func (o *Orchestrator) completePreparedPrivacySubjectErasure(
	ctx context.Context,
	prepared store.PrivacySubjectErasurePreparation,
) (store.PrivacySubjectErasure, error) {
	activeGeneration, err := o.log.ActiveGeneration(ctx)
	if err != nil {
		return store.PrivacySubjectErasure{}, fmt.Errorf("orchestrator: resolve prepared privacy generation: %w", err)
	}
	if activeGeneration != prepared.TargetGeneration {
		return store.PrivacySubjectErasure{}, fmt.Errorf(
			"orchestrator: prepared privacy generation %q is not active (active=%q)",
			prepared.TargetGeneration, activeGeneration,
		)
	}
	if err := o.rewriteLifecycleOutboxFromCanonicalHistory(ctx, prepared.TenantID); err != nil {
		return store.PrivacySubjectErasure{}, err
	}
	completion := projections.PrivacySubjectErased{
		OperationID:           prepared.OperationID,
		RequestBinding:        prepared.RequestBinding,
		SubjectRef:            prepared.SubjectRef,
		RequestedByRef:        prepared.RequestedByRef,
		Reason:                prepared.Reason,
		Selectors:             prepared.Selectors,
		Counts:                prepared.Counts,
		RecoveryFences:        prepared.RecoveryFences,
		SchedulerDispositions: prepared.SchedulerDispositions,
	}
	expected := events.Event{
		ID:            prepared.EventID,
		Type:          projections.EventPrivacySubjectErased,
		TenantID:      prepared.TenantID,
		Time:          prepared.ErasedAt,
		SchemaVersion: projections.PrivacySubjectErasedEventSchemaVersion,
		Actor:         prepared.EventActor,
	}
	if err := projections.ValidatePrivacySubjectErasedPayload(expected, completion); err != nil {
		return store.PrivacySubjectErasure{}, fmt.Errorf(
			"orchestrator: invalid durable privacy erasure preparation: %w", err,
		)
	}
	payload, err := json.Marshal(completion)
	if err != nil {
		return store.PrivacySubjectErasure{}, err
	}
	expected.Data = payload
	retained, found, err := o.log.EventByID(ctx, expected.ID)
	if err != nil {
		return store.PrivacySubjectErasure{}, err
	}
	if found {
		if retained.Type != expected.Type || retained.TenantID != expected.TenantID ||
			!retained.Time.Equal(expected.Time) || retained.SchemaVersion != expected.SchemaVersion ||
			!reflect.DeepEqual(retained.Data, expected.Data) || !reflect.DeepEqual(retained.Actor, expected.Actor) {
			return store.PrivacySubjectErasure{}, fmt.Errorf(
				"%w: retained privacy completion differs from its durable preparation",
				store.ErrIdempotencyConflict,
			)
		}
		if err := o.proj.Apply(ctx, retained); err != nil {
			return store.PrivacySubjectErasure{}, err
		}
	} else if _, err := o.emitPrepared(ctx, expected); err != nil {
		return store.PrivacySubjectErasure{}, err
	}
	return prepared.PrivacySubjectErasure, nil
}

func (o *Orchestrator) recoverPrivacyErasure(
	ctx context.Context,
	tenantID, subject string,
	identity PrivacySubjectErasureIdentity,
	requestBinding string,
) (store.PrivacySubjectErasure, bool, error) {
	if authoritative, found, err := o.findPrivacyErasureOperation(
		ctx, tenantID, subject, identity, requestBinding,
	); err != nil || found {
		return authoritative, found, err
	}

	// JetStream's Msg-Id deduplication collapses live races, while replay heals
	// the append-ACK/projection-failure gap. Once healed, the independent
	// PostgreSQL operation record is the long-window authority even if retention
	// moves this event from the live stream into the signed archive.
	canonical, found, err := o.findPrivacyErasureEvent(ctx, identity.EventID)
	if err != nil || !found {
		return store.PrivacySubjectErasure{}, false, err
	}
	authoritative, err := privacyErasureFromEvent(
		canonical, tenantID, subject, identity, requestBinding,
	)
	if err != nil {
		return store.PrivacySubjectErasure{}, false, err
	}
	if err := o.proj.Apply(ctx, canonical); err != nil {
		return store.PrivacySubjectErasure{}, false,
			fmt.Errorf("orchestrator: recover canonical privacy erasure projection: %w", err)
	}
	return authoritative, true, nil
}

func (o *Orchestrator) findPrivacyErasureOperation(
	ctx context.Context,
	tenantID, subject string,
	identity PrivacySubjectErasureIdentity,
	requestBinding string,
) (store.PrivacySubjectErasure, bool, error) {
	op, err := o.store.GetPrivacySubjectErasureOperationByEventID(ctx, tenantID, identity.EventID)
	if errors.Is(err, pgx.ErrNoRows) {
		return store.PrivacySubjectErasure{}, false, nil
	}
	if err != nil {
		return store.PrivacySubjectErasure{}, false, err
	}
	expectedSubjectRef := privacy.SubjectRef(tenantID, subject)
	if !crypto.ConstantTimeEqual([]byte(op.OperationID), []byte(identity.OperationID)) ||
		!crypto.ConstantTimeEqual([]byte(op.RequestBinding), []byte(requestBinding)) ||
		!crypto.ConstantTimeEqual([]byte(op.EventID), []byte(identity.EventID)) ||
		!crypto.ConstantTimeEqual([]byte(op.SubjectRef), []byte(expectedSubjectRef)) {
		return store.PrivacySubjectErasure{}, false,
			fmt.Errorf("%w: privacy erasure operation belongs to another command", ErrIdempotencyConflict)
	}
	return op.PrivacySubjectErasure, true, nil
}

func (o *Orchestrator) findPrivacyErasureEvent(ctx context.Context, eventID string) (events.Event, bool, error) {
	var found events.Event
	err := o.log.Replay(ctx, 1, func(ev events.Event) error {
		if ev.ID != eventID {
			return nil
		}
		found = ev
		return errPrivacyErasureEventFound
	})
	if errors.Is(err, errPrivacyErasureEventFound) {
		return found, true, nil
	}
	if err != nil {
		return events.Event{}, false, fmt.Errorf("orchestrator: find canonical privacy erasure event: %w", err)
	}
	return events.Event{}, false, nil
}

func privacyErasureFromEvent(
	ev events.Event,
	tenantID, subject string,
	identity PrivacySubjectErasureIdentity,
	requestBinding string,
) (store.PrivacySubjectErasure, error) {
	if ev.ID != identity.EventID ||
		ev.Type != projections.EventPrivacySubjectErased ||
		ev.TenantID != tenantID ||
		ev.SchemaVersion < projections.PrivacySubjectErasedOperationEventSchemaVersion ||
		ev.SchemaVersion > projections.PrivacySubjectErasedEventSchemaVersion {
		return store.PrivacySubjectErasure{}, fmt.Errorf("%w: privacy erasure event identity belongs to another command", ErrIdempotencyConflict)
	}
	var payload projections.PrivacySubjectErased
	if err := json.Unmarshal(ev.Data, &payload); err != nil {
		return store.PrivacySubjectErasure{}, fmt.Errorf("orchestrator: decode canonical privacy erasure event: %w", err)
	}
	if err := projections.ValidatePrivacySubjectErasedPayload(ev, payload); err != nil {
		return store.PrivacySubjectErasure{}, fmt.Errorf("%w: invalid canonical privacy erasure event: %v", ErrIdempotencyConflict, err)
	}
	expectedSubjectRef := privacy.SubjectRef(tenantID, subject)
	if !crypto.ConstantTimeEqual([]byte(payload.OperationID), []byte(identity.OperationID)) ||
		!crypto.ConstantTimeEqual([]byte(payload.RequestBinding), []byte(requestBinding)) ||
		!crypto.ConstantTimeEqual([]byte(payload.SubjectRef), []byte(expectedSubjectRef)) {
		return store.PrivacySubjectErasure{}, fmt.Errorf("%w: privacy erasure key belongs to another command", ErrIdempotencyConflict)
	}
	return store.PrivacySubjectErasure{
		TenantID:       tenantID,
		SubjectRef:     payload.SubjectRef,
		RequestedByRef: payload.RequestedByRef,
		Reason:         payload.Reason,
		Selectors:      payload.Selectors,
		Counts:         payload.Counts,
		ErasedAt:       ev.Time,
	}, nil
}

func sanitizedPrivacyErasureActor(ctx context.Context, tenantID, subject string) *events.Actor {
	actor, ok := events.ActorFromContext(ctx)
	if !ok {
		return nil
	}
	actor.Roles = append([]string(nil), actor.Roles...)
	actor.Subject = sanitizePrivacyErasureText(tenantID, subject, actor.Subject)
	for index := range actor.Roles {
		actor.Roles[index] = sanitizePrivacyErasureText(tenantID, subject, actor.Roles[index])
	}
	return &actor
}

func sanitizePrivacyErasureText(tenantID, subject, value string) string {
	if subject == "" || value == "" {
		return value
	}
	placeholder := privacy.Placeholder(privacy.SubjectRef(tenantID, subject))
	variants := []string{subject, url.QueryEscape(subject), url.PathEscape(subject)}
	if encoded, err := json.Marshal(subject); err == nil && len(encoded) >= 2 {
		variants = append(variants, string(encoded[1:len(encoded)-1]))
	}
	for _, variant := range variants {
		if variant != "" {
			value = strings.ReplaceAll(value, variant, placeholder)
		}
	}
	return value
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

// AttestPrivacyArchiveErasure records operator evidence that a pre-erasure backup
// or signed audit archive was deleted, placed under legal hold, or made
// unrecoverable by cryptographic shredding. The event carries subject_ref, not the
// raw subject, and redacts the raw subject from operator-supplied evidence text.
func (o *Orchestrator) AttestPrivacyArchiveErasure(ctx context.Context, tenantID, subject string, in store.PrivacyArchiveErasureAttestation) (store.PrivacyArchiveErasureAttestation, error) {
	if tenantID == "" {
		return store.PrivacyArchiveErasureAttestation{}, fmt.Errorf("orchestrator: archive erasure attestation requires tenant id (AN-1)")
	}
	subject = strings.TrimSpace(subject)
	if subject == "" {
		return store.PrivacyArchiveErasureAttestation{}, fmt.Errorf("orchestrator: archive erasure attestation requires subject")
	}
	in.ArtifactType = strings.TrimSpace(in.ArtifactType)
	in.Action = strings.TrimSpace(in.Action)
	if in.ArtifactType != "backup" && in.ArtifactType != "signed_audit_archive" {
		return store.PrivacyArchiveErasureAttestation{}, fmt.Errorf("orchestrator: archive erasure artifact_type must be backup or signed_audit_archive")
	}
	if in.Action != "deleted" && in.Action != "legal_hold" && in.Action != "cryptographic_shred" {
		return store.PrivacyArchiveErasureAttestation{}, fmt.Errorf("orchestrator: archive erasure action must be deleted, legal_hold, or cryptographic_shred")
	}
	subjectRef := privacy.SubjectRef(tenantID, subject)
	placeholder := privacy.Placeholder(subjectRef)
	out := store.PrivacyArchiveErasureAttestation{
		TenantID:      tenantID,
		AttestationID: uuid.NewString(),
		SubjectRef:    subjectRef,
		ArtifactType:  in.ArtifactType,
		ArtifactURI:   redactArchiveEvidenceValue(strings.TrimSpace(in.ArtifactURI), subject, placeholder),
		Action:        in.Action,
		Reason:        redactArchiveEvidenceValue(strings.TrimSpace(in.Reason), subject, placeholder),
		EvidenceRefs:  redactArchiveEvidenceRefs(in.EvidenceRefs, subject, placeholder),
		HeldUntil:     in.HeldUntil,
	}
	if actor, ok := events.ActorFromContext(ctx); ok {
		out.RequestedByRef = privacy.SubjectRef(tenantID, actor.Subject)
	}
	payload, err := json.Marshal(projections.PrivacyArchiveErasureAttested{
		AttestationID:  out.AttestationID,
		SubjectRef:     out.SubjectRef,
		RequestedByRef: out.RequestedByRef,
		ArtifactType:   out.ArtifactType,
		ArtifactURI:    out.ArtifactURI,
		Action:         out.Action,
		Reason:         out.Reason,
		EvidenceRefs:   out.EvidenceRefs,
		HeldUntil:      out.HeldUntil,
	})
	if err != nil {
		return store.PrivacyArchiveErasureAttestation{}, err
	}
	ev, err := o.emit(ctx, projections.EventPrivacyArchiveErasureAttested, tenantID, payload)
	if err != nil {
		return store.PrivacyArchiveErasureAttestation{}, err
	}
	out.AttestedAt = ev.Time
	return out, nil
}

func redactArchiveEvidenceRefs(refs []string, subject, placeholder string) []string {
	if len(refs) == 0 {
		return []string{}
	}
	out := make([]string, 0, len(refs))
	for _, ref := range refs {
		ref = redactArchiveEvidenceValue(strings.TrimSpace(ref), subject, placeholder)
		if ref != "" {
			out = append(out, ref)
		}
	}
	return out
}

func redactArchiveEvidenceValue(value, subject, placeholder string) string {
	if value == "" || subject == "" {
		return value
	}
	return strings.ReplaceAll(value, subject, placeholder)
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

// EnsureIdentity creates one identity at a caller-supplied deterministic id, or
// returns the already-projected identity after a worker restart. Only durable
// receivers should use it; public creation continues to use random ids.
func (o *Orchestrator) EnsureIdentity(ctx context.Context, tenantID, id string, in store.Identity) (store.Identity, error) {
	id = strings.TrimSpace(id)
	if id == "" {
		return store.Identity{}, errors.New("orchestrator: ensure identity requires id")
	}
	if existing, err := o.store.GetIdentity(ctx, tenantID, id); err == nil {
		if existing.Kind != in.Kind || existing.OwnerID != in.OwnerID || !sameOptionalString(existing.IssuerID, in.IssuerID) {
			return store.Identity{}, fmt.Errorf("orchestrator: deterministic identity %s belongs to another command", id)
		}
		return existing, nil
	} else if !errors.Is(err, pgx.ErrNoRows) {
		return store.Identity{}, err
	}
	payload, err := json.Marshal(projections.IdentityCreated{
		ID: id, Kind: string(in.Kind), Name: in.Name, OwnerID: in.OwnerID, IssuerID: in.IssuerID, Attributes: in.Attributes,
	})
	if err != nil {
		return store.Identity{}, err
	}
	ev, err := o.emitPrepared(ctx, events.Event{
		ID:   uuid.NewSHA1(uuid.NameSpaceOID, []byte("fleet-identity-event\x00"+tenantID+"\x00"+id)).String(),
		Type: projections.EventIdentityCreated, TenantID: tenantID, Data: payload,
	})
	if err != nil {
		return store.Identity{}, err
	}
	out := in
	out.ID, out.TenantID, out.Status, out.CreatedAt = id, tenantID, string(StateRequested), ev.Time
	return out, nil
}

func sameOptionalString(a, b *string) bool {
	if a == nil || b == nil {
		return a == nil && b == nil
	}
	return *a == *b
}

// UpsertDeploymentTarget records a tenant-owned connector target. The target
// config is metadata and credential references only; secret bytes stay outside
// this read model.
func (o *Orchestrator) UpsertDeploymentTarget(ctx context.Context, tenantID string, in store.DeploymentTarget) (store.DeploymentTarget, error) {
	id := strings.TrimSpace(in.ID)
	if id == "" {
		id = uuid.NewString()
	}
	enabled := in.Enabled
	if !in.EnabledSet {
		enabled = true
	}
	payload, err := json.Marshal(projections.DeploymentTargetUpserted{
		ID: id, Name: strings.TrimSpace(in.Name), Connector: strings.TrimSpace(in.Type), Config: in.Config, Enabled: &enabled,
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

// DeploymentRoute is the exported form, so a rollback derives the remote object
// from the SAME string a deploy did (epic D4).
//
// This matters more than it looks. Three connector families derive the installed
// object's name from the target string they are handed; a deploy is handed the
// routing attribute resolved here, while the rollback route naturally reaches for
// the target row's display Name. Where an operator set a routing key in the
// target config, those differ — and a rollback would then look for an object
// name that was never installed, reporting "the predecessor is not installed"
// for one that is sitting right there.
func DeploymentRoute(target store.DeploymentTarget) string { return deploymentRoute(target) }

func deploymentRoute(target store.DeploymentTarget) string {
	if len(target.Config) == 0 {
		return ""
	}
	var cfg map[string]any
	if err := json.Unmarshal(target.Config, &cfg); err != nil {
		return ""
	}
	// endpoint selects the management API. It is not the remote object that
	// receives the certificate. Treating it as the deployment route makes HTTP
	// connectors upload an object literally named after their own URL.
	for _, key := range []string{"target", "route", "deployment_route", "object", "virtual_service"} {
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
	return o.recordCertificateCommand(ctx, tenantID, in, nil)
}

// recordCertificateCommand binds one issued result to one immutable event.
// The predecessor is payload data, not identity: changing or removing it
// under the same tenant, fingerprint and key must conflict across both APIs.
// Empty keys remain ordinary observations with a new event on each call.
func (o *Orchestrator) recordCertificateCommand(ctx context.Context, tenantID string, in store.Certificate, replacesID *string) (store.Certificate, error) {
	if len(in.CertificatePEM) != 0 {
		public, err := certinfo.ParsePublicPEMChain(in.CertificatePEM, in.CertificateDER)
		if err != nil {
			return store.Certificate{}, err
		}
		in.CertificatePEM = public
	}
	id := uuid.NewString()
	eventID := ""
	if in.IssuanceIdempotencyKey != "" {
		// Keep the existing identity for lifecycle issuance; renewal, agent CSR
		// and other keyed issuers now use the same retry contract.
		tenantUUID, err := uuid.Parse(tenantID)
		if err != nil {
			return store.Certificate{}, fmt.Errorf("orchestrator: invalid certificate tenant: %w", err)
		}
		command := tenantUUID.String() + "\x00" + in.Fingerprint + "\x00" + in.IssuanceIdempotencyKey
		id = uuid.NewSHA1(uuid.NameSpaceOID, []byte("lifecycle-certificate-row\x00"+command)).String()
		eventID = uuid.NewSHA1(uuid.NameSpaceOID, []byte("lifecycle-certificate-event\x00"+command)).String()
	}
	material := certificateRecordedPayload(id, in, nil, nil)
	material.ReplacesID = replacesID
	payload, err := json.Marshal(material)
	if err != nil {
		return store.Certificate{}, err
	}
	if _, err := o.emitPrepared(ctx, events.Event{ID: eventID, Type: projections.EventCertificateRecorded, SchemaVersion: certificateRecordingSchema(in), TenantID: tenantID, Data: payload}); err != nil {
		return store.Certificate{}, err
	}
	return o.store.GetCertificateByFingerprint(ctx, tenantID, in.Fingerprint)
}

// CertificateCustodyAttestationEventID gives one installed certificate on one
// claim attempt a retry-stable immutable receipt identity.
func CertificateCustodyAttestationEventID(tenantID, fingerprint string, jobID int64, attempt int) string {
	return uuid.NewSHA1(uuid.NameSpaceOID, []byte(fmt.Sprintf(
		"certificate-custody-attestation\x00%s\x00%s\x00%d\x00%d",
		tenantID, fingerprint, jobID, attempt))).String()
}

// AttestCertificateCustody records and projects the exact verified terminal
// receipt. A retry may replay the same bytes; changed custody under the same
// job attempt is an idempotency conflict rather than a mutable correction.
func (o *Orchestrator) AttestCertificateCustody(ctx context.Context, tenantID string,
	in projections.CertificateCustodyAttested) error {
	payload, err := json.Marshal(in)
	if err != nil {
		return err
	}
	_, err = o.emitPreparedExact(ctx, events.Event{
		ID:   CertificateCustodyAttestationEventID(tenantID, in.Fingerprint, in.JobID, in.Attempt),
		Type: projections.EventCertificateCustodyAttested, TenantID: tenantID, Data: payload,
	})
	return err
}

// RecordCertificateWithApproval records an approval-gated certificate and
// consumes the exact immutable authority in the same tenant transaction as the
// certificate projection. Its event and inventory IDs are deterministic from
// request ID + digest, so a retry after append or projection returns the one
// canonical certificate instead of consuming the grant twice.
func (o *Orchestrator) RecordCertificateWithApproval(ctx context.Context, tenantID string, in store.Certificate, approval store.OperationApprovalUse, binding ephemerallib.ApprovalBinding, requestBindings ...string) (store.Certificate, error) {
	if strings.TrimSpace(tenantID) == "" || strings.TrimSpace(approval.RequestID) == "" ||
		strings.TrimSpace(approval.IntentDigest) == "" {
		return store.Certificate{}, fmt.Errorf("orchestrator: approved certificate requires tenant, request id, and intent digest")
	}
	requestBinding, err := binding.Digest()
	if err != nil {
		return store.Certificate{}, err
	}
	if len(requestBindings) > 0 {
		requestBinding = requestBindings[0]
	}
	eventID := CertificateApprovalEventID(tenantID, approval)
	rowID := projections.CertificateApprovalRowID(tenantID, approval)

	// A claimed fence is the durable first command. Do not manufacture a new
	// event timestamp while it survives: that would make an exact retry differ
	// from the bytes already authorized before the crash. The request-binding and
	// capability checks below keep a caller from using somebody else's fence as
	// a result cache.
	if fence, fenceErr := o.store.GetApprovedTargetFence(ctx, tenantID,
		store.ApprovedTargetEphemeralCertificate, binding.ClientRequestIDSHA256); fenceErr == nil {
		if fence.EventID != eventID || fence.EventType != projections.EventCertificateRecorded ||
			fence.SchemaVersion != projections.CertificateApprovalEventSchemaVersion ||
			!crypto.ConstantTimeEqual([]byte(fence.RequestBinding), []byte(requestBinding)) {
			return store.Certificate{}, fmt.Errorf("%w: approved certificate retry differs from durable command", store.ErrIdempotencyConflict)
		}
		request, err := o.store.GetOperationApproval(ctx, tenantID, approval.RequestID)
		if err != nil {
			return store.Certificate{}, err
		}
		if err := validateApprovedCertificateReplayUse(tenantID, request, approval, eventID); err != nil {
			return store.Certificate{}, err
		}
		attemptActor := approvedCertificateActor(ctx)
		if err := store.ValidateApprovedTargetActorPrivacyRewrite(tenantID,
			attemptActor, request.Requester, fence.Actor, approval.Requester); err != nil {
			return store.Certificate{}, fmt.Errorf("%w: approved certificate retry actor differs", err)
		}
		return o.ProjectApprovedCertificateFence(ctx, tenantID, fence)
	} else if !store.IsNotFound(fenceErr) {
		return store.Certificate{}, fenceErr
	}

	// Search retained source-of-truth history before checking target validity.
	// The approval row is then locked and revalidated. This ordering lets an
	// exact completed retry recover after the certificate has expired, while a
	// supersession that commits during the outside history scan wins before any
	// newly prepared certificate can report a less-authoritative drift error.
	retained, retainedFound, err := o.log.EventByID(ctx, eventID)
	if err != nil {
		return store.Certificate{}, err
	}
	var request store.OperationApprovalRequest
	err = o.store.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		var lockErr error
		request, lockErr = o.store.GetOperationApprovalForUpdateTx(ctx, tx, tenantID, approval.RequestID)
		if lockErr != nil {
			return lockErr
		}
		return validateApprovedCertificateReplayUse(tenantID, request, approval, eventID)
	})
	if err != nil {
		return store.Certificate{}, err
	}
	if retainedFound {
		canonical, currentUse, err := validateRetainedApprovedCertificate(ctx, tenantID,
			retained, rowID, in, approval, binding, request)
		if err != nil {
			return store.Certificate{}, err
		}
		if result, getErr := o.store.GetCertificate(ctx, tenantID, rowID); getErr == nil {
			return result, nil
		} else if !store.IsNotFound(getErr) {
			return store.Certificate{}, getErr
		}
		// Restore a lost read projection from the retained source event. Approval
		// text may have been erased after the event was written, so project the
		// exact current capability spelling after the semantic proof above.
		canonical.Approval = &currentUse
		projectData, err := json.Marshal(canonical)
		if err != nil {
			return store.Certificate{}, err
		}
		restored := retained
		restored.Data = projectData
		if err := o.proj.Apply(ctx, restored); err != nil {
			return store.Certificate{}, fmt.Errorf("orchestrator: restore retained approved certificate: %w", err)
		}
		return o.store.GetCertificate(ctx, tenantID, rowID)
	}
	if request.Status == store.ApprovalStatusConsumed {
		return store.Certificate{}, fmt.Errorf("%w: consumed certificate approval has no retained target event", store.ErrIdempotencyConflict)
	}

	candidate := certificateRecordedPayload(rowID, in, &approval, &binding)
	payload, err := json.Marshal(candidate)
	if err != nil {
		return store.Certificate{}, err
	}
	candidateEvent := events.Event{
		ID: eventID, Type: projections.EventCertificateRecorded,
		TenantID: tenantID, Time: approvedCertificateEventTime(time.Now()),
		SchemaVersion: projections.CertificateApprovalEventSchemaVersion,
		Data:          payload,
	}
	candidateEvent.Actor = approvedCertificateActor(ctx)
	if err := projections.ValidateApprovedCertificatePayload(candidateEvent, candidate); err != nil {
		return store.Certificate{}, err
	}
	semanticDigest, err := projections.ApprovedCertificateSemanticDigest(candidateEvent, candidate)
	if err != nil {
		return store.Certificate{}, err
	}
	fence, _, err := o.store.ClaimApprovedTargetFence(ctx, store.ApprovedTargetFence{
		TenantID: tenantID, TargetKind: store.ApprovedTargetEphemeralCertificate,
		CommandKey: binding.ClientRequestIDSHA256, RequestBinding: requestBinding,
		EventID: eventID, EventType: projections.EventCertificateRecorded,
		SchemaVersion: projections.CertificateApprovalEventSchemaVersion,
		EventTime:     candidateEvent.Time, Actor: candidateEvent.Actor, Payload: payload, SemanticDigest: semanticDigest,
	}, approval)
	if err != nil {
		return store.Certificate{}, err
	}
	return o.ProjectApprovedCertificateFence(ctx, tenantID, fence)
}

func approvedCertificateActor(ctx context.Context) *events.Actor {
	actor, ok := events.ActorFromContext(ctx)
	if !ok {
		return nil
	}
	return &actor
}

// approvedCertificateEventTime crosses the SQL fence and the event log as part
// of one semantic digest. PostgreSQL timestamps stop at microseconds, so remove
// sub-microsecond data before hashing; otherwise a valid command can look changed
// after the fence is read back.
func approvedCertificateEventTime(now time.Time) time.Time {
	return now.UTC().Truncate(time.Microsecond)
}

// validateApprovedCertificateReplayUse separates immutable capability identity
// from execution state. A consumed exact event remains replayable after expiry;
// every unconsumed request still honors expiry, quorum, and supersession.
func validateApprovedCertificateReplayUse(
	tenantID string,
	request store.OperationApprovalRequest,
	use store.OperationApprovalUse,
	eventID string,
) error {
	if request.TenantID != tenantID || request.ID != use.RequestID {
		return store.ErrApprovalDrifted
	}
	if err := store.ValidateOperationApprovalUseBinding(request, use); err != nil {
		if request.Status != store.ApprovalStatusConsumed || request.ConsumedEventID != eventID {
			return err
		}
		current, currentErr := store.OperationApprovalUseFromRequest(request)
		if currentErr != nil {
			return currentErr
		}
		if privacyErr := store.ValidateApprovedTargetPrivacyRewrite(tenantID, use, current, use); privacyErr != nil {
			return err
		}
	}
	switch request.Status {
	case store.ApprovalStatusConsumed:
		if request.ConsumedEventID != eventID {
			return store.ErrApprovalConsumed
		}
		return nil
	case store.ApprovalStatusSuperseded:
		return store.ErrApprovalSuperseded
	case store.ApprovalStatusExpired:
		return store.ErrApprovalExpired
	case store.ApprovalStatusApproved:
		if !time.Now().UTC().Before(request.ExpiresAt) {
			return store.ErrApprovalExpired
		}
		if request.ApprovalCount < request.RequiredApprovals {
			return store.ErrApprovalNotReady
		}
		return nil
	default:
		return store.ErrApprovalNotReady
	}
}

func validateRetainedApprovedCertificate(
	ctx context.Context,
	tenantID string,
	retained events.Event,
	rowID string,
	in store.Certificate,
	use store.OperationApprovalUse,
	binding ephemerallib.ApprovalBinding,
	request store.OperationApprovalRequest,
) (projections.CertificateRecorded, store.OperationApprovalUse, error) {
	if retained.ID != CertificateApprovalEventID(tenantID, use) ||
		retained.Type != projections.EventCertificateRecorded || retained.TenantID != tenantID ||
		retained.SchemaVersion != projections.CertificateApprovalEventSchemaVersion {
		return projections.CertificateRecorded{}, store.OperationApprovalUse{},
			fmt.Errorf("%w: retained approved certificate envelope differs", store.ErrIdempotencyConflict)
	}
	var canonical projections.CertificateRecorded
	if err := json.Unmarshal(retained.Data, &canonical); err != nil {
		return projections.CertificateRecorded{}, store.OperationApprovalUse{},
			fmt.Errorf("orchestrator: decode retained approved certificate: %w", err)
	}
	if err := projections.ValidateApprovedCertificatePayload(retained, canonical); err != nil {
		return projections.CertificateRecorded{}, store.OperationApprovalUse{}, err
	}
	if canonical.Approval == nil {
		return projections.CertificateRecorded{}, store.OperationApprovalUse{},
			fmt.Errorf("%w: retained approved certificate lacks authority", store.ErrIdempotencyConflict)
	}
	currentUse, err := store.OperationApprovalUseFromRequest(request)
	if err != nil {
		return projections.CertificateRecorded{}, store.OperationApprovalUse{}, err
	}
	if err := store.ValidateOperationApprovalUseBinding(request, *canonical.Approval); err != nil {
		if privacyErr := store.ValidateApprovedTargetPrivacyRewrite(tenantID,
			use, currentUse, *canonical.Approval); privacyErr != nil {
			return projections.CertificateRecorded{}, store.OperationApprovalUse{}, err
		}
	}
	attemptActor := approvedCertificateActor(ctx)
	if err := store.ValidateApprovedTargetActorPrivacyRewrite(tenantID,
		attemptActor, currentUse.Requester, retained.Actor, use.Requester); err != nil {
		return projections.CertificateRecorded{}, store.OperationApprovalUse{},
			fmt.Errorf("%w: retained approved certificate actor differs", err)
	}
	attempt := certificateRecordedPayload(rowID, in, &use, &binding)
	attemptEvent := retained
	attemptEvent.Actor = attemptActor
	attemptEvent.Data = nil
	if err := projections.ValidateApprovedCertificatePayload(attemptEvent, attempt); err != nil {
		return projections.CertificateRecorded{}, store.OperationApprovalUse{}, err
	}
	wantSemantic, err := projections.ApprovedCertificateSemanticDigest(attemptEvent, attempt)
	if err != nil {
		return projections.CertificateRecorded{}, store.OperationApprovalUse{}, err
	}
	gotSemantic, err := projections.ApprovedCertificateSemanticDigest(retained, canonical)
	if err != nil {
		return projections.CertificateRecorded{}, store.OperationApprovalUse{}, err
	}
	if !crypto.ConstantTimeEqual([]byte(wantSemantic), []byte(gotSemantic)) {
		return projections.CertificateRecorded{}, store.OperationApprovalUse{},
			fmt.Errorf("%w: retained approved certificate command differs", store.ErrIdempotencyConflict)
	}
	return canonical, currentUse, nil
}

// CertificateApprovalEventID is the stable target-event identity used both by
// the command and by crash recovery to prove a consumed request produced this
// exact certificate issuance.
func CertificateApprovalEventID(tenantID string, approval store.OperationApprovalUse) string {
	return projections.CertificateApprovalEventID(tenantID, approval)
}

// ProjectApprovedCertificateFence reconciles a command that already claimed its
// approval in PostgreSQL. A retry scans retained history before publishing, so it
// does not depend on JetStream still remembering the message ID. If restore lost
// the event, the exact fenced bytes and timestamp are republished.
func (o *Orchestrator) ProjectApprovedCertificateFence(ctx context.Context, tenantID string, fence store.ApprovedTargetFence) (store.Certificate, error) {
	var result store.Certificate
	err := o.store.WithPrivacyRecoveryBarrier(ctx, tenantID,
		"approved-certificate recovery privacy barrier", func(barrierCtx context.Context) error {
			latest, err := o.store.GetApprovedTargetFence(barrierCtx, tenantID,
				store.ApprovedTargetEphemeralCertificate, fence.CommandKey)
			if err != nil {
				return err
			}
			if latest.EventID != fence.EventID || latest.RequestBinding != fence.RequestBinding {
				return fmt.Errorf("%w: approved certificate fence changed across privacy barrier", store.ErrIdempotencyConflict)
			}
			result, err = o.projectApprovedCertificateFenceUnbarriered(barrierCtx, tenantID, latest)
			return err
		})
	return result, err
}

func (o *Orchestrator) projectApprovedCertificateFenceUnbarriered(
	ctx context.Context,
	tenantID string,
	fence store.ApprovedTargetFence,
) (store.Certificate, error) {
	if fence.TenantID != tenantID || fence.TargetKind != store.ApprovedTargetEphemeralCertificate {
		return store.Certificate{}, fmt.Errorf("%w: approved certificate fence scope differs", store.ErrIdempotencyConflict)
	}
	var proposed projections.CertificateRecorded
	if err := json.Unmarshal(fence.Payload, &proposed); err != nil {
		return store.Certificate{}, fmt.Errorf("orchestrator: decode certificate fence before locking: %w", err)
	}
	var canonical projections.CertificateRecorded
	err := o.store.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		// Match the inline/tail projector lock order: certificate first, then
		// approval. The public caller already owns the privacy-history barrier.
		if err := o.store.LockCertificateRecordingTx(ctx, tx, tenantID, proposed.Fingerprint); err != nil {
			return err
		}
		if err := o.catchUpCertificateRecordingTx(ctx, tx, tenantID, proposed.Fingerprint); err != nil {
			return err
		}
		locked, use, privacyRewritten, err := o.store.LockApprovedTargetFenceTx(ctx, tx, tenantID,
			store.ApprovedTargetEphemeralCertificate, fence.CommandKey)
		if err != nil {
			return err
		}
		var payload projections.CertificateRecorded
		if err := json.Unmarshal(locked.Payload, &payload); err != nil {
			return fmt.Errorf("orchestrator: decode approved certificate fence: %w", err)
		}
		if payload.Fingerprint != proposed.Fingerprint {
			return fmt.Errorf("%w: approved certificate fingerprint changed across lock", store.ErrIdempotencyConflict)
		}
		originalApproval := payload.Approval
		payload.Approval = &use
		data, err := json.Marshal(payload)
		if err != nil {
			return err
		}
		candidate := events.Event{
			ID: locked.EventID, Type: locked.EventType, TenantID: tenantID,
			Time: locked.EventTime, SchemaVersion: locked.SchemaVersion, Actor: locked.Actor, Data: data,
		}
		wantSemantic, err := projections.ApprovedCertificateSemanticDigest(candidate, payload)
		if err != nil || wantSemantic != locked.SemanticDigest {
			if err == nil {
				err = store.ErrIdempotencyConflict
			}
			return fmt.Errorf("%w: approved certificate fence semantic digest differs", err)
		}
		material, _, err := projections.CertificateRecordingMaterial(candidate)
		if err != nil {
			return err
		}
		if err := o.store.ValidateCertificateIssuanceBindingTx(ctx, tx, tenantID, material); err != nil {
			return err
		}
		// Refresh under the same lock: another process may have appended while
		// this process waited. Never rely on the pre-lock absence observation.
		retained, retainedFound, err := o.log.EventByID(ctx, locked.EventID)
		if err != nil {
			return err
		}
		event := retained
		if !retainedFound {
			if err := o.guardCertificateRecordingAppendTx(ctx, tx, tenantID, material); err != nil {
				return err
			}
			event, err = o.log.Append(ctx, candidate)
			if err != nil {
				return err
			}
		}
		if event.ID != locked.EventID || event.Type != locked.EventType || event.TenantID != tenantID ||
			event.SchemaVersion != locked.SchemaVersion || !event.Time.Equal(locked.EventTime) {
			return fmt.Errorf("%w: canonical approved certificate event envelope differs", store.ErrIdempotencyConflict)
		}
		if err := json.Unmarshal(event.Data, &canonical); err != nil {
			return fmt.Errorf("orchestrator: decode canonical approved certificate: %w", err)
		}
		gotSemantic, err := projections.ApprovedCertificateSemanticDigest(event, canonical)
		if err != nil || gotSemantic != locked.SemanticDigest {
			if err == nil {
				err = store.ErrIdempotencyConflict
			}
			return fmt.Errorf("%w: canonical approved certificate command differs", err)
		}
		if canonical.Approval == nil || originalApproval == nil {
			return fmt.Errorf("%w: canonical approved certificate lacks approval", store.ErrIdempotencyConflict)
		}
		if privacyRewritten {
			if err := store.ValidateApprovedTargetActorPrivacyRewrite(tenantID,
				locked.Actor, use.Requester, event.Actor, originalApproval.Requester); err != nil {
				return fmt.Errorf("%w: canonical approved certificate actor privacy rewrite differs", err)
			}
			if retainedFound {
				if err := store.ValidateApprovedTargetPrivacyRewrite(tenantID, *originalApproval, use, *canonical.Approval); err != nil {
					return fmt.Errorf("%w: canonical approved certificate privacy rewrite differs", err)
				}
			}
			canonical.Approval = &use
			projectData, err := json.Marshal(canonical)
			if err != nil {
				return err
			}
			event.Data = projectData
		} else if !reflect.DeepEqual(event.Actor, locked.Actor) || !reflect.DeepEqual(*canonical.Approval, *originalApproval) {
			return fmt.Errorf("%w: canonical approved certificate approval differs", store.ErrIdempotencyConflict)
		}
		return o.proj.ApplyTx(ctx, tx, event)
	})
	if err != nil {
		return store.Certificate{}, err
	}
	return o.store.GetCertificateByFingerprint(ctx, tenantID, canonical.Fingerprint)
}

func certificateRecordedPayload(id string, in store.Certificate, approval *store.OperationApprovalUse, approvalBinding *ephemerallib.ApprovalBinding) projections.CertificateRecorded {
	sans := in.SANs
	if sans == nil {
		sans = []string{}
	}
	return projections.CertificateRecorded{
		ID: id, CAID: in.CAID, OwnerID: in.OwnerID, Subject: in.Subject, SANs: sans, Issuer: in.Issuer, Serial: in.Serial,
		Fingerprint: in.Fingerprint, KeyAlgorithm: in.KeyAlgorithm, NotBefore: in.NotBefore, NotAfter: in.NotAfter,
		ValidityAnchor:     in.ValidityAnchor,
		DeploymentLocation: in.DeploymentLocation, Source: in.Source,
		CertificateDER:         in.CertificateDER,
		CertificatePEM:         in.CertificatePEM,
		IssuanceIdempotencyKey: in.IssuanceIdempotencyKey,
		IssuanceRequestBinding: in.IssuanceRequestBinding,
		BrokerIssuance:         in.BrokerIssuance,
		KeyOrigin:              in.KeyOrigin,
		KeyStorage:             in.KeyStorage,
		KeyExportable:          in.KeyExportable,
		KeyGeneratedBy:         in.KeyGeneratedBy,
		Approval:               approval,
		ApprovalBinding:        approvalBinding,
	}
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

// RevokeCertificateForCAWithEventID is the durable receiver form used by H3.
// The stable event identity closes the worker crash window: a retry may project
// the same revocation again, but it cannot append a second semantic revocation.
func (o *Orchestrator) RevokeCertificateForCAWithEventID(ctx context.Context, tenantID, eventID, fingerprint, serial, caID, reason string, reasonCode int) error {
	if strings.TrimSpace(eventID) == "" {
		return errors.New("orchestrator: revocation event id is required")
	}
	payload, err := json.Marshal(projections.CertificateRevoked{
		Fingerprint: fingerprint, CAID: caID, Serial: serial, Reason: reason, ReasonCode: reasonCode,
	})
	if err != nil {
		return err
	}
	_, err = o.emitPreparedExact(ctx, events.Event{
		ID: eventID, Type: projections.EventCertificateRevoked, TenantID: tenantID, Data: payload,
	})
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

// OffboardAgent records an agent.offboarded event and projects the agents read
// model to a terminal tombstone. The served mTLS channel rejects that tenant-scoped
// agent id before any future heartbeat, renewal, or inventory RPC can append work.
func (o *Orchestrator) OffboardAgent(ctx context.Context, tenantID, agentID, reason string) (store.Agent, error) {
	agentID = strings.TrimSpace(agentID)
	reason = strings.TrimSpace(reason)
	if agentID == "" {
		return store.Agent{}, fmt.Errorf("orchestrator: agent offboarding requires an agent id")
	}
	existing, err := o.store.GetAgent(ctx, tenantID, agentID)
	if err != nil {
		return store.Agent{}, err
	}
	actor := ""
	if a, ok := events.ActorFromContext(ctx); ok {
		actor = a.Subject
	}
	payload, err := json.Marshal(projections.AgentOffboarded{
		ID: agentID, Agent: existing.Name, Reason: reason, OffboardedBy: actor,
	})
	if err != nil {
		return store.Agent{}, err
	}
	if _, err := o.emit(ctx, projections.EventAgentOffboarded, tenantID, payload); err != nil {
		return store.Agent{}, err
	}
	return o.store.GetAgent(ctx, tenantID, agentID)
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
func (o *Orchestrator) CreateAPIToken(ctx context.Context, tenantID, subject string, scopes []string, expiresAt *time.Time) (store.APITokenRecord, []byte, error) {
	raw, hash, err := auth.GenerateAPIToken()
	if err != nil {
		return store.APITokenRecord{}, nil, err
	}
	id := uuid.NewString()
	payload, err := json.Marshal(projections.APITokenCreated{
		ID: id, TokenHash: hash, Subject: subject, Scopes: scopes, ExpiresAt: expiresAt,
	})
	if err != nil {
		secret.Wipe(raw)
		return store.APITokenRecord{}, nil, err
	}
	ev, err := o.emit(ctx, projections.EventAPITokenCreated, tenantID, payload)
	if err != nil {
		secret.Wipe(raw)
		return store.APITokenRecord{}, nil, err
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
// queued connector intent before an external connector worker produces a later
// delivered or failed receipt. A queued intent has zero attempts because no
// receiver I/O has happened yet.
func (o *Orchestrator) RecordConnectorDelivery(ctx context.Context, tenantID string, r store.ConnectorDeliveryReceipt) (store.ConnectorDeliveryReceipt, error) {
	return o.recordConnectorDelivery(ctx, tenantID, "", r)
}

// RecordConnectorDeliveryWithEventID is the durable-receiver form used when an
// enrolled agent reports the result of an outbox claim. The event ID is derived
// from the server-owned job binding, so a response loss can submit the same
// signed result again without appending a second immutable delivery fact. A
// changed body under the same ID fails closed.
func (o *Orchestrator) RecordConnectorDeliveryWithEventID(
	ctx context.Context,
	tenantID, eventID string,
	r store.ConnectorDeliveryReceipt,
) (store.ConnectorDeliveryReceipt, error) {
	if strings.TrimSpace(eventID) == "" {
		return store.ConnectorDeliveryReceipt{}, errors.New("orchestrator: connector delivery event id is required")
	}
	return o.recordConnectorDelivery(ctx, tenantID, eventID, r)
}

func (o *Orchestrator) recordConnectorDelivery(
	ctx context.Context,
	tenantID, eventID string,
	r store.ConnectorDeliveryReceipt,
) (store.ConnectorDeliveryReceipt, error) {
	if r.ID == "" {
		r.ID = uuid.NewString()
	}
	if r.Attempts == 0 && r.Status != "queued" {
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
	var ev events.Event
	if eventID == "" {
		ev, err = o.emit(ctx, projections.EventConnectorDeliveryRecorded, tenantID, payload)
	} else {
		ev, err = o.emitPreparedExact(ctx, events.Event{
			ID: eventID, Type: projections.EventConnectorDeliveryRecorded,
			TenantID: tenantID, Data: payload,
		})
	}
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
		IdempotencyKey: r.IdempotencyKey, RequestBinding: r.RequestBinding,
		InitialHTTPStatus: r.InitialHTTPStatus, InitialResponse: r.InitialResponse,
		TerminalReason: r.TerminalReason, CreatedBy: r.CreatedBy,
	})
	if err != nil {
		return store.RemediationPlaybookRun{}, err
	}
	var ev events.Event
	if err := o.store.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		var err error
		ev, err = o.log.Append(ctx, events.Event{Type: projections.EventRemediationPlaybookRunRecorded, TenantID: tenantID, Data: payload})
		if err != nil {
			return err
		}
		if err := o.proj.ApplyTx(ctx, tx, ev); err != nil {
			return err
		}
		if outboxDestination == "" {
			return nil
		}
		if o.outbox == nil {
			return fmt.Errorf("orchestrator: remediation playbook outbox is not configured")
		}
		_, err = o.outbox.EnqueueIfAbsent(ctx, tx, Entry{
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

// RecordConnectorRightSizeOperation appends and projects the deterministic
// durable command. The event projector atomically creates the queued run,
// receipt, and outbox intent. After projection this method reloads the row that
// won the key and compares it with the caller's command, so concurrent changed
// callers get a conflict and never inherit another caller's response.
func (o *Orchestrator) RecordConnectorRightSizeOperation(ctx context.Context, tenantID string, r store.RemediationPlaybookRun) (store.RemediationPlaybookRun, error) {
	identity := ConnectorRightSizeIdentityFor(tenantID, r.IdempotencyKey)
	if tenantID == "" || r.IdempotencyKey == "" || r.RequestBinding == "" ||
		r.ID != identity.OperationID || r.ConnectorDeliveryID == nil ||
		*r.ConnectorDeliveryID != identity.DeliveryID || r.Action != "right_size" ||
		r.InitialHTTPStatus == 0 || len(r.InitialResponse) == 0 {
		return store.RemediationPlaybookRun{}, fmt.Errorf("orchestrator: connector right-size operation is incomplete")
	}
	if r.CreatedAt.IsZero() {
		r.CreatedAt = time.Now().UTC()
	}
	r.UpdatedAt = r.CreatedAt
	payload, err := json.Marshal(projections.RemediationPlaybookRunRecorded{
		ID: r.ID, PlaybookID: r.PlaybookID, TargetIdentityID: r.TargetIdentityID,
		InventoryID: r.InventoryID, Status: r.Status, Phase: r.Phase, Action: r.Action,
		Reason: r.Reason, Connector: r.Connector, Target: r.Target,
		ConnectorDeliveryID: r.ConnectorDeliveryID, ScopeDelta: r.ScopeDelta,
		EvidenceRefs: r.EvidenceRefs, RollbackRefs: r.RollbackRefs,
		IdempotencyKey: r.IdempotencyKey, RequestBinding: r.RequestBinding,
		InitialHTTPStatus: r.InitialHTTPStatus, InitialResponse: r.InitialResponse,
		OutboxIdempotencyKey: identity.OutboxIdempotencyKey, CreatedBy: r.CreatedBy,
	})
	if err != nil {
		return store.RemediationPlaybookRun{}, err
	}
	ev, err := o.log.Append(ctx, events.Event{
		ID: identity.RequestedEventID, Type: projections.EventRemediationPlaybookRunRecorded,
		TenantID: tenantID, Time: r.CreatedAt, Data: payload,
	})
	if err != nil {
		return store.RemediationPlaybookRun{}, err
	}
	if err := o.store.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		return o.proj.ApplyTx(ctx, tx, ev)
	}); err != nil {
		if errors.Is(err, store.ErrIdempotencyConflict) {
			return store.RemediationPlaybookRun{}, ErrIdempotencyConflict
		}
		return store.RemediationPlaybookRun{}, err
	}
	authoritative, err := o.store.GetRemediationPlaybookRunByIdempotencyKey(ctx, tenantID, r.IdempotencyKey)
	if err != nil {
		return store.RemediationPlaybookRun{}, err
	}
	if authoritative.ID != identity.OperationID ||
		!crypto.ConstantTimeEqual([]byte(authoritative.RequestBinding), []byte(r.RequestBinding)) {
		return store.RemediationPlaybookRun{}, ErrIdempotencyConflict
	}
	return authoritative, nil
}

// RecordIncidentFleetReissuance records a compromised-issuer fleet reissuance
// evidence snapshot. The row is a projection of this event, so pause/resume,
// rollback evidence, rebuild, and snapshot restore all replay from the immutable
// log instead of mutating read state directly (AN-2).
func (o *Orchestrator) RecordIncidentFleetReissuance(ctx context.Context, tenantID string, r store.IncidentFleetReissuanceRun) (store.IncidentFleetReissuanceRun, error) {
	return o.recordIncidentFleetReissuance(ctx, tenantID, "", r)
}

// RecordIncidentFleetReissuanceWithEventID records a retry-stable H3 mirror of
// one H2 transition. Duplicate suppression is accepted only when the retained
// event has the exact same payload, so a crashed receiver cannot silently bind
// one transition identity to different incident evidence.
func (o *Orchestrator) RecordIncidentFleetReissuanceWithEventID(
	ctx context.Context,
	tenantID, eventID string,
	r store.IncidentFleetReissuanceRun,
) (store.IncidentFleetReissuanceRun, error) {
	if strings.TrimSpace(eventID) == "" {
		return store.IncidentFleetReissuanceRun{}, errors.New("orchestrator: incident fleet evidence event id is required")
	}
	return o.recordIncidentFleetReissuance(ctx, tenantID, eventID, r)
}

func (o *Orchestrator) recordIncidentFleetReissuance(
	ctx context.Context,
	tenantID, eventID string,
	r store.IncidentFleetReissuanceRun,
) (store.IncidentFleetReissuanceRun, error) {
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
		MigrationRunID: r.MigrationRunID, ReplacementAuthorityID: r.ReplacementAuthorityID,
		Mode: r.Mode, PlanDigest: r.PlanDigest, ExactTrustStoreIDs: r.ExactTrustStoreIDs,
		ExactTrustHosts: r.ExactTrustHosts, CandidateTrustStoreIDs: r.CandidateTrustStoreIDs,
		CandidateTrustHosts: r.CandidateTrustHosts,
		Reason:              r.Reason, BatchSize: r.BatchSize, NextBatchIndex: r.NextBatchIndex,
		HaltedReason: r.HaltedReason, Connector: r.Connector, Target: r.Target,
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
	var ev events.Event
	if eventID == "" {
		ev, err = o.emit(ctx, projections.EventIncidentFleetReissuanceRecorded, tenantID, payload)
	} else {
		expected := events.Event{
			ID: eventID, Type: projections.EventIncidentFleetReissuanceRecorded,
			TenantID: tenantID, Data: payload,
		}
		ev, err = o.emitPrepared(ctx, expected)
		if err == nil && (ev.ID != expected.ID || ev.Type != expected.Type ||
			ev.TenantID != expected.TenantID || !bytes.Equal(ev.Data, expected.Data)) {
			err = fmt.Errorf("%w: canonical incident fleet evidence differs", store.ErrIdempotencyConflict)
		}
	}
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

// RecordIncidentFleetReissuanceAndEnqueueBatch projects the cursor update and
// publishes that exact batch in one PostgreSQL transaction. The immutable event
// is also sufficient for ReconcileOutbox to heal the narrow event/SQL crash gap.
func (o *Orchestrator) RecordIncidentFleetReissuanceAndEnqueueBatch(
	ctx context.Context, tenantID string, r store.IncidentFleetReissuanceRun, batchIndex int,
) (store.IncidentFleetReissuanceRun, error) {
	if batchIndex <= 0 {
		return store.IncidentFleetReissuanceRun{}, errors.New("orchestrator: fleet batch index must be positive")
	}
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
		MigrationRunID: r.MigrationRunID, ReplacementAuthorityID: r.ReplacementAuthorityID,
		Mode: r.Mode, PlanDigest: r.PlanDigest, ExactTrustStoreIDs: r.ExactTrustStoreIDs,
		ExactTrustHosts: r.ExactTrustHosts, CandidateTrustStoreIDs: r.CandidateTrustStoreIDs,
		CandidateTrustHosts: r.CandidateTrustHosts,
		Reason:              r.Reason, BatchSize: r.BatchSize, NextBatchIndex: r.NextBatchIndex,
		HaltedReason: r.HaltedReason, Connector: r.Connector, Target: r.Target,
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
	commandPayload, err := json.Marshal(FleetReissuanceBatchCommand{RunID: r.ID, BatchIndex: batchIndex})
	if err != nil {
		return store.IncidentFleetReissuanceRun{}, err
	}
	var ev events.Event
	err = o.store.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		ev, err = o.log.Append(ctx, events.Event{
			Type: projections.EventIncidentFleetReissuanceRecorded, TenantID: tenantID, Data: payload,
		})
		if err != nil {
			return err
		}
		if err := o.proj.ApplyTx(ctx, tx, ev); err != nil {
			return err
		}
		_, err = o.outbox.EnqueueIfAbsent(ctx, tx, Entry{
			TenantID: tenantID, Destination: DestinationFleetReissuanceBatch,
			IdempotencyKey: FleetReissuanceBatchIdempotencyKey(r.ID, batchIndex),
			EffectLane:     DestinationFleetReissuanceBatch + ":" + r.ID,
			Payload:        commandPayload, RequiredAgentRole: "control_plane",
		})
		return err
	})
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
	if in.IssuanceIdempotencyKey != "" {
		return o.recordCertificateCommand(ctx, tenantID, in, &replacesID)
	}
	// Preserve the existing unkeyed observation contract. Keyed issuance
	// uses the canonical public payload and exact retained event above.
	id := uuid.NewString()
	sans := in.SANs
	if sans == nil {
		sans = []string{}
	}
	rep := replacesID
	payload, err := json.Marshal(projections.CertificateRecorded{
		ID: id, CAID: in.CAID, OwnerID: in.OwnerID, Subject: in.Subject, SANs: sans, Issuer: in.Issuer, Serial: in.Serial,
		Fingerprint: in.Fingerprint, KeyAlgorithm: in.KeyAlgorithm, NotBefore: in.NotBefore, NotAfter: in.NotAfter,
		ValidityAnchor:     in.ValidityAnchor,
		DeploymentLocation: in.DeploymentLocation, Source: in.Source, ReplacesID: &rep,
		CertificateDER:         in.CertificateDER,
		CertificatePEM:         in.CertificatePEM,
		IssuanceIdempotencyKey: in.IssuanceIdempotencyKey,
		KeyOrigin:              in.KeyOrigin,
		KeyStorage:             in.KeyStorage,
		KeyExportable:          in.KeyExportable,
		KeyGeneratedBy:         in.KeyGeneratedBy,
	})
	if err != nil {
		return store.Certificate{}, err
	}
	if _, err := o.emitPrepared(ctx, events.Event{Type: projections.EventCertificateRecorded, SchemaVersion: certificateRecordingSchema(in), TenantID: tenantID, Data: payload}); err != nil {
		return store.Certificate{}, err
	}
	return o.store.GetCertificateByFingerprint(ctx, tenantID, in.Fingerprint)
}

func certificateRecordingSchema(in store.Certificate) int {
	if in.ValidityAnchor != nil {
		return projections.CertificateValidityEventSchemaVersion
	}
	return events.DefaultSchemaVersion
}
