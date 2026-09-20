// SPDX-License-Identifier: BUSL-1.1

package orchestrator

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"

	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/issuancerequest"
	"trstctl.com/trstctl/internal/projections"
	"trstctl.com/trstctl/internal/store"
)

// defaultIssuanceRequestTTL is how long an unattended request waits.
//
// A request that never expires is a queue entry nobody is ever forced to look
// at, and a queue whose size only grows stops being read at all. Seven days is
// long enough to survive a holiday and short enough that the queue means
// something.
const defaultIssuanceRequestTTL = 7 * 24 * time.Hour

// ErrIssuanceRequestNotReady means the request is valid but has not reached the
// evidence-backed stage required by the attempted operation. The served API
// maps this to 409 so the console can explain the exact next step.
var ErrIssuanceRequestNotReady = errors.New("orchestrator: issuance request is not ready")

// IssuanceRequestIssueIdempotencyKey is the stable mint identity shared by the
// preparation response, browser client, certificate record, and completion
// verifier. Retrying the same approved request can never mint under a new key.
func IssuanceRequestIssueIdempotencyKey(id string) string {
	return "issuance-request-issue:" + strings.TrimSpace(id)
}

// IssuanceRequestCertificateIdempotencyKey is the canonical outbox/certificate
// identity derived by the guarded requested->issued transition.
func IssuanceRequestCertificateIdempotencyKey(id string) string {
	return "issue:transition:" + IssuanceRequestIssueIdempotencyKey(id)
}

// OpenIssuanceRequest records a new request (I3).
func (o *Orchestrator) OpenIssuanceRequest(ctx context.Context, tenantID string, in projections.IssuanceRequestOpened) (store.IssuanceRequest, error) {
	return o.openIssuanceRequest(ctx, tenantID, in, "")
}

// OpenIssuanceRequestFromRelay is the durable ticket-result receiver. Both the
// request and event identities derive from the outbox idempotency key and exact
// ticket reference, so a crash after append but before job completion replays
// the same fact instead of opening a second request.
func (o *Orchestrator) OpenIssuanceRequestFromRelay(ctx context.Context, tenantID, resultKey string, in projections.IssuanceRequestOpened) (store.IssuanceRequest, error) {
	binding := tenantID + "\x00" + resultKey + "\x00" + in.TicketRef
	in.ID = uuid.NewSHA1(uuid.NameSpaceOID, []byte("ticket-intake-request\x00"+binding)).String()
	eventID := uuid.NewSHA1(uuid.NameSpaceOID, []byte("ticket-intake-event\x00"+binding)).String()
	return o.openIssuanceRequest(ctx, tenantID, in, eventID)
}

func (o *Orchestrator) openIssuanceRequest(ctx context.Context, tenantID string, in projections.IssuanceRequestOpened, eventID string) (store.IssuanceRequest, error) {
	if strings.TrimSpace(in.Subject) == "" {
		return store.IssuanceRequest{}, fmt.Errorf("orchestrator: issuance request needs a subject")
	}
	if strings.TrimSpace(in.Requester) == "" {
		// Fail closed. A request with no requester cannot be separated from its
		// approver, so the separation-of-duties check would silently pass.
		return store.IssuanceRequest{}, fmt.Errorf(
			"orchestrator: issuance request needs a requester; without one the self-approval check " +
				"has nothing to compare and would pass by accident")
	}
	if in.ID == "" {
		in.ID = uuid.NewString()
	}
	if in.ExpiresAt.IsZero() {
		in.ExpiresAt = time.Now().UTC().Add(defaultIssuanceRequestTTL)
	}
	payload, err := json.Marshal(in)
	if err != nil {
		return store.IssuanceRequest{}, err
	}
	var ev events.Event
	if eventID == "" {
		ev, err = o.emit(ctx, projections.EventIssuanceRequestOpened, tenantID, payload)
	} else {
		ev, err = o.emitPrepared(ctx, events.Event{
			ID: eventID, Type: projections.EventIssuanceRequestOpened, TenantID: tenantID, Data: payload,
		})
	}
	if err != nil {
		return store.IssuanceRequest{}, err
	}
	return store.IssuanceRequest{
		ID: in.ID, TenantID: tenantID, Subject: in.Subject, Profile: in.Profile,
		OwnerID: in.OwnerID, CSRPEM: in.CSRPEM, Requester: in.Requester, Justification: in.Justification,
		Origin: in.Origin, TicketRef: in.TicketRef, Status: issuancerequest.StateRequested,
		ExpiresAt: in.ExpiresAt, CreatedAt: ev.Time,
	}, nil
}

// DecideIssuanceRequest moves a request to a new state.
//
// The transition legality and the separation-of-duties rule are checked HERE,
// against the request's current stored state, rather than in the handler: a
// rule enforced by whichever handler happens to run is a rule that holds until
// somebody adds a second caller.
func (o *Orchestrator) DecideIssuanceRequest(ctx context.Context, tenantID, id, to, decidedBy, reason, identityID string) (store.IssuanceRequest, error) {
	current, err := o.store.GetIssuanceRequest(ctx, tenantID, id)
	if err != nil {
		return store.IssuanceRequest{}, err
	}
	if _, err := issuancerequest.Transition(current.Status, to); err != nil {
		return store.IssuanceRequest{}, err
	}
	// Expiry is the one transition with no decider: nobody chose it, time ran
	// out. Every other decision needs a principal who is not the requester.
	if to != issuancerequest.StateExpired && to != issuancerequest.StateIssued {
		if to == issuancerequest.StateApproved || to == issuancerequest.StateDenied {
			if err := issuancerequest.CanDecide(current.Requester, decidedBy); err != nil {
				return store.IssuanceRequest{}, err
			}
		}
	}
	// Cancelling is the requester's own right, and only theirs.
	if to == issuancerequest.StateCancelled && decidedBy != current.Requester {
		return store.IssuanceRequest{}, fmt.Errorf(
			"orchestrator: only %s can withdraw their own request; someone else closing it is a "+
				"denial and must be recorded as one", current.Requester)
	}
	at := time.Now().UTC()
	payload, err := json.Marshal(projections.IssuanceRequestDecided{
		ID: id, Status: to, DecidedBy: decidedBy, Reason: reason,
		IdentityID: identityID, DecidedAt: at,
	})
	if err != nil {
		return store.IssuanceRequest{}, err
	}
	if _, err := o.emit(ctx, projections.EventIssuanceRequestDecided, tenantID, payload); err != nil {
		return store.IssuanceRequest{}, err
	}
	current.Status = to
	current.DecidedBy = decidedBy
	current.DecisionReason = reason
	current.DecidedAt = &at
	if identityID != "" {
		current.IdentityID = identityID
	}
	return current, nil
}

// PrepareIssuanceRequest creates or recovers the one deterministic requested
// identity bound to an approved first-class request. It does not mint anything;
// the returned public CSR still has to travel through the ordinary guarded
// identity transition and signer-backed outbox path.
func (o *Orchestrator) PrepareIssuanceRequest(ctx context.Context, tenantID, id, preparedBy string) (store.IssuanceRequest, store.Identity, error) {
	var request store.IssuanceRequest
	var identity store.Identity
	err := o.store.WithProjectionLock(ctx, func(lockCtx context.Context) error {
		current, err := o.store.GetIssuanceRequest(lockCtx, tenantID, id)
		if err != nil {
			return err
		}
		if current.Status != issuancerequest.StateApproved && current.Status != issuancerequest.StateIssued {
			return fmt.Errorf("%w: request %s is %s; only an approved request can be prepared",
				ErrIssuanceRequestNotReady, id, current.Status)
		}
		if strings.TrimSpace(current.OwnerID) == "" {
			return fmt.Errorf("%w: request %s has no owner_id; bind a real tenant owner before issuance",
				ErrIssuanceRequestNotReady, id)
		}

		profileName, profileVersion, err := o.ResolveIssuanceRequestProfileBinding(lockCtx, tenantID, current.Profile)
		if err != nil {
			return err
		}
		attrs, err := json.Marshal(map[string]any{
			"issuance_request_id": current.ID,
			"profile_name":        profileName,
			"profile_version":     profileVersion,
			"purpose":             current.Justification,
			"requester":           current.Requester,
		})
		if err != nil {
			return err
		}
		identityID := current.IdentityID
		if identityID == "" {
			identityID = uuid.NewSHA1(uuid.NameSpaceOID,
				[]byte("issuance-request-identity\x00"+tenantID+"\x00"+current.ID)).String()
		}
		identity, err = o.EnsureIdentity(lockCtx, tenantID, identityID, store.Identity{
			Kind: store.KindX509Certificate, Name: current.Subject, OwnerID: current.OwnerID,
			Attributes: attrs,
		})
		if err != nil {
			return err
		}
		if err := validatePreparedIssuanceIdentity(current, identity, profileName, profileVersion); err != nil {
			return err
		}
		if current.IdentityID == "" {
			at := time.Now().UTC()
			payload, err := json.Marshal(projections.IssuanceRequestPrepared{
				ID: current.ID, IdentityID: identity.ID, PreparedBy: preparedBy, PreparedAt: at,
			})
			if err != nil {
				return err
			}
			if _, err := o.emit(lockCtx, projections.EventIssuanceRequestPrepared, tenantID, payload); err != nil {
				return err
			}
			current.IdentityID = identity.ID
		}
		request = current
		return nil
	})
	return request, identity, err
}

// ResolveIssuanceRequestProfileBinding resolves the exact active profile revision
// used by both effect-free request preview/admission and later preparation. One
// shared rule prevents the review screen from saying a request is ready while the
// orchestrator would resolve a different or retired rule at mint time.
func (o *Orchestrator) ResolveIssuanceRequestProfileBinding(ctx context.Context, tenantID, binding string) (string, int, error) {
	name, version, err := parseIssuanceRequestProfileBinding(binding)
	if err != nil || name == "" {
		return name, version, err
	}
	var rec store.ProfileRecord
	if version > 0 {
		rec, err = o.store.GetProfileVersion(ctx, tenantID, name, version)
	} else {
		rec, err = o.store.GetActiveProfile(ctx, tenantID, name)
	}
	if err != nil {
		if store.IsNotFound(err) {
			return "", 0, fmt.Errorf("%w: profile %s is not available in this tenant; choose an active certificate rule",
				ErrIssuanceRequestNotReady, name)
		}
		return "", 0, err
	}
	if !rec.Active {
		return "", 0, fmt.Errorf("%w: profile %s:%d is no longer active; submit a new request for the current rule",
			ErrIssuanceRequestNotReady, rec.Name, rec.Version)
	}
	return rec.Name, rec.Version, nil
}

func parseIssuanceRequestProfileBinding(binding string) (string, int, error) {
	binding = strings.TrimSpace(binding)
	if binding == "" {
		return "", 0, nil
	}
	name := binding
	version := 0
	if split := strings.LastIndex(binding, ":"); split > 0 {
		parsed, err := strconv.Atoi(binding[split+1:])
		if err != nil || parsed <= 0 {
			return "", 0, fmt.Errorf("%w: request profile %q must end in a positive version",
				ErrIssuanceRequestNotReady, binding)
		}
		name, version = strings.TrimSpace(binding[:split]), parsed
	}
	if name == "" {
		return "", 0, fmt.Errorf("%w: request profile name is empty", ErrIssuanceRequestNotReady)
	}
	return name, version, nil
}

func validatePreparedIssuanceIdentity(request store.IssuanceRequest, identity store.Identity, profileName string, profileVersion int) error {
	if identity.Kind != store.KindX509Certificate || identity.Name != request.Subject || identity.OwnerID != request.OwnerID {
		return fmt.Errorf("%w: linked identity %s does not match request subject, owner, and X.509 kind",
			ErrIssuanceRequestNotReady, identity.ID)
	}
	var attrs struct {
		RequestID      string `json:"issuance_request_id"`
		ProfileName    string `json:"profile_name"`
		ProfileVersion int    `json:"profile_version"`
	}
	if err := json.Unmarshal(identity.Attributes, &attrs); err != nil {
		return fmt.Errorf("%w: decode linked identity attributes: %v", ErrIssuanceRequestNotReady, err)
	}
	if attrs.RequestID != request.ID || attrs.ProfileName != profileName || attrs.ProfileVersion != profileVersion {
		return fmt.Errorf("%w: linked identity %s does not match request and profile revision",
			ErrIssuanceRequestNotReady, identity.ID)
	}
	return nil
}

// validateCompletedIssuanceIdentity accepts the historical revision that was
// active when preparation and signing ran. A newer active revision must stop a
// not-yet-started mint, but it must not erase the truth that the old, exact
// revision already produced a real certificate.
func (o *Orchestrator) validateCompletedIssuanceIdentity(ctx context.Context, tenantID string, request store.IssuanceRequest, identity store.Identity) error {
	if identity.Kind != store.KindX509Certificate || identity.Name != request.Subject || identity.OwnerID != request.OwnerID {
		return fmt.Errorf("%w: linked identity %s does not match request subject, owner, and X.509 kind",
			ErrIssuanceRequestNotReady, identity.ID)
	}
	var attrs struct {
		RequestID      string `json:"issuance_request_id"`
		ProfileName    string `json:"profile_name"`
		ProfileVersion int    `json:"profile_version"`
	}
	if err := json.Unmarshal(identity.Attributes, &attrs); err != nil {
		return fmt.Errorf("%w: decode linked identity attributes: %v", ErrIssuanceRequestNotReady, err)
	}
	requestedName, requestedVersion, err := parseIssuanceRequestProfileBinding(request.Profile)
	if err != nil {
		return err
	}
	profileMatches := attrs.ProfileName == requestedName && attrs.ProfileVersion == requestedVersion
	if requestedName != "" && requestedVersion == 0 {
		profileMatches = attrs.ProfileName == requestedName && attrs.ProfileVersion > 0
	}
	if attrs.RequestID != request.ID || !profileMatches {
		return fmt.Errorf("%w: linked identity %s does not match request and historical profile revision",
			ErrIssuanceRequestNotReady, identity.ID)
	}
	if attrs.ProfileName != "" {
		if _, err := o.store.GetProfileVersion(ctx, tenantID, attrs.ProfileName, attrs.ProfileVersion); err != nil {
			return err
		}
	}
	return nil
}

// CompleteIssuanceRequest records the historical fulfillment proved by the exact
// signing command and its certificate. Later deployment, revocation or retirement
// cannot erase that fact; completion never changes the credential's current state.
func (o *Orchestrator) CompleteIssuanceRequest(ctx context.Context, tenantID, id string) (store.IssuanceRequest, error) {
	var completed store.IssuanceRequest
	err := o.store.WithProjectionLock(ctx, func(lockCtx context.Context) error {
		current, err := o.store.GetIssuanceRequest(lockCtx, tenantID, id)
		if err != nil {
			return err
		}
		if current.Status == issuancerequest.StateIssued {
			completed = current
			return nil
		}
		if current.Status != issuancerequest.StateApproved || current.IdentityID == "" {
			return fmt.Errorf("%w: request %s must be approved and prepared before completion",
				ErrIssuanceRequestNotReady, id)
		}
		identity, err := o.store.GetIdentity(lockCtx, tenantID, current.IdentityID)
		if err != nil {
			return err
		}
		if err := o.validateCompletedIssuanceIdentity(lockCtx, tenantID, current, identity); err != nil {
			return err
		}
		switch State(identity.Status) {
		case StateIssued, StateDeployed, StateRenewing, StateRenewalFailed, StateRevoked, StateRetired:
		default:
			return fmt.Errorf("%w: linked identity %s has no completed issuance", ErrIssuanceRequestNotReady, identity.ID)
		}
		result, err := o.store.GetIdentityIssuanceResult(lockCtx, tenantID, identity.ID, IssuanceRequestIssueIdempotencyKey(current.ID))
		if store.IsNotFound(err) || errors.Is(err, store.ErrIdempotencyConflict) {
			return fmt.Errorf("%w: exact issuance transition/result is unavailable or ambiguous", ErrIssuanceRequestNotReady)
		}
		if err != nil {
			return err
		}
		// The identity name is an operator-facing label. The certificate subject
		// and SANs come from the requester-held CSR and can legitimately differ.
		// The canonical issuance key is the exact command/result correlation;
		// owner, immutable issuance provenance, status, and real public bytes
		// close the remaining gaps; an ordinary import can change Source.
		if result.Certificate == nil {
			return fmt.Errorf("%w: signer-backed certificate for request %s is pending", ErrIssuanceRequestNotReady, current.ID)
		}
		certificate := *result.Certificate
		ownerMatches := certificate.OwnerID != nil && *certificate.OwnerID == current.OwnerID
		knownCertificateState := certificate.Status == "active" || certificate.Status == "superseded" || certificate.Status == "revoked"
		if !ownerMatches || certificate.IssuanceEventID == "" || !knownCertificateState ||
			(len(certificate.CertificateDER) == 0 || len(certificate.CertificatePEM) == 0) {
			return fmt.Errorf("%w: signer-backed certificate for request %s is not in inventory yet",
				ErrIssuanceRequestNotReady, current.ID)
		}
		// Attribute signing to its immutable original command, not to the person
		// or worker who later reconciles the request. Unattributed historical
		// events remain unattributed rather than fabricating a human issuer.
		issuedBy, err := o.issuanceRequestOriginalIssuer(lockCtx, tenantID, identity.ID, current.ID)
		if err != nil {
			return err
		}
		at := certificate.CreatedAt.UTC()
		if at.IsZero() {
			return fmt.Errorf("%w: certificate recording time is missing", ErrIssuanceRequestNotReady)
		}
		payload, err := json.Marshal(projections.IssuanceRequestIssued{
			ID: current.ID, IdentityID: identity.ID, IssuedBy: issuedBy, IssuedAt: at,
		})
		if err != nil {
			return err
		}
		if _, err := o.emit(lockCtx, projections.EventIssuanceRequestIssued, tenantID, payload); err != nil {
			return err
		}
		current.Status, current.IssuedBy, current.IssuedAt = issuancerequest.StateIssued, issuedBy, &at
		completed = current
		return nil
	})
	return completed, err
}

func (o *Orchestrator) issuanceRequestOriginalIssuer(ctx context.Context, tenantID, identityID, requestID string) (string, error) {
	initial, found, err := o.store.IdentityInitialIssuance(ctx, tenantID, identityID)
	if err != nil {
		return "", err
	}
	if !found || initial.IdempotencyKey != IssuanceRequestIssueIdempotencyKey(requestID) || o.log == nil {
		return "", fmt.Errorf("%w: original issuance command is unavailable", ErrIssuanceRequestNotReady)
	}
	event, found, err := o.log.EventAtSequence(ctx, initial.Seq)
	if err != nil {
		return "", err
	}
	if !found || event.Sequence != initial.Seq || event.TenantID != tenantID || event.Type != projections.EventIdentityIssued {
		return "", fmt.Errorf("%w: original issuance event does not match", ErrIssuanceRequestNotReady)
	}
	if err := projections.ValidateLifecycleApprovalEvent(event); err != nil {
		return "", err
	}
	var command transitionPayload
	if err := json.Unmarshal(event.Data, &command); err != nil {
		return "", err
	}
	if command.IdentityID != identityID || command.From != StateRequested || command.To != StateIssued || command.IdempotencyKey != initial.IdempotencyKey {
		return "", fmt.Errorf("%w: original issuance event names another command", ErrIssuanceRequestNotReady)
	}
	if event.Actor == nil {
		return "", nil
	}
	return event.Actor.Subject, nil
}

// CompleteIssuanceRequestForIdentity closes only the first-class request named
// by this exact issuance command. The durable outbox retries a failed completion
// without re-signing, so closing the browser cannot strand an issued request.
func (o *Orchestrator) CompleteIssuanceRequestForIdentity(ctx context.Context, tenantID, identityID, requestKey string) error {
	const prefix = "issuance-request-issue:"
	if !strings.HasPrefix(requestKey, prefix) {
		return nil
	}
	id := strings.TrimPrefix(requestKey, prefix)
	if _, err := uuid.Parse(id); err != nil {
		return nil // Ordinary idempotency keys may share the prefix.
	}
	request, err := o.store.GetIssuanceRequest(ctx, tenantID, id)
	if store.IsNotFound(err) {
		return nil // An ordinary caller's key is not itself a request binding.
	}
	if err != nil {
		return err
	}
	if request.IdentityID != identityID {
		return fmt.Errorf("%w: issuance command names another request identity", ErrIssuanceRequestNotReady)
	}
	if request.Status != issuancerequest.StateApproved && request.Status != issuancerequest.StateIssued {
		return nil // Preserve explicit denial, expiry or withdrawal.
	}
	_, err = o.CompleteIssuanceRequest(ctx, tenantID, id)
	return err
}

// ConfigureTicketIntake records the standing instruction to read the ITSM for
// certificate-request tickets (I3). TokenRef is a reference, never a value.
func (o *Orchestrator) ConfigureTicketIntake(ctx context.Context, tenantID string, in projections.TicketIntakeConfigured) error {
	payload, err := json.Marshal(in)
	if err != nil {
		return err
	}
	return o.store.WithProjectionLock(ctx, func(lockCtx context.Context) error {
		if current, found, loadErr := o.store.GetTicketIntakeSchedule(lockCtx, tenantID, in.System); loadErr != nil {
			return loadErr
		} else if found && current.CurrentSweepID != "" && !current.CoverageComplete {
			return ErrTicketIntakeSweepInProgress
		}
		_, err := o.emit(lockCtx, projections.EventTicketIntakeConfigured, tenantID, payload)
		return err
	})
}
