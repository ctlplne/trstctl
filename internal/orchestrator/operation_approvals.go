// SPDX-License-Identifier: MPL-2.0

package orchestrator

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/notify"
	"trstctl.com/trstctl/internal/privacy"
	"trstctl.com/trstctl/internal/projections"
	"trstctl.com/trstctl/internal/store"
)

const defaultOperationApprovalTTL = time.Hour

// OperationApprovalIntent is the exact immutable command reviewers see. A
// caller must supply the current target state/version; otherwise an approval
// could silently slide onto a later version of the same resource.
type OperationApprovalIntent struct {
	ResourceKind      string
	ResourceID        string
	ResourceName      string
	Action            string
	Requester         string
	FromState         string
	ToState           string
	TargetVersion     uint64
	Reason            string
	EvidenceRefs      []string
	RequiredApprovals int
	TTL               time.Duration
}

type OperationApprovalDecision struct {
	RequestID            string
	IntentDigest         string
	Approver             string
	Decision             string
	Reason               string
	ExpectedResourceKind string
	ExpectedResourceID   string
	ExpectedAction       string
}

// EnsureOperationApprovalRequest returns the one event-sourced request for an
// exact intent. It never creates authority from a reviewer decision. An earlier
// live request over the same requester/resource/action is superseded before the
// replacement becomes visible, so two digests cannot authorize concurrently.
func (o *Orchestrator) EnsureOperationApprovalRequest(ctx context.Context, tenantID string, intent OperationApprovalIntent) (store.OperationApprovalRequest, error) {
	intent = canonicalApprovalIntent(intent)
	if strings.TrimSpace(tenantID) == "" || intent.ResourceKind == "" || intent.ResourceID == "" ||
		intent.Action == "" || intent.Requester == "" {
		return store.OperationApprovalRequest{}, fmt.Errorf("orchestrator: approval tenant, resource kind/id, action, and requester are required")
	}
	if intent.RequiredApprovals <= 0 {
		intent.RequiredApprovals = 2
	}
	if intent.TTL <= 0 {
		intent.TTL = defaultOperationApprovalTTL
	}
	requestID, err := operationApprovalRequestID(tenantID, intent)
	if err != nil {
		return store.OperationApprovalRequest{}, err
	}
	retainedRequest, retainedRequestFound, err := operationApprovalEventByID(ctx, o.log, requestID)
	if err != nil {
		return store.OperationApprovalRequest{}, err
	}
	var canonicalRequest projections.ApprovalRequested
	if retainedRequestFound {
		canonicalRequest, err = validateCanonicalOperationApprovalRequestEvent(
			retainedRequest, tenantID, intent, requestID,
		)
		if err != nil {
			return store.OperationApprovalRequest{}, err
		}
	}

	// The request row does not exist on the first attempt, so a row lock cannot
	// serialize the read-before-create sequence. Hold one PostgreSQL advisory lock
	// for the complete scope while old authority is superseded and the replacement
	// request is appended/projected. Because every status event is appended before
	// its replacement request, a cold rebuild observes the same single-live-request
	// invariant as the warm projection.
	var result store.OperationApprovalRequest
	err = o.store.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		if err := o.store.LockOperationApprovalScopeTx(ctx, tx, tenantID, intent.ResourceKind,
			intent.ResourceID, intent.Action, intent.Requester); err != nil {
			return err
		}
		existing, getErr := o.store.GetOperationApprovalTx(ctx, tx, tenantID, requestID)
		if getErr == nil {
			result = existing
			return nil
		}
		if !errors.Is(getErr, store.ErrApprovalRequestNotFound) {
			return getErr
		}

		now := time.Now().UTC()
		if retainedRequestFound {
			now = canonicalRequest.CreatedAt
		}
		active, err := o.store.ActiveOperationApprovalsForScopeTx(ctx, tx, tenantID,
			intent.ResourceKind, intent.ResourceID, intent.Action, intent.Requester)
		if err != nil {
			return err
		}
		for _, current := range active {
			if current.ID == requestID {
				continue
			}
			if err := o.changeOperationApprovalStatusTx(ctx, tx, tenantID, current,
				store.ApprovalStatusSuperseded, requestID, now); err != nil {
				return err
			}
		}

		ev := retainedRequest
		canonical := canonicalRequest
		if !retainedRequestFound {
			payload := projections.ApprovalRequested{
				ID: requestID, ResourceKind: intent.ResourceKind, ResourceID: intent.ResourceID,
				ResourceName: intent.ResourceName, Action: intent.Action, Requester: intent.Requester,
				FromState: intent.FromState, ToState: intent.ToState, TargetVersion: intent.TargetVersion,
				Reason: intent.Reason, EvidenceRefs: append([]string(nil), intent.EvidenceRefs...),
				RequiredApprovals: intent.RequiredApprovals, CreatedAt: now, ExpiresAt: now.Add(intent.TTL),
			}
			payload.IntentDigest, err = operationApprovalIntentDigest(tenantID, payload)
			if err != nil {
				return err
			}
			raw, err := json.Marshal(payload)
			if err != nil {
				return err
			}
			ev, err = o.log.Append(ctx, events.Event{
				ID: requestID, Type: projections.EventApprovalRequested,
				TenantID: tenantID, Data: raw,
			})
			if err != nil {
				return err
			}
			canonical, err = validateCanonicalOperationApprovalRequestEvent(
				ev, tenantID, intent, requestID,
			)
			if err != nil {
				return err
			}
		}
		if err := o.proj.ApplyTx(ctx, tx, ev); err != nil {
			return err
		}
		if o.outbox != nil {
			entry, err := approvalRequestOutboxEntry(tenantID, canonical)
			if err != nil {
				return err
			}
			if _, err := o.outbox.EnqueueIfAbsent(ctx, tx, entry); err != nil {
				return err
			}
		}
		result, err = o.store.GetOperationApprovalTx(ctx, tx, tenantID, requestID)
		return err
	})
	return result, err
}

// RecordOperationApprovalDecision appends exactly one principal decision. The
// target and request row stay locked through final validation, canonical append,
// and projection, so a concurrent expiry, supersession, or consumption cannot put
// a decision into the log that the warm projector refuses. One request/digest/
// principal has one event ID regardless of the proposed decision: an opposite or
// changed command resolves to the first canonical bytes and fails before projection
// instead of appending a second event that would poison cold rebuild.
func (o *Orchestrator) RecordOperationApprovalDecision(ctx context.Context, tenantID string, decision OperationApprovalDecision) (store.OperationApprovalRequest, error) {
	decision.RequestID = strings.TrimSpace(decision.RequestID)
	decision.IntentDigest = strings.TrimSpace(decision.IntentDigest)
	decision.Approver = strings.TrimSpace(decision.Approver)
	decision.Decision = strings.TrimSpace(decision.Decision)
	if decision.RequestID == "" || decision.IntentDigest == "" {
		return store.OperationApprovalRequest{}, store.ErrApprovalRequestNotFound
	}
	if decision.Approver == "" {
		return store.OperationApprovalRequest{}, store.ErrAnonymousIssuanceApproval
	}
	if decision.Decision == "" {
		decision.Decision = store.ApprovalDecisionApprove
	}
	decision.Reason = strings.TrimSpace(decision.Reason)
	decision.ExpectedResourceKind = strings.TrimSpace(decision.ExpectedResourceKind)
	decision.ExpectedResourceID = strings.TrimSpace(decision.ExpectedResourceID)
	decision.ExpectedAction = strings.TrimSpace(decision.ExpectedAction)

	// This first read is only a lock-order hint. Identity execution locks the target
	// before the approval row, so the decision path does the same. Every field is read
	// and validated again under the transaction's row locks below.
	preview, err := o.store.GetOperationApproval(ctx, tenantID, decision.RequestID)
	if err != nil {
		return store.OperationApprovalRequest{}, err
	}
	eventID := projections.OperationApprovalDecisionEventID(tenantID,
		decision.RequestID, decision.IntentDigest, decision.Approver)
	retainedDecision, retainedDecisionFound, err := operationApprovalEventByID(ctx, o.log, eventID)
	if err != nil {
		return store.OperationApprovalRequest{}, err
	}
	var canonicalDecision projections.ApprovalDecisionRecorded
	if retainedDecisionFound {
		canonicalDecision, err = validateCanonicalOperationApprovalDecision(
			retainedDecision, tenantID, decision, eventID,
		)
		if err != nil {
			return store.OperationApprovalRequest{}, err
		}
	}

	var (
		result      store.OperationApprovalRequest
		terminalErr error
	)
	applyDecision := func(ctx context.Context) error {
		return o.store.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
			var (
				identity         store.Identity
				identityVersion  uint64
				secretVersion    int
				secretExists     bool
				secretShapeValid = true
			)
			switch preview.ResourceKind {
			case "identity":
				var lockErr error
				identity, identityVersion, lockErr = o.store.IdentityApprovalTargetTx(ctx, tx, tenantID, preview.ResourceID, true)
				if lockErr != nil {
					return lockErr
				}
			case "secret":
				name, ok := strings.CutPrefix(preview.ResourceID, "secret:")
				secretShapeValid = ok && name != "" && preview.ResourceName == name
				if secretShapeValid {
					var lockErr error
					secretVersion, secretExists, lockErr = o.store.ApplicationSecretApprovalTargetTx(
						ctx, tx, tenantID, name,
					)
					if lockErr != nil {
						return lockErr
					}
				}
			}

			request, lockErr := o.store.GetOperationApprovalForUpdateTx(ctx, tx, tenantID, decision.RequestID)
			if lockErr != nil {
				return lockErr
			}
			if request.ResourceKind != preview.ResourceKind || request.ResourceID != preview.ResourceID {
				return fmt.Errorf("%w: approval request identity changed", store.ErrIdempotencyConflict)
			}
			if err := validateOperationApprovalDecisionTarget(request, decision); err != nil {
				return err
			}
			var (
				managedKey        store.ManagedKey
				managedKeyExists  = true
				managedShapeValid = true
				managedProvider   string
				managedAlgorithm  string
			)
			if request.ResourceKind == "managed_key" {
				var providerOK, algorithmOK bool
				managedProvider, providerOK = operationApprovalEvidenceValue(
					request.EvidenceRefs, "managed-key-provider:",
				)
				managedAlgorithm, algorithmOK = operationApprovalEvidenceValue(
					request.EvidenceRefs, "managed-key-algorithm:",
				)
				managedShapeValid = providerOK && algorithmOK && request.ResourceName == request.ResourceID
				if managedShapeValid {
					managedKey, lockErr = o.store.ManagedKeyApprovalTargetTx(
						ctx, tx, tenantID, managedProvider, request.ResourceID, true,
					)
					if errors.Is(lockErr, pgx.ErrNoRows) {
						managedKeyExists = false
					} else if lockErr != nil {
						return lockErr
					}
				}
			}
			projectedDecision := store.OperationApprovalDecision{
				TenantID: tenantID, RequestID: decision.RequestID, IntentDigest: decision.IntentDigest,
				Approver: decision.Approver, Decision: decision.Decision, Reason: decision.Reason,
				EventID: eventID, ExpectedResourceKind: decision.ExpectedResourceKind,
				ExpectedResourceID: decision.ExpectedResourceID, ExpectedAction: decision.ExpectedAction,
			}
			if replay, replayErr := o.store.MatchOperationApprovalDecisionCommandTx(ctx, tx, projectedDecision); replayErr != nil {
				return replayErr
			} else if replay {
				result = request
				return nil
			}
			if retainedDecisionFound {
				if !canonicalDecision.DecidedAt.Before(request.ExpiresAt) {
					return store.ErrApprovalExpired
				}
				if err := o.proj.ApplyTx(ctx, tx, retainedDecision); err != nil {
					return err
				}
				result, lockErr = o.store.GetOperationApprovalTx(ctx, tx, tenantID, decision.RequestID)
				return lockErr
			}

			now := time.Now().UTC()
			if request.ResourceKind == "identity" &&
				(request.Status == store.ApprovalStatusPending || request.Status == store.ApprovalStatusApproved) {
				use, useErr := store.OperationApprovalUseFromRequest(request)
				if useErr != nil {
					return fmt.Errorf("%w: approval issuance evidence is invalid", store.ErrApprovalDrifted)
				}
				if use.Issuance != nil && use.Issuance.ProfileID != "" {
					if profileErr := o.store.ValidateActiveProfileApprovalBindingTx(ctx, tx, tenantID, *use.Issuance); profileErr != nil {
						if errors.Is(profileErr, store.ErrApprovalDrifted) {
							if statusErr := o.changeOperationApprovalStatusTx(ctx, tx, tenantID, request,
								store.ApprovalStatusSuperseded, "", now); statusErr != nil {
								return statusErr
							}
							terminalErr = store.ErrApprovalDrifted
							return nil
						}
						return profileErr
					}
				}
			}

			switch request.Status {
			case store.ApprovalStatusPending, store.ApprovalStatusApproved:
			case store.ApprovalStatusExpired:
				terminalErr = store.ErrApprovalExpired
				return nil
			case store.ApprovalStatusSuperseded:
				terminalErr = store.ErrApprovalSuperseded
				return nil
			case store.ApprovalStatusConsumed:
				terminalErr = store.ErrApprovalConsumed
				return nil
			default:
				terminalErr = store.ErrApprovalNotReady
				return nil
			}

			if !now.Before(request.ExpiresAt) {
				if err := o.changeOperationApprovalStatusTx(ctx, tx, tenantID, request,
					store.ApprovalStatusExpired, "", now); err != nil {
					return err
				}
				terminalErr = store.ErrApprovalExpired
				return nil
			}
			targetDrifted := false
			switch request.ResourceKind {
			case "identity":
				targetDrifted = identity.Status != request.FromState || identityVersion != request.TargetVersion
			case "secret":
				switch request.Action {
				case "create":
					targetDrifted = !secretShapeValid || secretExists || request.TargetVersion != 0 || request.FromState != "absent"
				case "rotate", "recover", "delete":
					targetDrifted = !secretShapeValid || !secretExists || uint64(secretVersion) != request.TargetVersion ||
						request.FromState != fmt.Sprintf("version:%d", request.TargetVersion)
				default:
					targetDrifted = true
				}
			case "managed_key":
				managedAction := strings.TrimPrefix(request.Action, "managedkey:")
				managedToState, actionOK := projections.ManagedKeyCommandTargetState(managedAction)
				targetDrifted = !managedShapeValid || !managedKeyExists || !actionOK ||
					managedKey.State != request.FromState || managedKey.Algorithm != managedAlgorithm ||
					uint64(managedKey.Version) != request.TargetVersion || request.ToState != managedToState
			}
			if targetDrifted {
				if err := o.changeOperationApprovalStatusTx(ctx, tx, tenantID, request,
					store.ApprovalStatusSuperseded, "", now); err != nil {
					return err
				}
				terminalErr = store.ErrApprovalDrifted
				return nil
			}

			payload := projections.ApprovalDecisionRecorded{
				RequestID: decision.RequestID, IntentDigest: decision.IntentDigest,
				Approver: decision.Approver, Decision: decision.Decision,
				Reason: decision.Reason, DecidedAt: now,
				ExpectedResourceKind: decision.ExpectedResourceKind,
				ExpectedResourceID:   decision.ExpectedResourceID,
				ExpectedAction:       decision.ExpectedAction,
			}
			raw, marshalErr := json.Marshal(payload)
			if marshalErr != nil {
				return marshalErr
			}
			event, appendErr := o.log.Append(ctx, events.Event{
				ID: eventID, Type: projections.EventApprovalDecisionRecorded,
				TenantID: tenantID, Data: raw,
			})
			if appendErr != nil {
				return appendErr
			}
			if _, err := validateCanonicalOperationApprovalDecision(event, tenantID, decision, eventID); err != nil {
				return err
			}
			if err := o.proj.ApplyTx(ctx, tx, event); err != nil {
				return err
			}
			result, lockErr = o.store.GetOperationApprovalTx(ctx, tx, tenantID, decision.RequestID)
			return lockErr
		})
	}
	previewUse, useErr := store.OperationApprovalUseFromRequest(preview)
	if useErr != nil {
		return store.OperationApprovalRequest{}, useErr
	}
	if preview.ResourceKind == "identity" && previewUse.Issuance != nil && previewUse.Issuance.ProfileID != "" {
		err = o.store.WithProjectionLock(ctx, applyDecision)
	} else {
		err = applyDecision(ctx)
	}
	if err != nil {
		return store.OperationApprovalRequest{}, err
	}
	if terminalErr != nil {
		return store.OperationApprovalRequest{}, terminalErr
	}
	return result, nil
}

func validateOperationApprovalDecisionTarget(request store.OperationApprovalRequest, decision OperationApprovalDecision) error {
	if request.IntentDigest != decision.IntentDigest {
		return store.ErrApprovalDigestMismatch
	}
	if request.Requester == decision.Approver {
		return store.ErrApprovalSelfDecision
	}
	if decision.ExpectedResourceKind != "" && decision.ExpectedResourceKind != request.ResourceKind ||
		decision.ExpectedResourceID != "" && decision.ExpectedResourceID != request.ResourceID ||
		decision.ExpectedAction != "" && decision.ExpectedAction != request.Action {
		return store.ErrApprovalDigestMismatch
	}
	return nil
}

func operationApprovalEvidenceValue(refs []string, prefix string) (string, bool) {
	value := ""
	found := false
	for _, ref := range refs {
		if !strings.HasPrefix(ref, prefix) {
			continue
		}
		candidate := strings.TrimPrefix(ref, prefix)
		if candidate == "" || found {
			return "", false
		}
		value = candidate
		found = true
	}
	return value, found
}

func validateCanonicalOperationApprovalDecision(event events.Event, tenantID string, decision OperationApprovalDecision, eventID string) (projections.ApprovalDecisionRecorded, error) {
	if err := validateOperationApprovalEventEnvelope(event, tenantID, eventID,
		projections.EventApprovalDecisionRecorded); err != nil {
		return projections.ApprovalDecisionRecorded{}, fmt.Errorf("%w: canonical operation approval decision envelope differs", err)
	}
	if err := validateOperationApprovalBoundActor(event.Actor, tenantID, decision.Approver); err != nil {
		return projections.ApprovalDecisionRecorded{}, fmt.Errorf("%w: canonical operation approval decision actor differs", err)
	}
	var canonical projections.ApprovalDecisionRecorded
	if err := json.Unmarshal(event.Data, &canonical); err != nil {
		return projections.ApprovalDecisionRecorded{}, fmt.Errorf("orchestrator: decode canonical approval decision: %w", err)
	}
	if canonical.DecidedAt.IsZero() {
		return projections.ApprovalDecisionRecorded{}, fmt.Errorf("%w: canonical operation approval decision has no time", store.ErrIdempotencyConflict)
	}
	expected := projections.ApprovalDecisionRecorded{
		RequestID: decision.RequestID, IntentDigest: decision.IntentDigest,
		Approver: decision.Approver, Decision: decision.Decision,
		Reason: decision.Reason, DecidedAt: canonical.DecidedAt,
		ExpectedResourceKind: decision.ExpectedResourceKind,
		ExpectedResourceID:   decision.ExpectedResourceID,
		ExpectedAction:       decision.ExpectedAction,
	}
	raw, err := json.Marshal(expected)
	if err != nil {
		return projections.ApprovalDecisionRecorded{}, err
	}
	matches, err := operationApprovalEventDataMatches(event, raw, tenantID, decision.Approver)
	if err != nil {
		return projections.ApprovalDecisionRecorded{}, fmt.Errorf("orchestrator: validate privacy-rewritten approval decision: %w", err)
	}
	if !matches {
		return projections.ApprovalDecisionRecorded{}, fmt.Errorf("%w: canonical operation approval decision differs", store.ErrIdempotencyConflict)
	}
	return canonical, nil
}

func (o *Orchestrator) changeOperationApprovalStatusTx(ctx context.Context, tx pgx.Tx, tenantID string, request store.OperationApprovalRequest, status, replacementID string, at time.Time) error {
	eventID := projections.OperationApprovalStatusEventID(tenantID,
		request.ID, request.IntentDigest, status, replacementID)
	retained, found, err := operationApprovalEventByID(ctx, o.log, eventID)
	if err != nil {
		return err
	}
	event := retained
	if found {
		if _, err := validateCanonicalOperationApprovalStatus(event, tenantID, request, status, replacementID, eventID); err != nil {
			return err
		}
	} else {
		next, err := operationApprovalStatusEvent(tenantID, request, status, replacementID, at)
		if err != nil {
			return err
		}
		event, err = o.log.Append(ctx, next)
		if err != nil {
			return err
		}
		if _, err := validateCanonicalOperationApprovalStatus(event, tenantID, request, status, replacementID, eventID); err != nil {
			return err
		}
	}
	return o.proj.ApplyTx(ctx, tx, event)
}

func operationApprovalStatusEvent(tenantID string, request store.OperationApprovalRequest, status, replacementID string, at time.Time) (events.Event, error) {
	payload, err := json.Marshal(projections.ApprovalStatusChanged{
		RequestID: request.ID, IntentDigest: request.IntentDigest,
		Status: status, ChangedAt: at, ReplacementID: replacementID,
	})
	if err != nil {
		return events.Event{}, err
	}
	return events.Event{
		ID: projections.OperationApprovalStatusEventID(tenantID, request.ID,
			request.IntentDigest, status, replacementID), Type: projections.EventApprovalStatusChanged,
		TenantID: tenantID, Data: payload,
	}, nil
}

func validateCanonicalOperationApprovalRequestEvent(
	event events.Event,
	tenantID string,
	intent OperationApprovalIntent,
	requestID string,
) (projections.ApprovalRequested, error) {
	if err := validateOperationApprovalEventEnvelope(event, tenantID, requestID,
		projections.EventApprovalRequested); err != nil {
		return projections.ApprovalRequested{}, fmt.Errorf("%w: canonical operation approval request envelope differs", err)
	}
	if err := validateOperationApprovalBoundActor(event.Actor, tenantID, intent.Requester); err != nil {
		return projections.ApprovalRequested{}, fmt.Errorf("%w: canonical operation approval request actor differs", err)
	}
	var canonical projections.ApprovalRequested
	if err := json.Unmarshal(event.Data, &canonical); err != nil {
		return projections.ApprovalRequested{}, fmt.Errorf("orchestrator: decode canonical approval request: %w", err)
	}
	if canonical.CreatedAt.IsZero() || canonical.ExpiresAt.Sub(canonical.CreatedAt) != intent.TTL {
		return projections.ApprovalRequested{}, fmt.Errorf("%w: canonical operation approval request lifetime differs", store.ErrIdempotencyConflict)
	}
	expected := projections.ApprovalRequested{
		ID: requestID, ResourceKind: intent.ResourceKind, ResourceID: intent.ResourceID,
		ResourceName: intent.ResourceName, Action: intent.Action, Requester: intent.Requester,
		FromState: intent.FromState, ToState: intent.ToState, TargetVersion: intent.TargetVersion,
		Reason: intent.Reason, EvidenceRefs: append([]string(nil), intent.EvidenceRefs...),
		RequiredApprovals: intent.RequiredApprovals,
		CreatedAt:         canonical.CreatedAt, ExpiresAt: canonical.ExpiresAt,
	}
	digest, err := operationApprovalIntentDigest(tenantID, expected)
	if err != nil {
		return projections.ApprovalRequested{}, err
	}
	expected.IntentDigest = digest
	raw, err := json.Marshal(expected)
	if err != nil {
		return projections.ApprovalRequested{}, err
	}
	matches, err := operationApprovalEventDataMatches(event, raw, tenantID, intent.Requester)
	if err != nil {
		return projections.ApprovalRequested{}, fmt.Errorf("orchestrator: validate privacy-rewritten approval request: %w", err)
	}
	if !matches {
		return projections.ApprovalRequested{}, fmt.Errorf("%w: canonical operation approval request differs", store.ErrIdempotencyConflict)
	}
	return canonical, nil
}

func validateCanonicalOperationApprovalStatus(
	event events.Event,
	tenantID string,
	request store.OperationApprovalRequest,
	status, replacementID, eventID string,
) (projections.ApprovalStatusChanged, error) {
	if err := validateOperationApprovalEventEnvelope(event, tenantID, eventID,
		projections.EventApprovalStatusChanged); err != nil {
		return projections.ApprovalStatusChanged{}, fmt.Errorf("%w: canonical operation approval status envelope differs", err)
	}
	var canonical projections.ApprovalStatusChanged
	if err := json.Unmarshal(event.Data, &canonical); err != nil {
		return projections.ApprovalStatusChanged{}, fmt.Errorf("orchestrator: decode canonical approval status: %w", err)
	}
	if canonical.ChangedAt.IsZero() {
		return projections.ApprovalStatusChanged{}, fmt.Errorf("%w: canonical operation approval status has no time", store.ErrIdempotencyConflict)
	}
	expected, err := json.Marshal(projections.ApprovalStatusChanged{
		RequestID: request.ID, IntentDigest: request.IntentDigest, Status: status,
		ChangedAt: canonical.ChangedAt, ReplacementID: replacementID,
	})
	if err != nil {
		return projections.ApprovalStatusChanged{}, err
	}
	if !bytes.Equal(event.Data, expected) {
		return projections.ApprovalStatusChanged{}, fmt.Errorf("%w: canonical operation approval status differs", store.ErrIdempotencyConflict)
	}
	return canonical, nil
}

func validateOperationApprovalEventEnvelope(event events.Event, tenantID, eventID, eventType string) error {
	if event.ID != eventID || event.Type != eventType || event.TenantID != tenantID ||
		event.SchemaVersion != events.DefaultSchemaVersion || event.Time.IsZero() {
		return store.ErrIdempotencyConflict
	}
	return nil
}

// validateOperationApprovalBoundActor keeps audit attribution tied to the
// principal named by request and decision commands. System/background producers
// legitimately have no actor. An attributed producer must name that exact
// principal, or the deterministic tenant-bound placeholder produced by the
// authorized privacy rewrite. Roles are retained audit metadata from the first
// canonical event; they are not part of the command identity and may differ from
// the caller's current roles on a later idempotent retry.
func validateOperationApprovalBoundActor(actor *events.Actor, tenantID, subject string) error {
	if actor == nil {
		return nil
	}
	if actor.Subject == subject ||
		actor.Subject == privacy.Placeholder(privacy.SubjectRef(tenantID, subject)) {
		return nil
	}
	return store.ErrIdempotencyConflict
}

func operationApprovalEventDataMatches(event events.Event, expected []byte, tenantID, privacySubject string) (bool, error) {
	if bytes.Equal(event.Data, expected) {
		return true, nil
	}
	rewritten, changed, err := events.PseudonymizeEventDataForSubject(
		expected, tenantID, privacySubject, event.Type, event.SchemaVersion,
	)
	if err != nil {
		return false, err
	}
	return changed && bytes.Equal(event.Data, rewritten), nil
}

func operationApprovalEventByID(ctx context.Context, log *events.Log, eventID string) (events.Event, bool, error) {
	event, found, err := log.EventByID(ctx, eventID)
	if errors.Is(err, events.ErrConflictingEventIdentity) {
		return events.Event{}, false, fmt.Errorf("%w: %v", store.ErrIdempotencyConflict, err)
	}
	return event, found, err
}

func approvalRequestOutboxEntry(tenantID string, request projections.ApprovalRequested) (Entry, error) {
	alert, err := json.Marshal(notify.Alert{
		Kind: notify.KindApprovalRequest, TenantID: tenantID,
		OperationID: "approval-" + request.ID, RequestBinding: request.IntentDigest,
		Subject: request.ResourceID,
		Detail: fmt.Sprintf("%s requested approval to %s %s %s", request.Requester,
			request.Action, request.ResourceKind, request.ResourceID),
		Severity: notify.AlertSeverityWarning,
	})
	if err != nil {
		return Entry{}, err
	}
	return Entry{
		TenantID: tenantID, Destination: notify.DestinationApproval,
		IdempotencyKey: "approval-request:" + request.ID,
		EffectLane:     notify.DestinationApproval + ":request:" + request.ID,
		Payload:        alert,
	}, nil
}

// operationApprovalRequestFromEvent validates the self-contained source event
// used by boot reconciliation. A normal event must still hash to its immutable
// intent digest. A privacy-shaped event keeps that original digest while its
// requester/text is replaced by the authorized tenant-bound placeholder, so it
// remains replayable without recreating erased personal data.
func operationApprovalRequestFromEvent(event events.Event) (projections.ApprovalRequested, error) {
	if err := validateOperationApprovalEventEnvelope(event, event.TenantID, event.ID,
		projections.EventApprovalRequested); err != nil {
		return projections.ApprovalRequested{}, fmt.Errorf("%w: approval request event envelope differs", err)
	}
	var request projections.ApprovalRequested
	if err := json.Unmarshal(event.Data, &request); err != nil {
		return projections.ApprovalRequested{}, fmt.Errorf("orchestrator: decode approval request event: %w", err)
	}
	if request.ID != event.ID || request.IntentDigest == "" || request.ResourceKind == "" ||
		request.ResourceID == "" || request.Action == "" || request.Requester == "" ||
		request.RequiredApprovals <= 0 || request.CreatedAt.IsZero() || !request.ExpiresAt.After(request.CreatedAt) {
		return projections.ApprovalRequested{}, fmt.Errorf("%w: approval request event is incomplete", store.ErrIdempotencyConflict)
	}
	if err := validateOperationApprovalBoundActor(event.Actor, event.TenantID, request.Requester); err != nil {
		return projections.ApprovalRequested{}, fmt.Errorf("%w: approval request event actor differs", err)
	}
	privacyShaped := privacy.IsPlaceholder(request.Requester) || strings.HasPrefix(request.Requester, "retained:")
	if !privacyShaped {
		digest, err := operationApprovalIntentDigest(event.TenantID, request)
		if err != nil {
			return projections.ApprovalRequested{}, err
		}
		if request.IntentDigest != digest {
			return projections.ApprovalRequested{}, fmt.Errorf("%w: approval request event digest differs", store.ErrIdempotencyConflict)
		}
	}
	return request, nil
}

func canonicalApprovalIntent(in OperationApprovalIntent) OperationApprovalIntent {
	in.ResourceKind = strings.TrimSpace(in.ResourceKind)
	in.ResourceID = strings.TrimSpace(in.ResourceID)
	in.ResourceName = strings.TrimSpace(in.ResourceName)
	in.Action = strings.TrimSpace(in.Action)
	in.Requester = strings.TrimSpace(in.Requester)
	in.FromState = strings.TrimSpace(in.FromState)
	in.ToState = strings.TrimSpace(in.ToState)
	in.Reason = strings.TrimSpace(in.Reason)
	seen := make(map[string]struct{}, len(in.EvidenceRefs))
	evidence := make([]string, 0, len(in.EvidenceRefs))
	for _, ref := range in.EvidenceRefs {
		ref = strings.TrimSpace(ref)
		if ref == "" {
			continue
		}
		if _, ok := seen[ref]; ok {
			continue
		}
		seen[ref] = struct{}{}
		evidence = append(evidence, ref)
	}
	sort.Strings(evidence)
	in.EvidenceRefs = evidence
	return in
}

func operationApprovalRequestID(tenantID string, intent OperationApprovalIntent) (string, error) {
	basis := struct {
		TenantID          string   `json:"tenant_id"`
		ResourceKind      string   `json:"resource_kind"`
		ResourceID        string   `json:"resource_id"`
		ResourceName      string   `json:"resource_name"`
		Action            string   `json:"action"`
		Requester         string   `json:"requester"`
		FromState         string   `json:"from_state"`
		ToState           string   `json:"to_state"`
		TargetVersion     uint64   `json:"target_version"`
		Reason            string   `json:"reason"`
		EvidenceRefs      []string `json:"evidence_refs"`
		RequiredApprovals int      `json:"required_approvals"`
	}{tenantID, intent.ResourceKind, intent.ResourceID, intent.ResourceName, intent.Action,
		intent.Requester, intent.FromState, intent.ToState, intent.TargetVersion,
		intent.Reason, intent.EvidenceRefs, intent.RequiredApprovals}
	raw, err := json.Marshal(basis)
	if err != nil {
		return "", err
	}
	return uuid.NewSHA1(uuid.NameSpaceOID, []byte("operation-approval\x00"+crypto.SHA256Hex(raw))).String(), nil
}

func operationApprovalIntentDigest(tenantID string, request projections.ApprovalRequested) (string, error) {
	bound := struct {
		TenantID string `json:"tenant_id"`
		projections.ApprovalRequested
	}{TenantID: tenantID, ApprovalRequested: request}
	bound.IntentDigest = ""
	raw, err := json.Marshal(bound)
	if err != nil {
		return "", err
	}
	return "sha256:" + crypto.SHA256Hex(raw), nil
}
