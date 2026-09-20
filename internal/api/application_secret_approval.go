// SPDX-License-Identifier: BUSL-1.1

package api

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"reflect"
	"slices"
	"strings"
	"time"

	googleuuid "github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"trstctl.com/trstctl/internal/authz"
	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/crypto/secret"
	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/privacy"
	"trstctl.com/trstctl/internal/projections"
	"trstctl.com/trstctl/internal/store"
	"trstctl.com/trstctl/internal/tenantseal"
)

var applicationSecretMutationNamespace = googleuuid.MustParse("639435c4-b02a-59fc-9f05-d3ae2e0d0042")

// ErrApplicationSecretMutationReconcileBlocked means crash recovery left one or
// more exact commands durably fenced by a bounded recoverability condition, such
// as unavailable tenant custody or a pre-0152 fence whose audit actor is absent
// from retained source history. It is safe for the process to start: affected
// commands stay fail-closed, other commands still reconcile, readiness degrades,
// and the periodic worker retries without exposing tenant or secret labels.
var ErrApplicationSecretMutationReconcileBlocked = errors.New("api: application-secret mutation reconciliation blocked")

var errApplicationSecretLegacyActorUnavailable = errors.New("api: legacy application-secret actor unavailable")

// errTerminalApplicationSecretApproval marks an exact approval authority that can
// never become usable (denied, expired, superseded, consumed, or drifted). The
// wrapper preserves the public problem detail while allowing the scheduler to
// advance only terminal poison rows and keep genuinely pending review retryable.
var errTerminalApplicationSecretApproval = errors.New("api: terminal application-secret approval authority")
var errPendingApplicationSecretApproval = errors.New("api: pending application-secret approval authority")

type terminalApplicationSecretApprovalError struct{ cause error }

func (e terminalApplicationSecretApprovalError) Error() string { return e.cause.Error() }
func (e terminalApplicationSecretApprovalError) Unwrap() error { return e.cause }
func (e terminalApplicationSecretApprovalError) Is(target error) bool {
	return target == errTerminalApplicationSecretApproval
}

func terminalApplicationSecretApproval(cause error) error {
	return terminalApplicationSecretApprovalError{cause: cause}
}

type pendingApplicationSecretApprovalError struct{ cause error }

func (e pendingApplicationSecretApprovalError) Error() string { return e.cause.Error() }
func (e pendingApplicationSecretApprovalError) Unwrap() error { return e.cause }
func (e pendingApplicationSecretApprovalError) Is(target error) bool {
	return target == errPendingApplicationSecretApproval
}

const applicationSecretReconcileLegacyActorUnavailable tenantseal.Status = "legacy_actor_unavailable"
const applicationSecretReconcilePrivacyPreparationActive tenantseal.Status = "privacy_erasure_prepared"

type canonicalApplicationSecretCommand struct {
	Domain          string    `json:"domain"`
	TenantEpoch     string    `json:"tenant_epoch"`
	Action          string    `json:"action"`
	Name            string    `json:"name"`
	OwnerID         string    `json:"owner_id,omitempty"`
	Surface         string    `json:"surface"`
	Provider        string    `json:"provider,omitempty"`
	Target          string    `json:"target,omitempty"`
	RemoteKey       string    `json:"remote_key,omitempty"`
	OldRef          string    `json:"old_ref,omitempty"`
	ExpectedVersion int       `json:"expected_version"`
	ResultVersion   int       `json:"result_version"`
	Value           []byte    `json:"value,omitempty"`
	RequestedAt     time.Time `json:"requested_at,omitempty"`
	SourceVersion   int       `json:"source_version,omitempty"`
	SourceWrittenAt time.Time `json:"source_written_at,omitempty"`
}

// applicationSecretRequestBinding protects the AN-5 recorder from accepting the
// same raw key for a different caller, route, or body. Plaintext-bearing request
// bytes exist only in this transient HMAC input and are wiped; only the HMAC and
// SHA-256 of the raw idempotency key may be persisted.
func (a *API) applicationSecretRequestBinding(
	tenantID, idempotencyKey, principal, method, escapedPath, action, surface, name string,
	request any,
) (keyDigest, binding string, err error) {
	key := []byte(idempotencyKey)
	defer secret.Wipe(key)
	keyDigest = crypto.SHA256Hex(key)
	if a.secrets == nil || a.secrets.be.CommandMAC == nil {
		return "", "", errors.New("api: server-keyed application-secret command evidence is unavailable")
	}
	material, err := json.Marshal(struct {
		TenantID             string `json:"tenant_id"`
		Principal            string `json:"principal"`
		Method               string `json:"method"`
		EscapedPath          string `json:"escaped_path"`
		Action               string `json:"action"`
		Surface              string `json:"surface"`
		Name                 string `json:"name"`
		IdempotencyKeyDigest string `json:"idempotency_key_sha256"`
		Request              any    `json:"request"`
	}{
		TenantID: tenantID, Principal: principal, Method: method, EscapedPath: escapedPath,
		Action: action, Surface: surface, Name: name,
		IdempotencyKeyDigest: keyDigest, Request: request,
	})
	if err != nil {
		return "", "", err
	}
	defer secret.Wipe(material)
	mac, err := a.secrets.be.CommandMAC(
		[]byte("trstctl.api.application-secret-request-binding.v2"), material)
	if err != nil {
		return "", "", err
	}
	if len(mac) != 32 {
		secret.Wipe(mac)
		return "", "", errors.New("api: application-secret request MAC has invalid length")
	}
	defer secret.Wipe(mac)
	return keyDigest, hex.EncodeToString(mac), nil
}

func (a *API) applicationSecretMaterializedResult(
	ctx context.Context,
	tenantID, eventID, requestBinding, name string,
	actions ...string,
) (store.ApplicationSecretMutationReceipt, bool, error) {
	receipt, err := a.secrets.be.Store.GetApplicationSecretMutationReceipt(ctx, tenantID, eventID)
	if store.IsNotFound(err) {
		return store.ApplicationSecretMutationReceipt{}, false, nil
	}
	if err != nil {
		return store.ApplicationSecretMutationReceipt{}, false, err
	}
	actionAllowed := false
	for _, action := range actions {
		actionAllowed = actionAllowed || receipt.Action == action
	}
	if receipt.Name != name || !actionAllowed ||
		!crypto.ConstantTimeEqual([]byte(receipt.RequestBinding), []byte(requestBinding)) {
		return store.ApplicationSecretMutationReceipt{}, false,
			fmt.Errorf("%w: application-secret mutation receipt %s", store.ErrIdempotencyConflict, eventID)
	}
	return receipt, true, nil
}

func applicationSecretReceiptMeta(receipt store.ApplicationSecretMutationReceipt) secretMetaResponse {
	return secretMetaResponse{
		Name: receipt.Name, Version: receipt.ResultVersion,
		OwnerID:   receipt.ResultOwnerID,
		CreatedAt: receipt.ResultCreatedAt, UpdatedAt: receipt.ResultUpdatedAt,
	}
}

func (a *API) applicationSecretCommandEvidence(tenantID, idempotencyKey string, command canonicalApplicationSecretCommand) (keyDigest, evidence string, err error) {
	key := []byte(idempotencyKey)
	defer secret.Wipe(key)
	keyDigest = crypto.SHA256Hex(key)
	if a.secrets == nil || a.secrets.be.CommandMAC == nil {
		return "", "", errors.New("api: server-keyed application-secret command evidence is unavailable")
	}
	canonical, err := json.Marshal(struct {
		IdempotencyKeyDigest string                            `json:"idempotency_key_sha256"`
		TenantID             string                            `json:"tenant_id"`
		Command              canonicalApplicationSecretCommand `json:"command"`
	}{IdempotencyKeyDigest: keyDigest, TenantID: tenantID, Command: command})
	if err != nil {
		return "", "", err
	}
	defer secret.Wipe(canonical)
	mac, err := a.secrets.be.CommandMAC(
		[]byte("trstctl.api.application-secret-command-evidence.v2"), canonical)
	if err != nil {
		return "", "", err
	}
	if len(mac) != 32 {
		secret.Wipe(mac)
		return "", "", errors.New("api: application-secret command MAC has invalid length")
	}
	defer secret.Wipe(mac)
	return keyDigest, hex.EncodeToString(mac), nil
}

func applicationSecretMutationEventID(tenantID, tenantEpoch, name, action, keyDigest string) string {
	return googleuuid.NewSHA1(applicationSecretMutationNamespace,
		[]byte(tenantID+"\x00"+tenantEpoch+"\x00"+name+"\x00"+action+"\x00"+keyDigest)).String()
}

func (a *API) applicationSecretTenantEpoch(ctx context.Context, tenantID string) (string, error) {
	if a.secrets == nil || a.secrets.be.Store == nil {
		return "", errors.New("api: application-secret tenant lifecycle is unavailable")
	}
	epoch, err := a.secrets.be.Store.ApplicationSecretTenantEpoch(ctx, tenantID)
	if err != nil {
		return "", fmt.Errorf("api: load application-secret tenant lifecycle: %w", err)
	}
	if epoch == "" {
		return "", errors.New("api: application-secret tenant lifecycle epoch is unavailable")
	}
	return epoch, nil
}

func validateApplicationSecretMutationFence(
	tenantID, name, operation, eventID, requestBinding string,
	fence store.ApplicationSecretMutationFence,
) (projections.ApplicationSecretMutation, error) {
	if fence.TenantID != tenantID || fence.Name != name || fence.Operation != operation ||
		fence.EventID != eventID || fence.SchemaVersion != projections.ApplicationSecretMutationSchemaVersion ||
		!crypto.ConstantTimeEqual([]byte(fence.RequestBinding), []byte(requestBinding)) {
		return projections.ApplicationSecretMutation{}, fmt.Errorf("%w: application-secret command fence differs", store.ErrIdempotencyConflict)
	}
	var payload projections.ApplicationSecretMutation
	if err := json.Unmarshal(fence.Payload, &payload); err != nil {
		return projections.ApplicationSecretMutation{}, fmt.Errorf("api: decode application-secret command fence: %w", err)
	}
	if payload.Approval != nil || payload.Name != name || payload.TenantEpoch == "" ||
		!crypto.ConstantTimeEqual([]byte(payload.RequestBinding), []byte(requestBinding)) ||
		applicationSecretMutationEventID(tenantID, payload.TenantEpoch, name, operation, payload.IdempotencyKeyDigest) != eventID {
		return projections.ApplicationSecretMutation{}, fmt.Errorf("%w: application-secret fenced payload differs", store.ErrIdempotencyConflict)
	}
	wantType := ""
	switch payload.Action {
	case "create":
		if payload.Surface != "native" && payload.Surface != "vault" || payload.ExpectedVersion != 0 || payload.ResultVersion != 1 ||
			len(payload.Sealed) == 0 || len(payload.CommandEvidence) != 64 {
			return projections.ApplicationSecretMutation{}, fmt.Errorf("%w: application-secret create fence is invalid", store.ErrIdempotencyConflict)
		}
		wantType = projections.EventApplicationSecretCreated
	case "rotate":
		wantType = projections.EventApplicationSecretRotated
	case "recover":
		wantType = projections.EventApplicationSecretRecovered
	case "delete":
		wantType = projections.EventApplicationSecretDeleted
	default:
		return projections.ApplicationSecretMutation{}, fmt.Errorf("%w: unsupported fenced application-secret action", store.ErrIdempotencyConflict)
	}
	if fence.EventType != wantType {
		return projections.ApplicationSecretMutation{}, fmt.Errorf("%w: application-secret fence event type differs", store.ErrIdempotencyConflict)
	}
	if payload.Action != "create" {
		if _, _, _, err := projections.ApplicationSecretApprovalBinding(payload); err != nil {
			return projections.ApplicationSecretMutation{}, err
		}
	}
	return payload, nil
}

func (a *API) applicationSecretMutationFence(
	ctx context.Context,
	tenantID, name, operation, eventID, requestBinding string,
) (store.ApplicationSecretMutationFence, projections.ApplicationSecretMutation, bool, error) {
	fence, err := a.secrets.be.Store.GetApplicationSecretMutationFence(ctx, tenantID, name)
	if store.IsNotFound(err) {
		return store.ApplicationSecretMutationFence{}, projections.ApplicationSecretMutation{}, false, nil
	}
	if err != nil {
		return store.ApplicationSecretMutationFence{}, projections.ApplicationSecretMutation{}, false, err
	}
	if fence.TenantID != tenantID || fence.Name != name || fence.Operation != operation ||
		fence.EventID != eventID ||
		!crypto.ConstantTimeEqual([]byte(fence.RequestBinding), []byte(requestBinding)) {
		// A different candidate must pass through Claim. The store alone may
		// replace this row, and only after locking it and proving its persisted
		// pending approval terminal. API callers never delete fences.
		return fence, projections.ApplicationSecretMutation{}, false, nil
	}
	payload, err := validateApplicationSecretMutationFence(
		tenantID, name, operation, eventID, requestBinding, fence)
	return fence, payload, true, err
}

func (a *API) claimApplicationSecretMutationFence(
	ctx context.Context,
	tenantID, name, operation, eventID, eventType, requestBinding string,
	payload projections.ApplicationSecretMutation,
) (store.ApplicationSecretMutationFence, projections.ApplicationSecretMutation, error) {
	payload.Approval = nil
	raw, err := json.Marshal(payload)
	if err != nil {
		return store.ApplicationSecretMutationFence{}, projections.ApplicationSecretMutation{}, err
	}
	approvalRequired := payload.Action != "create" && a.gate.RequireApproval
	var requesterSealed []byte
	requesterRef := ""
	if approvalRequired {
		principal, _ := ctx.Value(principalCtxKey).(authz.Principal)
		if principal.Subject == "" {
			return store.ApplicationSecretMutationFence{}, projections.ApplicationSecretMutation{},
				errStatus(http.StatusUnauthorized, "an authenticated requester is required")
		}
		requester := []byte(principal.Subject)
		defer secret.Wipe(requester)
		requesterSealed, err = a.secrets.seal(ctx, tenantID, requester,
			applicationSecretFenceRequesterAAD(tenantID, eventID))
		if err != nil {
			return store.ApplicationSecretMutationFence{}, projections.ApplicationSecretMutation{}, err
		}
		requesterRef = privacy.SubjectRef(tenantID, principal.Subject)
	}
	canonical, err := a.secrets.be.Store.ClaimApplicationSecretMutationFence(ctx, store.ApplicationSecretMutationFence{
		TenantID: tenantID, Name: name, Operation: operation, EventID: eventID,
		EventType: eventType, SchemaVersion: projections.ApplicationSecretMutationSchemaVersion,
		ApprovalRequired: approvalRequired, RequesterSealed: requesterSealed, RequesterRef: requesterRef,
		RequestBinding: requestBinding, Payload: raw, Actor: applicationSecretActorFromContext(ctx),
	})
	if err != nil {
		return store.ApplicationSecretMutationFence{}, projections.ApplicationSecretMutation{}, err
	}
	canonicalPayload, err := validateApplicationSecretMutationFence(
		tenantID, name, operation, eventID, requestBinding, canonical)
	return canonical, canonicalPayload, err
}

func applicationSecretActorFromContext(ctx context.Context) *events.Actor {
	actor, ok := events.ActorFromContext(ctx)
	if !ok {
		return nil
	}
	roles := append([]string(nil), actor.Roles...)
	slices.Sort(roles)
	roles = slices.Compact(roles)
	first := 0
	for first < len(roles) && roles[first] == "" {
		first++
	}
	roles = roles[first:]
	if len(roles) == 0 {
		roles = nil
	}
	actor.Roles = roles
	return &actor
}

func applicationSecretFenceRequesterAAD(tenantID, eventID string) []byte {
	return []byte(tenantID + "/application-secret-mutation-fence/" + eventID + "/requester")
}

func (a *API) finalizeApplicationSecretMutationFence(
	ctx context.Context,
	tenantID string,
	fence store.ApplicationSecretMutationFence,
	payload projections.ApplicationSecretMutation,
) (store.ApplicationSecretMutationFence, projections.ApplicationSecretMutation, error) {
	if fence.EventTime.IsZero() {
		var approval *store.OperationApprovalUse
		var err error
		if fence.ApprovalRequired {
			approval, err = a.authorizeRequiredApplicationSecretMutation(ctx, tenantID, payload)
		}
		if err != nil {
			if approval != nil {
				if _, bindErr := a.secrets.be.Store.BindApplicationSecretMutationFenceApproval(
					ctx, tenantID, payload.Name, fence.EventID, *approval); bindErr != nil {
					return store.ApplicationSecretMutationFence{}, projections.ApplicationSecretMutation{}, bindErr
				}
			}
			return store.ApplicationSecretMutationFence{}, projections.ApplicationSecretMutation{}, err
		}
		fence, err = a.secrets.be.Store.FinalizeApplicationSecretMutationFence(
			ctx, tenantID, payload.Name, fence.EventID, approval, time.Now().UTC())
		if err != nil {
			return store.ApplicationSecretMutationFence{}, projections.ApplicationSecretMutation{}, err
		}
	}
	approval, err := a.secrets.be.Store.ApplicationSecretMutationFenceApprovalUse(ctx, tenantID, fence)
	if err != nil {
		return store.ApplicationSecretMutationFence{}, projections.ApplicationSecretMutation{}, err
	}
	payload.Approval = approval
	return fence, payload, nil
}

func (a *API) authorizeRequiredApplicationSecretMutation(
	ctx context.Context,
	tenantID string,
	payload projections.ApplicationSecretMutation,
) (*store.OperationApprovalUse, error) {
	if a.gate.Checker == nil {
		return nil, errStatus(http.StatusForbidden, "dual control required but no approval store is configured")
	}
	exact, ok := a.gate.Checker.(ExactApprovalChecker)
	if !ok {
		return nil, errStatus(http.StatusForbidden, "dual control requires exact single-use approval authority")
	}
	principal, _ := ctx.Value(principalCtxKey).(authz.Principal)
	if principal.Subject == "" {
		return nil, errStatus(http.StatusUnauthorized, "an authenticated requester is required")
	}
	from, to, evidenceRefs, err := projections.ApplicationSecretApprovalBinding(payload)
	if err != nil {
		return nil, err
	}
	intent := ApprovalIntent{
		TenantID: tenantID, ResourceKind: "secret", ResourceID: secretApprovalResource(payload.Name),
		ResourceName: payload.Name, Action: payload.Action, Requester: principal.Subject,
		FromState: from, ToState: to,
		TargetVersion: uint64(payload.ExpectedVersion), // #nosec G115 -- ApplicationSecretApprovalBinding just proved the version is positive (CWE-190).
		Reason:        "authorize exact " + payload.Surface + " application-secret " + payload.Action,
		EvidenceRefs:  evidenceRefs,
	}
	authority, approved, reason := exact.AuthorizeApproval(ctx, intent)
	if authority.RequestID == "" || authority.IntentDigest == "" ||
		authority.Requester != principal.Subject || authority.ResourceKind != intent.ResourceKind ||
		authority.ResourceID != intent.ResourceID || authority.Action != intent.Action ||
		authority.FromState != from || authority.ToState != to ||
		authority.TargetVersion != intent.TargetVersion || authority.RequiredApprovals <= 0 {
		return nil, terminalApplicationSecretApproval(approvalAPIError(store.ErrApprovalDrifted))
	}
	use := &store.OperationApprovalUse{
		RequestID: authority.RequestID, IntentDigest: authority.IntentDigest,
		Requester: authority.Requester, ResourceKind: authority.ResourceKind,
		ResourceID: authority.ResourceID, Action: authority.Action,
		FromState: authority.FromState, ToState: authority.ToState,
		TargetVersion: authority.TargetVersion, RequiredApprovals: authority.RequiredApprovals,
	}
	if !approved {
		if reason == "" {
			reason = "this exact secret change awaits distinct approval"
		}
		denial := errStatus(http.StatusForbidden, fmt.Sprintf(
			"dual control: approval_required:%s request_id=%s intent_digest=%s: %s",
			intent.ResourceID, authority.RequestID, authority.IntentDigest, reason))
		if authority.Disposition.Terminal() {
			return use, terminalApplicationSecretApproval(denial)
		}
		return use, pendingApplicationSecretApprovalError{cause: denial}
	}
	return use, nil
}

func (a *API) appendAndProjectApplicationSecretMutation(
	ctx context.Context,
	tenantID string,
	fence store.ApplicationSecretMutationFence,
	payload projections.ApplicationSecretMutation,
	recoverExisting bool,
) (events.Event, projections.ApplicationSecretMutation, error) {
	if a.secrets == nil || a.secrets.be.Store == nil || a.secrets.be.EventLog == nil {
		return events.Event{}, projections.ApplicationSecretMutation{}, errors.New("api: event-sourced application-secret mutations are unavailable")
	}
	var (
		canonical        events.Event
		canonicalPayload projections.ApplicationSecretMutation
	)
	err := a.secrets.be.Store.WithApplicationSecretMutationPrivacyBarrier(ctx, tenantID, func(barrierCtx context.Context) error {
		// This argument may have been loaded before a privacy generation cutover
		// and then blocked on the history-operation lock. Reload only after the
		// shared barrier is held. The durable row is now either unchanged, deleted,
		// or atomically rewritten with its exact approval requester.
		latest, err := a.secrets.be.Store.GetApplicationSecretMutationFence(barrierCtx, tenantID, fence.Name)
		if err != nil {
			return err
		}
		if latest.EventID != fence.EventID || latest.Operation != fence.Operation ||
			latest.RequestBinding != fence.RequestBinding {
			return fmt.Errorf("%w: application-secret command changed across privacy barrier", store.ErrIdempotencyConflict)
		}
		latestPayload, err := validateApplicationSecretMutationFence(
			tenantID, latest.Name, latest.Operation, latest.EventID, latest.RequestBinding, latest)
		if err != nil {
			return err
		}
		if latestPayload.Name != payload.Name || latestPayload.Action != payload.Action ||
			latestPayload.TenantEpoch != payload.TenantEpoch ||
			!crypto.ConstantTimeEqual([]byte(latestPayload.RequestBinding), []byte(payload.RequestBinding)) {
			return fmt.Errorf("%w: application-secret payload changed across privacy barrier", store.ErrIdempotencyConflict)
		}
		approval, err := a.secrets.be.Store.ApplicationSecretMutationFenceApprovalUse(barrierCtx, tenantID, latest)
		if err != nil {
			return err
		}
		latestPayload.Approval = approval
		canonical, canonicalPayload, err = a.appendAndProjectApplicationSecretMutationUnbarriered(
			barrierCtx, tenantID, latest, latestPayload, recoverExisting)
		return err
	})
	return canonical, canonicalPayload, err
}

func (a *API) appendAndProjectApplicationSecretMutationUnbarriered(
	ctx context.Context,
	tenantID string,
	fence store.ApplicationSecretMutationFence,
	payload projections.ApplicationSecretMutation,
	recoverExisting bool,
) (events.Event, projections.ApplicationSecretMutation, error) {
	raw, err := json.Marshal(payload)
	if err != nil {
		return events.Event{}, projections.ApplicationSecretMutation{}, err
	}
	defer secret.Wipe(raw)
	if fence.EventTime.IsZero() || fence.EventID == "" || fence.EventType == "" {
		return events.Event{}, projections.ApplicationSecretMutation{}, errors.New("api: application-secret command fence is not finalized")
	}
	candidate := events.Event{
		ID: fence.EventID, Type: fence.EventType, TenantID: tenantID, Time: fence.EventTime,
		SchemaVersion: projections.ApplicationSecretMutationSchemaVersion, Data: raw,
	}
	// The durable fence owns the actor just like it owns ciphertext and event time.
	// A live retry must present that exact authenticated subject+roles; background
	// recovery reconstructs it without fabricating or losing attribution.
	requestActor := applicationSecretActorFromContext(ctx)
	if fence.Actor != nil {
		if requestActor != nil && !reflect.DeepEqual(requestActor, fence.Actor) {
			return events.Event{}, projections.ApplicationSecretMutation{},
				fmt.Errorf("%w: application-secret command actor differs", store.ErrIdempotencyConflict)
		}
		candidate.Actor = fence.Actor
	}
	canonical, canonicalPayload, err := recoverOrAppendApplicationSecretMutationEvent(
		ctx, a.secrets.be.EventLog, candidate, payload, recoverExisting)
	if err != nil {
		return events.Event{}, projections.ApplicationSecretMutation{}, err
	}
	projector := projections.New(a.secrets.be.Store)
	err = a.secrets.be.Store.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		// A finalized old-lifecycle command can be retained or arrive after the
		// tenant UUID is registered again. Check under this mutation transaction;
		// the store takes a row lock so offboard cannot interleave with projection.
		if err := a.secrets.be.Store.ValidateApplicationSecretTenantEpochTx(
			ctx, tx, tenantID, canonicalPayload.TenantEpoch); err != nil {
			return err
		}
		if payload.Approval != nil {
			_, validateErr := a.secrets.be.Store.ValidateOperationApprovalUseTx(ctx, tx, tenantID, *payload.Approval, fence.EventTime)
			if errors.Is(validateErr, store.ErrApprovalConsumed) {
				if err := a.secrets.be.Store.ConsumeOperationApprovalTx(ctx, tx, tenantID, *payload.Approval, fence.EventID, fence.EventTime); err != nil {
					return err
				}
			} else if validateErr != nil {
				return validateErr
			}
		}
		return projector.ApplyTx(ctx, tx, canonical)
	})
	if err != nil {
		return events.Event{}, projections.ApplicationSecretMutation{}, err
	}
	return canonical, canonicalPayload, nil
}

// recoverOrAppendApplicationSecretMutationEvent resolves the permanent command
// identity from retained source history before publishing. JetStream remembers a
// message ID only for a finite window; EventByID is therefore the correctness
// boundary for a retry that may be days old. The immutable envelope and every
// command field must match. ApplicationSecretMutationSemanticDigest deliberately
// omits only Approval.Requester, whose spelling may be rewritten by the authorized
// privacy-erasure transform while its capability fields remain exact.
func recoverOrAppendApplicationSecretMutationEvent(
	ctx context.Context,
	log *events.Log,
	candidate events.Event,
	payload projections.ApplicationSecretMutation,
	recoverExisting bool,
) (events.Event, projections.ApplicationSecretMutation, error) {
	var canonical events.Event
	found := false
	var err error
	if recoverExisting {
		// A previously prepared durable fence may sit on either side of the
		// Append/project crash gap, so old retained history is authoritative.
		canonical, found, err = log.EventByID(ctx, candidate.ID)
		if err != nil {
			return events.Event{}, projections.ApplicationSecretMutation{}, err
		}
	}
	if !found {
		// A fence first claimed by this request cannot already have an event. Send
		// its deterministic ID straight to JetStream instead of replaying lifetime
		// history to prove that impossible negative. JetStream still canonicalizes
		// an in-window duplicate, and the exact-envelope checks below remain closed.
		if candidate.Actor == nil {
			// A pre-0152 fence did not persist attribution. It is recoverable only
			// when retained source history already owns the canonical envelope. Do
			// not manufacture a permanently unattributed audit event on upgrade.
			return events.Event{}, projections.ApplicationSecretMutation{}, errors.Join(
				store.ErrIdempotencyConflict, errApplicationSecretLegacyActorUnavailable)
		}
		canonical, err = log.Append(ctx, candidate)
		if err != nil {
			return events.Event{}, projections.ApplicationSecretMutation{}, err
		}
	} else if candidate.Actor == nil {
		// The durable fence predates actor persistence, so retained history is the
		// only canonical copy of its already-recorded audit actor. This applies to
		// both background recovery and authenticated live retries: request context
		// must never be substituted for missing durable attribution. Reuse the exact
		// retained envelope field for append-success/SQL-rollback recovery.
		candidate.Actor = canonical.Actor
	}
	if canonical.ID != candidate.ID || canonical.Type != candidate.Type ||
		canonical.TenantID != candidate.TenantID || !canonical.Time.Equal(candidate.Time) ||
		canonical.SchemaVersion != candidate.SchemaVersion ||
		!applicationSecretRecoveryActorsEqual(canonical.Actor, candidate.Actor) {
		return events.Event{}, projections.ApplicationSecretMutation{},
			fmt.Errorf("%w: canonical application-secret event envelope differs", store.ErrIdempotencyConflict)
	}
	var canonicalPayload projections.ApplicationSecretMutation
	if err := json.Unmarshal(canonical.Data, &canonicalPayload); err != nil {
		return events.Event{}, projections.ApplicationSecretMutation{}, err
	}
	wantDigest, err := projections.ApplicationSecretMutationSemanticDigest(candidate, payload)
	if err != nil {
		return events.Event{}, projections.ApplicationSecretMutation{}, err
	}
	gotDigest, err := projections.ApplicationSecretMutationSemanticDigest(canonical, canonicalPayload)
	if err != nil {
		return events.Event{}, projections.ApplicationSecretMutation{}, err
	}
	if !crypto.ConstantTimeEqual([]byte(wantDigest), []byte(gotDigest)) {
		return events.Event{}, projections.ApplicationSecretMutation{},
			fmt.Errorf("%w: canonical application-secret command differs", store.ErrIdempotencyConflict)
	}
	return canonical, canonicalPayload, nil
}

func applicationSecretRecoveryActorsEqual(left, right *events.Actor) bool {
	if left == nil || right == nil {
		return left == nil && right == nil
	}
	if left.Subject != right.Subject || len(left.Roles) != len(right.Roles) {
		return false
	}
	leftRoles := append([]string(nil), left.Roles...)
	rightRoles := append([]string(nil), right.Roles...)
	slices.Sort(leftRoles)
	slices.Sort(rightRoles)
	return slices.Equal(leftRoles, rightRoles)
}

func applicationSecretResultMeta(current store.Secret, event events.Event, payload projections.ApplicationSecretMutation) store.Secret {
	return store.Secret{
		ID: current.ID, TenantID: current.TenantID, Name: current.Name, OwnerID: current.OwnerID,
		Sealed: payload.Sealed, Version: payload.ResultVersion,
		CreatedAt: current.CreatedAt, UpdatedAt: event.Time,
	}
}

// applicationSecretResultAfterFenceRetired answers a retry whose prepared fence
// was completed and retired by the crash-recovery sweep while the retry was in
// flight (DP2-058). The first attempt was shed by backpressure after claiming its
// durable fence; the sweep then finalized, appended and projected that exact
// command and retired the fence, so the retry's own finalize/append found no
// row. The command ran once: the retry gets the canonical receipt instead of
// the sweep's absence of a fence surfacing as 404.
func (a *API) applicationSecretResultAfterFenceRetired(
	ctx context.Context,
	tenantID, eventID, requestBinding, name, action string,
	err error,
) (store.ApplicationSecretMutationReceipt, bool, error) {
	if !applicationSecretFenceRetired(err) {
		return store.ApplicationSecretMutationReceipt{}, false, nil
	}
	receipt, ok, receiptErr := a.applicationSecretMaterializedResult(ctx, tenantID, eventID, requestBinding, name, action)
	if receiptErr != nil {
		return store.ApplicationSecretMutationReceipt{}, false, applicationSecretMutationError(receiptErr)
	}
	return receipt, ok, nil
}

// applicationSecretFenceRetired reports whether err is the store's not-found
// answer for a fence row that a retry expected to still exist. Only the generic
// row-level not-found qualifies; a missing secret is a different contract.
func applicationSecretFenceRetired(err error) bool {
	return err != nil && store.IsNotFound(err) && !errors.Is(err, store.ErrSecretNotFound)
}

func applicationSecretMutationError(err error) error {
	switch {
	case errors.Is(err, store.ErrSecretNotFound):
		return errStatus(http.StatusNotFound, "no such secret")
	case errors.Is(err, store.ErrApprovalRequestNotFound),
		errors.Is(err, store.ErrApprovalDigestMismatch),
		errors.Is(err, store.ErrApprovalSelfDecision),
		errors.Is(err, store.ErrApprovalExpired),
		errors.Is(err, store.ErrApprovalSuperseded),
		errors.Is(err, store.ErrApprovalConsumed),
		errors.Is(err, store.ErrApprovalDrifted),
		errors.Is(err, store.ErrApprovalNotReady):
		return approvalAPIError(err)
	case errors.Is(err, store.ErrIdempotencyConflict):
		return errStatus(http.StatusConflict, "Idempotency-Key belongs to a different application-secret command")
	case errors.Is(err, store.ErrApplicationSecretTenantEpochMismatch):
		return errStatus(http.StatusConflict, "application-secret command belongs to a prior tenant lifecycle")
	case errors.Is(err, errTerminalConnectorRotationDelivery):
		return errStatus(http.StatusServiceUnavailable, connectorRotationDeliveryFailedDetail)
	default:
		return err
	}
}

// ReconcileApplicationSecretMutationFences completes commands that crossed a
// process-crash boundary after their PostgreSQL fence committed. It needs only
// the canonical ciphertext/bindings and exact approval capability already in the
// fence: no plaintext and no raw Idempotency-Key. Pending authority remains
// blocked; terminal unfinalized authority remains available for the store's safe
// row-locked replacement rule.
func (a *API) ReconcileApplicationSecretMutationFences(ctx context.Context) (reconciled int, retErr error) {
	if a == nil {
		return 0, nil
	}
	a.applicationSecretReconcileRun.Lock()
	defer a.applicationSecretReconcileRun.Unlock()

	blocked := make(map[tenantseal.Status]int)
	defer func() {
		a.applicationSecretReconcileHealthMu.Lock()
		a.applicationSecretReconcileBlocked = blocked
		a.applicationSecretReconcileFailed = retErr != nil &&
			!errors.Is(retErr, ErrApplicationSecretMutationReconcileBlocked)
		a.applicationSecretReconcileHealthMu.Unlock()
	}()
	if a.secrets == nil || a.secrets.be.Store == nil || a.secrets.be.EventLog == nil {
		return 0, nil
	}
	tenants, err := a.secrets.be.Store.ListTenants(ctx)
	if err != nil {
		return 0, err
	}
	for _, tenant := range tenants {
		if err := a.secrets.be.Store.WithApplicationSecretMutationPrivacyBarrier(
			ctx, tenant.TenantID, func(context.Context) error { return nil }); err != nil {
			if errors.Is(err, store.ErrPrivacySubjectErasurePreparationActive) {
				blocked[applicationSecretReconcilePrivacyPreparationActive]++
				continue
			}
			return reconciled, err
		}
		fences, err := a.secrets.be.Store.ListApplicationSecretMutationFences(ctx, tenant.TenantID)
		if err != nil {
			return reconciled, err
		}
		for _, fence := range fences {
			payload, err := validateApplicationSecretMutationFence(
				tenant.TenantID, fence.Name, fence.Operation, fence.EventID,
				fence.RequestBinding, fence)
			if err != nil {
				return reconciled, err
			}
			// Migration 0152 cannot synthesize the actor of a command that was
			// already fenced. Retained source history is the only canonical copy.
			// Check before finalizing so an unavailable actor changes neither the
			// target read model nor the durable fence while readiness is degraded.
			if fence.Actor == nil {
				if _, found, lookupErr := a.secrets.be.EventLog.EventByID(ctx, fence.EventID); lookupErr != nil {
					return reconciled, lookupErr
				} else if !found {
					blocked[applicationSecretReconcileLegacyActorUnavailable]++
					continue
				}
			}
			if fence.EventTime.IsZero() {
				var use *store.OperationApprovalUse
				if fence.ApprovalRequired && fence.Approval == nil {
					requester, openErr := a.secrets.open(ctx, tenant.TenantID,
						fence.RequesterSealed, applicationSecretFenceRequesterAAD(tenant.TenantID, fence.EventID))
					if openErr != nil {
						if status, ok := tenantseal.StatusOf(openErr); ok {
							blocked[status]++
							continue
						}
						return reconciled, openErr
					}
					requesterSubject := string(requester)
					secret.Wipe(requester)
					authCtx := context.WithValue(ctx, principalCtxKey, authz.Principal{Subject: requesterSubject})
					use, err = a.authorizeRequiredApplicationSecretMutation(authCtx, tenant.TenantID, payload)
					if err != nil {
						if use == nil {
							return reconciled, err
						}
						if _, bindErr := a.secrets.be.Store.BindApplicationSecretMutationFenceApproval(
							ctx, tenant.TenantID, fence.Name, fence.EventID, *use); bindErr != nil {
							return reconciled, bindErr
						}
						continue
					}
				} else if fence.ApprovalRequired {
					use, err = a.secrets.be.Store.ApplicationSecretMutationFenceApprovalUse(
						ctx, tenant.TenantID, fence)
					if err != nil {
						return reconciled, err
					}
				}
				fence, err = a.secrets.be.Store.FinalizeApplicationSecretMutationFence(
					ctx, tenant.TenantID, fence.Name, fence.EventID, use, time.Now().UTC())
				if err != nil {
					if applicationSecretFenceRetired(err) {
						// The live retry completed and retired this fence under the
						// sweep (DP2-058): nothing is stranded any more.
						continue
					}
					if errors.Is(err, store.ErrApprovalNotReady) ||
						errors.Is(err, store.ErrApprovalExpired) ||
						errors.Is(err, store.ErrApprovalSuperseded) ||
						errors.Is(err, store.ErrApprovalConsumed) {
						continue
					}
					return reconciled, err
				}
			}
			use, err := a.secrets.be.Store.ApplicationSecretMutationFenceApprovalUse(
				ctx, tenant.TenantID, fence)
			if err != nil {
				if applicationSecretFenceRetired(err) {
					continue
				}
				return reconciled, err
			}
			payload.Approval = use
			if _, _, err := a.appendAndProjectApplicationSecretMutation(
				ctx, tenant.TenantID, fence, payload, true); err != nil {
				if applicationSecretFenceRetired(err) {
					continue
				}
				if errors.Is(err, errApplicationSecretLegacyActorUnavailable) {
					blocked[applicationSecretReconcileLegacyActorUnavailable]++
					continue
				}
				if errors.Is(err, store.ErrPrivacySubjectErasurePreparationActive) {
					blocked[applicationSecretReconcilePrivacyPreparationActive]++
					break
				}
				return reconciled, err
			}
			reconciled++
		}
	}
	blockedCount := 0
	for _, count := range blocked {
		blockedCount += count
	}
	if blockedCount > 0 {
		return reconciled, fmt.Errorf("%w: %d durable command(s)",
			ErrApplicationSecretMutationReconcileBlocked, blockedCount)
	}
	return reconciled, nil
}

// ApplicationSecretMutationReconcileHealth is the non-mutating readiness view of
// the last startup/periodic recovery pass. Details are deliberately low-cardinality
// custody statuses; the durable tenant/name fence remains the exact operator
// evidence in PostgreSQL under RLS.
func (a *API) ApplicationSecretMutationReconcileHealth(context.Context) error {
	if a == nil {
		return nil
	}
	a.applicationSecretReconcileHealthMu.RLock()
	defer a.applicationSecretReconcileHealthMu.RUnlock()
	if a.applicationSecretReconcileFailed {
		return errors.New("api: application-secret mutation reconciliation failed; durable commands remain fenced")
	}
	blocked := 0
	statuses := make([]string, 0, len(a.applicationSecretReconcileBlocked))
	for status, count := range a.applicationSecretReconcileBlocked {
		blocked += count
		statuses = append(statuses, string(status))
	}
	if blocked == 0 {
		return nil
	}
	slices.Sort(statuses)
	return fmt.Errorf("%w: %d durable command(s), status=%s",
		ErrApplicationSecretMutationReconcileBlocked, blocked, strings.Join(statuses, ","))
}

// ApplicationSecretMutationReconcileBlockedCount is the low-cardinality metric
// value for the most recent pass. It intentionally exposes no tenant or secret
// label, which avoids turning Prometheus into a cross-tenant naming oracle.
func (a *API) ApplicationSecretMutationReconcileBlockedCount() int {
	if a == nil {
		return 0
	}
	a.applicationSecretReconcileHealthMu.RLock()
	defer a.applicationSecretReconcileHealthMu.RUnlock()
	blocked := 0
	for _, count := range a.applicationSecretReconcileBlocked {
		blocked += count
	}
	return blocked
}

// ApplicationSecretMutationReconcileDegraded reports one unlabeled bit for
// metrics. It covers both tenant-custody blockage and structural recovery errors;
// the raw error, tenant, secret, and fence identity never become metric labels.
func (a *API) ApplicationSecretMutationReconcileDegraded() bool {
	if a == nil {
		return false
	}
	a.applicationSecretReconcileHealthMu.RLock()
	defer a.applicationSecretReconcileHealthMu.RUnlock()
	return a.applicationSecretReconcileFailed || len(a.applicationSecretReconcileBlocked) > 0
}
