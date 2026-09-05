// SPDX-License-Identifier: MPL-2.0

package orchestrator

import (
	"errors"
	"fmt"
	"time"

	"trstctl.com/trstctl/internal/store"
)

// State is a point in an identity's lifecycle.
type State string

const (
	StateRequested State = "requested"
	StateIssued    State = "issued"
	StateDeployed  State = "deployed"
	StateRenewing  State = "renewing"
	// StateRenewalFailed records a renewal attempt that did not produce a new
	// certificate. It exists because BOTH exits from renewing used to fire an
	// external side effect — connector.deploy or revocation.publish — so a failed
	// renewal had to either re-deploy a certificate that was never renewed, be
	// revoked, or sit in renewing forever. The identity is still operationally
	// deployed here: its previous certificate is untouched and still valid.
	StateRenewalFailed State = "renewal_failed"
	StateRevoked       State = "revoked"
	StateRetired       State = "retired"
)

// edge is an allowed (from -> to) transition.
type edge struct{ from, to State }

// transitionEvents maps each allowed transition to the event type it emits. It
// is the single source of truth for the lifecycle state machine: a pair absent
// from this map is an invalid transition.
//
//	requested      -> issued
//	issued         -> deployed | revoked
//	deployed       -> renewing | revoked
//	renewing       -> deployed | renewal_failed | revoked
//	renewal_failed -> renewing | deployed | revoked
//	revoked        -> retired        (retired is terminal)
var transitionEvents = map[edge]string{
	{StateRequested, StateIssued}:  "identity.issued",
	{StateIssued, StateDeployed}:   "identity.deployed",
	{StateIssued, StateRevoked}:    "identity.revoked",
	{StateDeployed, StateRenewing}: "identity.renewing",
	{StateDeployed, StateRevoked}:  "identity.revoked",
	{StateRenewing, StateDeployed}: "identity.renewed",
	{StateRenewing, StateRevoked}:  "identity.revoked",
	// A failed renewal is recorded, not papered over. No side effect: the previous
	// certificate is still deployed and must not be re-pushed.
	{StateRenewing, StateRenewalFailed}: "identity.renewal_failed",
	// Retry, or accept the current certificate and clear the flag, or give up.
	// renewal_failed -> deployed carries no side effect for the same reason:
	// nothing new was issued, so there is nothing to deploy.
	{StateRenewalFailed, StateRenewing}: "identity.renewing",
	{StateRenewalFailed, StateDeployed}: "identity.renewal_recovered",
	{StateRenewalFailed, StateRevoked}:  "identity.revoked",
	{StateRevoked, StateRetired}:        "identity.retired",
}

// sideEffects maps transitions that require an external call to the outbox
// destination that call goes to (AN-6). Transitions absent here are purely
// internal state changes with no side effect.
var sideEffects = map[edge]string{
	{StateRequested, StateIssued}:  "ca.issue",
	{StateIssued, StateDeployed}:   "connector.deploy",
	{StateDeployed, StateRenewing}: "ca.renew",
	{StateRenewing, StateDeployed}: "connector.deploy",
	{StateIssued, StateRevoked}:    "revocation.publish",
	{StateDeployed, StateRevoked}:  "revocation.publish",
	{StateRenewing, StateRevoked}:  "revocation.publish",
	// Retrying a renewal re-runs the CA call; the other two exits from
	// renewal_failed deliberately have none.
	{StateRenewalFailed, StateRenewing}: "ca.renew",
	{StateRenewalFailed, StateRevoked}:  "revocation.publish",
}

// CanTransition reports whether from -> to is a valid lifecycle transition.
func CanTransition(from, to State) bool {
	_, ok := transitionEvents[edge{from, to}]
	return ok
}

// EventTypeFor returns the event type emitted by a valid transition, and whether
// the transition is valid.
func EventTypeFor(from, to State) (string, bool) {
	t, ok := transitionEvents[edge{from, to}]
	return t, ok
}

// LifecycleEventTypes returns the distinct set of event types the lifecycle state
// machine emits, derived from the transition registry (the source of truth). The
// COVER-008 completeness test uses it to assert every served lifecycle transition
// maps to a catalogued event name in the event ledger — so a new transition cannot
// ship an event type the audit catalog does not know about.
func LifecycleEventTypes() map[string]struct{} {
	out := make(map[string]struct{}, len(transitionEvents))
	for _, t := range transitionEvents {
		out[t] = struct{}{}
	}
	return out
}

func sideEffectFor(from, to State) (string, bool) {
	d, ok := sideEffects[edge{from, to}]
	return d, ok
}

// SideEffectFor reports the outbox destination a valid lifecycle edge will
// enqueue. It is intentionally read-only: operator previews use the same
// registry as execution instead of maintaining a second, drift-prone table.
func SideEffectFor(from, to State) (string, bool) {
	return sideEffectFor(from, to)
}

// ErrInvalidTransition matches any invalid-transition rejection via errors.Is.
var ErrInvalidTransition = errors.New("orchestrator: invalid lifecycle transition")

// ErrStaleLifecyclePreview means the identity changed after an operator
// reviewed a lifecycle plan. The action must be previewed again; silently
// applying an old plan would make review theatre rather than authority.
var ErrStaleLifecyclePreview = errors.New("orchestrator: stale lifecycle preview")

// TransitionError is the structured error returned when a transition is not
// permitted by the state machine.
type TransitionError struct {
	IdentityID string
	From       State
	To         State
}

// Error implements error.
func (e *TransitionError) Error() string {
	return fmt.Sprintf("orchestrator: invalid transition for identity %s: %s -> %s", e.IdentityID, e.From, e.To)
}

// Is reports whether the target is the ErrInvalidTransition sentinel.
func (e *TransitionError) Is(target error) bool { return target == ErrInvalidTransition }

// Transition is one applied lifecycle change, as reconstructed from the log.
type Transition struct {
	From     State
	To       State
	Event    string
	Reason   string
	Sequence uint64
	At       time.Time
}

// transitionPayload is the JSON body of a lifecycle event.
type transitionPayload struct {
	IdentityID     string `json:"identity_id"`
	From           State  `json:"from"`
	To             State  `json:"to"`
	Reason         string `json:"reason,omitempty"`
	IdempotencyKey string `json:"idempotency_key,omitempty"`
	// SubjectCSRPEM carries a caller-supplied PKCS#10 certificate request for a
	// requested→issued transition (epic B1). When present, the issuance path
	// signs THIS request and generates no key: the subject private key stays
	// wherever the caller made it and never reaches the control plane. A CSR is
	// public material, so it travels in the event log and outbox like any other
	// transition field.
	//
	// Absent means the legacy path — the control plane generates the subject key
	// itself — which is retained for one release train behind a recorded
	// deprecation event.
	SubjectCSRPEM string                      `json:"subject_csr_pem,omitempty"`
	SideEffect    *transitionSideEffect       `json:"side_effect,omitempty"`
	Approval      *store.OperationApprovalUse `json:"approval,omitempty"`
	// Issuance is the exact profile revision and TTL used by an issuance that
	// does not require dual control. Approval-gated issuance carries the same
	// binding inside Approval instead, so each command has one canonical copy.
	Issuance           *store.OperationApprovalIssuanceBinding `json:"issuance,omitempty"`
	OwnershipReadiness *store.OwnershipReadinessEvidence       `json:"ownership_readiness,omitempty"`
}

// transitionSideEffect carries the durable outbox intent for lifecycle events
// whose transition has an external side effect. It makes the append-then-enqueue
// crash gap replayable: reconciliation can derive both the payload and the
// idempotency key from the event itself.
type transitionSideEffect struct {
	Destination    string `json:"destination"`
	IdempotencyKey string `json:"idempotency_key"`
	Payload        []byte `json:"payload,omitempty"`
	// RequiredAgentRole is the per-row claim demand stamped on the outbox entry
	// (epic A3). It is durable HERE, in the event, because reconciliation
	// rebuilds the outbox row from this record — a classifier consulted only at
	// first enqueue would strand replayed rows unstamped. Classified once, from
	// the pre-seal payload; replay copies, never re-derives.
	RequiredAgentRole string `json:"required_agent_role,omitempty"`
	// Completed is true only when a trusted signed result proves the executor
	// already performed this effect. The event keeps the intended destination
	// for audit/replay validation, while reconciliation treats it as a receipt
	// and never recreates an outbox command.
	Completed bool `json:"completed,omitempty"`
}
