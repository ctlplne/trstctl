package orchestrator

import (
	"errors"
	"fmt"
	"time"
)

// State is a point in an identity's lifecycle.
type State string

const (
	StateRequested State = "requested"
	StateIssued    State = "issued"
	StateDeployed  State = "deployed"
	StateRenewing  State = "renewing"
	StateRevoked   State = "revoked"
	StateRetired   State = "retired"
)

// edge is an allowed (from -> to) transition.
type edge struct{ from, to State }

// transitionEvents maps each allowed transition to the event type it emits. It
// is the single source of truth for the lifecycle state machine: a pair absent
// from this map is an invalid transition.
//
//	requested -> issued
//	issued    -> deployed | revoked
//	deployed  -> renewing | revoked
//	renewing  -> deployed | revoked
//	revoked   -> retired        (retired is terminal)
var transitionEvents = map[edge]string{
	{StateRequested, StateIssued}:  "identity.issued",
	{StateIssued, StateDeployed}:   "identity.deployed",
	{StateIssued, StateRevoked}:    "identity.revoked",
	{StateDeployed, StateRenewing}: "identity.renewing",
	{StateDeployed, StateRevoked}:  "identity.revoked",
	{StateRenewing, StateDeployed}: "identity.renewed",
	{StateRenewing, StateRevoked}:  "identity.revoked",
	{StateRevoked, StateRetired}:   "identity.retired",
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

// ErrInvalidTransition matches any invalid-transition rejection via errors.Is.
var ErrInvalidTransition = errors.New("orchestrator: invalid lifecycle transition")

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
}
