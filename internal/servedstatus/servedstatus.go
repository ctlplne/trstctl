// SPDX-License-Identifier: MPL-2.0

// Package servedstatus is the single source of truth for the status strings the
// served API hands an operator to describe what trstctl actually did to a target
// system. A status is a claim, and an operator reads it as one: "delivered" is
// read as "the certificate is on the box", "passed" is read as "something checked
// and it was fine". When the code did less than the word implies, the surface is
// lying even though every test is green.
//
// The mechanism is a small registry. Each status value declares, as data, exactly
// which of four things the recorded attempt did: contacted the target, mutated the
// target, independently verified the result, or evaluated a verdict from evidence.
// The API constructs receipts from these constants instead of string literals, the
// OpenAPI enum is generated from the same registry, and a guard test
// (docs/status_vocabulary_test.go) fails the build when a value's spelling promises
// more than its flags allow.
//
// The contract: a status value may not contain a word implying an action whose flag
// is false. "test_succeeded" cannot exist on a code path that never opened a socket;
// "passed" cannot exist on a gate that evaluated nothing. Renaming the status is the
// cheap, honest move while the real capability is being built — see WS-D in the CLM
// remediation plan, where ContactedTarget/Verified become true for real.
package servedstatus

import "strings"

// Claim is one served status value and the exact set of actions the code performed
// when it recorded that value. The flags are the contract; the spelling is checked
// against them.
type Claim struct {
	// Value is the string the API serves and an operator reads.
	Value string
	// ContactedTarget reports whether the recorded attempt reached the target
	// system over the network or its management API. Local config validation,
	// schema checks, and credential-reference resolution are not contact.
	ContactedTarget bool
	// MutatedTarget reports whether the attempt changed state on the target.
	MutatedTarget bool
	// Verified reports whether the served result was independently re-read —
	// a management-API readback or a TLS handshake against the live listener.
	Verified bool
	// Evaluated reports whether a verdict-shaped status (a gate) was computed
	// from recorded evidence rather than assumed.
	Evaluated bool
	// Meaning is the operator-facing sentence for this value. It states the
	// limits plainly; docs and console tooltips read from here.
	Meaning string
}

// Retired is a status value the code no longer writes but that still exists in
// stored rows, so the served contract must keep describing it. Retiring a value is
// not the same as deleting it: a receipt written last month is still read back
// today, and dropping the value from the OpenAPI enum would make the API serve
// data outside its own published contract (and narrow an enum, which the
// additive-only schema policy forbids).
type Retired struct {
	// Value is the old string, still present in stored rows.
	Value string
	// Replacement is the honest value written in its place.
	Replacement string
	// Why records what the old spelling claimed that the code never did.
	Why string
}

// Registry is a named set of status values for one served surface: the values the
// code may write today, plus the values it used to write and can still read back.
type Registry struct {
	Surface string
	// Claims are writable today and are held to the honesty contract by Audit.
	Claims []Claim
	// Retired are read-only history. They are never constructed, and the guard
	// test proves it, but they stay in the served enum so historical rows remain
	// in contract.
	Retired []Retired
}

// Values returns every status string the surface can serve — writable first, then
// retired — for the OpenAPI enum and the docs table.
func (r Registry) Values() []string {
	out := make([]string, 0, len(r.Claims)+len(r.Retired))
	for _, c := range r.Claims {
		out = append(out, c.Value)
	}
	for _, c := range r.Retired {
		out = append(out, c.Value)
	}
	return out
}

// WritableValues returns only the status strings the code may write today.
func (r Registry) WritableValues() []string {
	out := make([]string, 0, len(r.Claims))
	for _, c := range r.Claims {
		out = append(out, c.Value)
	}
	return out
}

// Lookup returns the writable claim for a status value.
func (r Registry) Lookup(value string) (Claim, bool) {
	for _, c := range r.Claims {
		if c.Value == value {
			return c, true
		}
	}
	return Claim{}, false
}

// IsRetired reports whether value is read-only history on this surface.
func (r Registry) IsRetired(value string) bool {
	for _, c := range r.Retired {
		if c.Value == value {
			return true
		}
	}
	return false
}

// AllRetired returns every retired value across every surface, for the guard test
// that proves none of them is still constructed.
func AllRetired() []Retired {
	var out []Retired
	for _, reg := range Registries {
		out = append(out, reg.Retired...)
	}
	return out
}

// Connector delivery receipt statuses. These are the values served on
// connector_delivery_receipts and in the ConnectorDelivery OpenAPI schema.
const (
	// ConnectorQueued means the intent is committed on the outbox (AN-6) and no
	// connector has run yet.
	ConnectorQueued = "queued"
	// ConnectorDelivered means a connector executed the mutation against the
	// target. It does NOT mean the endpoint was re-read and proven to serve the
	// new credential — that is WS-D/D3's separate `verified` state.
	ConnectorDelivered = "delivered"
	// ConnectorFailed means the attempt ran and did not succeed.
	ConnectorFailed = "failed"
	// ConnectorVerified means the credential was applied AND a TLS handshake
	// afterwards observed the endpoint serving it (epic D3).
	//
	// This is the third state the delivery vocabulary has been missing, and
	// ConnectorDelivered's own Meaning has pointed at it since it shipped:
	// "the endpoint has not been independently re-read; live verification is a
	// separate state". Issued, delivered, and verified are three different
	// claims — a certificate can be all three, or issued and delivered but not
	// verified, and only the third one is what an operator actually wanted.
	ConnectorVerified = "verified"
	// ConnectorVerifyFailed means the credential was applied and the endpoint
	// is NOT serving it.
	//
	// Distinct from ConnectorFailed, which means the attempt did not complete.
	// The difference decides what to do next: a failed deploy is retried, a
	// verified-failed deploy is rolled back, and retrying the second would run
	// forever against a listener that already has the file and ignored it.
	ConnectorVerifyFailed = "verify_failed"
	// ConnectorConfigValidated means target metadata, schema, and credential
	// references were validated locally. The target was NOT contacted. This
	// replaces the former "test_succeeded", which claimed a successful test on a
	// code path that opens no connection (truth-integrity 3). It becomes a real
	// contacting dry-run under epic D5.
	ConnectorConfigValidated = "config_validated"
	// ConnectorRollbackRecorded means an operator-attested rollback intent is
	// recorded in the evidence chain. No rollback was executed against the target
	// and no predecessor bundle was restored (truth-integrity 4). Epic D4 makes
	// this an executed job with a restore transcript.
	ConnectorRollbackRecorded = "rollback_recorded"
	// ConnectorRollbackQueued means an executable rollback has been QUEUED for a
	// relay (epic D4). Deliberately not a result: the relay has not reported
	// yet, and a status that read as an outcome here would repeat the defect
	// rollback_recorded was created to expose, one step further along.
	ConnectorRollbackQueued = "rollback_queued"
	// ConnectorRolledBack means a relay reported that it re-bound the target to
	// the predecessor object. The listener was contacted and its binding was
	// changed; what it now serves has not been independently re-read, which is
	// verification and a separate state.
	ConnectorRolledBack = "rolled_back"
	// ConnectorRollbackRefused means the relay declined the rollback WITHOUT
	// reaching the target — it could not execute the connector, the connector
	// cannot re-bind, no predecessor was named, the credential was not granted,
	// or the sandbox blocked the operation.
	//
	// It exists because the alternative was recording these as a generic
	// failure whose registry entry asserts ContactedTarget. That would tell an
	// operator the appliance rejected something it never heard about, and send
	// them to check an appliance that is fine.
	ConnectorRollbackRefused = "rollback_refused"
	// ConnectorRollbackFailed means the relay REACHED the target and the
	// re-bind did not succeed — including the case where the predecessor object
	// is no longer installed, which is the reason an operator most needs
	// distinguished, since no retry will produce one.
	ConnectorRollbackFailed = "rollback_failed"
	// ConnectorTestQueued means a relay-executed dry-run has been QUEUED (epic
	// D5). It is deliberately not a result: the relay has not reported yet. A
	// status that read as an outcome here would repeat the defect
	// config_validated was created to fix, one step further along.
	ConnectorTestQueued = "dry_run_queued"
	// ConnectorTestPlanned means a relay ran the dry-run and reported that a real
	// deploy WOULD proceed: credentials resolved, endpoint answered, mutation
	// plan returned. Nothing was changed — the dry-run path never invokes a
	// connector's Deploy, so zero writes is structural rather than promised.
	ConnectorTestPlanned = "dry_run_planned"
	// ConnectorTestBlocked means a relay ran the dry-run and a real deploy would
	// NOT proceed. The reason names the step that stopped it.
	ConnectorTestBlocked = "dry_run_blocked"
)

// ConnectorDelivery is the served vocabulary for connector delivery receipts.
var ConnectorDelivery = Registry{
	Surface: "connector delivery receipt",
	Claims: []Claim{
		{
			Value:   ConnectorQueued,
			Meaning: "Intent committed to the outbox in the same transaction as the state change. No connector has run.",
		},
		{
			Value:           ConnectorDelivered,
			ContactedTarget: true,
			MutatedTarget:   true,
			Meaning:         "A connector reached the target and applied the credential. The endpoint has not been independently re-read; live verification is a separate state.",
		},
		{
			Value:           ConnectorFailed,
			ContactedTarget: true,
			Meaning:         "The attempt ran and did not succeed. The reason field carries the cause.",
		},
		{
			Value:           ConnectorVerified,
			ContactedTarget: true,
			MutatedTarget:   true,
			Verified:        true,
			Meaning:         "A connector applied the credential and a TLS handshake against the endpoint afterwards observed it serving that exact identity. This is the only delivery state that says the certificate is live rather than that it was sent.",
		},
		{
			Value:           ConnectorVerifyFailed,
			ContactedTarget: true,
			MutatedTarget:   true,
			Verified:        true,
			Meaning:         "A connector applied the credential and a handshake found the endpoint serving something else. The delivery succeeded; the endpoint did not take it. This is a renewal that did not land, not a delivery that failed.",
		},
		{
			Value:   ConnectorConfigValidated,
			Meaning: "Target metadata, schema, and credential references validated locally. The target was not contacted and nothing was changed.",
		},
		{
			Value:   ConnectorRollbackRecorded,
			Meaning: "An operator-attested rollback intent is recorded as evidence. No rollback was executed against the target.",
		},
		{
			Value:   ConnectorRollbackQueued,
			Meaning: "An executable rollback was queued for a relay. No relay has reported yet, so the target is unchanged so far as this control plane knows.",
		},
		{
			Value:           ConnectorRolledBack,
			ContactedTarget: true,
			MutatedTarget:   true,
			Meaning:         "A relay re-bound the target to the predecessor certificate already installed on it. No key was uploaded. What the endpoint now serves has not been independently re-read.",
		},
		{
			Value:   ConnectorRollbackRefused,
			Meaning: "A relay declined the rollback before contacting the target. The reason names which precondition it failed; the target was not reached and is unchanged.",
		},
		{
			Value:           ConnectorRollbackFailed,
			ContactedTarget: true,
			Meaning:         "A relay reached the target and the re-bind did not succeed. The reason distinguishes a predecessor that is no longer installed — which no retry will fix — from a failure at the appliance.",
		},
		{
			Value:   ConnectorTestQueued,
			Meaning: "A relay-executed dry-run was queued. No relay has reported yet, so nothing is known about the target beyond its configuration.",
		},
		{
			Value:           ConnectorTestPlanned,
			ContactedTarget: true,
			Meaning:         "A relay reached the target, resolved every credential a deploy needs, and returned the mutation plan. Nothing was changed: the dry-run path never invokes a connector's deploy.",
		},
		{
			Value:           ConnectorTestBlocked,
			ContactedTarget: true,
			Meaning:         "A relay ran the dry-run and a real deploy would not proceed. The reason names the step that stopped it. Nothing was changed.",
		},
	},
	Retired: []Retired{{
		Value:       "test_succeeded",
		Replacement: ConnectorConfigValidated,
		Why:         "claimed a successful test on a route that validates configuration locally and never opens a connection to the target (truth-integrity 3)",
	}},
}

// Fleet re-issuance health-gate statuses. A gate is a verdict, so its vocabulary
// carries Evaluated rather than the target-contact flags.
const (
	// FleetGateNotEvaluated is the honest default: the run recorded no evidence
	// from which a verdict could be computed. Until epic D6 wires gates to WS-D
	// verification receipts, every gate trstctl fills in itself is this value.
	FleetGateNotEvaluated = "not_evaluated"
	// FleetGatePassed means a verdict was computed from recorded evidence and the
	// gate held.
	FleetGatePassed = "passed"
	// FleetGateFailed means a verdict was computed from recorded evidence and the
	// gate did not hold.
	FleetGateFailed = "failed"
)

// Endpoint verification statuses (epic D2).
//
// This is the family the connector-delivery vocabulary has been pointing at
// since it shipped: ConnectorDelivered says plainly that "the endpoint has not
// been independently re-read; live verification is a separate state". This is
// that state.
//
// It is the only family in this file whose values may carry Verified, and they
// earn it in the way the flag's own definition names — a TLS handshake against
// the live listener. Everything before it could say what trstctl DID; these say
// what the listener is serving.
const (
	// EndpointVerified means a handshake observed the listener serving the
	// expected identity.
	EndpointVerified = "verified"
	// EndpointDiverged means a handshake succeeded and what it found is not
	// what was deployed. The mismatch class names which way.
	EndpointDiverged = "diverged"
	// EndpointUnreachable means the handshake did not complete. Deliberately
	// NOT a divergence: a network problem and a certificate problem send an
	// operator to different people, and it must never read as verified.
	EndpointUnreachable = "unreachable"
	// EndpointNotChecked is the honest default for an endpoint nothing has
	// probed — including every endpoint for which no operator has configured a
	// listener address. Absence of a check is not absence of a problem.
	EndpointNotChecked = "not_checked"
)

// EndpointVerification is the served vocabulary for observed endpoint identity.
var EndpointVerification = Registry{
	Surface: "endpoint verification",
	Claims: []Claim{
		{
			Value:           EndpointVerified,
			ContactedTarget: true,
			Verified:        true,
			Meaning:         "A TLS handshake against the live listener observed it serving the expected identity. What was checked — fingerprint, and optionally the name set and chain — travels with the record.",
		},
		{
			Value:           EndpointDiverged,
			ContactedTarget: true,
			Verified:        true,
			Meaning:         "A TLS handshake succeeded and the listener is not serving what was deployed. The mismatch class names the difference; this is a renewal that did not land, not a delivery that failed.",
		},
		{
			Value:           EndpointUnreachable,
			ContactedTarget: false,
			Meaning:         "The handshake did not complete, so nothing was observed and nothing is claimed. This is not a divergence and it is not a pass.",
		},
		{
			Value:   EndpointNotChecked,
			Meaning: "No verification has been performed for this endpoint from this vantage. An endpoint with no configured listener address stays here permanently, which is the honest answer rather than a passing one.",
		},
	},
}

// FleetHealthGate is the served vocabulary for fleet re-issuance health gates.
var FleetHealthGate = Registry{
	Surface: "fleet re-issuance health gate",
	Claims: []Claim{
		{
			Value:   FleetGateNotEvaluated,
			Meaning: "No evidence has been recorded for this gate, so no verdict exists. Not a pass.",
		},
		{
			Value:     FleetGatePassed,
			Evaluated: true,
			Meaning:   "A verdict was computed from recorded evidence and the gate held.",
		},
		{
			Value:     FleetGateFailed,
			Evaluated: true,
			Meaning:   "A verdict was computed from recorded evidence and the gate did not hold.",
		},
	},
}

// Fleet re-issuance batch statuses. A batch is a durable execution unit.
const (
	// FleetBatchPlanned means the batch exists as a partition of the affected
	// identities but has not been published to the worker.
	FleetBatchPlanned = "planned"
	// FleetBatchQueued means the batch has one durable outbox command. The
	// command may not have started and no target mutation is claimed yet.
	FleetBatchQueued = "queued"
	// FleetBatchWaitingVerification means replacement issuance/deployment work
	// for this batch was published, but no signed endpoint verdict exists yet.
	FleetBatchWaitingVerification = "waiting_verification"
	// FleetBatchExecuted means the batch ran as its own unit.
	FleetBatchExecuted = "executed"
	// FleetBatchFailed means the batch ran as its own unit and failed.
	FleetBatchFailed = "failed"
	// FleetBatchHalted means the batch did NOT run because an earlier batch's
	// verification failed (epic D6).
	//
	// Distinct from failed, and the distinction is the whole value of a canary:
	// a halted batch was never attempted, so nothing about it is broken and
	// nothing about it needs fixing. Reporting it as failed would send an
	// operator to investigate targets that are still serving perfectly well,
	// during an incident, which is the worst possible time to waste attention.
	FleetBatchHalted = "halted"
)

// FleetBatch is the served vocabulary for fleet re-issuance batches.
var FleetBatch = Registry{
	Surface: "fleet re-issuance batch",
	Claims: []Claim{
		{
			Value:   FleetBatchHalted,
			Meaning: "This batch was not attempted because an earlier batch's verification failed. Nothing here was changed and nothing here is known to be broken; the run stopped before reaching it.",
		},
		{
			Value:   FleetBatchPlanned,
			Meaning: "A partition of the affected identities that has not been published to the worker. Nothing in it has been attempted.",
		},
		{
			Value:   FleetBatchQueued,
			Meaning: "One durable outbox command exists for this batch. No target mutation is claimed until the worker records it.",
		},
		{
			Value:   FleetBatchWaitingVerification,
			Meaning: "Replacement work for this batch was published, but a signature-verified agent receipt has not yet proved what endpoints serve. Later batches remain unpublished.",
		},
		{
			Value:         FleetBatchExecuted,
			MutatedTarget: true,
			Evaluated:     true,
			Meaning:       "The batch ran as its own execution unit and completed.",
		},
		{
			Value:         FleetBatchFailed,
			MutatedTarget: true,
			Evaluated:     true,
			Meaning:       "The batch ran as its own execution unit and failed.",
		},
	},
	Retired: []Retired{{
		Value:       "completed",
		Replacement: FleetBatchPlanned,
		Why:         "every batch was stamped completed at planning time, before anything ran per batch (truth-integrity 2)",
	}},
}

// Registries is every served status vocabulary, for the guard test and the docs
// generator to walk.
var Registries = []Registry{ConnectorDelivery, EndpointVerification, FleetHealthGate, FleetBatch}

// overclaim is one banned spelling and the flag that must be true to use it.
type overclaim struct {
	// Word is matched against the status value's underscore-separated words and
	// against the whole value, so "test_succeeded" and "succeeded" both match.
	Word string
	// Flag names the Claim field that licenses the word.
	Flag string
	// Why explains the failure in the guard test's message.
	Why string
}

// overclaims is the honesty contract: a status value may not spell an action it
// did not perform. Keep this list conservative — it exists to catch the specific
// failure the gap analysis found (a status string that reads like an outcome on a
// code path that produced no outcome), not to police vocabulary in general.
var overclaims = []overclaim{
	{"succeeded", "ContactedTarget", "reads as a successful interaction with the target"},
	{"success", "ContactedTarget", "reads as a successful interaction with the target"},
	{"tested", "ContactedTarget", "reads as the target having been tested"},
	{"reachable", "ContactedTarget", "reads as the target having been reached"},
	{"connected", "ContactedTarget", "reads as a connection to the target"},

	{"deployed", "MutatedTarget", "reads as the credential being installed on the target"},
	{"installed", "MutatedTarget", "reads as the credential being installed on the target"},
	{"applied", "MutatedTarget", "reads as a change applied to the target"},
	{"completed", "MutatedTarget", "reads as work having finished against the target"},
	{"executed", "MutatedTarget", "reads as work having run against the target"},
	{"rolled_back", "MutatedTarget", "reads as a rollback having been executed"},
	{"restored", "MutatedTarget", "reads as a predecessor having been restored"},

	{"verified", "Verified", "reads as the served state having been independently re-read"},
	{"confirmed", "Verified", "reads as the served state having been independently re-read"},
	{"proven", "Verified", "reads as the served state having been independently re-read"},

	{"passed", "Evaluated", "reads as a verdict computed from evidence"},
	{"healthy", "Evaluated", "reads as a verdict computed from evidence"},
	{"green", "Evaluated", "reads as a verdict computed from evidence"},
}

// Violation is one status value whose spelling promises more than its flags allow.
type Violation struct {
	Surface string
	Value   string
	Word    string
	Flag    string
	Why     string
}

func (v Violation) Error() string {
	return v.Surface + " status " + quote(v.Value) + ": the word " + quote(v.Word) +
		" " + v.Why + ", but " + v.Flag + " is false"
}

func quote(s string) string { return `"` + s + `"` }

// Audit walks every registry and returns each status value that spells an action
// its flags say the code did not perform. An empty result means the served status
// vocabulary does not overstate itself.
func Audit() []Violation {
	var out []Violation
	for _, reg := range Registries {
		for _, claim := range reg.Claims {
			for _, oc := range overclaims {
				if !containsWord(claim.Value, oc.Word) {
					continue
				}
				if claimFlag(claim, oc.Flag) {
					continue
				}
				out = append(out, Violation{
					Surface: reg.Surface, Value: claim.Value,
					Word: oc.Word, Flag: oc.Flag, Why: oc.Why,
				})
			}
		}
	}
	return out
}

// containsWord reports whether value contains word as a whole underscore-separated
// token or as a suffix token, so "test_succeeded" matches "succeeded" while
// "unsuccessful_precondition" does not match "success" by accident. Multi-word
// entries like "rolled_back" are matched against the joined value.
func containsWord(value, word string) bool {
	if strings.Contains(word, "_") {
		return strings.Contains(value, word)
	}
	for _, token := range strings.Split(value, "_") {
		if token == word {
			return true
		}
	}
	return false
}

func claimFlag(c Claim, name string) bool {
	switch name {
	case "ContactedTarget":
		return c.ContactedTarget
	case "MutatedTarget":
		return c.MutatedTarget
	case "Verified":
		return c.Verified
	case "Evaluated":
		return c.Evaluated
	default:
		return false
	}
}
