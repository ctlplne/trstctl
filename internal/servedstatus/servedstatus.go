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

// Fleet re-issuance batch statuses. A batch is an execution unit under epic D6;
// today it is a planning partition of the affected set.
const (
	// FleetBatchPlanned means the batch exists as a partition of the affected
	// identities. It is not an execution unit and nothing ran per batch.
	FleetBatchPlanned = "planned"
	// FleetBatchExecuted means the batch ran as its own unit.
	FleetBatchExecuted = "executed"
	// FleetBatchFailed means the batch ran as its own unit and failed.
	FleetBatchFailed = "failed"
)

// FleetBatch is the served vocabulary for fleet re-issuance batches.
var FleetBatch = Registry{
	Surface: "fleet re-issuance batch",
	Claims: []Claim{
		{
			Value:   FleetBatchPlanned,
			Meaning: "A partition of the affected identities. The run does not execute batch by batch yet, so this is a plan, not a result.",
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
var Registries = []Registry{ConnectorDelivery, FleetHealthGate, FleetBatch}

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
