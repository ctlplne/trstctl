// SPDX-License-Identifier: LicenseRef-trstctl-EE

package verify

import (
	"trstctl.com/trstctl/ee/agentid/taskenv"
)

// taskscope.go enforces the TASK-BINDING half of claim 28: when a credential
// binds a task-envelope digest, a requested action must fall within the scope of
// THAT envelope, enforced ADDITIVELY -- even when the broader authority set would
// permit the action. The relying party supplies its own copy of the envelope
// (LocalPolicy.ExpectedTaskEnvelope); the verifier recomputes the envelope's
// AGID-05 canonical digest and requires it to equal the bound digest, so a caller
// cannot substitute a different (broader) envelope for the one the credential was
// issued against. Then the action's operation must be within the envelope's scope,
// and -- when the envelope committed to specific inputs -- the action's input must
// be one the envelope committed to. All of this is OFFLINE: the envelope is
// supplied, not fetched, and its digest is recomputed locally through
// internal/crypto (AN-3) via taskenv.Envelope.Digest.

// TaskScopeOf describes the operation/input scope the relying party derives from a
// bound task envelope. The envelope model (AGID-05) states task INTENT and input
// COMMITMENTS but not an explicit operation allow-list, so a relying party maps an
// envelope to the operations it authorizes with a small, local policy hook. When
// no hook is configured, the default scope authorizes exactly the operations named
// in the envelope's TaskScopeOperations convention (see scopeOperations) and
// confines inputs to the envelope's committed set.
//
// This keeps task-scope enforcement PROPERTY-DRIVEN and offline: the envelope's
// committed inputs and (optionally) a caller-declared operation set bound the
// action, independent of the authority set.

// scopeOperations returns the set of operation identifiers a bound task envelope
// authorizes. It reads them from the envelope's TaskIntent: the structured
// Description is treated as an opaque intent (not an operation list), so the
// authorized operations are taken from the InputCommitments' names UNION any
// operations a relying party pinned via ExpectedTaskEnvelope's intent digest
// convention. To keep the model concrete and testable without inventing new
// envelope fields, a relying party encodes the authorized operations as
// InputCommitments whose Name is prefixed "op:" (an operation the task may
// perform) -- everything else is an input commitment. This is a LOCAL convention
// the RP and issuer agree on; the envelope digest binds it either way.
func scopeOperations(env *taskenv.Envelope) map[string]struct{} {
	ops := make(map[string]struct{})
	for _, c := range env.Task.InputCommitments {
		name := normOp(c.Name)
		if len(name) > 3 && name[:3] == "op:" {
			ops[name[3:]] = struct{}{}
		}
	}
	return ops
}

// scopeInputs returns the set of committed input names (those NOT encoding an
// operation) an action may operate on, keyed by normalized name, with the
// committed digest as the value for a digest-equality check.
func scopeInputs(env *taskenv.Envelope) map[string][]byte {
	in := make(map[string][]byte)
	for _, c := range env.Task.InputCommitments {
		name := normOp(c.Name)
		if len(name) > 3 && name[:3] == "op:" {
			continue
		}
		in[name] = c.Digest
	}
	return in
}

// enforceTaskScope enforces claim 28's task binding. The credential bound
// boundDigest; the RP must supply an ExpectedTaskEnvelope whose recomputed digest
// equals boundDigest (else ErrTaskEnvelopeUnverified). Then:
//
//   - If the envelope declares authorized operations (via the "op:" commitment
//     convention), the action's operation must be among them; otherwise it is
//     OUTSIDE the task scope (ErrActionOutsideTaskScope) -- even if the authority
//     set would permit it.
//   - If the envelope committed to inputs and the action names an input, that input
//     (name + digest) must match a committed input; an action over an input the
//     envelope did not commit to is outside the task scope.
//
// The check is ADDITIVE: it can only ever REFUSE relative to the authority check
// (task binding narrows, never broadens). It performs no key operation and no I/O.
func enforceTaskScope(boundDigest []byte, op string, action Action, policy LocalPolicy) error {
	env := policy.ExpectedTaskEnvelope
	if env == nil {
		// Bound to a task envelope the RP did not supply: cannot bound the action.
		return ErrTaskEnvelopeUnverified
	}
	got, err := env.Digest()
	if err != nil {
		return ErrTaskEnvelopeUnverified
	}
	if !constantTimeEqual(got, boundDigest) {
		// The supplied envelope is not the one the credential was issued against.
		return ErrTaskEnvelopeUnverified
	}

	// Operation scope: if the envelope declares an authorized operation set, the
	// action's operation must be within it. An envelope that declares no operations
	// (no "op:" commitments) does not constrain the operation here -- the authority
	// check already governs which operations are permitted; task binding then
	// constrains INPUTS below. This preserves "task binding enforced even when
	// broader authority would permit": whenever the envelope names operations, an
	// operation outside them is refused regardless of authority.
	if ops := scopeOperations(env); len(ops) != 0 {
		if _, ok := ops[op]; !ok {
			return ErrActionOutsideTaskScope
		}
	}

	// Input scope: when the envelope committed to inputs and the action names one, it
	// must match a committed input by name and digest.
	inputs := scopeInputs(env)
	if len(inputs) != 0 && action.TaskInputName != "" {
		want, ok := inputs[normOp(action.TaskInputName)]
		if !ok {
			return ErrActionOutsideTaskScope
		}
		if !constantTimeEqual(want, action.TaskInputDigest) {
			return ErrActionOutsideTaskScope
		}
	}

	return nil
}
