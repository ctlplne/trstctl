// SPDX-License-Identifier: LicenseRef-trstctl-EE

package verify

// helpers.go holds small, allocation-light constructors a relying party uses to
// assemble a LocalPolicy. They perform no I/O and no key operation.

// NewLocalPolicy returns an empty policy with initialized maps, ready for the
// Approve* helpers. A zero-value LocalPolicy is also usable (the verifier treats
// nil maps as fail-closed empties), but this avoids nil-map panics when a caller
// assigns into the maps directly.
func NewLocalPolicy() LocalPolicy {
	return LocalPolicy{
		ApprovedAgentStackDigests: make(map[string]struct{}),
		PermittedAuthorityClasses: make(map[string]struct{}),
		PermittedOperations:       make(map[string]map[string]struct{}),
	}
}

// ApproveAgentStack adds an agent-stack representation digest to the approved set,
// so a credential binding that digest passes the local-policy comparison (claim
// 28). The digest is the AGID-03 Representation.Digest of an approved
// prompt/tool/model stack. Returns the policy for chaining.
func (p LocalPolicy) ApproveAgentStack(agentStackDigest []byte) LocalPolicy {
	if p.ApprovedAgentStackDigests == nil {
		return p
	}
	p.ApprovedAgentStackDigests[digestKey(cloneBytes(agentStackDigest))] = struct{}{}
	return p
}

// PermitClass records that the relying party accepts the given bound authority
// class. When at least one class is permitted, a credential whose bound class is
// not among them is refused. Returns the policy for chaining.
func (p LocalPolicy) PermitClass(class string) LocalPolicy {
	if p.PermittedAuthorityClasses == nil {
		return p
	}
	p.PermittedAuthorityClasses[class] = struct{}{}
	return p
}

// GrantOperations grants a bound authority class the set of operation identifiers
// it may perform. An action whose operation is not granted for the credential's
// bound class exceeds authority and is refused (AGID-claim-28). Operations are
// normalized (trim + lowercase). Returns the policy for chaining.
func (p LocalPolicy) GrantOperations(class string, ops ...string) LocalPolicy {
	if p.PermittedOperations == nil {
		return p
	}
	set := p.PermittedOperations[class]
	if set == nil {
		set = make(map[string]struct{}, len(ops))
		p.PermittedOperations[class] = set
	}
	for _, o := range ops {
		set[normOp(o)] = struct{}{}
	}
	return p
}

// WithToolManifest sets the relying party's approved tool manifest (the tool list
// whose digest is bound in the agent-stack representation). Returns the policy for
// chaining.
func (p LocalPolicy) WithToolManifest(tools ...string) LocalPolicy {
	p.ApprovedToolManifest = append([]string(nil), tools...)
	return p
}
