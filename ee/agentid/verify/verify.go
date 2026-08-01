// SPDX-License-Identifier: LicenseRef-trstctl-EE

package verify

import (
	"errors"
	"strings"

	"trstctl.com/trstctl/internal/crypto"
)

// verify.go is the OFFLINE relying-party verification entrypoint (AGID-claims 28, 29,
// 7 relying-party side / INV-A7 RP half). Verify runs a FAIL-CLOSED sequence of
// checks in a deliberate order: cheap structural refusals first, then the
// credential SIGNATURE against the trust root, then the AGENT-STACK-vs-policy
// comparison, then AUTHORITY and TASK-SCOPE, then the TOOL-MANIFEST membership
// (AGID-claim-29), then the short-TTL VALIDITY from the credential alone (AGID-claim-7).
// Every check that can refuse runs before any "allow" is returned; Verify returns
// nil only when all pass. It performs NO network access and constructs NO network
// client (see TestCredential_ShortTTLNoStatusQuery).

// Result reports what the verifier accepted, for a caller's audit log. It carries
// only non-secret values (digests, identifiers). It is meaningful only when Verify
// returns a nil error; on refusal a zero Result and the typed error are returned.
type Result struct {
	// Form is the carriage form the credential was presented in.
	Form Form
	// AgentStackDigest is the bound agent-stack representation digest that matched
	// local policy (empty for a chain-only credential that binds no agent stack).
	AgentStackDigest []byte
	// AuthorityClass is the bound authority-indication class that was honored.
	AuthorityClass string
	// TaskEnvelopeBound reports whether the credential bound a task-envelope digest
	// (and, when true, that the presented action fell within the enforced task
	// scope).
	TaskEnvelopeBound bool
	// Operation / Tool echo the accepted action for the audit record.
	Operation string
	Tool      string
}

// Verification errors, all fail-closed. A caller matches them with errors.Is to
// distinguish refusal reasons. Signature/validity/decode errors live in
// credential.go (ErrSignatureInvalid, ErrCredentialExpired, ErrNoTrustRoot, ...);
// carriage/repr decode errors surface as carriage.Err* / ErrMalformedRepr.
var (
	// ErrNothingBound is returned when the credential binds neither a chain-head nor
	// an agent-stack digest -- there is no subject to verify. Fail-closed.
	ErrNothingBound = errors.New("verify: credential binds no subject (neither chain-head nor agent-stack)")
	// ErrAgentStackNotApproved is returned when the credential binds an agent stack
	// but its digest is not in the relying party's approved set (AGID-claim-28). The
	// bounded guarantee (HARNESS 1.5 note (a)) applies: this confirms the
	// ISSUANCE-TIME binding is one the RP approved, not that the running agent still
	// matches it -- drift is bounded by the credential's short TTL.
	ErrAgentStackNotApproved = errors.New("verify: bound agent-stack representation is not in the relying party's approved policy")
	// ErrAuthorityClassNotPermitted is returned when the bound authority-indication
	// class is not one the relying party accepts.
	ErrAuthorityClassNotPermitted = errors.New("verify: bound authority class is not permitted by local policy")
	// ErrActionExceedsAuthority is returned when the requested action's operation is
	// not within the set the bound authority class permits (AGID-claim-28).
	ErrActionExceedsAuthority = errors.New("verify: requested action exceeds the authority bound in the credential")
	// ErrActionOutsideTaskScope is returned when a task envelope is bound and the
	// requested action falls outside its task scope, EVEN IF the broader authority
	// would permit it (AGID-claim-28 -- task binding is enforced additively).
	ErrActionOutsideTaskScope = errors.New("verify: requested action is outside the bound task-envelope scope")
	// ErrTaskEnvelopeUnverified is returned when the credential binds a task-envelope
	// digest but the policy supplies no matching envelope to bound the action, or the
	// supplied envelope's digest does not equal the bound one. Fail-closed: a
	// task-bound credential is not honored without the verified envelope.
	ErrTaskEnvelopeUnverified = errors.New("verify: credential binds a task-envelope digest that local policy did not supply or does not match")
	// ErrToolAbsentFromManifest is returned when the requested action's tool is not a
	// member of the tool manifest whose digest is bound in the agent-stack
	// representation (AGID-claim-29).
	ErrToolAbsentFromManifest = errors.New("verify: requested action's tool is absent from the bound tool manifest")
	// ErrToolManifestMismatch is returned when the relying party's supplied tool
	// manifest does not have the digest bound in the agent-stack representation, so
	// the RP cannot soundly reason about which tools the agent is confined to.
	// Fail-closed: an action naming a tool is refused when the bound manifest cannot
	// be reconstructed from local policy.
	ErrToolManifestMismatch = errors.New("verify: local tool manifest does not match the tool-manifest digest bound in the agent-stack representation")
	// ErrNoAction is returned when Verify is asked to authorize an action that names
	// no operation. An action must state what it does.
	ErrNoAction = errors.New("verify: requested action names no operation")
)

// Verify is the offline relying-party decision (AGID-claims 28/29/7 RP side). It
// decodes the presented credential, verifies its signature against the pinned
// trust root, compares the bound agent-stack representation to local policy,
// enforces the bound authority and (when present) the bound task scope on the
// requested action, confines the action to the bound tool manifest, and checks
// the credential's short-TTL validity from the credential alone. On success it
// returns a non-nil-free (nil-error) Result describing what was honored; on ANY
// failure it returns a zero Result and a typed, fail-closed error.
//
// clk supplies the instant for the validity check; a nil clk defaults to the
// system clock. The verifier constructs no network client and issues no
// query for a credential's revocation state on any path.
func Verify(cred Credential, root TrustRoot, policy LocalPolicy, action Action, clk Clock) (Result, error) {
	if clk == nil {
		clk = systemClock{}
	}

	// (0) Structural: an action must name an operation.
	op := normOp(action.Operation)
	if op == "" {
		return Result{}, ErrNoAction
	}

	// (1) Decode the carriage form and verify the credential SIGNATURE against the
	// trust root (offline). A tampered or unanchored credential fails here before any
	// policy is consulted.
	bv, win, err := decodeAndVerify(cred, root)
	if err != nil {
		return Result{}, err
	}

	// (2) Fail-closed: the credential must bind SOME subject.
	if len(bv.ChainHeadDigest) == 0 && len(bv.AgentStackDigest) == 0 {
		return Result{}, ErrNothingBound
	}

	// (3) Agent-stack representation vs. LOCAL POLICY (AGID-claim-28). Only when the
	// credential binds an agent stack; a chain-only credential (AGID-claim-31 fallback)
	// carries no representation to compare and is governed by authority + task scope
	// alone.
	var boundRep *boundRepr
	if len(bv.AgentStackDigest) != 0 {
		if !agentStackApproved(bv.AgentStackDigest, policy) {
			return Result{}, ErrAgentStackNotApproved
		}
		// Recover the bound prompt/tool/model digests from the opaque representation so
		// the tool-manifest (AGID-claim-29) can be enforced. A representation the RP approved
		// by digest but whose opaque bytes are absent/malformed is refused fail-closed.
		if len(bv.AgentStackRepr) == 0 {
			// Approved by digest but no repr bytes to confine tools against: only safe if
			// the action names no tool. If it does, refuse (cannot prove membership).
			if normTool(action.Tool) != "" {
				return Result{}, ErrToolManifestMismatch
			}
		} else {
			r, derr := decodeBoundRepr(bv.AgentStackRepr)
			if derr != nil {
				return Result{}, derr
			}
			// Defense in depth: the recovered representation's own digest must equal the
			// separately-bound AgentStackDigest, so the opaque bytes cannot disagree with
			// the digest the RP approved.
			if !constantTimeEqual(reprDigest(bv.AgentStackRepr), bv.AgentStackDigest) {
				return Result{}, ErrAgentStackNotApproved
			}
			boundRep = &r
		}
	}

	// (4) TOOL MANIFEST (AGID-claim-29): when the action names a tool, it must be a member
	// of the manifest whose digest is bound in the representation. The RP supplies the
	// approved manifest; the verifier confirms it is the bound one (digest match) and
	// then checks membership. A credential that binds NO agent-stack representation
	// (a chain-only credential) carries no tool manifest, so an action naming a tool
	// cannot be proven confined and is REFUSED fail-closed (AGID-claim-29 confines the
	// agent to the BOUND subset; with no bound subset, no tool is permitted).
	if boundRep != nil {
		if err := enforceToolManifest(boundRep, policy, action); err != nil {
			return Result{}, err
		}
	} else if normTool(action.Tool) != "" {
		return Result{}, ErrToolManifestMismatch
	}

	// (5) AUTHORITY (AGID-claim-28): the bound class must be permitted, and the action's
	// operation must be within that class's permitted operations.
	if err := enforceAuthority(bv.DesignatedClass, op, policy); err != nil {
		return Result{}, err
	}

	// (6) TASK SCOPE (AGID-claim-28): when the credential binds a task-envelope digest,
	// the action must fall within the bound envelope's scope -- enforced ADDITIVELY,
	// even if the authority above would permit it. A bound envelope the RP cannot
	// supply/verify refuses fail-closed.
	taskBound := len(bv.TaskEnvelopeDigest) != 0
	if taskBound {
		if err := enforceTaskScope(bv.TaskEnvelopeDigest, op, action, policy); err != nil {
			return Result{}, err
		}
	}

	// (7) Short-TTL VALIDITY from the credential alone (AGID-claim-7): expiry/not-yet-valid
	// is decided from the bound window and the caller's clock, with NO status query.
	// When the credential carries a window, it is enforced; a credential presenting no
	// determinable window is honored only if the caller did not require one.
	if err := checkValidity(win, clk, false); err != nil {
		return Result{}, err
	}

	return Result{
		Form:              cred.Form,
		AgentStackDigest:  cloneBytes(bv.AgentStackDigest),
		AuthorityClass:    bv.DesignatedClass,
		TaskEnvelopeBound: taskBound,
		Operation:         op,
		Tool:              normTool(action.Tool),
	}, nil
}

// agentStackApproved reports whether the bound agent-stack digest is in the
// relying party's approved set. An empty approved set refuses every agent-stacked
// credential fail-closed (a relying party that approved nothing honors nothing).
func agentStackApproved(digest []byte, policy LocalPolicy) bool {
	if len(policy.ApprovedAgentStackDigests) == 0 {
		return false
	}
	_, ok := policy.ApprovedAgentStackDigests[digestKey(digest)]
	return ok
}

// enforceToolManifest enforces AGID-claim-29. When the action names no tool, there is
// nothing to confine (the manifest membership check is skipped). When it names a
// tool, the RP's supplied ApprovedToolManifest must have the digest bound in the
// representation (so the RP is reasoning about the right tool set), and the tool
// must be a member of that manifest.
func enforceToolManifest(rep *boundRepr, policy LocalPolicy, action Action) error {
	tool := normTool(action.Tool)
	if tool == "" {
		return nil
	}
	// The supplied manifest must be the bound one.
	if !constantTimeEqual(toolManifestDigest(policy.ApprovedToolManifest), rep.ToolManifestDigest) {
		return ErrToolManifestMismatch
	}
	// Membership: the tool must be in the (canonicalized) approved manifest.
	for _, t := range canonicalTools(policy.ApprovedToolManifest) {
		if t == tool {
			return nil
		}
	}
	return ErrToolAbsentFromManifest
}

// enforceAuthority enforces the authority half of AGID-claim-28: the bound class must
// be permitted (when the policy constrains classes), and the operation must be
// within the class's permitted operations. A class with no permitted-operations
// entry permits NO operation (fail-closed): authority is explicit.
func enforceAuthority(boundClass, op string, policy LocalPolicy) error {
	class := boundClass // authority-class identifiers are compared verbatim (as bound)
	if len(policy.PermittedAuthorityClasses) != 0 {
		if _, ok := policy.PermittedAuthorityClasses[class]; !ok {
			return ErrAuthorityClassNotPermitted
		}
	}
	ops, ok := policy.PermittedOperations[class]
	if !ok || len(ops) == 0 {
		// No operations granted for this class -> the action exceeds authority.
		return ErrActionExceedsAuthority
	}
	if _, ok := ops[op]; !ok {
		return ErrActionExceedsAuthority
	}
	return nil
}

// reprDigest recomputes the AGID signer-bound agent-stack representation digest from
// its opaque canonical bytes, mirroring delegation.AgentStackDigestOf without importing
// the signer-linked package into the RP verifier. The domain tag and length framing are
// part of the AGID-04 binding semantics, so the RP compares against the exact digest the
// signer embedded in the credential.
func reprDigest(repr []byte) []byte {
	var b []byte
	b = append(b, "agid/agentid/agent-stack-repr/v1"...)
	b = appendVerifyU64(b, uint64(len(repr)))
	b = append(b, repr...)
	return crypto.SHA256Sum(b)
}

func appendVerifyU64(b []byte, v uint64) []byte {
	return append(b,
		byte(v>>56), byte(v>>48), byte(v>>40), byte(v>>32),
		byte(v>>24), byte(v>>16), byte(v>>8), byte(v))
}

// normOp normalizes an operation identifier (trim + lowercase) for comparison,
// matching the tool-id normalization discipline.
func normOp(s string) string { return strings.ToLower(strings.TrimSpace(s)) }

// constantTimeEqual compares two digests through internal/crypto's constant-time
// helper. These are public digests (not secrets); using the constant-time helper
// keeps a single comparison discipline. A nil/empty operand never matches a set
// one (fail-closed).
func constantTimeEqual(a, b []byte) bool {
	if len(a) == 0 || len(b) == 0 {
		return false
	}
	return crypto.ConstantTimeEqual(a, b)
}

// digestKey renders digest bytes as a map key without importing encoding/hex into
// the hot path repeatedly; a plain string(conv) of the raw bytes is a stable,
// collision-free key for a set of digests.
func digestKey(digest []byte) string { return string(digest) }

// cloneBytes returns a copy so a returned Result never aliases the decoded
// credential's buffers.
func cloneBytes(p []byte) []byte {
	if len(p) == 0 {
		return nil
	}
	return append([]byte(nil), p...)
}
