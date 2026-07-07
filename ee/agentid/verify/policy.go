// SPDX-License-Identifier: LicenseRef-trstctl-EE

package verify

import (
	"time"

	"trstctl.com/trstctl/ee/agentid/taskenv"
)

// policy.go defines the RELYING PARTY's LOCAL POLICY, the REQUESTED ACTION, and
// the CREDENTIAL a caller presents, plus the CLOCK. Everything the verifier needs
// is supplied by the caller (offline: nothing is fetched). None of these types
// holds a secret; digests and identifiers are non-secret and safe to carry.

// TrustRoot supplies the offline trust anchor for the credential SIGNATURE, in
// exactly the shape each carriage form needs. A relying party configures ONE of
// these out of band (a pinned CA, a pinned issuer key, a static JWKS bundle) --
// never fetched at verify time. At least one must be set for the presented form;
// a form with no matching trust root fails closed (ErrNoTrustRoot).
type TrustRoot struct {
	// CACertDER is the DER of the trusted issuing CA for the X.509 carriage form.
	// The credential certificate must chain to (be signed by) this CA. Offline: no
	// AIA/CDP fetch, no path building beyond the single pinned CA.
	CACertDER []byte

	// IssuerPublicDER is the PKIX/DER SubjectPublicKeyInfo of the trusted issuer key
	// used to verify a DETACHED signature over the workload-identity document or the
	// signed-token form when the caller presents the signature separately
	// (Credential.Signature). It also verifies a workload-identity document whose
	// issuer signs the canonical document bytes.
	IssuerPublicDER []byte

	// JWKSJSON is a STATIC JSON Web Key Set (bytes) the relying party pinned out of
	// band; the signed-token form's signature is verified against the key it selects
	// by kid. It is parsed locally -- never fetched from a jwks_uri. Empty disables
	// JWKS-based token verification.
	JWKSJSON []byte
}

// LocalPolicy is the relying party's approved-configuration policy the bound
// credential is checked against (claim 28 / claim 29). It is entirely local and
// static; the verifier consults nothing else.
type LocalPolicy struct {
	// ApprovedAgentStackDigests is the set of agent-stack representation digests
	// (each the AGID-03 Representation.Digest of an APPROVED prompt/tool/model stack)
	// the relying party will honor. The bound agent-stack digest must be a member;
	// an out-of-policy representation is REFUSED (ErrAgentStackNotApproved). At least
	// one entry is required for a credential that binds an agent stack -- an empty
	// approved set refuses every agent-stacked credential fail-closed.
	//
	// Keyed by the raw digest bytes rendered as a hex-independent map key (the
	// verifier uses a byte-safe encoding internally); callers add entries with
	// ApproveAgentStack.
	ApprovedAgentStackDigests map[string]struct{}

	// ApprovedToolManifest is the relying party's copy of the tool manifest whose
	// digest is bound in the agent-stack representation (claim 29). The verifier
	// recomputes its digest and requires it to equal the bound tool-manifest digest;
	// then a requested action's tool must be a member of this manifest. When empty,
	// tool-manifest enforcement still runs: the bound representation's tool-manifest
	// digest must equal the digest of the EMPTY manifest, and any action naming a
	// tool is refused (an empty manifest confines the agent to no tools).
	ApprovedToolManifest []string

	// PermittedAuthorityClasses is the set of authority-indication classes
	// (BoundValues.DesignatedClass) the relying party accepts. A credential whose
	// bound class is not listed is refused (an unknown authority indication is not
	// honored). Empty means "accept any bound class" (the class check is skipped);
	// authority-vs-action scope is still enforced via PermittedOperations.
	PermittedAuthorityClasses map[string]struct{}

	// PermittedOperations maps a bound authority class to the set of operation
	// identifiers that class is permitted to perform. A requested action whose
	// operation is not in the bound class's permitted set EXCEEDS the bound authority
	// and is refused (ErrActionExceedsAuthority). A class absent from this map (or a
	// nil map) permits NO operation for that class (fail-closed): authority must be
	// explicitly granted. Operation identifiers are compared after normalization
	// (trim + lowercase).
	PermittedOperations map[string]map[string]struct{}

	// ExpectedTaskEnvelope, when set, is the relying party's copy of the AGID-05 task
	// envelope whose digest is bound in the credential. The verifier recomputes its
	// digest and requires it to equal BoundValues.TaskEnvelopeDigest (so the caller
	// cannot substitute a different envelope), then enforces TASK SCOPE: a requested
	// action must fall within the envelope's task scope (its InputCommitments /
	// operation allow-list) even when the broader authority would permit it (claim
	// 28 -- task binding is enforced additively). When the credential binds a
	// task-envelope digest but the policy supplies no ExpectedTaskEnvelope, the
	// action is refused fail-closed (ErrTaskEnvelopeUnverified): a task-bound
	// credential cannot be honored without the envelope to bound it.
	ExpectedTaskEnvelope *taskenv.Envelope
}

// Action is the operation a caller wants the credentialed agent to perform, which
// the relying party checks against the bound authority, task scope, and tool
// manifest. The caller supplies it; the verifier fetches nothing.
type Action struct {
	// Operation is the operation identifier the action performs (e.g.
	// "read-object", "invoke-payment"). It is checked against the bound authority's
	// permitted operations (claim 28) and, when a task envelope is bound, against the
	// task scope. Compared after normalization (trim + lowercase). An empty operation
	// is refused fail-closed (an action must name what it does).
	Operation string

	// Tool is the tool identifier the action would use. It must be a member of the
	// bound tool manifest (claim 29); a tool absent from the manifest refuses the
	// action (ErrToolAbsentFromManifest). Compared after normalization (trim +
	// lowercase). Empty means the action uses no tool -- the tool-manifest membership
	// check is then skipped for this action (the authority and task-scope checks
	// still run).
	Tool string

	// TaskInputName / TaskInputDigest, when both set, name an input the action
	// operates on. When a task envelope is bound and enforced, the action's input
	// must correspond to one of the envelope's InputCommitments (matching name and
	// digest); an action over an input the envelope did not commit to is OUTSIDE the
	// task scope and refused. When the envelope carries no InputCommitments, input
	// binding is not enforced (the operation-scope check still applies).
	TaskInputName   string
	TaskInputDigest []byte
}

// Clock supplies the current time for the short-TTL validity check (claim 7). It
// is an interface (not time.Now) so the offline validity decision is testable and
// so the verify path never reaches for a wall clock through any network-adjacent
// facility. A nil Clock passed to Verify defaults to the system clock.
type Clock interface {
	Now() time.Time
}

// systemClock is the default Clock (time.Now). It performs no I/O and constructs
// no network client.
type systemClock struct{}

func (systemClock) Now() time.Time { return time.Now() }

// fixedClock is a deterministic Clock for tests and vectors.
type fixedClock struct{ t time.Time }

func (c fixedClock) Now() time.Time { return c.t }

// unixToTime converts a Unix-second timestamp to a time.Time (UTC). It is used by
// the conformance-vector runner to evaluate a vector at its fixed instant without
// a wall clock.
func unixToTime(sec int64) time.Time { return time.Unix(sec, 0).UTC() }

// FixedClock returns a Clock that always reports t. It lets a relying party (and
// the conformance-vector runner) evaluate a credential's validity at a chosen
// instant without a wall clock.
func FixedClock(t time.Time) Clock { return fixedClock{t: t} }
