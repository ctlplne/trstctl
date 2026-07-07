// SPDX-License-Identifier: LicenseRef-trstctl-EE

package revoke

import (
	"context"

	agidstore "trstctl.com/trstctl/ee/agentid/delegation/store"
)

// refuse_active.go is the in-signer REFUSE-WHILE-ACTIVE half of AGID-11 (claim 20): while
// a revocation directive is ACTIVE against any delegation record of a chain, the isolated
// signing process refuses any ISSUANCE OR RENEWAL whose chain includes the subject. It
// does this by REUSING the AGID-04 gate seam — the gate already consults a
// delegation.RevocationReader per hop and refuses (CheckRevocation, no key op) when any
// hop reports revoked. AGID-11 supplies a directive-backed RevocationReader: a hop whose
// record names a subject under an active directive reports revoked. There is NO new
// internal/signing option and NO new gate check — the extension is entirely in what the
// reader answers (the card's "extending AGID-04's gate — no new core option").
//
// AN-4 (why this lives in ee/agentid/revoke, NOT the signer-linked delegation package):
// the SQL-backed reader is a CONTROL-PLANE implementation — it reaches the AGID-02
// projection over the core store (a SQL driver). If it lived in the `delegation` package
// (which the signer links), the signer's dependency closure would pull in pgx and the
// store. Instead the reader lives HERE, in the control-plane `revoke` package; the signer
// links only the delegation.RevocationReader INTERFACE. Production wiring (AGID-INT-WIRE)
// constructs this reader in the control plane and hands the gate the interface value, so
// the signer closure stays SQL-free (verified by internal/signing DependencyClosure /
// NoSQLDriver). This is the same boundary the cascade itself respects: the control plane
// holds the SQL; the signer holds interfaces.
//
// RENEWAL is not exempt (§7.4 / card): AGID-07's renewal path re-verifies the chain
// through this same gate, so a renewal whose chain includes a subject under an active
// directive fails the per-hop non-revocation check exactly like a fresh issuance — the
// directive "fails ancestor non-revocation." Terminal (revoked-with-evidence) directives
// no longer refuse (their cascade has fully evidenced), so an unrelated fresh chain is not
// force-refused forever; the refusal is scoped to the ACTIVE window.

// DirectiveRevocationReader is a delegation.RevocationReader backed by the AGID-02 active
// -directive projection. For a chain hop's record digest it reports revoked iff a
// NON-TERMINAL revocation directive names the record's delegator or delegate as its
// subject (RecordDigestUnderActiveDirective). It is a PURE READ over the control-plane
// store — no key op, no mutation — so it is safe to hand the gate as the per-hop
// non-revocation reader while keeping SQL out of the signer's own linked packages.
//
// It satisfies delegation.RevocationReader structurally (IsRevoked(tenantID string,
// recordDigest []byte) (bool, error)); the compile-time assertion lives in the wiring/test
// that constructs the gate with it, so this package does not import the signer seam.
type DirectiveRevocationReader struct {
	repo *agidstore.Repo
	// ctx is the context the per-hop reads run under. The gate's RevocationReader
	// interface (IsRevoked) takes no context (it is a signer-facing, deadline-free
	// hot-path read), so the control-plane reader carries one it was constructed with;
	// production supplies a request/background context, tests supply context.Background.
	ctx context.Context
}

// NewDirectiveRevocationReader builds the directive-backed reader over the AGID-02 repo,
// carrying ctx for its reads. repo is required; ctx defaults to context.Background when
// nil so a misconfigured reader still runs (fail-closed reads, never a nil-context panic).
func NewDirectiveRevocationReader(repo *agidstore.Repo, ctx context.Context) *DirectiveRevocationReader {
	if ctx == nil {
		ctx = context.Background()
	}
	return &DirectiveRevocationReader{repo: repo, ctx: ctx}
}

// IsRevoked reports whether the delegation record identified by recordDigest is under an
// ACTIVE (non-terminal) revocation directive for tenantID — the per-hop non-revocation
// answer the gate consults before any key op (claim 20). A nil repo (misconfiguration)
// or a read error surfaces to the gate, which FAILS CLOSED (refuses with CheckRevocation):
// a reader that cannot answer must not let issuance/renewal proceed. A record with no
// matching row (unknown digest, or no active directive naming its subjects) reports false,
// so an ordinary chain issues normally while a subtree under an active directive is
// refused.
func (d *DirectiveRevocationReader) IsRevoked(tenantID string, recordDigest []byte) (bool, error) {
	if d == nil || d.repo == nil {
		// Fail closed: an unconfigured reader reports "revoked" so the gate refuses rather
		// than silently approving under a broken revocation view.
		return true, errNoRevocationRepo
	}
	return d.repo.RecordDigestUnderActiveDirective(d.ctx, tenantID, recordDigest)
}

// errNoRevocationRepo is returned by a nil/unconfigured DirectiveRevocationReader so the
// gate's fail-closed reader-error path refuses (CheckRevocation) rather than approving.
var errNoRevocationRepo = revocationConfigError("revoke: directive revocation reader has no store (fail-closed)")

// revocationConfigError is a tiny error type so the fail-closed sentinel needs no fmt
// import here and reads clearly at the call site.
type revocationConfigError string

func (e revocationConfigError) Error() string { return string(e) }
