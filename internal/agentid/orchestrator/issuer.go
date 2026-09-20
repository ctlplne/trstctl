// SPDX-License-Identifier: BUSL-1.1

package orchestrator

import (
	"context"
	"errors"
	"time"

	"trstctl.com/trstctl/internal/attest"
	"trstctl.com/trstctl/internal/ephemeral"
)

// issuer.go builds the minimal ephemeral issuer the core broker requires at construction
// (broker.New rejects a nil Issuer). On the chain-bound production path this issuer is not
// supposed to mint: the brokerstore precondition drives GatedIssue in the isolated signer
// and returns the public credential result directly. This issuer exists only as a
// fail-closed fallback if a future precondition approves without returning signer-minted
// public material.
//
// It is deliberately fail-closed by construction: its attestation verifier holds no
// attestors (so any Verify refuses) and its Sign func returns an error. If some future
// path ever reached it, it would refuse — never mint an unattested badge.
// The free single-hop broker.Issue path is served by internal/server's own broker
// construction, not this one (this worker only ever calls IssueChainBound); this issuer is
// solely to satisfy the chain-bound broker's constructor invariant.

// errIssuerNotProvisioned is returned by the fail-closed issuer's Sign func. It should be
// unreachable on the chain-bound path (the precondition returns the signer result first),
// but if reached it refuses rather than minting.
var errIssuerNotProvisioned = errors.New("agentid orchestrator: local fallback issuer is not provisioned; chain-bound issuance must mint inside the signer")

// failClosedIssuer builds the minimal, refuse-by-construction ephemeral issuer for the
// chain-bound broker. The attestation verifier has no attestors (any Verify refuses) and
// the Sign func errors, so this issuer mints nothing; it only satisfies broker.New's
// non-nil Issuer invariant. A build error is impossible for these fixed inputs, so a nil
// issuer on error is acceptable — broker.New would then reject it fail-closed.
func failClosedIssuer(tenantID string) *ephemeral.Issuer {
	verifier, err := attest.NewVerifier(attest.Config{TenantID: tenantID})
	if err != nil {
		return nil
	}
	iss, err := ephemeral.New(ephemeral.Config{
		TenantID: tenantID,
		Verifier: verifier,
		Sign: func(_ context.Context, _ attest.Attestation, _ []byte, _ time.Duration) ([]byte, error) {
			return nil, errIssuerNotProvisioned
		},
		Policy: ephemeral.TTLPolicy{Default: 10 * time.Minute, Max: time.Hour},
		Idem:   ephemeral.NewMemoryIdempotencer(),
	})
	if err != nil {
		return nil
	}
	return iss
}
