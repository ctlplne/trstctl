// SPDX-License-Identifier: LicenseRef-trstctl-EE

package delegation

import (
	"context"

	"trstctl.com/trstctl/internal/signing"
)

// PassthroughGate is a placeholder issuance-precondition gate: it approves every
// request and returns an empty binding. It exists so the AGID-04a core seam
// (signing.WithIssuanceGate) is EXERCISED end to end -- the EE signer attaches a
// real signing.IssuanceGate, and the core-only build attaches none -- while the
// actual verify-before-keygen logic (chain/attestation verification, authority
// narrowing, signed-refusal minting, credential binding) is deliberately deferred
// to AGID-04b, which replaces this with the real verifier.
//
// It performs NO private-key operation and holds no key material: it only returns an
// approving decision, so the signer's own key-op path (behind the gate) is what mints
// anything. This keeps INV-A1 intact by construction here (the gate approves; the key
// op is the signer's) and lets 04a prove the seam ordering without pulling the 04b
// verifier forward.
type PassthroughGate struct{}

// NewPassthroughGate returns the placeholder gate attached by the EE signer in
// AGID-04a. AGID-04b replaces the construction site with the real verifier.
func NewPassthroughGate() *PassthroughGate { return &PassthroughGate{} }

// VerifyIssuancePreconditions approves unconditionally with an empty binding. This
// is the free single-hop path, which is never gated (the license/policy gate is the
// control plane's job, AGID-07); the real precondition verification lands in 04b.
func (*PassthroughGate) VerifyIssuancePreconditions(_ context.Context, _ signing.IssuancePreconditions) (signing.IssuanceDecision, error) {
	return signing.IssuanceDecision{Approved: true}, nil
}

// Compile-time assertion that the placeholder satisfies the core seam interface, so
// the attach line in cmd/trstctl-signer/ee_attach.go type-checks and 04b can swap the
// implementation behind the same interface.
var _ signing.IssuanceGate = (*PassthroughGate)(nil)
