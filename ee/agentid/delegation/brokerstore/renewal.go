// SPDX-License-Identifier: LicenseRef-trstctl-EE

package brokerstore

import (
	"context"

	"trstctl.com/trstctl/internal/broker"
)

// renewal.go is the AGID-07b renewal path (claim 8): a renewal request RE-INVOKES the
// FULL in-signer verification (chain + attestation) via the AGID-04 gate, and re-runs the
// policy gate, BEFORE any key op — nothing is trusted from the prior issuance. It is a
// thin wrapper over the same gauntlet CheckIssuancePrecondition runs, tagged as a renewal
// so the intent is explicit and so a later card (AGID-11) can layer the
// refuse-while-directive-active check onto this exact entry point without changing the
// verification it performs.
//
// The renewal deliberately does NOT short-circuit any step: a renewed credential is a
// fresh credential and must clear policy, the in-signer chain+attestation verification,
// the sub-hour ceiling, and the attestation-replay defense identically to a first
// issuance. In particular a renewal presenting the SAME attestation evidence as the
// credential it renews is refused by the evidence-digest unique index (claim 9), so a
// renewal must present fresh attestation — exactly the property that makes a short-TTL
// credential's renewal a re-attestation, not a rubber stamp.

// CheckRenewalPrecondition is the renewal entry point. It runs the SAME full gauntlet as
// a first chain-bound issuance (policy → in-signer chain+attestation verification →
// sub-hour ceiling → attestation bind/replay under idempotency), re-invoking the AGID-04
// gate before any key op (claim 8). It returns nil only when every step approves; any
// refusal returns a non-nil error and no key op is performed.
//
// It takes the generic broker.IssuanceView (the same the core broker forwards on its
// chain-bound path) so a renewal is driven through the identical seam as an issuance; the
// edition control plane stages the renewal's chain/attestation via the RequestResolver
// keyed by the view's idempotency key, exactly as for a first issuance.
func (p *BrokerPrecondition) CheckRenewalPrecondition(ctx context.Context, view broker.IssuanceView) error {
	_, err := p.evaluate(ctx, view, true)
	return err
}
