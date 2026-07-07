// SPDX-License-Identifier: LicenseRef-trstctl-EE

package delegation

import (
	"context"
	"errors"

	"trstctl.com/trstctl/internal/broker"
)

// brokerhook_stub.go is the AGID-07a placeholder for the chain-bound broker issuance
// precondition attached through the core feature-neutral seam
// broker.WithIssuancePrecondition. It exists so the single FeatureAgentDelegation
// block in cmd/trstctl/ee_attach.go is EXERCISED end to end — when licensed the block
// attaches this hook; the core-only / unlicensed build attaches none, and the seam
// stays inert — while the real chain-bound precondition (delegation-chain verification,
// attestation binding, reachability/policy consult) is deliberately deferred to
// AGID-07b, which replaces NewBrokerHookStub with the production precondition.
//
// Fail-closed by construction (mirroring signerwiring's NewSignerGate stance): the
// placeholder REFUSES every chain-bound request. A chain-bound issuance is a delegated,
// multi-hop credential that the AGID-07b precondition must verify before any mint; until
// that verifier is wired, refusing is the only safe default — an operator who licenses
// AGID before 07b lands gets a refusal, never an unverified chain-bound credential.
//
// Zero removal (INV-A10): this hook is consulted ONLY on broker.IssueChainBound. The
// free single-hop attested-ephemeral badge (broker.Issue) never consults it, so
// attaching this placeholder does not gate, move, or degrade the free badge in any way.
type brokerHookStub struct{}

// NewBrokerHookStub returns the AGID-07a placeholder chain-bound issuance precondition
// attached by the EE control plane. AGID-07b replaces this constructor with the real
// precondition. It holds no key material and performs no key operation.
func NewBrokerHookStub() broker.IssuancePrecondition { return brokerHookStub{} }

// ErrChainBoundNotYetEnabled is the fail-closed refusal the placeholder returns for
// every chain-bound request until AGID-07b wires the real precondition.
var ErrChainBoundNotYetEnabled = errors.New("delegation: chain-bound issuance precondition not yet enabled (AGID-07b)")

// CheckIssuancePrecondition refuses every chain-bound request (fail closed). It never
// approves an unverified chain-bound issuance; the single-hop free path is unaffected
// because it does not route through this precondition.
func (brokerHookStub) CheckIssuancePrecondition(_ context.Context, _ broker.IssuanceView) error {
	return ErrChainBoundNotYetEnabled
}

// Compile-time assertion that the placeholder satisfies the core seam interface, so the
// attach line in cmd/trstctl/ee_attach.go type-checks and AGID-07b can swap the
// implementation behind the same interface.
var _ broker.IssuancePrecondition = brokerHookStub{}
