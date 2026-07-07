// SPDX-License-Identifier: MPL-2.0

package editionseam

import (
	"context"
	"time"

	"trstctl.com/trstctl/internal/api"
	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/orchestrator"
	"trstctl.com/trstctl/internal/signing"
	"trstctl.com/trstctl/internal/store"
)

type LicensedLeafSigner func(caCertDER []byte, caSigner crypto.DigestSigner, csrDER []byte, ttl time.Duration, prof crypto.LeafProfile) ([]byte, error)

type LicensedCSRInspector func(csrDER []byte, classical crypto.CSRInfo) (useLicensedSigner bool, err error)

type LicensedAPIOptionsFactory func(LicensedAPIOptionsDeps) ([]api.Option, error)

type LicensedOutboxFactory func(LicensedOutboxDeps) (LicensedOutboxHandler, error)

type LicensedAPIOptionsDeps struct {
	Store  *store.Store
	Log    *events.Log
	Outbox *orchestrator.Outbox
}

type ProtocolLeafIssuer func(ctx context.Context, tenantID, protocol, idempotencyKey string, csrDER []byte) ([]byte, error)

// SuccessionMinter mints a PCAS successor inside the out-of-process signer over the
// signer transport (satisfied by *signing.Client). It is optional in
// LicensedOutboxDeps: nil when no out-of-process signer is configured, in which case
// a PCAS licensed-outbox handler mints nothing and fails closed.
type SuccessionMinter interface {
	MintSuccessor(ctx context.Context, req signing.MintRequest) (signing.MintResult, error)
}

// IssuanceGate drives a gated agent-credential issuance inside the out-of-process signer
// over the signer transport (AGID-INT-WIRE), satisfied by *signing.Client. It carries the
// opaque issuance preconditions across the boundary and receives only public material back
// (the issued credential public key + opaque records); no private key crosses. It is
// optional in LicensedOutboxDeps: nil when no out-of-process signer is configured, in which
// case the AGID chain-bound issuance path fails closed (brokerstore.ErrNoSignerGate) rather
// than minting an unverified credential. The algorithm argument names the agent-credential
// key algorithm the signer generates inside the boundary on approval.
type IssuanceGate interface {
	GatedIssue(ctx context.Context, req signing.IssuancePreconditions, alg crypto.Algorithm) (signing.IssuanceDecision, error)
}

// Compile-time proof the out-of-process signer client satisfies both licensed-outbox
// signer seams, so internal/server can wire *signing.Client into LicensedOutboxDeps.Minter
// and LicensedOutboxDeps.IssuanceGate directly (a signature drift is a build error).
var (
	_ SuccessionMinter = (*signing.Client)(nil)
	_ IssuanceGate     = (*signing.Client)(nil)
)

type LicensedOutboxDeps struct {
	Store             *store.Store
	Log               *events.Log
	Idempotency       *orchestrator.Idempotency
	IssueProtocolLeaf ProtocolLeafIssuer
	// Minter is the out-of-process signer as a succession minter (INT-04); nil when no
	// signer is configured. A PCAS licensed-outbox handler uses it to mint on a
	// pcas.succession-request message.
	Minter SuccessionMinter
	// IssuanceGate is the out-of-process signer as an AGID chain-bound issuance gate
	// (AGID-INT-WIRE); nil when no signer is configured. The AGID licensed-outbox handler
	// uses it to drive a REAL gated issuance over the signer transport on an
	// agentid.issue-chain-bound message, so the control plane requests but cannot forge.
	IssuanceGate IssuanceGate
}

type LicensedOutboxHandler interface {
	DeliverLicensed(context.Context, orchestrator.Message) (handled bool, err error)
}
