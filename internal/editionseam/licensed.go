// SPDX-License-Identifier: BUSL-1.1

package editionseam

import (
	"context"
	"time"

	"trstctl.com/trstctl/internal/api"
	"trstctl.com/trstctl/internal/connector"
	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/crypto/seal"
	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/orchestrator"
	"trstctl.com/trstctl/internal/protocols/spiffe"
	"trstctl.com/trstctl/internal/signing"
	"trstctl.com/trstctl/internal/store"
	"trstctl.com/trstctl/internal/tenantseal"
	"trstctl.com/trstctl/internal/transit"
)

type LicensedLeafSigner func(caCertDER []byte, caSigner crypto.DigestSigner, csrDER []byte, ttl time.Duration, prof crypto.LeafProfile) ([]byte, error)

// PreparedSubjectLeafSigner verifies the requested subject proofs and signs
// the retained public template through the supplied CA signer. Core runtime
// attachment supplies this for PQC; it grants no private-key custody capability.
type PreparedSubjectLeafSigner func(caCertDER []byte, caSigner crypto.DigestSigner, csrDER []byte, ttl time.Duration, prof crypto.LeafProfile, prepared crypto.LeafPreparation) (crypto.IssuedLeaf, error)

type LicensedCSRInspector func(csrDER []byte, classical crypto.CSRInfo) (useLicensedSigner bool, err error)

// LicensedCSRParser verifies and describes a subject algorithm the core Go
// toolchain cannot inspect yet. recognized=false means the request is not owned
// by this parser; recognized=true with an error is a fail-closed malformed
// licensed request. The parser is supplied only by the tagged attach seam.
type LicensedCSRParser func(csrDER []byte) (info crypto.CSRInfo, recognized bool, err error)

// LicensedSPIFFESVIDFactory attaches an additional X509-SVID key/certificate
// issuer after the server provisions its signer-backed CA. Nil keeps the core
// Workload API's single-key response.
type LicensedSPIFFESVIDFactory func(caCertDER []byte, caSigner crypto.DigestSigner) (spiffe.AdditionalX509SVIDIssuer, error)

type LicensedAPIOptionsFactory func(LicensedAPIOptionsDeps) ([]api.Option, error)

type LicensedOutboxFactory func(LicensedOutboxDeps) (LicensedOutboxHandler, error)

type LicensedAPIOptionsDeps struct {
	Store              *store.Store
	Log                *events.Log
	Outbox             *orchestrator.Outbox
	TLSPostureDeployer connector.TLSPostureDeployer
	OutboxIntegrityKey seal.KeyWrapper
	TenantCrypto       tenantseal.Access
	SignerKeyStoreDir  string
	KEMCustody         KEMCustody
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

type KEMCustody interface {
	SignerForHandle(ctx context.Context, handle string) (*signing.RemoteSigner, error)
	SignerForHandleWithPurpose(ctx context.Context, handle string, purpose signing.KeyPurpose) (*signing.RemoteSigner, error)
	GenerateKeyHandle(ctx context.Context, algorithm crypto.Algorithm, handle string) (*signing.RemoteSigner, error)
	GenerateSuccessorKEM(ctx context.Context, handle string, alg signing.KEMAlgorithm) (signing.KEMPublicKey, error)
	Decapsulate(ctx context.Context, handle string, ciphertext []byte) ([]byte, error)
	ZeroizeKey(ctx context.Context, handle string) error
}

// ManagedKeyCustody is the isolated signer command surface for cloud/HSM key
// lifecycle operations. The control plane's outbox handler uses it; no API
// handler or provider constructor receives private-key capability directly.
type ManagedKeyCustody interface {
	ManageKey(context.Context, signing.ManagedKeyCommand) (signing.ManagedKeyResult, error)
}

// GatedDestruction is the isolated signer's narrow irreversible-operation
// surface. It is supplied only to licensed outbox workers: API handlers receive
// no signer destruction capability, so every external custody effect must first
// exist as a recoverable outbox command (AN-6).
type GatedDestruction interface {
	GatedDestroy(context.Context, signing.GatedDestroyRequest) (signing.GatedDestroyDecision, error)
}

// Compile-time proof the out-of-process signer client satisfies both licensed-outbox
// signer seams, so internal/server can wire *signing.Client into LicensedOutboxDeps.Minter
// and LicensedOutboxDeps.IssuanceGate directly (a signature drift is a build error).
var (
	_ SuccessionMinter  = (*signing.Client)(nil)
	_ IssuanceGate      = (*signing.Client)(nil)
	_ KEMCustody        = (*signing.Client)(nil)
	_ ManagedKeyCustody = (*signing.Client)(nil)
	_ GatedDestruction  = (*signing.Client)(nil)
)

type LicensedOutboxDeps struct {
	Store              *store.Store
	Log                *events.Log
	Idempotency        *orchestrator.Idempotency
	IssueProtocolLeaf  ProtocolLeafIssuer
	TLSPostureDeployer connector.TLSPostureDeployer
	OutboxIntegrityKey seal.KeyWrapper
	TenantCrypto       tenantseal.Access
	// FeatureObserver records low-cardinality feature/action/outcome/duration signals
	// on served licensed outbox hot paths. Labels must be closed, non-tenant, and
	// non-secret so the shared metrics endpoint never leaks AN-1/AN-8 material.
	FeatureObserver func(feature, action, outcome string, seconds float64)
	// SignerKeyStoreDir is the shared signer provisioning floor. Licensed handlers may
	// write public, non-secret trust material here for the isolated signer to read without
	// linking SQL, NATS, or HTTP.
	SignerKeyStoreDir string
	// Minter is the out-of-process signer as a succession minter (INT-04); nil when no
	// signer is configured. A PCAS licensed-outbox handler uses it to mint on a
	// pcas.succession-request message.
	Minter SuccessionMinter
	// IssuanceGate is the out-of-process signer as an AGID chain-bound issuance gate
	// (AGID-INT-WIRE); nil when no signer is configured. The AGID licensed-outbox handler
	// uses it to drive a REAL gated issuance over the signer transport on an
	// agentid.issue-chain-bound message, so the control plane requests but cannot forge.
	IssuanceGate IssuanceGate
	// KEMCustody is the out-of-process signer as PCAS encapsulation-key custody: it
	// generates the private key inside the signer, decapsulates only through the
	// signer RPC, and zeroizes on retirement. nil means KEM re-wrap fails closed.
	KEMCustody KEMCustody
	// ManagedKeyCustody is the same out-of-process signer client narrowed to the
	// managed-key lifecycle RPC. nil makes managedkey.command fail closed.
	ManagedKeyCustody ManagedKeyCustody
	// GatedDestruction is the out-of-process signer narrowed to the generic
	// verify-then-destroy RPC. nil makes VDEC retirement fail closed.
	GatedDestruction GatedDestruction
	// Transit is the core envelope/transit service. Licensed outbox handlers may use
	// it for public ciphertext re-wrap operations; nil means those operations fail
	// closed instead of inventing a non-durable substitute.
	Transit *transit.Service
}

type LicensedOutboxHandler interface {
	DeliverLicensed(context.Context, orchestrator.Message) (handled bool, err error)
}

// LicensedOutboxTerminalFailureHandler is an optional seam for edition-owned
// destinations whose event-sourced read model needs a terminal failure fact.
// Keeping it separate preserves compatibility for handlers with no domain state.
type LicensedOutboxTerminalFailureHandler interface {
	DeliverLicensedTerminalFailure(context.Context, orchestrator.Message, error) (handled bool, err error)
}
