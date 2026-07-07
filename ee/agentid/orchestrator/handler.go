// SPDX-License-Identifier: LicenseRef-trstctl-EE

package orchestrator

import (
	"fmt"

	agidstore "trstctl.com/trstctl/ee/agentid/delegation/store"
	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/editionseam"
	coreorch "trstctl.com/trstctl/internal/orchestrator"
	"trstctl.com/trstctl/internal/policy"
)

// handler.go assembles the composed AGID licensed-outbox handler from the live deps: it
// builds the AGID-02 repo over the core store, a core outbox handle over the SAME shared
// outbox table (so the per-descendant cascade jobs the cascade enqueues are drained by the
// server's dispatcher), a conservative S10.1 policy engine (deny-by-default BaseModule),
// and the issuance + cascade workers that hold the constructed mechanisms.
//
// The core outbox handle is constructed here (orchestrator.NewOutbox over d.Store) because
// the LicensedOutboxDeps seam does not forward the server's *Outbox (it forwards Store,
// Log, Idempotency, Minter). A handle over the same store writes the same `outbox` table,
// so the cascade's EnqueueIfAbsent lands rows the server dispatcher claims — the AN-6
// transactional-outbox contract holds regardless of which handle enqueued (the table, not
// the handle, is the queue).

// newHandler builds the composed AGID handler. signer is the control-plane evidence signer
// (AN-3) the cascade/executor/terminal use to sign completion + aggregate evidence.
func newHandler(d editionseam.LicensedOutboxDeps, signer crypto.Signer) (*handler, error) {
	if d.Store == nil {
		return nil, fmt.Errorf("agentid outbox: nil store")
	}
	if d.Log == nil {
		// The revocation cascade/terminal/interval append durable-first to the AN-2 log;
		// without it the verifiable kill cannot record evidence. Fail closed at wiring.
		return nil, fmt.Errorf("agentid outbox: nil event log")
	}
	repo := agidstore.New(d.Store)

	// A core outbox handle over the same shared outbox table (the cascade enqueues
	// per-descendant jobs here; the server dispatcher drains them).
	outbox := coreorch.NewOutbox(d.Store)

	// The conservative S10.1 policy engine the chain-bound precondition consults. The
	// BaseModule is deny-by-default and permits issuance only with a bound certificate
	// profile, which is the safe default until a deployment provisions a policy module
	// (AGID-INT-WIRE). A compile error here is a build bug, surfaced fail-closed.
	policyEngine, err := policy.New(policy.Config{Log: d.Log})
	if err != nil {
		return nil, fmt.Errorf("agentid outbox: build policy engine: %w", err)
	}

	// The AGID-04 in-signer gate driven over the out-of-process signer transport
	// (AGID-INT-WIRE): the control-plane adapter that calls the signer's GatedIssue RPC.
	// Nil when no signer is configured (d.IssuanceGate nil) => the chain-bound precondition
	// fails closed (brokerstore.ErrNoSignerGate) and mints nothing. The agent-credential key
	// algorithm the signer generates inside the boundary is ECDSA P-256 (the control-plane
	// norm; the signer's key op picks its own default if left empty).
	signerGate := NewSignerIssuanceGate(d.IssuanceGate, crypto.ECDSAP256)
	issue := newIssuanceWorker(d.Store, repo, policyEngine, signerGate)
	cascade, err := newCascadeWorker(d.Store, repo, d.Log, outbox, signer)
	if err != nil {
		return nil, err
	}

	return &handler{
		deps:    d,
		signer:  signer,
		issue:   issue,
		cascade: cascade,
	}, nil
}
