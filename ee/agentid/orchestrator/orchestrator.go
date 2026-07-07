// SPDX-License-Identifier: LicenseRef-trstctl-EE

// Package orchestrator is the AGID licensed-outbox worker: the PRODUCTION CALLER that
// DRAINS the AGID outbox destinations enqueued by ee/agentid/api and DRIVES the AGID
// mechanisms, exactly as ee/succession/orchestrator drains pcas.succession-request and
// drives the minter. It is the control-plane counterpart to the API: the API stages a
// request onto the AN-6 outbox and returns an id; this worker turns that staged request
// into a real invocation of the mechanism.
//
// It registers, on the server's outbox dispatcher (INT-04, via the FeatureAgentDelegation
// attach block), handlers for the two AGID user journeys plus the cascade's own job
// destinations:
//
//   - agentid.issue-chain-bound  -> issuance.go: compute the reachability verdict with
//     reach.NewEngine (the production caller for the reach engine), then drive
//     broker.IssueChainBound (which consults the AGID-04 in-signer gate via the
//     brokerstore precondition). The reach ceiling policy (reach.NewCeilingPolicy), the
//     agent-stack tool sets (agentstack.NewRegisteredToolSet / delegation.NewToolRegistry),
//     and the directive-backed revocation reader (revoke.NewDirectiveRevocationReader)
//     are all constructed here so those previously test-only constructors gain a
//     non-test caller on the attach path.
//   - agentid.revoke-directive   -> revocation.go: drive revoke.NewCascade
//     (descendant determination + transactional per-descendant job enqueue).
//   - agent.revocation.job       -> revocation.go: drive revoke.NewExecutor (idempotent
//     job execution + signed evidence), then check the terminal transition
//     (revoke.NewTerminalTransition) + the interval monitor (revoke.NewIntervalMonitor).
//   - agent.revocation.downstream-plane -> acknowledged (the KRL/CRL publication is the
//     downstream plane's concern; here it is a successful no-op so the outbox row marks
//     delivered, mirroring PCAS's pcas.rp-publish ack).
//
// FAIL-CLOSED substrate (AGID-INT-WIRE boundary). Where a REAL dependency is an
// AGID-INT-WIRE concern — the out-of-process signer's delegation Gate (the AGID-04
// verify-before-keygen boundary), provisioned root trust anchors, a CA-backed ephemeral
// issuer — this worker keeps the documented fail-closed default: it still CONSTRUCTS every
// mechanism and CALLS each one so the path is reachable (RTA), but a chain-bound issuance
// refuses (no provisioned in-signer gate ⇒ brokerstore.ErrNoSignerGate) rather than
// minting an unverified credential (INV-A1). The reachability, cascade, executor, terminal,
// and evidence mechanisms run for real against the live store/log/outbox the deps provide;
// only the final in-signer key op is deferred.
//
// It reuses the MPL core store, its RLS-scoped transaction, the core event log, and the
// core outbox table; it forks none of them (AN-6). It holds no issuance key material; the
// per-job/aggregate evidence signer is a control-plane software signer (AN-3), distinct
// from the isolated AN-4 signer.
package orchestrator

import (
	"context"
	"errors"
	"fmt"

	agidapi "trstctl.com/trstctl/ee/agentid/api"
	"trstctl.com/trstctl/ee/agentid/revoke"
	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/editionseam"
	coreorch "trstctl.com/trstctl/internal/orchestrator"
)

// The AGID outbox destinations this worker drains. The two journey destinations mirror
// the constants ee/agentid/api enqueues under (same string value, duplicated to keep the
// API off the mechanism import graph, exactly as PCAS duplicates its destination). The
// cascade job destinations are re-exported from ee/agentid/revoke.
const (
	// IssuanceRequestDestination carries a staged chain-bound issuance request from the
	// AGID API. Its handler drives reach.NewEngine + broker.IssueChainBound.
	IssuanceRequestDestination = agidapi.IssuanceRequestDestination // "agentid.issue-chain-bound"
	// RevocationDirectiveDestination carries a staged revocation directive from the AGID
	// API. Its handler drives revoke.NewCascade.
	RevocationDirectiveDestination = agidapi.RevocationDirectiveDestination // "agentid.revoke-directive"
	// RevocationJobDestination is the per-descendant cascade job the cascade enqueues.
	// Its handler drives revoke.NewExecutor and then the terminal transition.
	RevocationJobDestination = revoke.DestinationRevocationJob // "agent.revocation.job"
	// DownstreamPlaneDestination is the downstream trust-plane revocation-entry
	// publication (KRL/CRL). Acknowledged here (the downstream plane consumes it).
	DownstreamPlaneDestination = revoke.DestinationDownstreamPlane // "agent.revocation.downstream-plane"
)

// NewLicensedOutboxFactory returns the AGID licensed-outbox factory (INT-04). The
// control-plane attach seam registers it on the server's outbox dispatcher, gated on the
// AGID (FeatureAgentDelegation) license, which makes the AGID mechanisms real production
// callers: an agentid.issue-chain-bound message enqueued by the API is drained here and
// driven through reach.NewEngine + broker.IssueChainBound; an agentid.revoke-directive
// message is driven through the cascade; the cascade's own jobs execute through the
// executor and converge to the terminal transition. It mirrors PCAS
// orchestrator.NewLicensedOutboxFactory exactly.
func NewLicensedOutboxFactory() editionseam.LicensedOutboxFactory {
	return func(d editionseam.LicensedOutboxDeps) (editionseam.LicensedOutboxHandler, error) {
		if d.Store == nil {
			return nil, errors.New("agentid outbox: nil store")
		}
		// A control-plane software evidence signer (AN-3) for per-job completion evidence
		// and the aggregate terminal artifact. It is NOT the isolated AN-4 issuance signer
		// (this worker performs no credential key op); it signs only revocation evidence,
		// exactly as the AGID-10/11 mechanisms require a crypto.Signer for evidence. ECDSA
		// P-256 is keygen-able by the software backend and is the control-plane norm.
		evidenceSigner, err := crypto.NewSoftwareBackend().GenerateKey(crypto.ECDSAP256)
		if err != nil {
			return nil, fmt.Errorf("agentid outbox: generate evidence signer: %w", err)
		}
		h, err := newHandler(d, evidenceSigner)
		if err != nil {
			return nil, err
		}
		return h, nil
	}
}

// handler is the composed AGID licensed-outbox handler. It holds the live substrates the
// mechanisms run against (store, log, outbox, repo) and the control-plane evidence signer,
// and routes each AGID destination to the mechanism it drives.
type handler struct {
	deps    editionseam.LicensedOutboxDeps
	signer  crypto.Signer
	issue   *issuanceWorker
	cascade *cascadeWorker
}

// DeliverLicensed routes the AGID outbox destinations. It returns handled=false for a
// non-AGID destination so the composed (chained) handler can try the next edition's
// handler, exactly as the PCAS handler does.
func (h *handler) DeliverLicensed(ctx context.Context, m coreorch.Message) (bool, error) {
	switch m.Destination {
	case IssuanceRequestDestination: // agentid.issue-chain-bound
		return true, h.issue.deliver(ctx, m)
	case RevocationDirectiveDestination: // agentid.revoke-directive
		return true, h.cascade.deliverDirective(ctx, m)
	case RevocationJobDestination: // agent.revocation.job
		return true, h.cascade.deliverJob(ctx, m)
	case DownstreamPlaneDestination: // agent.revocation.downstream-plane
		// The revocation entry is already durable in the ledger (the executor recorded the
		// effect + signed evidence); downstream-plane KRL/CRL push is the downstream
		// plane's concern. A successful no-op marks the outbox row delivered, mirroring
		// PCAS's pcas.rp-publish ack.
		return true, nil
	default:
		return false, nil
	}
}
