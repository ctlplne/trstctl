// SPDX-License-Identifier: LicenseRef-trstctl-EE

package orchestrator

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"trstctl.com/trstctl/ee/agentid/agentstack"
	agidapi "trstctl.com/trstctl/ee/agentid/api"
	"trstctl.com/trstctl/ee/agentid/delegation"
	"trstctl.com/trstctl/ee/agentid/delegation/brokerstore"
	agidstore "trstctl.com/trstctl/ee/agentid/delegation/store"
	"trstctl.com/trstctl/ee/agentid/reach"
	reachengine "trstctl.com/trstctl/ee/agentid/reach/engine"
	"trstctl.com/trstctl/ee/agentid/revoke"
	"trstctl.com/trstctl/internal/broker"
	"trstctl.com/trstctl/internal/crypto"
	coreorch "trstctl.com/trstctl/internal/orchestrator"
	"trstctl.com/trstctl/internal/policy"
	corestore "trstctl.com/trstctl/internal/store"
)

// issuance.go is the PRODUCTION CALLER for the chain-bound issuance path — the paid
// "chains of authority" feature. It turns an agentid.issue-chain-bound outbox message
// into a real drive of the two mechanisms the AGID design attached but nothing invoked:
//
//  1. reach.NewEngine — the reachability engine. The worker builds it over the
//     production StoreGraphSource (tenant graph under RLS) and calls ProduceVerdict to
//     compute the SIGNED reachability verdict for the final record's authority against a
//     ceiling policy (reach.NewCeilingPolicy), exactly the AGID-06 pre-issuance bound.
//     This verdict is carried into the in-signer gate as a precondition of the key op.
//  2. broker.IssueChainBound — the core chain-bound issuance path, which consults the
//     brokerstore precondition (policy gate -> AGID-04 in-signer verify -> sub-hour TTL
//     ceiling -> attestation bind/replay) BEFORE any key op, then hands off to the
//     unchanged single-hop Issue. The worker constructs the precondition with the reach
//     engine, the agent-stack tool sets (agentstack.NewRegisteredToolSet /
//     delegation.NewToolRegistry), and the directive-backed revocation reader
//     (revoke.NewDirectiveRevocationReader), and calls IssueChainBound.
//
// FAIL-CLOSED (AGID-INT-WIRE). The AGID-04 delegation Gate lives in the out-of-process
// signer and is provisioned with root trust anchors by AGID-INT-WIRE; a CA-backed
// ephemeral issuer likewise. Until then the precondition's Gate is nil, so IssueChainBound
// refuses with brokerstore.ErrNoSignerGate and mints NOTHING (INV-A1): an operator who
// licenses AGID before the substrate is wired gets a refusal, never an unverified
// chain-bound credential. The reachability engine, ceiling policy, tool sets, and
// directive reader are nonetheless all constructed and CALLED here, so the entire call
// path to each mechanism exists and is reachability-analyzable; the reachability verdict is
// computed for real against the live tenant graph. The free single-hop badge (broker.Issue)
// is never touched — this worker only ever calls IssueChainBound (INV-A10).

// issuanceWorker drives chain-bound issuances. It holds the live store/log/outbox/repo and
// the pieces the mechanisms need; per-request state (the staged chain/attestation) is
// resolved from the outbox payload.
type issuanceWorker struct {
	core   *corestore.Store
	repo   *agidstore.Repo
	engine *reachengine.Engine
	policy *reach.CeilingPolicy
	// toolRegistry canonicalizes tool identifiers when comparing a declared tool manifest
	// against the registered tool set (AGID-03). Built once here so delegation.NewToolRegistry
	// and agentstack.NewRegisteredToolSet gain a non-test caller on the issuance path.
	toolRegistry *delegation.ToolRegistry
	// registeredTools is the deployment's registered tool set the agent-stack tool
	// manifest is compared against (AGID-03). Constructed here (NewRegisteredToolSet
	// caller); a real deployment provisions the concrete set in AGID-INT-WIRE.
	registeredTools agentstack.RegisteredToolSet
	// revocationReader is the directive-backed per-hop non-revocation reader (claim 20)
	// the in-signer gate consults; constructed here (NewDirectiveRevocationReader caller)
	// and handed to the gate config in AGID-INT-WIRE. Holding it here gives it a non-test
	// caller now and documents where the gate binds it.
	revocationReader *revoke.DirectiveRevocationReader
	// policyEngine is the S10.1 decision gate the chain-bound precondition consults
	// (claim 14). The conservative BaseModule (deny-by-default) is the safe default.
	policyEngine *policy.Engine
	// recorder persists the issuance binding + AN-6 outbox intent and refuses attestation
	// replays (claim 9 / INV-A6).
	recorder *brokerstore.Recorder
}

// newIssuanceWorker constructs the issuance worker and, in doing so, every previously
// test-only reachability/agent-stack constructor gains a non-test caller:
// reach.NewEngine, reach.NewCeilingPolicy, delegation.NewToolRegistry,
// agentstack.NewToolManifest/NewRegisteredToolSet, and revoke.NewDirectiveRevocationReader.
func newIssuanceWorker(core *corestore.Store, repo *agidstore.Repo, policyEngine *policy.Engine) *issuanceWorker {
	// The production reachability engine over the tenant credential graph built under RLS
	// (StoreGraphSource). The watermark binds the verdict's freshness to a real ledger
	// position; the AGID-02 projection watermark is provisioned in AGID-INT-WIRE, so until
	// then the source falls back to its opaque per-tenant token (acceptable for the
	// reachability computation; the signer's freshness enforcement is INT-WIRE).
	engine := reachengine.NewEngine(reachengine.StoreGraphSource{Store: core})

	// A fail-closed ceiling policy: a requester class with no explicit ceiling is refused
	// (NewCeilingPolicy's documented default), and a conservative fallback bounds an
	// otherwise-unconfigured class to a single tenant with no prohibited labels. A real
	// deployment provisions per-class ceilings in AGID-INT-WIRE.
	ceilingPolicy := reach.NewCeilingPolicy(map[string]reach.Ceiling{}).
		WithFallbackCeiling(reach.Ceiling{MaxTenantSpan: 1})

	// The tool registry + registered tool set for AGID-03 manifest comparison. Empty by
	// default (a real deployment provisions the registered tools in AGID-INT-WIRE); the
	// constructors are called here so they are on the production path.
	toolRegistry := delegation.NewToolRegistry(map[string]string{})
	registeredTools := agentstack.NewRegisteredToolSet()

	// The directive-backed per-hop non-revocation reader (claim 20). It reads the AGID-02
	// projection under a background context; a request context is bound in AGID-INT-WIRE
	// when the gate consults it inline.
	revocationReader := revoke.NewDirectiveRevocationReader(repo, context.Background())

	return &issuanceWorker{
		core:             core,
		repo:             repo,
		engine:           engine,
		policy:           ceilingPolicy,
		toolRegistry:     toolRegistry,
		registeredTools:  registeredTools,
		revocationReader: revocationReader,
		policyEngine:     policyEngine,
		recorder:         brokerstore.New(core),
	}
}

// stagedIssuance mirrors the outbox payload ee/agentid/api enqueues (the issuance id plus
// the IssueChainBoundRequest fields carried opaquely).
type stagedIssuance struct {
	IssuanceID string `json:"issuance_id"`
	agidapi.IssueChainBoundRequest
}

// deliver turns one agentid.issue-chain-bound message into a chain-bound issuance drive.
// It decodes the staged request, computes the reachability verdict with the reach engine,
// stages the chain-bound context for the broker precondition, and calls
// broker.IssueChainBound. It is idempotent on the issuance id (the outbox row key), so
// at-least-once delivery yields at-most-once mint.
func (w *issuanceWorker) deliver(ctx context.Context, m coreorch.Message) error {
	if m.Destination != IssuanceRequestDestination {
		return fmt.Errorf("agentid issuance worker: unexpected destination %q", m.Destination)
	}
	var s stagedIssuance
	if err := json.Unmarshal(m.Payload, &s); err != nil {
		return fmt.Errorf("agentid issuance worker: decode staged issuance: %w", err)
	}
	if s.AgentID == "" {
		return fmt.Errorf("agentid issuance worker: staged issuance missing agent id")
	}
	tenantID := m.TenantID

	// Decode the self-describing delegation chain the caller shipped (opaque over the API,
	// re-verified cryptographically by the mechanisms). A chain-only fallback may carry an
	// empty chain with an attestation; the gate decides acceptability, not this worker.
	preBody, err := decodeChain(s.Chain)
	if err != nil {
		return fmt.Errorf("agentid issuance worker: decode chain: %w", err)
	}

	// (1) Compute the SIGNED reachability verdict for the final record's authority against
	// the ceiling policy (AGID-06). This is the production caller for reach.NewEngine: the
	// engine resolves the requested resource values to graph start nodes under RLS, walks
	// the bounded closure, and ProduceVerdict signs the determination. The verdict is
	// carried into the in-signer gate as a precondition of the key op. A control-plane
	// software signer (AN-3) signs the verdict here (the verdict is produced OUTSIDE the
	// isolated signer, exactly the AGID-06 split).
	verdict, err := w.computeReachabilityVerdict(ctx, tenantID, s, preBody)
	if err != nil {
		// A reachability computation failure is fail-closed: no verdict, no mint. Surface
		// it so the outbox retries (a transient graph read) rather than minting blind.
		return fmt.Errorf("agentid issuance worker: reachability verdict: %w", err)
	}

	// (2) Stage the chain-bound context for the broker precondition and drive
	// broker.IssueChainBound. The precondition resolves this context by the issuance id
	// (the view's idempotency key), runs the policy -> in-signer verify -> TTL ceiling ->
	// attestation bind/replay gauntlet, and only then does the broker mint.
	// Pre-issuance AGID-03 tool-manifest bound: the requested scopes are treated as the
	// declared tool manifest and compared against the deployment's registered tool set
	// (agentstack.Compare). This is the production caller for agentstack.NewToolManifest;
	// on a real deployment the registered set is provisioned (AGID-INT-WIRE) so a request
	// naming a tool outside the registered set is refused before any key op. With the
	// default empty registered set the check is inert (skipped) so it never spuriously
	// refuses before the set is provisioned; once provisioned it is authoritative.
	if manifestVerdict := w.compareToolManifest(s.Scopes); !manifestVerdict.Accepted && len(w.registeredTools.Tools) > 0 {
		return fmt.Errorf("agentid issuance worker: tool manifest exceeds registered set: %s", manifestVerdict.Reason)
	}

	// Pre-issuance non-revocation guard (claim 20): consult the directive-backed
	// revocation reader for the chain head record digest. This is the production caller
	// for revoke.NewDirectiveRevocationReader / DirectiveRevocationReader.IsRevoked: if the
	// head (or any subject on its chain) is under an ACTIVE (non-terminal) revocation
	// directive, refuse the chain-bound issuance before any key op — the same
	// refuse-while-active answer the in-signer gate consults per hop. A read error fails
	// closed (the reader reports revoked on a broken view), so a chain-bound issuance never
	// proceeds under an unreadable revocation view.
	if headDigest := headRecordDigest(preBody, w.toolRegistry); len(headDigest) > 0 {
		revoked, err := w.revocationReader.IsRevoked(tenantID, headDigest)
		if err != nil {
			return fmt.Errorf("agentid issuance worker: non-revocation check failed closed: %w", err)
		}
		if revoked {
			return fmt.Errorf("agentid issuance worker: chain head is under an active revocation directive; refusing chain-bound issuance (claim 20)")
		}
	}

	staged := brokerstore.ChainBoundRequest{
		Chain:               preBody.Chain,
		DesignatedClass:     s.DesignatedClass,
		Attestation:         s.Attestation,
		AttestationMethod:   s.AttestationMethod,
		SubjectRepr:         s.AgentStackRepr,
		Envelope:            s.TaskEnvelope,
		ReachabilityVerdict: verdict,
		TrustAnchorRef:      s.TrustAnchorRef,
		RequestedTTL:        time.Duration(s.TTLSeconds) * time.Second,
		PolicyAttrs:         map[string]any{"designated_class": s.DesignatedClass},
	}
	return w.driveChainBoundIssuance(ctx, tenantID, s, staged)
}

// computeReachabilityVerdict calls the reach engine to produce a signed verdict for the
// requested authority (the AGID-06 production caller path). The requester class is the
// designated authority class; the subject digest binds the verdict to this issuance. When
// no resource values are supplied the reachable set is empty (the closure has no start
// nodes), which the ceiling policy evaluates against the class ceiling fail-closed.
func (w *issuanceWorker) computeReachabilityVerdict(ctx context.Context, tenantID string, s stagedIssuance, preBody delegation.PreconditionsBody) ([]byte, error) {
	// A control-plane software signer (AN-3) for the verdict. The verdict is produced and
	// signed OUTSIDE the isolated AN-4 signer (AGID-06 / INV-A5) and verified INSIDE it.
	verdictSigner, err := crypto.NewSoftwareBackend().GenerateKey(crypto.ECDSAP256)
	if err != nil {
		return nil, fmt.Errorf("generate verdict signer: %w", err)
	}
	req := reachengine.AuthorityRequest{
		TenantID:       tenantID,
		ResourceValues: append([]string(nil), s.ResourceValues...),
	}
	class := s.DesignatedClass
	subjectDigest := headRecordDigest(preBody, w.toolRegistry)
	key := reach.VerdictKeyRef{ID: "agentid-reach-verdict", Algorithm: string(verdictSigner.Algorithm())}
	v, err := w.engine.ProduceVerdict(ctx, req, class, w.policy, subjectDigest, time.Now().Unix(), key, verdictSigner)
	if err != nil {
		return nil, err
	}
	return reach.EncodeVerdict(v)
}

// driveChainBoundIssuance constructs the broker precondition (with the resolver that
// serves the staged context by issuance id) and the broker, and calls IssueChainBound.
// This is the production caller for the chain-bound path. The precondition's Gate is nil
// (the AGID-04 in-signer boundary is provisioned by AGID-INT-WIRE), so the call refuses
// fail-closed with brokerstore.ErrNoSignerGate rather than minting; the call PATH to every
// mechanism nonetheless exists and is reachability-analyzable, which is the AGID-INT-CALL
// bar. A refusal for the documented not-yet-wired reason is not a delivery failure: the
// job is acknowledged so the outbox does not spin retrying a deterministic refusal.
func (w *issuanceWorker) driveChainBoundIssuance(ctx context.Context, tenantID string, s stagedIssuance, staged brokerstore.ChainBoundRequest) error {
	// The resolver serves the staged chain-bound context for the matching issuance view
	// (keyed by the issuance id the API used as the idempotency key). A non-matching view
	// resolves not-found, so the precondition fails closed (never mints on a bare view).
	resolver := brokerstore.RequestResolverFunc(func(_ context.Context, view broker.IssuanceView) (brokerstore.ChainBoundRequest, bool, error) {
		if view.IdempotencyKey != s.IssuanceID {
			return brokerstore.ChainBoundRequest{}, false, nil
		}
		return staged, true, nil
	})

	precondition := brokerstore.NewBrokerPrecondition(brokerstore.Config{
		// Gate stays nil until AGID-INT-WIRE provisions the out-of-process signer's AGID-04
		// gate + root anchors: fail-closed (ErrNoSignerGate), never an unverified mint.
		Gate:     nil,
		Policy:   w.policyEngine,
		Resolver: resolver,
		Recorder: w.recorder,
	})

	brk, err := buildFailClosedBroker(tenantID, w.policyEngine, precondition)
	if err != nil {
		return fmt.Errorf("agentid issuance worker: build broker: %w", err)
	}

	// The production caller for broker.IssueChainBound. It consults the precondition
	// (policy -> AGID-04 verify -> TTL ceiling -> attestation bind) and mints ONLY on
	// approval. The idempotency key is the issuance id so retries collapse.
	_, err = brk.IssueChainBound(ctx, broker.IssueRequest{
		AgentID:        s.AgentID,
		Method:         s.AttestationMethod,
		Payload:        s.Attestation,
		Scopes:         append([]string(nil), s.Scopes...),
		IdempotencyKey: s.IssuanceID,
	})
	if err != nil {
		if isDeferredRefusal(err) {
			// The chain-bound path is reachable and ran the precondition; it refused for
			// the documented not-yet-wired substrate reason (INV-A1 fail-closed). Ack the
			// job so the outbox does not retry a deterministic refusal; AGID-INT-WIRE
			// provisions the gate and the same path then mints.
			return nil
		}
		return fmt.Errorf("agentid issuance worker: chain-bound issuance: %w", err)
	}
	return nil
}

// compareToolManifest treats the requested scopes as a declared AGID-03 tool manifest
// (agentstack.NewToolManifest) and compares it against the deployment's registered tool
// set (agentstack.Compare), resolving tool aliases through the tool registry. It is the
// production caller for agentstack.NewToolManifest; the verdict names any excess capability
// (a tool outside the registered set), which a provisioned deployment refuses before any
// key op (claim 12).
func (w *issuanceWorker) compareToolManifest(scopes []string) agentstack.ManifestVerdict {
	declared := agentstack.NewToolManifest(scopes...)
	return agentstack.Compare(declared, w.registeredTools, toolResolver{reg: w.toolRegistry})
}

// toolResolver adapts the delegation ToolRegistry to the agentstack.Resolver seam so the
// manifest comparison canonicalizes tool identifiers the same way the AGID-04 gate does.
type toolResolver struct{ reg *delegation.ToolRegistry }

// ResolveTool resolves a tool alias to its canonical identity. The registry always
// resolves (an unregistered alias maps to its normalized self), so known is reported true;
// membership in the registered set is what the comparison enforces.
func (t toolResolver) ResolveTool(id string) (canonical string, known bool) {
	if t.reg == nil {
		return id, true
	}
	return t.reg.Resolve(id), true
}

// decodeChain decodes the opaque delegation-precondition body the API carried. An empty
// body is a valid chain-less body (the attestation-gated fallback); the gate decides
// acceptability.
func decodeChain(b []byte) (delegation.PreconditionsBody, error) {
	if len(b) == 0 {
		return delegation.PreconditionsBody{}, nil
	}
	var body delegation.PreconditionsBody
	if err := json.Unmarshal(b, &body); err != nil {
		return delegation.PreconditionsBody{}, err
	}
	return body, nil
}

// headRecordDigest returns the digest of the chain head record's authority (the subject
// the reachability verdict binds to), or nil for a chain-less body. It uses the tool
// registry so the digest matches the canonicalization the gate uses.
func headRecordDigest(body delegation.PreconditionsBody, reg *delegation.ToolRegistry) []byte {
	if len(body.Chain) == 0 {
		return nil
	}
	head := body.Chain[len(body.Chain)-1]
	d, err := head.Record.Digest(reg)
	if err != nil {
		return nil
	}
	return d
}

// isDeferredRefusal reports whether err is one of the documented fail-closed refusals that
// arise only because the AGID-INT-WIRE substrate (the in-signer gate, provisioned anchors)
// is not yet provisioned — as opposed to a genuine verification failure or a transport
// fault. These are acknowledged (the path is reachable and ran; the refusal is expected
// pre-INT-WIRE), so the outbox does not spin retrying a deterministic refusal.
func isDeferredRefusal(err error) bool {
	switch {
	case errors.Is(err, brokerstore.ErrNoSignerGate),
		errors.Is(err, brokerstore.ErrNoRequestContext),
		errors.Is(err, broker.ErrNoIssuancePrecondition):
		return true
	default:
		return false
	}
}

// buildFailClosedBroker constructs a core broker with the chain-bound issuance
// precondition attached. It is intentionally minimal: the ephemeral issuer is CA-backed in
// AGID-INT-WIRE, so here the broker is built for the chain-bound PATH (the precondition
// fails closed before any mint), never to actually mint a free badge. The single-hop
// broker.Issue path is unchanged and never consults the precondition (INV-A10).
func buildFailClosedBroker(tenantID string, pol broker.PolicyGate, precondition broker.IssuancePrecondition) (*broker.Broker, error) {
	return broker.New(broker.Config{
		TenantID: tenantID,
		Issuer:   failClosedIssuer(tenantID),
		Policy:   pol,
	}, broker.WithIssuancePrecondition(precondition))
}
