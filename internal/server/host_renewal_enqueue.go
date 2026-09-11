// SPDX-License-Identifier: MPL-2.0

package server

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/jackc/pgx/v5"

	"trstctl.com/trstctl/internal/agent/transport"
	"trstctl.com/trstctl/internal/crypto/certinfo"
	"trstctl.com/trstctl/internal/crypto/mtls"
	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/orchestrator"
	"trstctl.com/trstctl/internal/store"
)

// Handing a renewal to the host instead of minting for it (epic B2).
//
// This is the piece that makes host-generated keys REACHABLE. Everything else
// in B2 — the job kind, the CSR RPC, the agent executor, the parity gate — is
// machinery that runs only if something queues the work, and until this existed
// nothing did. The capability would have shipped, passed its tests, been
// documented, and never once executed in production: the exact defect class this
// whole workstream is here to remove, reproduced inside the fix for it.
//
// The branch is at MINT TIME, not deploy time, and that placement is the whole
// design. By the time a certificate has been minted the control plane has
// already generated a private key — refusing to deploy it afterwards would be
// too late to make any custody claim, because the key already existed here. So
// the question "does this identity's target want host-generated keys?" has to be
// asked before anything is minted at all.

// hostRenewalSubject reports the DNS names a certificate asserts, and whether
// the host-generated path can faithfully reproduce it.
//
// store.Certificate.SANs is the FLATTENED list sansOf() builds — DNS names, IP
// addresses, rfc822Names and URIs concatenated with their types erased. Feeding
// that to a renewal binding as SubjectDNSNames would be wrong in both
// directions: an IP would be offered as a permitted DNS name, and the renewed
// certificate would silently STOP asserting the IP, because a host-generated
// CSR may carry DNS identifiers only.
//
// A silent narrowing of what an endpoint asserts is the worst available outcome
// — the deploy succeeds, verification passes against the fingerprint, and some
// client that connected by IP starts failing. So a certificate carrying any
// non-DNS identifier is REFUSED for this path and left on the one that can
// represent it. That is a real limitation of host-generated renewal, and acting
// on it is better than papering over it.
func hostRenewalSubject(cert store.Certificate) (dnsNames []string, ok bool) {
	if len(cert.CertificateDER) == 0 {
		// Nothing to inspect means nothing can be asserted about the shape.
		return nil, false
	}
	info, err := certinfo.Inspect(cert.CertificateDER)
	if err != nil {
		return nil, false
	}
	if len(info.IPAddresses) > 0 || len(info.EmailAddresses) > 0 || len(info.URIs) > 0 {
		return nil, false
	}
	if len(info.DNSNames) == 0 {
		return nil, false
	}
	return append([]string(nil), info.DNSNames...), true
}

// hostRenewalTargetFor reports whether this identity's deployment target has
// opted into host-generated keys, and returns it if so.
//
// Three ways to answer "no", all of them meaning the legacy path: the identity
// names no target, the target cannot be loaded, or the target is not marked. A
// target that cannot be loaded is deliberately NOT an error here — the renewal
// then proceeds down the path it would have taken before this feature existed,
// which is the safe direction. Failing the renewal because a new code path could
// not read a config field would turn an optional migration into an outage.
func (d *issuanceDispatcher) hostRenewalTargetFor(
	ctx context.Context, tenantID string, ident store.Identity,
) (store.DeploymentTarget, bool, error) {
	if d.store == nil {
		return store.DeploymentTarget{}, false, nil
	}
	targetID := deploymentTargetID(ident.Attributes)
	if targetID == "" {
		// No target row, so no executor marker, so nothing was opted out of.
		return store.DeploymentTarget{}, false, nil
	}
	configured, err := d.store.GetDeploymentTarget(ctx, tenantID, targetID)
	if err != nil {
		// A read failure is NOT "no". The earlier version swallowed this and
		// called falling through "the safe direction", which had it exactly
		// backwards: the fallback mints a control-plane key, so a transient
		// database blip would silently generate one for a target whose operator
		// had opted out — the single outcome this epic exists to prevent, caused
		// by a hiccup nobody would ever see.
		//
		// Failing the renewal is recoverable; the scheduler retries. Generating
		// the key is not.
		return store.DeploymentTarget{}, false, fmt.Errorf(
			"server: cannot determine the executor for deployment target %s, so this renewal "+
				"will not fall back to control-plane key generation: %w", targetID, err)
	}
	if !configured.Enabled || !targetExecutorIsAgent(configured.Config) {
		return store.DeploymentTarget{}, false, nil
	}
	return configured, true, nil
}

// enqueueHostRenewal queues an endpoint.renew job for an agent-executed target.
//
// The payload carries the subject binding and NO credential material — there is
// none to carry, which is the point. It also carries the verification address so
// the agent runs D2's post-deploy handshake, because a renewal that installed
// and does not serve is not a success.
func (d *issuanceDispatcher) enqueueHostRenewal(
	ctx context.Context,
	tenantID string,
	ident store.Identity,
	target store.DeploymentTarget,
	commonName string,
	dnsNames []string,
	predecessorCertificateID, rotationRunID string,
	issuance *store.OperationApprovalIssuanceBinding,
	idempotencyKey string,
) error {
	if d.outbox == nil {
		return fmt.Errorf("server: cannot queue host-generated renewal for %s: the outbox is not configured", ident.ID)
	}
	_, routed := deploymentRoutingAttrs(ident.Attributes)
	if routed == "" {
		routed = target.Name
	}
	verifyAddress, verifyServerName := verifyTargetFromConfig(target.Config)
	selection, err := endpointIssuingAuthority(ident.Attributes)
	if err != nil {
		return err
	}

	intent := RelayDeployIntent{
		Connector:                target.Type,
		Target:                   routed,
		TargetID:                 target.ID,
		Revision:                 target.RevisionID,
		IdentityID:               ident.ID,
		TargetConfig:             target.Config,
		VerifyAddress:            verifyAddress,
		VerifyServerName:         verifyServerName,
		SubjectCommonName:        commonName,
		SubjectDNSNames:          dnsNames,
		PredecessorCertificateID: predecessorCertificateID,
		RotationRunID:            rotationRunID,
		IssuingAuthoritySource:   selection.Source,
		IssuingAuthorityID:       selection.ID,
		Issuance:                 issuance,
	}
	payload, err := json.Marshal(intent)
	if err != nil {
		return fmt.Errorf("server: encode host renewal intent: %w", err)
	}

	// HOST role demanded per row, not just per kind. The kind-level vantage map
	// already says endpoint.renew is host work; stamping the demand on the row
	// too means the claim predicate enforces it against the certificate the
	// agent authenticated with, which is where it actually bites.
	//
	// EnqueueIfAbsent, not Enqueue: a renewal retried after a crash must not
	// queue a second job for the same identity, or two agents each generate a
	// key and one of the two certificates becomes an orphan nothing serves.
	return d.store.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		_, err := d.outbox.EnqueueIfAbsent(ctx, tx, orchestrator.Entry{
			TenantID:          tenantID,
			Destination:       agentJobKindEndpointRenew,
			IdempotencyKey:    idempotencyKey,
			Payload:           payload,
			EffectLane:        agentJobKindEndpointRenew + ":identity:" + ident.ID,
			RequiredAgentRole: mtls.AgentRoleHost,
		})
		return err
	})
}

// recordAgentRenewalDispatch appends the audit event for a handed-off renewal.
//
// Best effort, like the server-keygen deprecation event it sits beside: failing
// to record the handoff must not fail the renewal an operator is relying on.
// But it is worth recording, because this is the moment custody changes for an
// identity, and an auditor asking "when did this endpoint stop receiving keys
// from the control plane" needs a dated answer rather than an inference from
// the absence of deploy receipts.
func (d *issuanceDispatcher) recordAgentRenewalDispatch(
	ctx context.Context, tenantID string, ident store.Identity,
	target store.DeploymentTarget, dnsNames []string,
) {
	if d.log == nil {
		return
	}
	body, err := json.Marshal(struct {
		IdentityID string   `json:"identity_id"`
		TargetID   string   `json:"target_id"`
		TargetName string   `json:"target_name"`
		Connector  string   `json:"connector"`
		DNSNames   []string `json:"dns_names"`
		Custody    string   `json:"custody"`
		Detail     string   `json:"detail"`
	}{
		IdentityID: ident.ID, TargetID: target.ID, TargetName: target.Name,
		Connector: target.Type, DNSNames: dnsNames, Custody: "host_agent",
		Detail: "this target is marked executor=agent, so the renewal was handed to a host agent " +
			"that will generate the subject key on the machine serving it; the control plane " +
			"minted nothing and holds no private key for this renewal",
	})
	if err != nil {
		return
	}
	_, _ = d.log.Append(ctx, events.Event{
		TenantID: tenantID, Type: "issuance.host_renewal_dispatched", Data: body,
	})
}

// completeHostRenewal closes the lifecycle edge after a host agent reports a
// host-generated first issuance or renewal (epic B2).
//
// The dispatcher hands the renewal off and returns without transitioning,
// because at that moment there is no certificate to transition to. That leaves
// exactly one party who can close the loop: the agent, when it reports. If this
// never runs the identity sits in `renewing` permanently, and the consequence is
// worse than a wrong label — the lifecycle scheduler does not re-renew an
// identity already in renewing, so the endpoint quietly stops being renewed and
// expires, with the rotation run that started it still reading "succeeded".
//
// First issuance advances only after execution (and, when configured,
// verification). Renewal success returns to deployed; failure moves to the
// explicit retryable renewal_failed state while the predecessor remains the
// known deployed credential. The transition records that the signed agent
// result already completed the connector effect, so it must not enqueue a
// duplicate connector.deploy after the private material was destroyed.
func (s *Server) completeHostRenewal(ctx context.Context, tenantID string, payload []byte, outcome string) error {
	if s.orch == nil || len(payload) == 0 {
		return nil
	}
	var intent RelayDeployIntent
	if err := json.Unmarshal(payload, &intent); err != nil {
		return nil
	}
	identityID := intent.IdentityID
	if identityID == "" {
		return nil
	}
	state, err := s.orch.State(ctx, tenantID, identityID)
	if err != nil {
		return err
	}
	switch state {
	case orchestrator.StateIssued:
		// endpoint.renew also carries first issuance for an agent-executed
		// target: the name reflects where the key is generated, not the prior
		// lifecycle state. Only a completed deploy may advance first issuance.
		if outcome != transport.JobOutcomeExecuted && outcome != transport.JobOutcomeVerified {
			return nil
		}
		return s.orch.TransitionAfterCompletedSideEffect(ctx, tenantID, identityID,
			orchestrator.StateDeployed, "host-generated first issuance deployed", "connector.deploy")
	case orchestrator.StateRenewing:
		if outcome == transport.JobOutcomeFailed || outcome == transport.JobOutcomeVerifyFailed {
			return s.orch.Transition(ctx, tenantID, identityID, orchestrator.StateRenewalFailed,
				"host-generated renewal finished without a verified endpoint: "+outcome)
		}
		return s.orch.TransitionAfterCompletedSideEffect(ctx, tenantID, identityID,
			orchestrator.StateDeployed, "host-generated renewal deployed", "connector.deploy")
	case orchestrator.StateRenewalFailed:
		if outcome == transport.JobOutcomeExecuted || outcome == transport.JobOutcomeVerified {
			return s.orch.Transition(ctx, tenantID, identityID, orchestrator.StateDeployed,
				"host-generated renewal retry deployed")
		}
		return nil
	default:
		// Already deployed means a duplicate signed report. Every other state is
		// outside this receiver's authority and remains untouched.
		return nil
	}
}

// dispatchHostRenewal hands a renewal to a host agent instead of minting for it,
// reporting whether it took the work (epic B2).
//
// It sits AHEAD of the mint loop in handleRenew, and that placement is the whole
// design: custody is decided by who generates the key, and once
// mintServedLeafForRenewal has run for a server-keygen identity the control
// plane already holds one. Refusing later, at deploy time, would be a refusal to
// SHIP a key it had already made — a different and much weaker claim.
//
// The running rotation stays open across this handoff. Only an authenticated
// terminal host report can record its successor and complete the run.
func (d *issuanceDispatcher) dispatchHostRenewal(
	ctx context.Context,
	tenantID string,
	ident store.Identity,
	predecessor store.Certificate,
	run rotationRunEvidence,
	idemKey string,
) (bool, error) {
	target, hostExecuted, err := d.hostRenewalTargetFor(ctx, tenantID, ident)
	if err != nil {
		_ = d.recordRotationRun(ctx, tenantID, run, "failed", err.Error())
		return false, err
	}
	dnsNames, hostRenewable := hostRenewalSubject(predecessor)
	if !hostExecuted || !hostRenewable {
		return false, nil
	}
	if err := d.enqueueHostRenewal(ctx, tenantID, ident, target,
		dnsNames[0], dnsNames, predecessor.ID, run.ID, nil, "host-renew:"+idemKey); err != nil {
		_ = d.recordRotationRun(ctx, tenantID, run, "failed", err.Error())
		return false, err
	}
	d.recordAgentRenewalDispatch(ctx, tenantID, ident, target, dnsNames)
	return true, nil
}

// completeRecoveredRenewalRun finishes a renewal whose certificates were already
// minted before a crash.
//
// Extracted from handleRenew as a named stage. It is the crash-recovery path:
// the mint committed, the transition did not, and a redelivery finds the
// certificates already on record. Re-minting would issue a second successor for
// one renewal, so the run adopts what is there and completes the transition that
// was lost.
func (d *issuanceDispatcher) completeRecoveredRenewalRun(
	ctx context.Context,
	tenantID string,
	p transitionTrigger,
	run rotationRunEvidence,
	recovered []store.Certificate,
) ([]byte, error) {
	recoveredLast := recovered[len(recovered)-1]
	if recoveredLast.ReplacesID != nil {
		predecessor, err := d.store.GetCertificate(ctx, tenantID, *recoveredLast.ReplacesID)
		if err != nil {
			_ = d.recordRotationRun(ctx, tenantID, run, "failed", err.Error())
			return nil, fmt.Errorf("server: load recovered renewal predecessor: %w", err)
		}
		run.PredecessorFingerprint = predecessor.Fingerprint
	}
	if err := d.recordRotationRun(ctx, tenantID, run, "running", ""); err != nil {
		return nil, err
	}
	if err := d.completeRecoveredRenewal(ctx, tenantID, p.IdentityID, p.Reason); err != nil {
		_ = d.recordRotationRun(ctx, tenantID, run, "failed", err.Error())
		return nil, fmt.Errorf("server: complete recovered renewal transition: %w", err)
	}
	run.SuccessorFingerprint = recoveredLast.Fingerprint
	if err := d.recordRotationRun(ctx, tenantID, run, "succeeded", ""); err != nil {
		return nil, err
	}
	return []byte(fmt.Sprintf("renewed:%d", len(recovered))), nil
}
