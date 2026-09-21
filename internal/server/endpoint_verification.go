// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"time"

	"fmt"
	"trstctl.com/trstctl/internal/agent/relay"
	"trstctl.com/trstctl/internal/agent/transport"
	"trstctl.com/trstctl/internal/crypto/certinfo"

	"trstctl.com/trstctl/internal/orchestrator"
	"trstctl.com/trstctl/internal/projections"
	"trstctl.com/trstctl/internal/servedstatus"
	"trstctl.com/trstctl/internal/store"
)

// Turning an agent's verification report into estate state (epic D2).
//
// R1 shipped a relay probe whose report goes into the job's outcome detail and
// is decoded by nobody — the observation exists, briefly, and then only a
// human reading a job row would ever see it. This is the ingest that epic did
// not build, and the reason it matters here is that verification is not a
// diagnostic: it is the source of truth that replaces inventory-only expiry
// alerting, so an observation nothing records is an observation that changes
// nothing.
//
// Two rules run through all of it.
//
// First, the control plane never learns an endpoint's identity from the agent's
// report. The endpoint id and address come from the job payload the control
// plane itself queued. An agent that could name a different endpoint in its
// result could overwrite another endpoint's state with its own observation, and
// the signature on the receipt would be perfectly valid over that lie.
//
// Second, a report that cannot be read is not an empty report. A decode failure
// records nothing rather than recording "no divergence found", because writing
// a clean result for a report we could not parse is the false-assurance failure
// the whole epic exists to remove.

// recordDeployVerification ingests the local-vantage report a deploy produced
// and writes both records it implies (epics D2 + D3).
//
// Two writes for one observation, deliberately: the endpoint verification is
// CURRENT state ("this listener is serving X now") and the delivery receipt is
// HISTORICAL ("this delivery was verified when it ran"). A certificate verified
// in June whose listener silently reverted in August must show a June receipt
// still reading verified and an endpoint state reading diverged. Collapsing the
// two would either rewrite history or freeze current state, and the tri-state's
// whole value is that issued, delivered and verified have three lifetimes.
func (s *Server) recordDeployVerification(ctx context.Context, tenantID, agentName string, claim store.AgentJobResultClaim, req *transport.ReportJobResultRequest) error {
	if s.orch == nil || s.store == nil {
		return errors.New("deployment verification receiver is unavailable")
	}
	// The shipping agent can report a failure before a probe transcript exists.
	// Preserve that signed failure, but never manufacture an endpoint observation.
	if req.Outcome == transport.JobOutcomeVerifyFailed && req.EvidenceDigest == "" {
		return nil
	}
	intent, _ := deployIntentForVerificationReceipt(claim.Payload)
	if claim.Destination == agentJobKindEndpointRenew {
		intent.Fingerprint = req.CredentialFingerprint
	}
	cert, err := s.store.GetCertificateByFingerprint(ctx, tenantID, normalizeVerificationFingerprint(intent.Fingerprint))
	if err != nil {
		return fmt.Errorf("load verification's issued certificate: %w", err)
	}
	expected, err := certinfo.ExpectationFromChain(cert.CertificateDER)
	if err != nil {
		return fmt.Errorf("reconstruct verification's issued identity: %w", err)
	}
	if expected.SHA256Fingerprint != normalizeVerificationFingerprint(intent.Fingerprint) {
		return errors.New("stored verification certificate differs from its claimed fingerprint")
	}
	result, err := validateDeploymentVerificationReport(intent, expected, req.Detail, req.EvidenceDigest, req.Outcome)
	if err != nil {
		return err
	}
	attemptKey := fmt.Sprintf("%s:attempt:%d", claim.IdempotencyKey, req.Attempt)
	eventID := orchestrator.DiscoveryRelayEventID(tenantID, attemptKey, "endpoint-verification:"+result.EndpointID)
	if err := s.appendEndpointVerificationWithEventID(ctx, tenantID, agentName, result.EndpointID, result.Transcript, result.Detail, eventID); err != nil {
		return err
	}

	return nil
}

// deployIntentForVerificationReceipt reads only the public routing half of a
// queued deploy. Modern credential-bearing jobs are sealed, so unmarshaling
// them directly as DeployIntent silently produced an empty connector/target on
// the verified receipt even though the agent executed the right work.
func deployIntentForVerificationReceipt(jobPayload []byte) (relay.DeployIntent, bool) {
	var rollback relay.RollbackIntent
	if json.Unmarshal(jobPayload, &rollback) == nil && strings.TrimSpace(rollback.PredecessorFingerprint) != "" {
		if rollback.VerifyAddress == "" {
			rollback.VerifyAddress, rollback.VerifyServerName = verifyTargetFromConfig(rollback.TargetConfig)
		}
		return relay.DeployIntent{
			Connector: rollback.Connector, Target: rollback.Target, TargetID: rollback.TargetID,
			IdentityID: rollback.IdentityID, Fingerprint: rollback.PredecessorFingerprint,
			TargetConfig: rollback.TargetConfig, VerifyAddress: rollback.VerifyAddress,
			VerifyServerName: rollback.VerifyServerName,
		}, true
	}
	var wrapped sealedConnectorDeployPayload
	if json.Unmarshal(jobPayload, &wrapped) == nil && wrapped.Format == connectorDeploySealedFormat {
		address, serverName := verifyTargetFromConfig(wrapped.TargetConfig)
		return relay.DeployIntent{Connector: wrapped.Connector, Target: wrapped.Target, TargetID: wrapped.TargetID, Revision: wrapped.Revision, IdentityID: wrapped.IdentityID, Fingerprint: wrapped.Fingerprint, TargetConfig: append(json.RawMessage(nil), wrapped.TargetConfig...), VerifyAddress: address, VerifyServerName: serverName}, false
	}
	var direct relay.DeployIntent
	if json.Unmarshal(jobPayload, &direct) == nil && strings.TrimSpace(direct.Connector) != "" {
		if direct.VerifyAddress == "" {
			direct.VerifyAddress, direct.VerifyServerName = verifyTargetFromConfig(direct.TargetConfig)
		}
		return direct, false
	}
	return relay.DeployIntent{}, false
}

// recordEndpointVerificationSweep ingests a relay's endpoint.verify report.
func (s *Server) recordEndpointVerificationSweep(ctx context.Context, tenantID, agentName, idempotencyKey string, jobPayload []byte, reportJSON, evidenceDigest string) error {
	if s.log == nil || s.orch == nil || strings.TrimSpace(tenantID) == "" {
		return errors.New("endpoint verification receiver is unavailable")
	}
	report, err := validateEndpointVerificationReport(jobPayload, reportJSON, evidenceDigest)
	if err != nil {
		return err
	}
	for _, res := range report.Results {
		id := res.EndpointID
		eventID := orchestrator.DiscoveryRelayEventID(tenantID, idempotencyKey, "endpoint-verification:"+id)
		if err := s.appendEndpointVerificationWithEventID(ctx, tenantID, agentName, id, res.Transcript, res.Detail, eventID); err != nil {
			return err
		}

	}
	return nil
}

// appendEndpointVerification records and projects one observation while holding
// the same metadata admission fence as certificate issuance and revocation.
func (s *Server) appendEndpointVerification(
	ctx context.Context, tenantID, agentName, endpointID string,
	tr transport.ProbeTranscript, detail string,
) error {
	return s.appendEndpointVerificationWithEventID(ctx, tenantID, agentName, endpointID, tr, detail, "")
}

func (s *Server) appendEndpointVerificationWithEventID(
	ctx context.Context, tenantID, agentName, endpointID string,
	tr transport.ProbeTranscript, detail, eventID string,
) error {
	if err := tr.Validate(); err != nil {
		// A transcript that does not canonicalize cannot have been signed over
		// coherently, and an unsigned observation is not evidence. Dropping it
		// is better than storing a verdict with nothing behind it.
		return err
	}
	if s.orch == nil {
		return errors.New("server: endpoint verification recorder is unavailable")
	}
	observedAt := time.Unix(tr.ObservedAtUnix, 0).UTC()
	if tr.ObservedAtUnix == 0 {
		observedAt = time.Now().UTC()
	}
	var notBefore, notAfter time.Time
	if tr.Reached && tr.ObservedFingerprint != "" {
		// Unix epoch is a real certificate date. Only an absent parsed
		// peer has no validity window.
		notBefore = time.Unix(tr.NotBeforeUnix, 0).UTC()
		notAfter = time.Unix(tr.NotAfterUnix, 0).UTC()
	}
	observation := projections.EndpointVerificationObserved{
		EndpointID:          endpointID,
		Address:             tr.Address,
		Vantage:             string(tr.Vantage),
		Reached:             tr.Reached,
		Mismatch:            string(tr.Mismatch),
		ExpectedFingerprint: tr.ExpectedFingerprint,
		ObservedFingerprint: tr.ObservedFingerprint,
		CheckedSANs:         tr.CheckedSANs,
		CheckedChain:        tr.CheckedChain,
		NotBefore:           notBefore,
		NotAfter:            notAfter,
		Detail:              detail,
		EvidenceDigest:      tr.Digest(),
		AgentCommonName:     agentName,
		ObservedAt:          observedAt,
	}
	if eventID != "" {
		return s.orch.RecordEndpointVerificationWithEventID(ctx, tenantID, eventID, observation)
	}
	return s.orch.RecordEndpointVerification(ctx, tenantID, observation)
}

// recordVerificationReceipt writes the third state into the delivery evidence
// chain (epic D3).
//
// A SECOND receipt, not an edit of the delivery one. Both facts belong in the
// chain and they have different lifetimes: "a connector applied the credential"
// is true forever once it happens, and "the endpoint was serving it" is true of
// the moment it was observed. Overwriting the first would destroy the record
// that delivery succeeded — which is exactly what an operator needs when
// working out whether the problem is the pipeline or the listener.
//
// The same shape the dry-run result uses (D5): a distinct idempotency key
// suffix, because "we asked" and "here is the answer" are different rows.
func deploymentVerificationReceipt(intent relay.DeployIntent, tr transport.ProbeTranscript, detail string) store.ConnectorDeliveryReceipt {
	status := servedstatus.ConnectorVerified
	reason := "endpoint_serving_deployed_identity"
	if !tr.Reached {
		// Unreachable is not "verify failed" — nothing was observed, so nothing
		// diverged. Recording it as a verification failure would send an
		// operator to look at a certificate when the problem is a route.
		status = servedstatus.ConnectorVerifyFailed
		reason = "endpoint_unreachable"
		if detail == "" {
			detail = "the endpoint could not be reached to verify what it is serving"
		}
	} else if tr.Mismatch != "" {
		status = servedstatus.ConnectorVerifyFailed
		reason = "endpoint_serving_" + string(tr.Mismatch) + "_mismatch"
	}

	identityID := strings.TrimSpace(intent.IdentityID)
	var identityIDRef *string
	if identityID != "" {
		identityIDRef = &identityID
	}
	return store.ConnectorDeliveryReceipt{
		IdentityID:  identityIDRef,
		Destination: "connector.deploy",
		Connector:   intent.Connector,
		Target:      intent.Target,
		// The fingerprint recorded is the one that was DEPLOYED, so the receipt
		// answers "was this certificate served" rather than "what is out there".
		// The observed one lives in the endpoint verification row beside it.
		Fingerprint: tr.ExpectedFingerprint,
		Status:      status,
		Attempts:    1,
		Reason:      reason,
		Detail:      detail,
	}
}
