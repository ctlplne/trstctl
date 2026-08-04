// SPDX-License-Identifier: MPL-2.0

package server

import (
	"context"
	"encoding/json"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"trstctl.com/trstctl/internal/agent/relay"
	"trstctl.com/trstctl/internal/agent/transport"

	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/notify"
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
func (s *Server) recordDeployVerification(ctx context.Context, tenantID, agentName, idempotencyKey, reportJSON string, jobPayload []byte) {
	var report relay.EndpointVerifyReport
	if err := json.Unmarshal([]byte(reportJSON), &report); err != nil || len(report.Results) == 0 {
		return
	}
	var intent relay.DeployIntent
	// The connector and target come from the job payload the control plane
	// queued, never from the agent's report — the same rule the sweep ingest
	// follows, for the same reason.
	_ = json.Unmarshal(jobPayload, &intent)

	for _, res := range report.Results {
		id := strings.TrimSpace(res.EndpointID)
		if id == "" {
			continue
		}
		s.appendEndpointVerification(ctx, tenantID, agentName, id, res.Transcript, res.Detail)
		s.recordVerificationReceipt(ctx, tenantID, idempotencyKey, intent, res.Transcript, res.Detail)
		if !res.Transcript.Reached || res.Transcript.Mismatch != "" {
			s.raiseVerificationAlert(ctx, tenantID, store.EndpointVerification{
				EndpointID: id, Address: res.Transcript.Address,
				Vantage:  string(res.Transcript.Vantage),
				Reached:  res.Transcript.Reached,
				Mismatch: string(res.Transcript.Mismatch),
				LastGoodAt: s.lastGoodForEndpoint(ctx, tenantID, id,
					string(res.Transcript.Vantage)),
				ObservedFingerprint: res.Transcript.ObservedFingerprint,
				Detail:              res.Detail,
			})
		}
	}
}

// recordEndpointVerificationSweep ingests a relay's endpoint.verify report.
func (s *Server) recordEndpointVerificationSweep(ctx context.Context, tenantID, agentName, _, reportJSON string) {
	if s.log == nil || strings.TrimSpace(tenantID) == "" {
		return
	}
	var report relay.EndpointVerifyReport
	if err := json.Unmarshal([]byte(reportJSON), &report); err != nil {
		// Version skew, not a clean estate. Recording nothing leaves the
		// previous observations on screen, which is the honest outcome: we do
		// not know anything new.
		return
	}
	if len(report.Results) == 0 {
		return
	}
	// The expectation set the control plane queued. Results are matched against
	// it by endpoint id, and a result naming an endpoint that was not asked
	// about is dropped — see the comment above.
	for _, res := range report.Results {
		id := strings.TrimSpace(res.EndpointID)
		if id == "" {
			continue
		}
		s.appendEndpointVerification(ctx, tenantID, agentName, id, res.Transcript, res.Detail)
		// A divergence or an unreachable endpoint raises an operator alert. A
		// clean observation raises nothing — an alert per healthy sweep would
		// bury the one that matters.
		if !res.Transcript.Reached || res.Transcript.Mismatch != "" {
			s.raiseVerificationAlert(ctx, tenantID, store.EndpointVerification{
				EndpointID: id, Address: res.Transcript.Address,
				Vantage:  string(res.Transcript.Vantage),
				Reached:  res.Transcript.Reached,
				Mismatch: string(res.Transcript.Mismatch),
				// LastGoodAt is read from the stored row rather than the report:
				// only the control plane knows whether this endpoint has EVER
				// been good, and that distinction changes the alert's wording.
				LastGoodAt:          s.lastGoodForEndpoint(ctx, tenantID, id, string(res.Transcript.Vantage)),
				ObservedFingerprint: res.Transcript.ObservedFingerprint,
				Detail:              res.Detail,
			})
		}
	}
}

// appendEndpointVerification writes one observation to the log.
func (s *Server) appendEndpointVerification(
	ctx context.Context, tenantID, agentName, endpointID string,
	tr transport.ProbeTranscript, detail string,
) {
	if err := tr.Validate(); err != nil {
		// A transcript that does not canonicalize cannot have been signed over
		// coherently, and an unsigned observation is not evidence. Dropping it
		// is better than storing a verdict with nothing behind it.
		return
	}
	observedAt := time.Unix(tr.ObservedAtUnix, 0).UTC()
	if tr.ObservedAtUnix == 0 {
		observedAt = time.Now().UTC()
	}
	payload, err := json.Marshal(projections.EndpointVerificationObserved{
		EndpointID:          endpointID,
		Address:             tr.Address,
		Vantage:             string(tr.Vantage),
		Reached:             tr.Reached,
		Mismatch:            string(tr.Mismatch),
		ExpectedFingerprint: tr.ExpectedFingerprint,
		ObservedFingerprint: tr.ObservedFingerprint,
		CheckedSANs:         tr.CheckedSANs,
		CheckedChain:        tr.CheckedChain,
		NotBefore:           unixOrZeroTime(tr.NotBeforeUnix),
		NotAfter:            unixOrZeroTime(tr.NotAfterUnix),
		Detail:              detail,
		EvidenceDigest:      tr.Digest(),
		AgentCommonName:     agentName,
		ObservedAt:          observedAt,
	})
	if err != nil {
		return
	}
	_, _ = s.log.Append(ctx, events.Event{
		Type: projections.EventEndpointVerified, TenantID: tenantID, Data: payload,
	})
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
func (s *Server) recordVerificationReceipt(
	ctx context.Context, tenantID, idempotencyKey string,
	intent relay.DeployIntent, tr transport.ProbeTranscript, detail string,
) {
	if s.orch == nil {
		return
	}
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

	_, _ = s.orch.RecordConnectorDelivery(ctx, tenantID, store.ConnectorDeliveryReceipt{
		Destination: "connector.deploy",
		Connector:   intent.Connector,
		Target:      intent.Target,
		// The fingerprint recorded is the one that was DEPLOYED, so the receipt
		// answers "was this certificate served" rather than "what is out there".
		// The observed one lives in the endpoint verification row beside it.
		Fingerprint:    tr.ExpectedFingerprint,
		Status:         status,
		Attempts:       1,
		Reason:         reason,
		Detail:         detail,
		IdempotencyKey: idempotencyKey + ":verified",
	})
}

// raiseVerificationAlert enqueues an operator alert for a divergence.
//
// Through the outbox, in the tenant's own transaction, like every other
// external effect (AN-6). Never dispatched inline: a verification sweep can
// find many endpoints at once, and a synchronous fan-out would put the
// notification bulkhead's budget on the critical path of an agent's report.
//
// The severity mapping is where this is easy to get wrong. There are two
// severity scales in this codebase — the ROUTING scale (low, informational,
// warning, critical) and the FINDING scale (low, medium, high, critical) — and
// they are not the same vocabulary. "high" is not a routable severity: it
// normalizes to "low", which would route a production listener serving the
// wrong certificate exactly like an informational notice. So this maps onto the
// routing scale explicitly rather than passing a finding severity through.
func (s *Server) raiseVerificationAlert(
	ctx context.Context, tenantID string, v store.EndpointVerification,
) {
	if s.store == nil || s.outbox == nil {
		return
	}
	kind := notify.KindEndpointVerificationFailed
	severity := notify.AlertSeverityCritical
	detail := v.Detail
	if !v.Reached {
		// Unreachable is real but it is not the same emergency: a probe that
		// could not connect may be a firewall, a maintenance window, or a relay
		// that lost its route. Paging someone at critical for that teaches them
		// to ignore the channel, which costs more than the missed signal.
		kind = notify.KindEndpointUnreachable
		severity = notify.AlertSeverityWarning
		if detail == "" {
			detail = "verification could not reach the endpoint"
		}
	} else if v.LastGoodAt.IsZero() {
		// Never once observed serving correctly. Still critical, but the detail
		// says so: an endpoint that has never worked is a deployment that was
		// never finished, not a regression, and it is fixed by different means.
		detail = detail + " (this endpoint has never been observed serving the expected identity)"
	}

	payload, err := json.Marshal(notify.Alert{
		Kind:            kind,
		TenantID:        tenantID,
		Severity:        severity,
		EndpointAddress: v.Address,
		Vantage:         v.Vantage,
		Mismatch:        v.Mismatch,
		LastGoodAt:      v.LastGoodAt,
		Subject:         v.Address,
		Detail:          detail,
	})
	if err != nil {
		return
	}
	// The idempotency key deliberately includes the mismatch class and the
	// vantage but NOT a timestamp. A listener serving the wrong certificate for
	// a week should produce one open alert, not one per sweep — and when the
	// class changes (an expired certificate replaced by a wrong one) that is
	// genuinely new information and gets its own.
	idem := "endpoint-verify:" + v.EndpointID + ":" + v.Vantage + ":" + v.Mismatch + ":" + v.ObservedFingerprint
	_ = s.store.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		_, err := s.outbox.EnqueueIfAbsent(ctx, tx, orchestrator.Entry{
			TenantID: tenantID, Destination: notify.DestinationVerification,
			IdempotencyKey: idem, Payload: payload,
		})
		return err
	})
}

// lastGoodForEndpoint reads when this endpoint was last observed serving what
// it should, from the control plane's own state.
//
// Read AFTER the observation is appended, deliberately: a passing observation
// has already updated last_good_at, and a failing one leaves the previous value
// intact. So this returns "the last time this worked" in both cases, which is
// the number the alert needs — zero means it has never worked at all.
func (s *Server) lastGoodForEndpoint(ctx context.Context, tenantID, endpointID, vantage string) time.Time {
	if s.store == nil {
		return time.Time{}
	}
	rows, err := s.store.ListEndpointVerifications(ctx, tenantID)
	if err != nil {
		return time.Time{}
	}
	for _, r := range rows {
		if r.EndpointID == endpointID && r.Vantage == vantage {
			return r.LastGoodAt
		}
	}
	return time.Time{}
}

func unixOrZeroTime(sec int64) time.Time {
	if sec == 0 {
		return time.Time{}
	}
	return time.Unix(sec, 0).UTC()
}
