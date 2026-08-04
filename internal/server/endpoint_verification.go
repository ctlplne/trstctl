// SPDX-License-Identifier: MPL-2.0

package server

import (
	"context"
	"encoding/json"
	"strings"
	"time"

	"trstctl.com/trstctl/internal/agent/relay"
	"trstctl.com/trstctl/internal/agent/transport"
	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/projections"
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

func unixOrZeroTime(sec int64) time.Time {
	if sec == 0 {
		return time.Time{}
	}
	return time.Unix(sec, 0).UTC()
}
