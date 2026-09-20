// SPDX-License-Identifier: BUSL-1.1

package relay

import (
	"context"
	"encoding/json"
	"time"

	"trstctl.com/trstctl/internal/agent/transport"
	"trstctl.com/trstctl/internal/agent/verify"
	"trstctl.com/trstctl/internal/crypto/certinfo"
)

// The relay vantage: seeing an endpoint as a client sees it (epic D2).
//
// This is the half of verification the host cannot do. A host agent checking
// its own listener proves the file landed and the service reloaded; it says
// nothing about whether anything else can reach the endpoint, and for an
// appliance there is no host agent at all — nothing runs on an F5. A network
// agent connecting across the segment is the only witness for those, and the
// only one whose success means "a client could get this".
//
// It redeems nothing. Like the revocation probe and the segment sweep, it reads
// what a listener publicly presents, so it is routed before the credential step
// — an attempt that redeems material it has no use for burns the attempt's one
// redemption for nothing.

// KindEndpointVerify is the claimable kind for network-vantage verification.
//
// The control plane has gated this to network agents since A2, with the
// reasoning that it is a vantage observation. That gate is correct and this
// executor is written to fit it rather than to widen it: the host's own
// post-deploy check is not a claimed job at all, because it needs the deployed
// material and a claimed job would never be allowed to hold it.
const KindEndpointVerify = "endpoint.verify"

// EndpointVerifyIntent is the payload for one verification sweep.
//
// A LIST, because a sweep across a segment amortises one claim over many
// endpoints; claiming a job per listener would spend more on the protocol than
// on the work.
type EndpointVerifyIntent struct {
	Endpoints []EndpointExpectation `json:"endpoints"`
	// TimeoutSeconds bounds each handshake. Zero uses the package default.
	TimeoutSeconds int `json:"timeout_seconds,omitempty"`
}

// EndpointExpectation is one listener and what it should be serving.
type EndpointExpectation struct {
	// EndpointID identifies the row this observation belongs to, so a report
	// can be matched back without the control plane trusting the address.
	EndpointID string `json:"endpoint_id"`
	Address    string `json:"address"`
	ServerName string `json:"server_name,omitempty"`
	// Connector selects a known application's TLS negotiation. Empty retains
	// direct TLS for legacy jobs; PostgreSQL requires its SSLRequest exchange.
	Connector string `json:"connector,omitempty"`
	// Fingerprint is the expected leaf SHA-256, hex.
	Fingerprint string `json:"fingerprint"`
	// DNSNames and ChainFingerprints are optional. Absent means NOT CHECKED —
	// never means "expected to be empty", which is why the report says which
	// comparisons ran.
	DNSNames          []string `json:"dns_names,omitempty"`
	ChainFingerprints []string `json:"chain_fingerprints,omitempty"`
}

// EndpointVerifyReport is what the relay reports back.
type EndpointVerifyReport struct {
	Results []EndpointVerifyResult `json:"results"`
}

// EndpointVerifyResult is one endpoint's outcome.
//
// It carries the transcript rather than a summary of it: the control plane
// re-derives the digest from these bytes and checks it against the one inside
// the agent's signed statement. A summary would leave the signature committing
// to something the server cannot reconstruct.
type EndpointVerifyResult struct {
	EndpointID string                    `json:"endpoint_id"`
	Transcript transport.ProbeTranscript `json:"transcript"`
	// Detail is the operator-facing explanation, already sanitized.
	Detail string `json:"detail,omitempty"`
}

// runEndpointVerify probes every endpoint in the intent and reports the lot.
//
// One report for the whole sweep, and the job outcome is EXECUTED whenever the
// sweep ran — even when every endpoint diverged. A divergence is a finding, not
// a job failure: reporting it as a failure would put the job back on the queue
// to be retried forever against a listener that is simply serving the wrong
// certificate, and the retry would never fix it.
func runEndpointVerify(ctx context.Context, ch Channel, job Job) bool {
	var intent EndpointVerifyIntent
	if err := decodeJobPayload(job.Payload, &intent); err != nil {
		report(ctx, ch, job, OutcomeFailed, "job payload is not an endpoint verification intent")
		return false
	}
	if len(intent.Endpoints) == 0 {
		// An empty sweep is a control-plane bug, and reporting it as a clean
		// run would record "nothing diverged" for a sweep that looked at
		// nothing — the false-assurance shape this epic exists to remove.
		report(ctx, ch, job, OutcomeFailed, "endpoint verification intent named no endpoints")
		return false
	}

	timeout := verify.DefaultTimeout
	if intent.TimeoutSeconds > 0 {
		timeout = time.Duration(intent.TimeoutSeconds) * time.Second
	}

	out := EndpointVerifyReport{Results: make([]EndpointVerifyResult, 0, len(intent.Endpoints))}
	for _, want := range intent.Endpoints {
		res, err := verify.Endpoint(ctx, verify.Request{
			Address:      want.Address,
			ServerName:   want.ServerName,
			Vantage:      transport.VantageRelay,
			Timeout:      timeout,
			PreHandshake: connectorTLSNegotiation(want.Connector),
			Expect: certinfo.Expectation{
				SHA256Fingerprint: want.Fingerprint,
				DNSNames:          want.DNSNames,
				ChainFingerprints: want.ChainFingerprints,
			},
		})
		if err != nil {
			// A malformed request for one endpoint does not abandon the rest of
			// the sweep. It is recorded as an unreached observation so the
			// endpoint does not silently vanish from the report — an endpoint
			// missing from a sweep reads as one that was fine.
			out.Results = append(out.Results, EndpointVerifyResult{
				EndpointID: want.EndpointID,
				Transcript: transport.ProbeTranscript{
					Address:        addressOrPlaceholder(want.Address),
					Vantage:        transport.VantageRelay,
					Error:          transport.SanitizeProbeError(err),
					ObservedAtUnix: time.Now().UTC().Unix(),
				},
				Detail: "endpoint could not be probed: " + transport.SanitizeProbeError(err),
			})
			continue
		}
		out.Results = append(out.Results, EndpointVerifyResult{
			EndpointID: want.EndpointID,
			Transcript: res.Transcript,
			Detail:     res.Verdict.Detail,
		})
	}

	detail, err := json.Marshal(out)
	if err != nil {
		report(ctx, ch, job, OutcomeFailed, "endpoint verification report could not be encoded")
		return false
	}
	// The evidence digest covers the SWEEP, so the signed receipt commits to
	// the whole report rather than to one endpoint's transcript.
	reportWithEvidence(ctx, ch, job, OutcomeExecuted, string(detail), sweepDigest(out))
	return true
}

// sweepDigest commits to every transcript in the sweep, in report order.
func sweepDigest(rep EndpointVerifyReport) string {
	var b []byte
	for _, r := range rep.Results {
		b = append(b, r.Transcript.Canonical()...)
		b = append(b, '\n')
	}
	if len(b) == 0 {
		return ""
	}
	return transport.SweepDigest(b)
}

// addressOrPlaceholder keeps a transcript canonicalizable when the control
// plane sent an empty address: Validate refuses an empty one, and a result that
// cannot be reported would drop the endpoint from the sweep entirely.
func addressOrPlaceholder(addr string) string {
	if addr == "" {
		return "(no address supplied)"
	}
	return addr
}
