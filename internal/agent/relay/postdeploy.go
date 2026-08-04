// SPDX-License-Identifier: MPL-2.0

package relay

import (
	"context"
	"time"

	"trstctl.com/trstctl/internal/agent/transport"
	"trstctl.com/trstctl/internal/agent/verify"
	"trstctl.com/trstctl/internal/crypto/certinfo"
)

// Verifying a deploy against the listener it just changed (epic D2).
//
// This runs in the one window where it can: after the connector wrote its files
// and ran its reload, and before the redeemed material is destroyed. Nothing
// downstream has the certificate any more — defer destroy() ends its life when
// runJob returns — so a check that ran later would have to be TOLD what to
// expect, and would be verifying against a description rather than against the
// bytes that were actually deployed.
//
// The step it observes is the one nothing else does. A connector's reload is a
// single exec call inside its own Deploy method; if it fails, or if the service
// ignores it, the connector still returns success and every downstream record
// says the certificate is live. That is the gap: not "did we write the file"
// but "is the process serving what we wrote".
//
// It is deliberately NOT an endpoint.verify job. That kind is gated to network
// agents because it is a vantage observation — connect as a client would, from
// across the segment — and this is the opposite: the agent looking at its own
// machine, with material a claimed job would never be allowed to hold. Widening
// the vantage gate to fit this in would break the reasoning that makes the gate
// worth having.

// postDeployVerification handshakes the deployed listener and reports what it
// found.
//
// The returned outcome and detail replace the plain success report when
// verification ran. A zero VerifyAddress means the operator configured no
// listener address, and that yields NO verification rather than a passing one —
// stated in the detail so an operator reading a deploy receipt can tell "not
// checked" from "checked and fine".
func postDeployVerification(ctx context.Context, intent DeployIntent, material Material) (outcome, detail, evidence string) {
	if intent.VerifyAddress == "" {
		// Honest silence. Reporting OutcomeVerified here would be the exact
		// overclaim the epic exists to remove, one layer down.
		return OutcomeExecuted, "", ""
	}
	certPEM, ok := material["credential.cert_pem"]
	if !ok || len(certPEM) == 0 {
		return OutcomeExecuted, "", ""
	}

	// The expectation comes from the bytes that were just deployed, not from
	// the intent's fingerprint field. Both should agree; building from the
	// material means a disagreement between them cannot silently become a
	// verification against the wrong expectation.
	expect, err := certinfo.ExpectationFromChain(certPEM)
	if err != nil {
		return transport.OutcomeVerifyFailed,
			"deployed certificate could not be inspected to build a verification expectation", ""
	}

	probeCtx, cancel := context.WithTimeout(ctx, verify.DefaultTimeout+2*time.Second)
	defer cancel()

	res, err := verify.Endpoint(probeCtx, verify.Request{
		Address:    intent.VerifyAddress,
		ServerName: intent.VerifyServerName,
		Vantage:    transport.VantageLocal,
		Expect:     expect,
	})
	if err != nil {
		return transport.OutcomeVerifyFailed, "post-deploy verification could not run: " +
			transport.SanitizeProbeError(err), ""
	}
	if verr := res.Transcript.Validate(); verr != nil {
		// A transcript that cannot be canonicalized cannot be signed, and an
		// unsigned verification is not evidence. Report the failure rather than
		// reporting a verdict nothing backs.
		return transport.OutcomeVerifyFailed, "verification transcript was not reportable", ""
	}
	evidence = res.Transcript.Digest()

	if !res.OK() {
		// This is what justifies a rollback: the files landed and the listener
		// is still not serving them. Distinct from OutcomeFailed, which means
		// the deploy itself did not complete — rolling back a deploy that never
		// applied would undo something that was never done.
		return transport.OutcomeVerifyFailed, res.Verdict.Detail, evidence
	}
	return transport.OutcomeVerified, "", evidence
}
