// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"encoding/json"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/agent/relay"
	"trstctl.com/trstctl/internal/agent/transport"
	"trstctl.com/trstctl/internal/crypto/certinfo"
)

// simulatedHostVerification supplies complete signed evidence to receiver
// fixtures. The certificate was really issued and the routing comes from the
// actual claim; the listener observation is simulated. Separate shipping-agent
// and installed journeys prove deployment and listener behavior.
func simulatedHostVerification(t *testing.T, h *roleHarness, job transport.ClaimedJob, fingerprint, outcome string) (string, string) {
	t.Helper()
	if outcome != transport.JobOutcomeVerified && outcome != transport.JobOutcomeVerifyFailed {
		return "", ""
	}
	intent, _ := deployIntentForVerificationReceipt(job.Payload)
	if intent.TargetID == "" || intent.VerifyAddress == "" {
		t.Fatal("verified receiver fixture must have a bound target and probe address")
	}
	cert, err := h.store.GetCertificateByFingerprint(t.Context(), h.tenant, fingerprint)
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := certinfo.Inspect(cert.CertificateDER)
	if err != nil {
		t.Fatal(err)
	}
	if leaf.SHA256Fingerprint != fingerprint {
		t.Fatal("receiver fixture certificate differs from the signed credential")
	}
	tr := transport.ProbeTranscript{
		Address: intent.VerifyAddress, ServerName: intent.VerifyServerName,
		Vantage: transport.VantageLocal, ExpectedFingerprint: fingerprint,
		ExpectedSANDigest: transport.SANSetDigest(leaf.DNSNames),
		ObservedAtUnix:    time.Now().UTC().Unix(),
	}
	if outcome == transport.JobOutcomeVerifyFailed {
		tr.Error = "simulated listener connection refusal"
	} else {
		tr.Reached = true
		tr.ObservedFingerprint = fingerprint
		tr.ObservedSANDigest = tr.ExpectedSANDigest
		tr.CheckedSANs = len(leaf.DNSNames) != 0
		tr.NotBeforeUnix = leaf.NotBefore.Unix()
		tr.NotAfterUnix = leaf.NotAfter.Unix()
		tr.ChainBytes = len(cert.CertificateDER)
	}
	detail, err := json.Marshal(relay.EndpointVerifyReport{Results: []relay.EndpointVerifyResult{{
		EndpointID: intent.TargetID, Transcript: tr, Detail: tr.Error,
	}}})
	if err != nil {
		t.Fatal(err)
	}
	return string(detail), tr.Digest()
}
