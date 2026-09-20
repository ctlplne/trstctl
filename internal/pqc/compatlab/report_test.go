// SPDX-License-Identifier: BUSL-1.1

package compatlab

import (
	"context"
	"encoding/json"
	"testing"

	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/signing"
)

func readyCohort() Cohort {
	return Cohort{
		Name:     "edge-tls-frontends",
		Targeted: []string{"client-b", "client-a", "client-c"},
		Results: []Result{
			{ClientID: "client-a", Outcome: OutcomeNegotiated, HandshakeBytes: 5100, LatencyMS: 12},
			{ClientID: "client-b", Outcome: OutcomeNegotiated, HandshakeBytes: 5200, LatencyMS: 14},
			{ClientID: "client-c", Outcome: OutcomeNegotiated, HandshakeBytes: 4900, LatencyMS: 11},
		},
	}
}

// A readiness report signs inside the isolated signer and verifies offline from
// the report alone — the acceptance's "evidence exported as a signed readiness
// report". The verdict is DERIVED into the signed body, and the cohort's
// handshake cost travels with it.
func TestReadinessReportSignsAndVerifiesOffline(t *testing.T) {
	signer, err := NewArtifactSigner("")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(signer.Destroy)

	report, err := BuildReport("tenant-x", "pqc-lab", readyCohort(), 1_700_000_000)
	if err != nil {
		t.Fatalf("BuildReport: %v", err)
	}
	if !report.Verdict.Ready {
		t.Fatalf("cohort should be ready: %s", report.Verdict.Summary)
	}
	signed, err := SignReport(context.Background(), signer, report, "")
	if err != nil {
		t.Fatalf("SignReport: %v", err)
	}
	trust := map[string]crypto.PublicKey{signer.KeyID(): signer.Public()}
	if err := signed.Verify(trust); err != nil {
		t.Fatalf("offline Verify: %v", err)
	}

	// The signed body carries the cost, so a reader can weigh it — a report
	// omitting cost would recommend a rollout that triples handshake size.
	found := false
	for _, r := range signed.Report.Results {
		if r.ClientID == "client-a" {
			found = true
			if r.HandshakeBytes != 5100 {
				t.Fatalf("cost dropped from the signed report: %+v", r)
			}
		}
	}
	if !found {
		t.Fatal("signed report lost a client's evidence")
	}
}

// A tampered verdict fails verification: the signature covers the whole body,
// so flipping "ready" after signing cannot pass. This is the property the
// signature exists for — a readiness recommendation nobody can silently edit.
func TestTamperedReportFailsVerification(t *testing.T) {
	signer, err := NewArtifactSigner("")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(signer.Destroy)
	report, err := BuildReport("tenant-x", "pqc-lab", readyCohort(), 1_700_000_000)
	if err != nil {
		t.Fatal(err)
	}
	signed, err := SignReport(context.Background(), signer, report, "")
	if err != nil {
		t.Fatal(err)
	}
	trust := map[string]crypto.PublicKey{signer.KeyID(): signer.Public()}

	tampered := signed
	tampered.Report.Verdict.Ready = false
	tampered.Report.Verdict.Summary = "NOT READY (edited after signing)"
	if err := tampered.Verify(trust); err == nil {
		t.Fatal("an edited verdict verified; the signature must cover the whole body")
	}

	// An untrusted key is refused even if it embeds a valid-looking signature.
	other, err := NewArtifactSigner("other-key")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(other.Destroy)
	if err := signed.Verify(map[string]crypto.PublicKey{other.KeyID(): other.Public()}); err == nil {
		t.Fatal("a report verified against a key that did not sign it")
	}
}

// The signer refuses any artifact kind but the readiness report, so its key
// cannot be borrowed to sign a witness or a plan through the shared chain.
func TestReadinessSignerRefusesOtherKinds(t *testing.T) {
	signer, err := NewArtifactSigner("")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(signer.Destroy)
	_, err = signer.SignArtifact(context.Background(), signing.ArtifactSignRequest{
		Kind: "divergence-witness", TenantID: "t", AuthorityID: "a", Payload: []byte("x"),
	})
	if err == nil {
		t.Fatal("the readiness signer signed a non-readiness kind")
	}
}

// A cohort that is NOT ready still produces a valid, signed report — the report
// exports the verdict whatever it is, and a halt is exactly the evidence a
// pilot exists to capture.
func TestNotReadyReportIsStillSignedEvidence(t *testing.T) {
	signer, err := NewArtifactSigner("")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(signer.Destroy)
	c := readyCohort()
	c.Results[1].Outcome = OutcomeRejected // one client refuses the PQ leaf
	report, err := BuildReport("tenant-x", "pqc-lab", c, 1_700_000_000)
	if err != nil {
		t.Fatal(err)
	}
	if !report.Verdict.Halt || report.Verdict.Ready {
		t.Fatalf("a cohort with a rejection must halt and not be ready: %+v", report.Verdict)
	}
	signed, err := SignReport(context.Background(), signer, report, "")
	if err != nil {
		t.Fatal(err)
	}
	if err := signed.Verify(map[string]crypto.PublicKey{signer.KeyID(): signer.Public()}); err != nil {
		t.Fatalf("a halt report must still verify as evidence: %v", err)
	}

	// The signed report round-trips through JSON — it is an export artifact, so
	// it must survive being written and read.
	raw, err := json.Marshal(signed)
	if err != nil {
		t.Fatal(err)
	}
	var back SignedReport
	if err := json.Unmarshal(raw, &back); err != nil {
		t.Fatal(err)
	}
	if err := back.Verify(map[string]crypto.PublicKey{signer.KeyID(): signer.Public()}); err != nil {
		t.Fatalf("the exported report did not verify after a JSON round-trip: %v", err)
	}
}
