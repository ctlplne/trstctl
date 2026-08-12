// SPDX-License-Identifier: MPL-2.0

package relay

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/connector"
	"trstctl.com/trstctl/internal/crypto"
)

func TestTrustDistributionInstallsVerifiesAndRemovesExactAnchorAUD40(t *testing.T) {
	root := t.TempDir()
	trustDir := filepath.Join(root, "trust")
	if err := os.Mkdir(trustDir, 0o700); err != nil {
		t.Fatal(err)
	}
	key, err := crypto.GenerateLockedKey(crypto.ECDSAP256)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(key.Destroy)
	der, err := crypto.SelfSignedCACert(key, "AUD-40 successor root", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	pemBytes := crypto.EncodeCertificatePEM(der)
	fingerprint := crypto.SHA256Hex(der)
	path := filepath.Join(trustDir, "successor.pem")
	profile := connector.LocalOpsConfig{AllowedRoots: []string{root}}

	intent := TrustDistributionIntent{
		RunID: "run-40", WaveID: "canary", IdentityID: "leaf-a", Operation: TrustInstall,
		AnchorPath: path, AnchorPEM: pemBytes, AnchorFingerprint: fingerprint,
	}
	report, err := ExecuteTrustDistribution(context.Background(), profile, intent)
	if err != nil {
		t.Fatalf("install trust: %v", err)
	}
	if report.Verdict != TrustVerified || report.ObservedFingerprint != fingerprint || report.Operation != TrustInstall {
		t.Fatalf("install report = %+v", report)
	}
	got, err := os.ReadFile(path)
	if err != nil || string(got) != string(pemBytes) {
		t.Fatalf("installed anchor = %q err=%v", got, err)
	}

	// Same intent is an idempotent readback. A different anchor at the same path
	// is refused instead of overwritten, because that would erase trust evidence
	// for another run.
	if _, err := ExecuteTrustDistribution(context.Background(), profile, intent); err != nil {
		t.Fatalf("idempotent install: %v", err)
	}
	drifted := intent
	drifted.AnchorFingerprint = crypto.SHA256Hex([]byte("different"))
	if _, err := ExecuteTrustDistribution(context.Background(), profile, drifted); err == nil {
		t.Fatal("install accepted a fingerprint that did not match the anchor")
	}

	remove := intent
	remove.Operation = TrustRemove
	if err := os.WriteFile(path, []byte("foreign-anchor"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := ExecuteTrustDistribution(context.Background(), profile, remove); err == nil {
		t.Fatal("remove deleted a path whose bytes no longer belonged to this run")
	}
	if got, err := os.ReadFile(path); err != nil || string(got) != "foreign-anchor" {
		t.Fatalf("refused removal changed foreign path: %q err=%v", got, err)
	}
	if err := os.WriteFile(path, pemBytes, 0o600); err != nil {
		t.Fatal(err)
	}
	report, err = ExecuteTrustDistribution(context.Background(), profile, remove)
	if err != nil || report.Verdict != TrustVerified || report.Operation != TrustRemove {
		t.Fatalf("remove trust = report=%+v err=%v", report, err)
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatalf("removed anchor remains: %v", err)
	}
	if _, err := ExecuteTrustDistribution(context.Background(), profile, remove); err != nil {
		t.Fatalf("idempotent remove: %v", err)
	}
}

func TestTrustJobRoutesBeforeCredentialRedemptionAndReportsClosedEvidenceAUD40(t *testing.T) {
	root := t.TempDir()
	key, err := crypto.GenerateLockedKey(crypto.ECDSAP256)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(key.Destroy)
	der, _ := crypto.SelfSignedCACert(key, "AUD-40 root", time.Hour)
	anchor := crypto.EncodeCertificatePEM(der)
	intent := TrustDistributionIntent{
		RunID: "run-40", WaveID: "canary", IdentityID: "leaf-a", Operation: TrustInstall,
		AnchorPath: filepath.Join(root, "successor.pem"), AnchorPEM: anchor, AnchorFingerprint: crypto.SHA256Hex(der),
	}
	payload, _ := json.Marshal(intent)
	ch := &trustTestChannel{jobs: []Job{{JobID: 40, Attempt: 1, Kind: KindTrustDistribute, Payload: payload}}}

	if _, err := RunOnceWithHost(context.Background(), ch, nil, connector.LocalOpsConfig{AllowedRoots: []string{root}}, 1, 30); err != nil {
		t.Fatal(err)
	}
	if ch.redeemCalls != 0 {
		t.Fatalf("trust job redeemed credential material %d time(s)", ch.redeemCalls)
	}
	if len(ch.reports) != 1 || ch.reports[0].outcome != OutcomeExecuted || ch.reports[0].detail == "" || ch.reports[0].evidence == "" {
		t.Fatalf("trust receipt = %+v", ch.reports)
	}
	var report TrustDistributionReport
	if err := json.Unmarshal([]byte(ch.reports[0].detail), &report); err != nil || report.Verdict != TrustVerified {
		t.Fatalf("closed trust report = %+v err=%v", report, err)
	}
}

type trustTestChannel struct {
	jobs        []Job
	redeemCalls int
	reports     []trustTestReport
}

type trustTestReport struct {
	outcome  string
	detail   string
	evidence string
}

func (c *trustTestChannel) ClaimJobs(context.Context, []string, int, int) ([]Job, error) {
	return c.jobs, nil
}

func (c *trustTestChannel) RedeemJobCredential(context.Context, int64, int) (map[string][]byte, error) {
	c.redeemCalls++
	return nil, nil
}

func (c *trustTestChannel) ReportJobResult(_ context.Context, _ int64, _ int, outcome, detail, evidence string) (bool, error) {
	c.reports = append(c.reports, trustTestReport{outcome: outcome, detail: detail, evidence: evidence})
	return true, nil
}
