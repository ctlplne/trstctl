// SPDX-License-Identifier: MPL-2.0

package relay_test

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"trstctl.com/trstctl/internal/agent/relay"
)

// The relay executor's contract (epic A3). What matters here is not that a
// deploy succeeds — the connector packages own that — but that the relay never
// redeems a credential it cannot use, never forwards what a target echoes back,
// and never leaves material alive after an attempt.

const (
	// A password that no redactor and no entropy floor recognizes. It is the
	// shape that actually leaks in practice.
	appliancePassword = "hunter2-lab"
	testKeyPEM        = "-----BEGIN PRIVATE KEY-----\nMIIEvQIBADANBgkq\n-----END PRIVATE KEY-----"
	testCertPEM       = "-----BEGIN CERTIFICATE-----\nZmFrZQ==\n-----END CERTIFICATE-----"
)

// fakeChannel records what the relay asked for and what it reported.
type fakeChannel struct {
	jobs      []relay.Job
	redeemed  int
	redeemErr error
	material  map[string][]byte
	reports   []report
}

type report struct {
	jobID   int64
	outcome string
	detail  string
}

func (f *fakeChannel) ClaimJobs(context.Context, []string, int, int) ([]relay.Job, error) {
	return f.jobs, nil
}

func (f *fakeChannel) RedeemJobCredential(context.Context, int64, int) (map[string][]byte, error) {
	f.redeemed++
	if f.redeemErr != nil {
		return nil, f.redeemErr
	}
	// Fresh copies: AdoptMaterial wipes what it is handed, so returning the same
	// backing arrays twice would hand out zeroes the second time.
	out := make(map[string][]byte, len(f.material))
	for name, value := range f.material {
		out[name] = append([]byte(nil), value...)
	}
	return out, nil
}

func (f *fakeChannel) ReportJobResult(_ context.Context, jobID int64, outcome, detail, _ string) (bool, error) {
	f.reports = append(f.reports, report{jobID: jobID, outcome: outcome, detail: detail})
	return true, nil
}

func intentJob(t *testing.T, jobID int64, intent relay.DeployIntent) relay.Job {
	t.Helper()
	payload, err := json.Marshal(intent)
	if err != nil {
		t.Fatal(err)
	}
	return relay.Job{JobID: jobID, Kind: "connector.deploy", Attempt: 1, Payload: payload}
}

// TestRelayRefusesUnexecutableWorkBeforeRedeeming is the ordering that matters
// most: a credential redeemed for an attempt that was never going to run is
// material outside the seal for nothing, and it burns the attempt's one
// redemption so no other agent can take the work either.
func TestRelayRefusesUnexecutableWorkBeforeRedeeming(t *testing.T) {
	ch := &fakeChannel{
		jobs: []relay.Job{intentJob(t, 1, relay.DeployIntent{
			// nginx is host-local work; it should never reach a relay, and if it
			// does, the relay refuses rather than trusting the claim gate.
			Connector: "nginx", Target: "web-1",
		})},
		material: map[string][]byte{"credential.key_pem": []byte(testKeyPEM)},
	}
	executed, err := relay.RunOnce(context.Background(), ch, http.DefaultClient, 4, 60)
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	if executed != 0 {
		t.Fatalf("executed %d jobs, want 0", executed)
	}
	if ch.redeemed != 0 {
		t.Fatalf("relay redeemed %d credentials for work it cannot execute, want 0", ch.redeemed)
	}
	if len(ch.reports) != 1 || ch.reports[0].outcome != relay.OutcomeFailed {
		t.Fatalf("reports = %+v, want one failure", ch.reports)
	}
}

// TestRelayNeverForwardsWhatTheTargetEchoes: a real appliance can put the
// credential it was just handed into its error body. The relay reports a closed
// phrase and keeps the target's words local.
func TestRelayNeverForwardsWhatTheTargetEchoes(t *testing.T) {
	hostile := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		// The hostile echo: the appliance replies with the credential.
		_, _ = w.Write([]byte("auth failed for password " + appliancePassword + " key " + testKeyPEM))
	}))
	defer hostile.Close()

	targetConfig, err := json.Marshal(map[string]string{ // #nosec G101 -- "password_ref" is a reference NAME the test asserts on, not a credential (CWE-798)
		"endpoint":     hostile.URL,
		"username":     "admin",
		"password_ref": "secret://appliance-admin",
	})
	if err != nil {
		t.Fatal(err)
	}
	ch := &fakeChannel{
		jobs: []relay.Job{intentJob(t, 7, relay.DeployIntent{
			Connector: "f5", Target: "edge-f5", TargetConfig: targetConfig, Fingerprint: "ff00",
		})},
		material: map[string][]byte{
			"credential.cert_pem":      []byte(testCertPEM),
			"credential.key_pem":       []byte(testKeyPEM),
			"secret://appliance-admin": []byte(appliancePassword),
		},
	}
	if _, err := relay.RunOnce(context.Background(), ch, hostile.Client(), 4, 60); err != nil {
		t.Fatalf("run: %v", err)
	}
	if ch.redeemed != 1 {
		t.Fatalf("relay redeemed %d times, want exactly 1", ch.redeemed)
	}
	if len(ch.reports) != 1 {
		t.Fatalf("reports = %+v, want one", ch.reports)
	}
	got := ch.reports[0]
	if got.outcome != relay.OutcomeFailed {
		t.Fatalf("outcome = %q, want failed", got.outcome)
	}
	for _, canary := range []string{appliancePassword, testKeyPEM, hostile.URL} {
		if strings.Contains(got.detail, canary) {
			t.Fatalf("reported detail leaked %q: %q", canary, got.detail)
		}
	}
}

// TestRelayRefusesWhenARequiredReferenceWasNotRedeemed: deploying with no
// password would either fail confusingly or, worse, succeed against an
// unauthenticated appliance.
func TestRelayRefusesWhenARequiredReferenceWasNotRedeemed(t *testing.T) {
	targetConfig, err := json.Marshal(map[string]string{ // #nosec G101 -- "password_ref" is a reference NAME the test asserts on, not a credential (CWE-798)
		"endpoint":     "https://f5.example.internal",
		"username":     "admin",
		"password_ref": "secret://appliance-admin",
	})
	if err != nil {
		t.Fatal(err)
	}
	material := map[string][]byte{
		"credential.cert_pem": []byte(testCertPEM),
		"credential.key_pem":  []byte(testKeyPEM),
		// The password reference is deliberately absent.
	}
	if _, err := relay.Execute(context.Background(), http.DefaultClient, relay.DeployIntent{
		Connector: "f5", Target: "edge-f5", TargetConfig: targetConfig,
	}, material); err == nil {
		t.Fatal("relay executed a deploy with an unredeemed credential reference")
	}
}

// TestAdoptMaterialWipesTheWireCopy: the values that arrive over the channel are
// ordinary heap bytes. Adoption moves them into locked buffers and wipes the
// originals, so the only surviving copy is the one that gets destroyed.
func TestAdoptMaterialWipesTheWireCopy(t *testing.T) {
	wire := []byte(appliancePassword)
	items := map[string][]byte{"secret://appliance-admin": wire}

	material, destroy, err := relay.AdoptMaterial(items)
	if err != nil {
		t.Fatalf("adopt: %v", err)
	}
	if string(material["secret://appliance-admin"]) != appliancePassword {
		t.Fatal("adopted material does not carry the value")
	}
	if strings.Contains(string(wire), appliancePassword) {
		t.Fatal("the wire copy still holds the credential after adoption")
	}
	destroy()
}

// TestRelayExecutesOnlyItsDeclaredConnectors keeps the shipped census and the
// executor from drifting: every declared kind must build, and nothing outside
// the census may.
func TestRelayExecutesOnlyItsDeclaredConnectors(t *testing.T) {
	for _, kind := range relay.RelayConnectorKinds() {
		if !relay.Executes(kind) {
			t.Errorf("declared relay connector %q is not executable", kind)
		}
	}
	for _, kind := range []string{"nginx", "apache", "aws-acm", "azure-keyvault", "envoy", ""} {
		if relay.Executes(kind) {
			t.Errorf("relay claims it can execute %q, which is not relay work", kind)
		}
	}
	shipped := relay.ShippedJobKinds()
	if len(shipped) != 1 || shipped[0].Kind != "connector.deploy" {
		t.Fatalf("shipped job kinds = %+v, want exactly connector.deploy", shipped)
	}
	if len(shipped[0].Flags) == 0 {
		t.Error("a shipped kind that needs a flag must name it, or it reads as coverage that is not running")
	}
	if _, ok := relay.UnshippedJobKinds()["connector.rollback"]; !ok {
		t.Error("connector.rollback must be named as unshipped with its reason")
	}
}

// TestRelayReportsADeniedCapabilityAsFailure: the sandbox refusing an operation
// is a capability-declaration bug, and it must not read as a clean deploy.
func TestRelayReportsADeniedCapabilityAsFailure(t *testing.T) {
	ch := &fakeChannel{
		jobs:      []relay.Job{intentJob(t, 9, relay.DeployIntent{Connector: "f5", Target: "t"})},
		redeemErr: errors.New("redemption refused"),
	}
	if _, err := relay.RunOnce(context.Background(), ch, http.DefaultClient, 4, 60); err != nil {
		t.Fatalf("run: %v", err)
	}
	if len(ch.reports) != 1 || ch.reports[0].outcome != relay.OutcomeFailed {
		t.Fatalf("reports = %+v, want one failure", ch.reports)
	}
	if strings.Contains(ch.reports[0].detail, "redemption refused") {
		t.Fatal("the relay forwarded the redemption error text instead of a closed phrase")
	}
}
