// SPDX-License-Identifier: MPL-2.0

package relay_test

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"trstctl.com/trstctl/internal/agent/relay"
	"trstctl.com/trstctl/internal/connector"
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
	kinds := map[string]bool{}
	for _, s := range shipped {
		kinds[s.Kind] = true
		if len(s.Flags) == 0 {
			t.Errorf("shipped kind %q needs a flag and must name it, or it reads as coverage that is not running", s.Kind)
		}
		// Connector work must name its connectors; a revocation probe drives
		// none and must not pretend otherwise.
		if strings.HasPrefix(s.Kind, "connector.") && len(s.Connectors) == 0 {
			t.Errorf("connector kind %q declares no connectors", s.Kind)
		}
	}
	if !kinds["connector.deploy"] || !kinds[relay.KindConnectorTest] {
		t.Fatalf("shipped job kinds = %+v, want connector.deploy and connector.test", shipped)
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

// TestDryRunNeverMutatesAndNamesTheCause is D5's acceptance, both halves at
// once: against a healthy target it returns the mutation plan, against a broken
// one it names the specific cause — and in neither case does it write.
func TestDryRunNeverMutatesAndNamesTheCause(t *testing.T) {
	var writes int
	healthy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			writes++
		}
		// A management API answering 401 to a bare GET is the normal case, and
		// must not read as unreachable.
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer healthy.Close()

	material := map[string][]byte{
		"credential.cert_pem":      []byte(testCertPEM),
		"credential.key_pem":       []byte(testKeyPEM),
		"secret://appliance-admin": []byte(appliancePassword),
	}
	config := func(endpoint string) []byte {
		raw, err := json.Marshal(map[string]string{ // #nosec G101 -- reference NAME, not a credential (CWE-798)
			"endpoint":     endpoint,
			"username":     "admin",
			"password_ref": "secret://appliance-admin",
			"object_name":  "edge-cert",
		})
		if err != nil {
			t.Fatal(err)
		}
		return raw
	}

	plan, err := relay.DryRun(context.Background(), healthy.Client(), relay.DeployIntent{
		Connector: "f5", Target: "edge-f5", TargetConfig: config(healthy.URL),
	}, material)
	if err != nil {
		t.Fatalf("dry-run: %v", err)
	}
	if !plan.Ready {
		t.Fatalf("healthy target is not ready: %+v", plan.Steps)
	}
	if len(plan.WouldMutate) == 0 {
		t.Error("a ready plan must say what a real deploy would change")
	}
	if writes != 0 {
		t.Fatalf("the dry-run made %d non-GET requests; zero writes is the whole point", writes)
	}

	// Unreachable: a specific cause, not "test failed".
	closed := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	closedURL := closed.URL
	closed.Close()
	broken, err := relay.DryRun(context.Background(), healthy.Client(), relay.DeployIntent{
		Connector: "f5", Target: "edge-f5", TargetConfig: config(closedURL),
	}, material)
	if err != nil {
		t.Fatalf("dry-run against a closed target returned a transport error instead of a plan: %v", err)
	}
	if broken.Ready {
		t.Fatal("an unreachable target reported ready")
	}
	if len(broken.WouldMutate) != 0 {
		t.Error("a plan that cannot run must not describe mutations it would make")
	}
	var reach relay.PlanStep
	for _, step := range broken.Steps {
		if step.Name == "reachability" {
			reach = step
		}
	}
	if reach.Status != relay.StepFailed || reach.Detail == "" {
		t.Fatalf("reachability step = %+v, want a failure naming the cause", reach)
	}
}

// TestDryRunFailsOnAnUnredeemedCredential: the test must not pass on a
// credential set the deploy after it would reject.
func TestDryRunFailsOnAnUnredeemedCredential(t *testing.T) {
	raw, err := json.Marshal(map[string]string{ // #nosec G101 -- reference NAME (CWE-798)
		"endpoint":     "https://f5.example.internal",
		"username":     "admin",
		"password_ref": "secret://appliance-admin",
	})
	if err != nil {
		t.Fatal(err)
	}
	plan, err := relay.DryRun(context.Background(), http.DefaultClient, relay.DeployIntent{
		Connector: "f5", Target: "edge-f5", TargetConfig: raw,
	}, map[string][]byte{"credential.cert_pem": []byte(testCertPEM)})
	if err != nil {
		t.Fatalf("dry-run: %v", err)
	}
	if plan.Ready {
		t.Fatal("dry-run passed with an unredeemed credential reference")
	}
	for _, step := range plan.Steps {
		if step.Name == "credentials" && step.Status == relay.StepFailed {
			if strings.Contains(step.Detail, appliancePassword) {
				t.Fatal("the credentials step leaked a credential value")
			}
			return
		}
	}
	t.Fatal("no failed credentials step in the plan")
}

// TestHostProfileRefusesToDefaultOpen is D1's security property. A host executor
// that fell back to "any command" on a missing or empty profile would be the
// most dangerous failure mode available, and one an operator would not discover
// until it mattered.
func TestHostProfileRefusesToDefaultOpen(t *testing.T) {
	dir := t.TempDir()
	empty := filepath.Join(dir, "empty.json")
	if err := os.WriteFile(empty, []byte(`{"allowed_roots":[],"actions":[]}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := relay.LoadHostProfile(empty); err == nil {
		t.Fatal("a profile with no allowed roots was accepted")
	}
	if _, err := relay.LoadHostProfile(filepath.Join(dir, "missing.json")); err == nil {
		t.Fatal("a missing profile was accepted")
	}
	bad := filepath.Join(dir, "bad.json")
	if err := os.WriteFile(bad, []byte(`{"allowed_roots":["/tmp"],"actions":[{"logical_name":"reload"}]}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := relay.LoadHostProfile(bad); err == nil {
		t.Fatal("an action with no command was accepted")
	}
}

// TestHostExecutorRefusesWorkItCannotDo keeps the two vantages from bleeding
// into each other: a host agent handed appliance work refuses it rather than
// attempting a filesystem deploy against an F5.
func TestHostExecutorRefusesWorkItCannotDo(t *testing.T) {
	for _, name := range relay.HostConnectorKinds() {
		if !relay.ExecutesOnHost(name) {
			t.Errorf("declared host connector %q is not host-executable", name)
		}
		if relay.Executes(name) {
			t.Errorf("%q is claimed by BOTH the host and relay executors; one job must have one executor", name)
		}
	}
	for _, name := range relay.RelayConnectorKinds() {
		if relay.ExecutesOnHost(name) {
			t.Errorf("appliance connector %q is claimed by the host executor", name)
		}
	}
	if _, err := relay.ExecuteOnHost(context.Background(),
		connectorLocalOpsForTest(t), relay.DeployIntent{Connector: "f5", Target: "edge"},
		map[string][]byte{"credential.cert_pem": []byte(testCertPEM), "credential.key_pem": []byte(testKeyPEM)},
	); err == nil {
		t.Fatal("the host executor accepted appliance work")
	}
}

func connectorLocalOpsForTest(t *testing.T) connector.LocalOpsConfig {
	t.Helper()
	return connector.LocalOpsConfig{AllowedRoots: []string{t.TempDir()}}
}

// TestRevocationProbeDistinguishesItsFailures is R1's point. "Unreachable",
// "stale", and "answered but not a CRL" are three different problems needing
// three different people, and a probe that reported them alike would be worse
// than none — it would send operators confidently to the wrong place.
func TestRevocationProbeDistinguishesItsFailures(t *testing.T) {
	// A proxy or captive portal returning HTML with a 200. This is the case
	// that looks like success to anything checking only the status code.
	html := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("<html><body>Authentication required</body></html>"))
	}))
	defer html.Close()

	notFound := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer notFound.Close()

	dead := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	deadURL := dead.URL
	dead.Close()

	report, err := relay.ProbeRevocation(context.Background(), html.Client(), relay.RevocationProbeIntent{
		Endpoints: []string{html.URL, notFound.URL, deadURL, "ldap://pki.corp.internal/cn=crl", "not a url at all"},
	})
	if err != nil {
		t.Fatalf("probe: %v", err)
	}
	if report.Healthy {
		t.Fatal("a report full of broken endpoints claimed healthy")
	}
	byEndpoint := map[string]relay.RevocationFinding{}
	for _, f := range report.Findings {
		byEndpoint[f.Endpoint] = f
	}
	if got := byEndpoint[html.URL].Status; got != relay.RevocationUnparseable {
		t.Errorf("a 200 of HTML classified %q, want unparseable — this is the captive-portal case", got)
	}
	if got := byEndpoint[notFound.URL].Status; got != relay.RevocationUnreachable {
		t.Errorf("HTTP 404 classified %q, want unreachable", got)
	}
	if got := byEndpoint[deadURL].Status; got != relay.RevocationUnreachable {
		t.Errorf("a closed port classified %q, want unreachable", got)
	}
	// An LDAP CDP is real in AD CS estates. Saying it is not fetchable beats
	// reporting it unreachable, which sends someone to check a network path that
	// was never the problem.
	if got := byEndpoint["ldap://pki.corp.internal/cn=crl"].Status; got != relay.RevocationUnparseable {
		t.Errorf("an LDAP CDP classified %q, want unparseable with a scheme explanation", got)
	}
	// Every endpoint is probed even after one fails: an operator needs the whole
	// picture, not the first problem.
	if len(report.Findings) != 5 {
		t.Fatalf("probed %d of 5 endpoints; a failure must not stop the sweep", len(report.Findings))
	}
}

// TestRevocationProbeDedupesEndpoints: one CA's CDP is named by every
// certificate it issued. Probing the raw list would be monitoring that causes
// the outage it watches for.
func TestRevocationProbeDedupesEndpoints(t *testing.T) {
	var hits int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		hits++
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()

	repeated := make([]string, 0, 50)
	for i := 0; i < 50; i++ {
		repeated = append(repeated, srv.URL)
	}
	report, err := relay.ProbeRevocation(context.Background(), srv.Client(), relay.RevocationProbeIntent{
		Endpoints: repeated,
	})
	if err != nil {
		t.Fatalf("probe: %v", err)
	}
	if len(report.Findings) != 1 {
		t.Fatalf("50 copies of one endpoint produced %d findings, want 1", len(report.Findings))
	}
	if hits != 1 {
		t.Fatalf("the probe hit the endpoint %d times, want 1", hits)
	}
}

// TestRevocationProbeNeedsEndpoints: an empty probe reporting healthy would be
// the worst possible answer — a green revocation dashboard for an estate nobody
// checked.
func TestRevocationProbeNeedsEndpoints(t *testing.T) {
	if _, err := relay.ProbeRevocation(context.Background(), http.DefaultClient,
		relay.RevocationProbeIntent{}); err == nil {
		t.Fatal("a probe with no endpoints succeeded; an empty green report is worse than none")
	}
}
