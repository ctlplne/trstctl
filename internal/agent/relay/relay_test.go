// SPDX-License-Identifier: MPL-2.0

package relay_test

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"testing"
	"trstctl.com/trstctl/internal/agent/transport"
	"trstctl.com/trstctl/internal/crypto/tlsprobe"

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
	jobID int64
	// attempt is recorded because the receipt signature commits to it (A1): a
	// relay reporting the wrong generation would produce a receipt the server
	// refuses, and the refusal would look like a forgery rather than a bug.
	attempt int
	outcome string
	detail  string
	// evidence is the probe transcript digest (D2). Recorded because a
	// verification verdict with no evidence behind it is an assertion, not a
	// receipt: the digest is what lets an operator prove the transcript they
	// are reading is the one the agent signed.
	evidence string
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(req *http.Request) (*http.Response, error) { return f(req) }

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

func (f *fakeChannel) ReportJobResult(_ context.Context, jobID int64, attempt int, outcome, detail, evidence string) (bool, error) {
	f.reports = append(f.reports, report{
		jobID: jobID, attempt: attempt, outcome: outcome, detail: detail, evidence: evidence,
	})
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
	// D5 is served from both actual vantages. Keeping only the appliance list
	// here made the console queue Apache/IIS/etc. tests the host binary did not
	// advertise, even though their deploy executor was already present.
	wantTestConnectors := append(append([]string(nil), relay.RelayConnectorKinds()...), relay.HostConnectorKinds()...)
	for _, s := range shipped {
		if s.Kind != relay.KindConnectorTest {
			continue
		}
		if !slices.Equal(s.Connectors, wantTestConnectors) {
			t.Errorf("connector.test advertises %v, want relay and host executors %v", s.Connectors, wantTestConnectors)
		}
		if !slices.Contains(s.Flags, "--host-exec-profile") {
			t.Errorf("connector.test flags = %v, want the host authority boundary named", s.Flags)
		}
	}
	// D4: rollback ships now, for the families whose API can re-bind. The
	// assertion moved from "named as unshipped" to "shipped for exactly the
	// rollback-capable subset" — advertising the rest would take a claim, burn
	// a redemption, and change nothing while a bad certificate kept serving.
	if !kinds[relay.KindConnectorRollback] {
		t.Fatalf("shipped job kinds = %+v, want connector.rollback", shipped)
	}
	if _, ok := relay.UnshippedJobKinds()["connector.rollback"]; ok {
		t.Error("connector.rollback is shipped and must not also be listed as unshipped")
	}
	capable := relay.RollbackExecutableKinds()
	if len(capable) == 0 {
		t.Fatal("no relay connector can roll back; connector.rollback must not be advertised")
	}
	for _, kind := range capable {
		if !relay.Executes(kind) && !relay.ExecutesOnHost(kind) {
			t.Errorf("rollback census names %q, which this agent cannot execute", kind)
		}
	}
	for _, s := range shipped {
		if s.Kind != relay.KindConnectorRollback {
			continue
		}
		if len(s.Connectors) != len(capable) {
			t.Errorf("connector.rollback advertises %v but executable families are %v", s.Connectors, capable)
		}
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

// A host connector's test must be a real, terminal, zero-write preflight on
// the machine that will receive the certificate. The API intentionally queues
// this job without a certificate fingerprint: it is testing the target path,
// not pretending a particular credential was deployed. The old shared runner
// applied the host-deploy rollback identity check before the dry-run branch,
// reported failure, and let the server requeue the same deterministic refusal
// as fast as the agent could poll.
func TestHostDryRunFinishesWithoutDeployIdentityOrMutation(t *testing.T) {
	listener, err := tlsprobe.NewServingTestServer("apache.example.test")
	if err != nil {
		t.Fatalf("start Apache listener: %v", err)
	}
	defer listener.Close()

	root := t.TempDir()
	certPath := filepath.Join(root, "site.crt")
	keyPath := filepath.Join(root, "site.key")
	if err := os.WriteFile(certPath, []byte("bootstrap certificate"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyPath, []byte("bootstrap key"), 0o600); err != nil {
		t.Fatal(err)
	}
	beforeCert := mustReadTempFixture(t, certPath)
	beforeKey := mustReadTempFixture(t, keyPath)

	intent := relay.DeployIntent{
		Connector: "apache",
		Target:    "payments Apache",
		TargetID:  "target-apache-1",
		// Deliberately no Fingerprint or credential.cert_pem/key_pem. A target
		// test is not a deploy and must not manufacture either.
		TargetConfig: mustJSON(t, map[string]any{
			"cert_path":          certPath,
			"key_path":           keyPath,
			"verify_address":     listener.Addr,
			"verify_server_name": "apache.example.test",
		}),
		VerifyAddress:    listener.Addr,
		VerifyServerName: "apache.example.test",
	}
	payload, err := json.Marshal(intent)
	if err != nil {
		t.Fatal(err)
	}
	ch := &fakeChannel{
		jobs: []relay.Job{{JobID: 91, Kind: relay.KindConnectorTest, Attempt: 1, Payload: payload}},
	}
	profile := connector.LocalOpsConfig{
		AllowedRoots: []string{root},
		Actions: []connector.LocalAction{{
			LogicalName: "apachectl", Command: trueCommand(), PassArgs: true,
		}},
	}

	executed, err := relay.RunOnceWithHost(context.Background(), ch, http.DefaultClient, profile, 1, 60)
	if err != nil {
		t.Fatalf("run host dry-run: %v", err)
	}
	if executed != 1 {
		t.Fatalf("executed = %d, want one ready dry-run", executed)
	}
	if ch.redeemed != 0 {
		t.Fatalf("credential redemption calls = %d, want zero because this host target names no management-secret reference", ch.redeemed)
	}
	if len(ch.reports) != 1 || ch.reports[0].outcome != relay.OutcomeExecuted {
		t.Fatalf("reports = %+v, want one terminal executed plan", ch.reports)
	}
	var plan relay.Plan
	if err := json.Unmarshal([]byte(ch.reports[0].detail), &plan); err != nil {
		t.Fatalf("decode host plan: %v", err)
	}
	if !plan.Ready || plan.Endpoint != listener.Addr || len(plan.WouldMutate) < 3 {
		t.Fatalf("host plan = %+v, want reachable ready plan naming file and reload changes", plan)
	}
	afterCert := mustReadTempFixture(t, certPath)
	afterKey := mustReadTempFixture(t, keyPath)
	if string(afterCert) != string(beforeCert) || string(afterKey) != string(beforeKey) {
		t.Fatalf("host dry-run changed target files: cert=%q key=%q", afterCert, afterKey)
	}
}

// A first deployment may target files or a service that is not listening yet.
// verify_address is therefore an optional verification contract, not a
// prerequisite to writing the credential. Preview must disclose the missing
// live check without turning an otherwise executable deployment into a block.
func TestHostDryRunWithoutVerifyAddressPlansButDoesNotClaimLive(t *testing.T) {
	root := t.TempDir()
	certPath := filepath.Join(root, "site.crt")
	keyPath := filepath.Join(root, "site.key")
	if err := os.WriteFile(certPath, []byte("bootstrap certificate"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyPath, []byte("bootstrap key"), 0o600); err != nil {
		t.Fatal(err)
	}
	plan, err := relay.DryRunOnHost(context.Background(), http.DefaultClient,
		connector.LocalOpsConfig{
			AllowedRoots: []string{root},
			Actions: []connector.LocalAction{{
				LogicalName: "apachectl", Command: trueCommand(), PassArgs: true,
			}},
		}, relay.DeployIntent{
			Connector: "apache", Target: "first Apache deployment",
			TargetConfig: mustJSON(t, map[string]string{
				"cert_path": certPath, "key_path": keyPath,
			}),
		}, nil)
	if err != nil {
		t.Fatalf("host dry-run: %v", err)
	}
	if !plan.Ready || plan.Endpoint != "" {
		t.Fatalf("plan = %+v, want executable plan with no claimed listener", plan)
	}
	foundSkipped := false
	for _, step := range plan.Steps {
		if step.Name == "reachability" && step.Status == relay.StepSkipped && strings.Contains(step.Detail, "will not claim") {
			foundSkipped = true
		}
	}
	if !foundSkipped {
		t.Fatalf("plan does not clearly disclose absent live verification: %+v", plan.Steps)
	}
}

// A deterministic local refusal is the ANSWER to a target test, not a reason
// to requeue it forever. Reporting an executed blocked plan makes the outbox
// row terminal while telling the operator exactly which prerequisite is absent.
func TestHostDryRunWithoutOperatorProfileReportsTerminalBlockedPlan(t *testing.T) {
	payload, err := json.Marshal(relay.DeployIntent{
		Connector: "apache", Target: "payments Apache", TargetID: "target-apache-1",
		TargetConfig: mustJSON(t, map[string]string{
			"cert_path": "/srv/apache/site.crt", "key_path": "/srv/apache/site.key",
		}),
	})
	if err != nil {
		t.Fatal(err)
	}
	ch := &fakeChannel{
		jobs: []relay.Job{{JobID: 92, Kind: relay.KindConnectorTest, Attempt: 1, Payload: payload}},
	}

	executed, err := relay.RunOnceWithHost(context.Background(), ch, http.DefaultClient,
		connector.LocalOpsConfig{}, 1, 60)
	if err != nil {
		t.Fatalf("run blocked host dry-run: %v", err)
	}
	if executed != 0 {
		t.Fatalf("executed = %d, want blocked plan", executed)
	}
	if ch.redeemed != 0 {
		t.Fatalf("blocked host test redeemed %d time(s); an absent operator authority must be refused before redemption", ch.redeemed)
	}
	if len(ch.reports) != 1 || ch.reports[0].outcome != relay.OutcomeExecuted {
		t.Fatalf("reports = %+v, want one terminal executed blocked plan", ch.reports)
	}
	var plan relay.Plan
	if err := json.Unmarshal([]byte(ch.reports[0].detail), &plan); err != nil {
		t.Fatalf("decode blocked host plan: %v", err)
	}
	if plan.Ready {
		t.Fatalf("missing operator profile reported ready: %+v", plan)
	}
	found := false
	for _, step := range plan.Steps {
		if step.Name == "host-authority" && step.Status == relay.StepFailed && strings.Contains(step.Detail, "host exec profile") {
			found = true
		}
	}
	if !found {
		t.Fatalf("blocked plan does not name the missing host authority: %+v", plan.Steps)
	}
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

// AUD-33: E1's product denominator and the relay binary's executable set are
// different facts. Migrated and architecture-exception appliance families have
// relay constructors today; the six unimplemented E1 families must stay
// visible in ParityProgram without being advertised by this executor.
func TestE1DispositionMatchesTheAgentExecutorsThatActuallyShip(t *testing.T) {
	for _, status := range connector.ParityProgram() {
		executes := relay.Executes(status.Family)
		switch status.Disposition {
		case connector.ParityDispositionMigrated, connector.ParityDispositionArchitectureException:
			if !executes {
				t.Errorf("%s is %s but the network-relay binary has no constructor", status.Family, status.Disposition)
			}
		case connector.ParityDispositionUnimplemented:
			if executes {
				t.Errorf("%s is classified unimplemented but the relay advertises it", status.Family)
			}
		default:
			t.Errorf("%s has unknown E1 disposition %q", status.Family, status.Disposition)
		}
	}
}

// Envoy is host-vantage even though its local side effect is HTTP: the SDS
// management socket is co-resident and commonly loopback-only. Prove the agent
// carries that fourteenth constructor and uses its own client without asking
// for an unrelated filesystem/exec grant.
func TestHostExecutorDeploysToCoResidentEnvoy(t *testing.T) {
	puts := 0
	client := &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
		status := http.StatusNotFound
		switch r.Method {
		case http.MethodGet:
		case http.MethodPut:
			puts++
			status = http.StatusNoContent
		default:
			status = http.StatusMethodNotAllowed
		}
		return &http.Response{StatusCode: status, Body: io.NopCloser(strings.NewReader("")), Header: make(http.Header)}, nil
	})}
	config, err := json.Marshal(map[string]string{"endpoint": "http://127.0.0.1:9901", "secret_name": "edge-cert"})
	if err != nil {
		t.Fatal(err)
	}
	stats, err := relay.ExecuteOnHost(context.Background(), connector.LocalOpsConfig{}, relay.DeployIntent{
		Connector: "envoy", Target: "edge", TargetConfig: config, Fingerprint: "sha256:edge",
	}, map[string][]byte{
		"credential.cert_pem": []byte(testCertPEM),
		"credential.key_pem":  []byte(testKeyPEM),
	}, client)
	if err != nil {
		t.Fatalf("ExecuteOnHost(envoy): %v", err)
	}
	if puts != 1 || stats.Denied != 0 {
		t.Fatalf("envoy requests: puts=%d stats=%+v, want one permitted update", puts, stats)
	}
}

func TestHostExecutorRefusesNonLoopbackEnvoyEndpointBeforeIO(t *testing.T) {
	requests := 0
	client := &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
		requests++
		return nil, errors.New("request must not run")
	})}
	config, err := json.Marshal(map[string]string{"endpoint": "https://envoy.remote.example", "secret_name": "edge-cert"})
	if err != nil {
		t.Fatal(err)
	}
	_, err = relay.ExecuteOnHost(context.Background(), connector.LocalOpsConfig{}, relay.DeployIntent{
		Connector: "envoy", Target: "edge", TargetConfig: config,
	}, map[string][]byte{
		"credential.cert_pem": []byte(testCertPEM),
		"credential.key_pem":  []byte(testKeyPEM),
	}, client)
	if err == nil || !strings.Contains(err.Error(), "loopback") {
		t.Fatalf("ExecuteOnHost(remote envoy) error = %v, want loopback refusal", err)
	}
	if requests != 0 {
		t.Fatalf("remote Envoy endpoint received %d HTTP requests, want zero", requests)
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

// TestSweepRefusesReservedRangesByDefault is C2's safety property. The
// reserved-range guard is not a control-plane policy a relay escapes by moving
// the scan: it lives in the scanner, so it travels with it.
func TestSweepRefusesReservedRangesByDefault(t *testing.T) {
	report, err := relay.Sweep(context.Background(), relay.DiscoveryScanIntent{
		Mode:    relay.DiscoveryModeTLS,
		Targets: []string{"127.0.0.1:443"},
	})
	if err != nil {
		t.Fatalf("sweep: %v", err)
	}
	if report.Blocked == 0 {
		t.Fatal("a loopback target was not blocked; the reserved-range guard did not travel with the scanner")
	}
	if len(report.Findings) != 0 {
		t.Fatalf("a blocked sweep produced %d findings", len(report.Findings))
	}
	// Blocked must be visible rather than presenting as an empty segment: an
	// operator who scanned the wrong range should see a refusal.
	if report.Targets == 0 {
		t.Error("the sweep reported no attempted targets, so a refusal reads as an empty segment")
	}
}

// TestSweepNeedsTargetsAndAKnownMode: an empty sweep reporting success would be
// a green discovery dashboard for a segment nobody scanned.
func TestSweepNeedsTargetsAndAKnownMode(t *testing.T) {
	if _, err := relay.Sweep(context.Background(), relay.DiscoveryScanIntent{
		Mode: relay.DiscoveryModeTLS,
	}); err == nil {
		t.Fatal("a sweep with no targets succeeded")
	}
	if _, err := relay.Sweep(context.Background(), relay.DiscoveryScanIntent{
		Mode: "portscan", Targets: []string{"10.0.0.1"},
	}); err == nil {
		t.Fatal("an unknown sweep mode was accepted")
	}
}

// TestSweepFindsWhatASegmentServes proves the sweep actually collects, against
// a real TLS listener — otherwise the guard tests above would pass on a scanner
// that found nothing ever.
func TestSweepFindsWhatASegmentServes(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {}))
	defer srv.Close()
	addr := strings.TrimPrefix(srv.URL, "https://")

	report, err := relay.Sweep(context.Background(), relay.DiscoveryScanIntent{
		Mode:    relay.DiscoveryModeTLS,
		Targets: []string{addr},
		// The listener is on loopback, which is exactly what the guard refuses —
		// so the lab escape hatch is what makes this testable, and its existence
		// is the reason the guard test above matters.
		AllowReservedRanges: true,
	})
	if err != nil {
		t.Fatalf("sweep: %v", err)
	}
	if report.Discovered == 0 || len(report.Findings) == 0 {
		t.Fatalf("the sweep found nothing against a live TLS listener: %+v", report)
	}
	if report.Findings[0].Fingerprint == "" {
		t.Error("a finding carries no fingerprint, so it cannot be reconciled with the inventory")
	}
}

// Kill the reload and verification catches it (epic D2 acceptance).
//
// This is the criterion the epic is written around, and it is the failure the
// rest of the pipeline structurally cannot see. A connector's reload is one
// exec call inside its own Deploy method; when it does not take effect the
// connector still returns success, the delivery receipt still says delivered,
// and the inventory still says the new certificate exists — all of which are
// TRUE. The listener is simply still serving the old one, and only a handshake
// can say so.
//
// The test models exactly that: the deploy runs and succeeds, and the listener
// keeps presenting a different certificate, because nothing reloaded it.
func TestAKilledReloadIsCaughtByPostDeployVerification(t *testing.T) {
	// The listener, still on its old certificate.
	stale, err := tlsprobe.NewServingTestServer("api.example.test")
	if err != nil {
		t.Fatalf("start stale listener: %v", err)
	}
	defer stale.Close()

	// The certificate the deploy delivers. A different one for the same name —
	// which is what a renewal produces.
	fresh, err := tlsprobe.NewServingTestServer("api.example.test")
	if err != nil {
		t.Fatalf("mint the deployed certificate: %v", err)
	}
	defer fresh.Close()

	dir := t.TempDir()
	ch := &fakeChannel{
		jobs: []relay.Job{intentJob(t, 1, relay.DeployIntent{
			Connector:      "nginx",
			Target:         "edge",
			CredentialRefs: []string{"credential.cert_pem", "credential.key_pem"},
			TargetConfig: mustJSON(t, map[string]string{
				"cert_path": filepath.Join(dir, "server.crt"),
				"key_path":  filepath.Join(dir, "server.key"),
			}),
			// The operator told us where the listener is. Without this there is
			// no verification at all — and no claim of one.
			VerifyAddress: stale.Addr,
		})},
		material: map[string][]byte{
			"credential.cert_pem": fresh.LeafPEM,
			"credential.key_pem":  []byte(testKeyPEM),
		},
	}

	_, _ = relay.RunOnceWithHost(context.Background(), ch, http.DefaultClient,
		hostProfileForNginx(t, dir), 1, 30)

	if len(ch.reports) != 1 {
		t.Fatalf("got %d reports, want 1: %+v", len(ch.reports), ch.reports)
	}
	got := ch.reports[0]
	if got.outcome != transport.OutcomeVerifyFailed {
		t.Fatalf("outcome = %q, want %q — the files landed and the listener is still serving the "+
			"old certificate, which every other record in the pipeline reports as a clean deploy",
			got.outcome, transport.OutcomeVerifyFailed)
	}
	// verify_failed is deliberately NOT plain failure: the deploy applied, so a
	// rollback is the right response, whereas rolling back a deploy that never
	// applied would undo something that was never done.
	if got.outcome == relay.OutcomeFailed {
		t.Error("a verification failure was reported as a deploy failure")
	}
	if got.evidence == "" {
		t.Error("no probe transcript digest accompanied the verdict; the receipt would commit " +
			"to nothing and the verdict would be a bare assertion")
	}
	if !strings.Contains(got.detail, "different certificate") {
		t.Errorf("detail = %q; it must say what the listener is actually serving", got.detail)
	}
}

// The same deploy against a listener that DID reload verifies, and says so with
// evidence behind it.
func TestAReloadedListenerVerifiesWithEvidence(t *testing.T) {
	served, err := tlsprobe.NewServingTestServer("api.example.test")
	if err != nil {
		t.Fatalf("start listener: %v", err)
	}
	defer served.Close()

	dir := t.TempDir()
	ch := &fakeChannel{
		jobs: []relay.Job{intentJob(t, 2, relay.DeployIntent{
			Connector:      "nginx",
			Target:         "edge",
			CredentialRefs: []string{"credential.cert_pem", "credential.key_pem"},
			TargetConfig: mustJSON(t, map[string]string{
				"cert_path": filepath.Join(dir, "server.crt"),
				"key_path":  filepath.Join(dir, "server.key"),
			}),
			VerifyAddress: served.Addr,
		})},
		material: map[string][]byte{
			// The listener is serving exactly this.
			"credential.cert_pem": served.LeafPEM,
			"credential.key_pem":  []byte(testKeyPEM),
		},
	}

	_, _ = relay.RunOnceWithHost(context.Background(), ch, http.DefaultClient,
		hostProfileForNginx(t, dir), 1, 30)

	if len(ch.reports) != 1 {
		t.Fatalf("got %d reports, want 1: %+v", len(ch.reports), ch.reports)
	}
	if got := ch.reports[0]; got.outcome != transport.OutcomeVerified {
		t.Fatalf("outcome = %q, want %q (detail: %s)", got.outcome, transport.OutcomeVerified, got.detail)
	}
	if ch.reports[0].evidence == "" {
		t.Error("a passing verification carried no transcript digest")
	}
}

// A deploy with no configured listener address reports plain success and
// claims NO verification.
//
// This is the honesty rule that makes the whole surface trustworthy. An
// operator who has not told us where the listener is gets "deployed", not
// "verified" — because the alternative, treating an absent address as nothing
// to check and therefore fine, is the same overclaim the epic exists to remove.
func TestNoListenerAddressYieldsNoVerificationClaim(t *testing.T) {
	dir := t.TempDir()
	ch := &fakeChannel{
		jobs: []relay.Job{intentJob(t, 3, relay.DeployIntent{
			Connector:      "nginx",
			Target:         "edge",
			CredentialRefs: []string{"credential.cert_pem", "credential.key_pem"},
			TargetConfig: mustJSON(t, map[string]string{
				"cert_path": filepath.Join(dir, "server.crt"),
				"key_path":  filepath.Join(dir, "server.key"),
			}),
		})},
		material: map[string][]byte{
			"credential.cert_pem": []byte(testCertPEM),
			"credential.key_pem":  []byte(testKeyPEM),
		},
	}

	_, _ = relay.RunOnceWithHost(context.Background(), ch, http.DefaultClient,
		hostProfileForNginx(t, dir), 1, 30)

	if len(ch.reports) != 1 {
		t.Fatalf("got %d reports, want 1: %+v", len(ch.reports), ch.reports)
	}
	got := ch.reports[0]
	if got.outcome != relay.OutcomeExecuted {
		t.Fatalf("outcome = %q, want %q — an unverifiable deploy must report what it did, not "+
			"what it did not check", got.outcome, relay.OutcomeExecuted)
	}
	if got.outcome == transport.OutcomeVerified {
		t.Error("a deploy with no listener address claimed verification")
	}
	if got.evidence != "" {
		t.Error("a deploy that ran no probe carried a transcript digest")
	}
}

func mustJSON(t *testing.T, v any) json.RawMessage {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func mustReadTempFixture(t *testing.T, path string) []byte {
	t.Helper()
	b, err := os.ReadFile(path) // #nosec G304 -- callers pass paths created inside this test package's t.TempDir fixtures (CWE-22).
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// hostProfileForNginx binds nginx's two exec calls to a harmless command.
//
// The connector's own Deploy runs `nginx -t` then `nginx -s reload`. Binding
// them to /bin/true is what makes "the deploy succeeded" true in the test while
// leaving the listener untouched — which is precisely the production failure
// being modelled: the reload ran, or claimed to, and the process kept serving
// what it had.
func hostProfileForNginx(t *testing.T, root string) connector.LocalOpsConfig {
	t.Helper()
	return connector.LocalOpsConfig{
		AllowedRoots: []string{root},
		Actions: []connector.LocalAction{
			{LogicalName: "nginx", Command: trueCommand(), PassArgs: false},
		},
	}
}

// trueCommand is a command that exits 0 and does nothing.
func trueCommand() string {
	if runtime.GOOS == "windows" {
		return "cmd"
	}
	return "/usr/bin/true"
}
