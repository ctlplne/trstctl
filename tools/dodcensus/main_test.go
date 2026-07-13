// SPDX-License-Identifier: MPL-2.0

package main

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"go/ast"
	"go/build"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	internalcrypto "trstctl.com/trstctl/internal/crypto"
)

type scriptedRunner struct {
	results []commandResult
	calls   []commandCall
	hook    func(commandCall)
}

func (r *scriptedRunner) PrepareRuntime(_ context.Context, _ string, profile BuildProfile) (BuildProfile, error) {
	profile.RuntimeRunnerImage = "sha256:" + strings.Repeat("a", 64)
	return profile, nil
}

func (r *scriptedRunner) Run(_ context.Context, dir string, profile BuildProfile, name string, args ...string) commandResult {
	call := commandCall{Dir: dir, Profile: profile, Name: name, Args: append([]string(nil), args...)}
	r.calls = append(r.calls, call)
	if r.hook != nil {
		r.hook(call)
	}
	if len(r.results) == 0 {
		return commandResult{Err: os.ErrNotExist}
	}
	result := r.results[0]
	r.results = r.results[1:]
	return result
}

func TestPlannedRequiredProfileStaysRedAndNeverExecutes(t *testing.T) {
	repo := t.TempDir()
	writeGateFixture(t, repo, false)
	manifest := validManifest(t, repo, enforcementRequired)
	planned := manifest.BuildProfiles["static"]
	planned.Release = releasePlanned
	planned.Artifact = ArtifactProof{}
	manifest.BuildProfiles["static"] = planned
	runner := &scriptedRunner{}

	report, err := evaluate(context.Background(), repo, manifest, runner, selection{})
	if err != nil {
		t.Fatalf("evaluate planned profile: %v", err)
	}
	entry := report.Entries["connector.nginx"]
	if entry.Status != statusLibraryOnly || report.Summary.RequiredFailed != 1 {
		t.Fatalf("planned required profile escaped red: status=%q summary=%+v evidence=%+v", entry.Status, report.Summary, entry.Evidence)
	}
	if len(runner.calls) != 0 {
		t.Fatalf("planned profile executed fictional build/runtime commands: %+v", runner.calls)
	}
}

func TestDeliberatelyUnwiredShippedRequiredRowFails(t *testing.T) {
	repo := t.TempDir()
	writeGateFixture(t, repo, false)
	manifest := validManifest(t, repo, enforcementRequired)
	manifest.Entries[0].Dependencies = []string{"trstctl.com/trstctl/internal/connector/deliberately_unwired"}
	runner := &scriptedRunner{results: []commandResult{{Stdout: "trstctl.com/trstctl/internal/server\n"}}}
	report, err := evaluate(context.Background(), repo, manifest, runner, selection{})
	if err != nil {
		t.Fatal(err)
	}
	if got := report.Entries["connector.nginx"]; got.Status == statusServed || report.Summary.RequiredFailed != 1 {
		t.Fatalf("unwired required row escaped red: %+v summary=%+v", got, report.Summary)
	}
}

func TestPendingServedRowCannotCloseExactCard(t *testing.T) {
	report := Report{Entries: map[string]entryResult{
		"connector.nginx": {CardID: "WIRE-CONN-101", Status: statusServed, Enforcement: enforcementPending},
	}}
	matched, served := selectedStatus(report, selection{CardID: "WIRE-CONN-101"})
	if !matched || served {
		t.Fatalf("pending served row closed card: matched=%v served=%v", matched, served)
	}
}

func TestExactSelectionRunsOnlyTargetRuntimeAndMarksEverySiblingUnevaluated(t *testing.T) {
	for _, tc := range []struct {
		name string
		sel  selection
	}{
		{name: "entry id", sel: selection{Capability: "connector.nginx"}},
		{name: "card id", sel: selection{CardID: "WIRE-CONN-101"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			repo := t.TempDir()
			writeGateFixture(t, repo, false)
			manifest := validManifest(t, repo, enforcementRequired)
			sibling := manifest.Entries[0]
			sibling.ID = "connector.apache"
			sibling.CardID = "WIRE-CONN-102"
			sibling.Runtime.Test = "TestDODMustNeverRun"
			sibling.Runtime.File = "internal/server/dod_must_never_run_test.go"
			sibling.Runtime.Path = "/api/v1/connectors/apache"
			manifest.Entries = append(manifest.Entries, sibling)

			runner := &scriptedRunner{results: []commandResult{
				{Stdout: "trstctl.com/trstctl/internal/server\ntrstctl.com/trstctl/internal/connector/nginx\n"},
				{Stdout: goTestPass("TestDODConnectorNginxServed")},
			}}
			runner.hook = func(call commandCall) {
				if len(call.Args) == 0 || call.Args[0] != "test" {
					return
				}
				if containsArg(call.Args, "^TestDODMustNeverRun$") {
					t.Fatal("nonselected runtime test executed")
				}
				var expectations []runtimeExpectation
				if err := json.Unmarshal([]byte(call.Profile.RuntimeEnv["TRSTCTL_DOD_EXPECTATIONS"]), &expectations); err != nil {
					t.Fatalf("decode selected runtime expectations: %v", err)
				}
				if len(expectations) != 1 || expectations[0].ID != "connector.nginx" {
					t.Fatalf("selected runtime received nonselected expectations: %+v", expectations)
				}
				broker := call.Profile.RuntimeBroker
				broker.mu.Lock()
				expected := broker.expect["connector.nginx"]
				broker.mu.Unlock()
				candidate := receiptFor(expected)
				candidate.MAC = ""
				writeJSON(t, expected.EvidenceFile, candidate)
				broker.mu.Lock()
				broker.receipts[expected.ID] = append([]byte(nil), candidate.ExecutionReceipt...)
				broker.mu.Unlock()
			}

			report, err := evaluate(context.Background(), repo, manifest, runner, tc.sel)
			if err != nil {
				t.Fatalf("evaluate exact selection: %v", err)
			}
			selected := report.Entries["connector.nginx"]
			if selected.Status != statusServed {
				t.Fatalf("selected exact row did not serve: %+v", selected)
			}
			matched, served := selectedStatus(report, tc.sel)
			if !matched || !served {
				t.Fatalf("exact REQUIRED+SERVED row did not satisfy selection: matched=%v served=%v", matched, served)
			}
			other := report.Entries["connector.apache"]
			if other.Status != statusUnknown || other.Status == statusServed || !strings.Contains(other.Evidence.Runtime.Detail, "not evaluated") || !strings.Contains(other.Evidence.Runtime.Detail, "non-SERVED") {
				t.Fatalf("nonselected sibling is not explicitly unevaluated and nonserved: %+v", other)
			}
			testCalls := 0
			for _, call := range runner.calls {
				if len(call.Args) > 0 && call.Args[0] == "test" {
					testCalls++
				}
			}
			if testCalls != 1 {
				t.Fatalf("focused selection executed %d runtime groups, want exactly one: %+v", testCalls, runner.calls)
			}
		})
	}
}

func TestAggregateCapabilitySelectionIsRejectedBeforeAnyCommand(t *testing.T) {
	repo := t.TempDir()
	writeGateFixture(t, repo, false)
	manifest := validManifest(t, repo, enforcementRequired)
	sibling := manifest.Entries[0]
	sibling.ID = "connector.apache"
	sibling.CardID = "WIRE-CONN-102"
	sibling.Runtime.Path = "/api/v1/connectors/apache"
	manifest.Entries = append(manifest.Entries, sibling)
	runner := &scriptedRunner{}

	if _, err := evaluate(context.Background(), repo, manifest, runner, selection{Capability: "connector"}); !errors.Is(err, errSelectionNoMatch) {
		t.Fatalf("aggregate family selection error = %v, want exact-entry rejection", err)
	}
	if len(runner.calls) != 0 {
		t.Fatalf("rejected aggregate family executed proof commands: %+v", runner.calls)
	}
	report := Report{
		Entries: map[string]entryResult{
			"connector.nginx":  {Status: statusServed, Enforcement: enforcementRequired},
			"connector.apache": {Status: statusStub, Enforcement: enforcementRequired},
		},
		Capabilities: map[string]capabilityResult{"connector": {Status: statusServed}},
	}
	if matched, served := selectedStatus(report, selection{Capability: "connector"}); matched || served {
		t.Fatalf("aggregate family hid a red sibling: matched=%v served=%v", matched, served)
	}
}

func TestPendingServedRowCannotCloseExactEntrySelection(t *testing.T) {
	report := Report{Entries: map[string]entryResult{
		"connector.nginx": {CardID: "WIRE-CONN-101", Status: statusServed, Enforcement: enforcementPending},
	}}
	matched, served := selectedStatus(report, selection{Capability: "connector.nginx"})
	if !matched || served {
		t.Fatalf("pending served row closed exact entry selection: matched=%v served=%v", matched, served)
	}
}

func TestOCIArtifactProofRejectsEveryReleaseDataflowSubstitution(t *testing.T) {
	baseWorkflow := releaseFixture()
	baseDockerfile := dockerfileFixture()
	profile := testStaticProfile()
	tests := []struct {
		name       string
		workflow   string
		dockerfile string
		mutate     func(*BuildProfile)
	}{
		{"workflow substring only", strings.Replace(baseWorkflow, "jobs:\n  image:", "# docker/build-push-action@10e90e3645eae34f1e60eeb005ba3a3d33f178e8 push: true\njobs:\n  other:", 1), baseDockerfile, nil},
		{"build only", strings.Replace(baseWorkflow, "push: true", "load: true", 1), baseDockerfile, nil},
		{"push false", strings.Replace(baseWorkflow, "push: true", "push: false", 1), baseDockerfile, nil},
		{"no registry permission", strings.Replace(baseWorkflow, "packages: write", "packages: read", 1), baseDockerfile, nil},
		{"no image tags", strings.Replace(baseWorkflow, "tags: ${{ steps.tags.outputs.tags }}", "tags: ''", 1), baseDockerfile, nil},
		{"wrong Dockerfile", strings.Replace(baseWorkflow, "file: deploy/docker/Dockerfile", "file: deploy/docker/Otherfile", 1), baseDockerfile, nil},
		{"wrong platform", strings.Replace(baseWorkflow, "linux/amd64,linux/arm64", "linux/arm64", 1), baseDockerfile, nil},
		{"wrong package", baseWorkflow, strings.Replace(baseDockerfile, "./cmd/trstctl", "./cmd/trstctl-agent", 1), nil},
		{"wrong CGO", baseWorkflow, strings.Replace(baseDockerfile, "CGO_ENABLED=0", "CGO_ENABLED=1", 1), nil},
		{"wrong target OS", baseWorkflow, strings.Replace(baseDockerfile, "GOOS=${TARGETOS}", "GOOS=linux", 1), nil},
		{"wrong target architecture", baseWorkflow, strings.Replace(baseDockerfile, "GOARCH=${TARGETARCH}", "GOARCH=amd64", 1), nil},
		{"missing tags", baseWorkflow, baseDockerfile, func(profile *BuildProfile) { profile.Tags = []string{"pkcs11cgo"} }},
		{"wrong build output", baseWorkflow, strings.Replace(baseDockerfile, "-o /out/trstctl ", "-o /out/other ", 1), nil},
		{"wrong COPY", baseWorkflow, strings.Replace(baseDockerfile, "COPY --from=build /out/trstctl /usr/local/bin/trstctl", "COPY --from=build /out/other /usr/local/bin/trstctl", 1), nil},
		{"wrong ENTRYPOINT", baseWorkflow, strings.Replace(baseDockerfile, `ENTRYPOINT ["/usr/local/bin/trstctl"]`, `ENTRYPOINT ["/usr/local/bin/other"]`, 1), nil},
		{"missing signer companion build", baseWorkflow, strings.Replace(baseDockerfile, "RUN go build -trimpath -o /out/trstctl-signer ./cmd/trstctl-signer\n", "", 1), nil},
		{"missing signer companion copy", baseWorkflow, strings.Replace(baseDockerfile, "COPY --from=build /out/trstctl-signer /usr/local/bin/trstctl-signer\n", "", 1), nil},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			repo := t.TempDir()
			writeFile(t, repo, ".github/workflows/release.yml", tc.workflow, 0o600)
			writeFile(t, repo, "deploy/docker/Dockerfile", tc.dockerfile, 0o600)
			candidate := profile
			if tc.mutate != nil {
				tc.mutate(&candidate)
			}
			if evidence := inspectOCIArtifact(repo, candidate); evidence.OK {
				t.Fatalf("adversarial release substitution passed: %+v", evidence)
			}
		})
	}
}

func TestCommittedStaticArtifactProofFollowsPublishedOCIImage(t *testing.T) {
	manifest, err := loadManifest("manifest.json")
	if err != nil {
		t.Fatalf("load committed manifest: %v", err)
	}
	evidence := inspectOCIArtifact(filepath.Clean("../.."), manifest.BuildProfiles["static"])
	if !evidence.OK {
		t.Fatalf("committed static OCI proof is red: %+v", evidence)
	}
	if manifest.BuildProfiles["pkcs11_cgo"].Release != releaseShipped || !artifactConfigured(manifest.BuildProfiles["pkcs11_cgo"].Artifact) {
		t.Fatal("PKCS#11 profile must remain an explicitly shipped cgo signer artifact")
	}
	if evidence := inspectOCIArtifact(filepath.Clean("../.."), manifest.BuildProfiles["pkcs11_cgo"]); !evidence.OK {
		t.Fatalf("committed PKCS#11 cgo signer OCI proof is red: %+v", evidence)
	}
}

func TestRuntimeReceiptRejectsStaleWrongIdentityDigestAndLogOnly(t *testing.T) {
	dir := t.TempDir()
	expected := testExpectation(filepath.Join(dir, "receipt.json"))
	valid := receiptFor(expected)
	tests := []struct {
		name   string
		mutate func(*runtimeReceipt)
		write  bool
	}{
		{"log only no file", nil, false},
		{"stale nonce", func(r *runtimeReceipt) { r.Nonce = strings.Repeat("0", 64) }, true},
		{"wrong id", func(r *runtimeReceipt) { r.ID = "connector.apache" }, true},
		{"wrong substrate digest", func(r *runtimeReceipt) { r.ContractDigest = "sha256:" + strings.Repeat("0", 64) }, true},
		{"missing readback", func(r *runtimeReceipt) { delete(r.Observations, "readback_digest") }, true},
		{"raw log receipt", func(r *runtimeReceipt) { r.Observations["execution_receipt_digest"] = "DOD-CENSUS: served" }, true},
		{"plaintext expectation forgery has no MAC", func(r *runtimeReceipt) { r.MAC = "" }, true},
		{"attacker-chosen MAC", func(r *runtimeReceipt) { r.MAC = "hmac-sha256:" + strings.Repeat("0", 64) }, true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_ = os.Remove(expected.ReceiptFile)
			candidate := valid
			candidate.Observations = cloneStrings(valid.Observations)
			if tc.mutate != nil {
				tc.mutate(&candidate)
			}
			if tc.write {
				writeJSON(t, expected.ReceiptFile, candidate)
			}
			if err := validateReceipt(expected); err == nil {
				t.Fatal("invalid/log-only receipt was accepted")
			}
		})
	}
}

func TestLaunchedRuntimeReceiptRequiresExactProcessWitness(t *testing.T) {
	expected := testExpectation(filepath.Join(t.TempDir(), "launched.receipt.json"))
	expected.RuntimeMode = "launched-binary"
	expected.LaunchedModulePath = "trstctl.com/trstctl"
	expected.LaunchedBinaryPackage = "./cmd/trstctl"
	expected.LaunchedCGOEnabled = "0"
	expected.LaunchedGOOS = "linux"
	expected.LaunchedGOARCH = "amd64"
	expected.LaunchedTags = []string{"release-tag"}
	valid := receiptFor(expected)
	valid.MAC = ""
	if err := validateRuntimeReceiptBody(expected, valid, false, nil); err != nil {
		t.Fatalf("valid launched process receipt rejected: %v", err)
	}
	missingRunner := expected
	missingRunner.RuntimeRunnerImage = ""
	if err := validateRuntimeReceiptBody(missingRunner, valid, false, nil); err == nil {
		t.Fatal("runtime receipt passed without a content-addressed runner image expectation")
	}
	tests := []struct {
		name   string
		mutate func(*runtimeReceipt)
	}{
		{"missing process", func(r *runtimeReceipt) { r.LaunchedProcess = nil }},
		{"wrong pid", func(r *runtimeReceipt) { r.LaunchedProcess.PID = 0 }},
		{"missing start time", func(r *runtimeReceipt) { r.LaunchedProcess.ProcessStartTicks = "" }},
		{"unknown process mode", func(r *runtimeReceipt) { r.LaunchedProcess.ProcessMode = "unknown" }},
		{"wrong module", func(r *runtimeReceipt) { r.LaunchedProcess.BinaryModulePath = "example.invalid/fake" }},
		{"wrong package", func(r *runtimeReceipt) { r.LaunchedProcess.BinaryPackage = "./cmd/fake" }},
		{"wrong cgo", func(r *runtimeReceipt) { r.LaunchedProcess.BinaryCGOEnabled = "1" }},
		{"wrong goos", func(r *runtimeReceipt) { r.LaunchedProcess.BinaryGOOS = "darwin" }},
		{"wrong goarch", func(r *runtimeReceipt) { r.LaunchedProcess.BinaryGOARCH = "arm64" }},
		{"wrong tags", func(r *runtimeReceipt) { r.LaunchedProcess.BinaryTags = []string{"attacker-tag"} }},
		{"mutable digest", func(r *runtimeReceipt) { r.LaunchedProcess.BinaryDigest = "trstctl:latest" }},
		{"missing binary device", func(r *runtimeReceipt) { r.LaunchedProcess.BinaryDevice = "" }},
		{"missing binary inode", func(r *runtimeReceipt) { r.LaunchedProcess.BinaryInode = "" }},
		{"non-loopback address", func(r *runtimeReceipt) { r.LaunchedProcess.Address = "example.com:8443" }},
		{"invalid port", func(r *runtimeReceipt) { r.LaunchedProcess.Address = "127.0.0.1:0" }},
		{"invalid inode", func(r *runtimeReceipt) { r.LaunchedProcess.ListenerInode = "not-an-inode" }},
		{"missing accepted socket", func(r *runtimeReceipt) { r.LaunchedProcess.AcceptedConnectionInode = "" }},
		{"same listener and accepted socket", func(r *runtimeReceipt) { r.LaunchedProcess.AcceptedConnectionInode = r.LaunchedProcess.ListenerInode }},
		{"native adds interpreter", func(r *runtimeReceipt) { r.LaunchedProcess.InterpreterDigest = "sha256:" + strings.Repeat("a", 64) }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			candidate := valid
			process := *valid.LaunchedProcess
			candidate.LaunchedProcess = &process
			test.mutate(&candidate)
			if err := validateRuntimeReceiptBody(expected, candidate, false, nil); err == nil {
				t.Fatal("forged launched process receipt passed")
			}
		})
	}
}

func TestParentSignerRejectsFullChildForgeryWithoutParentCapturedReceipt(t *testing.T) {
	dir := t.TempDir()
	expected := testExpectation(filepath.Join(dir, "final.receipt.json"))
	expected.BrokerEndpoint = "http://127.0.0.1:1"
	expected.BrokerToken = strings.Repeat("f", 64)
	broker := newInMemorySubstrateBroker(dir, dir)
	broker.configure(map[string]runtimeExpectation{expected.ID: expected})
	forged := receiptFor(expected)

	// Even a child that somehow reconstructs every plaintext field and supplies
	// a syntactically valid MAC cannot pre-create the parent-owned final file.
	writeJSON(t, expected.ReceiptFile, forged)
	if err := finalizeParentReceipt(expected, broker); err == nil || !strings.Contains(err.Error(), "pre-created final receipt") {
		t.Fatalf("full final-receipt forgery was not rejected: %v", err)
	}
	if err := os.Remove(expected.ReceiptFile); err != nil {
		t.Fatal(err)
	}

	// Reading every child environment/file reveals the unsigned evidence path,
	// but not the parent key and not a receipt captured from a parent-owned PID.
	forged.MAC = ""
	writeJSON(t, expected.EvidenceFile, forged)
	payload, err := sortedExpectationJSON(map[string]runtimeExpectation{expected.ID: expected})
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(payload, expected.ReceiptMACKey) {
		t.Fatal("parent MAC key leaked into child expectation JSON")
	}
	if err := finalizeParentReceipt(expected, broker); err == nil || !strings.Contains(err.Error(), "no independently captured receipt") {
		t.Fatalf("plaintext full-field evidence forgery was not rejected: %v", err)
	}

	// A structurally perfect raw receipt still fails when it differs from the
	// exact receipt bytes the parent got from the process it launched.
	var actual brokerReceipt
	if err := json.Unmarshal(forged.ExecutionReceipt, &actual); err != nil {
		t.Fatal(err)
	}
	actual.PID++
	actualRaw, err := json.Marshal(actual)
	if err != nil {
		t.Fatal(err)
	}
	broker.receipts[expected.ID] = actualRaw
	if err := finalizeParentReceipt(expected, broker); err == nil || !strings.Contains(err.Error(), "does not match") {
		t.Fatalf("forged raw substrate fields escaped parent byte cross-check: %v", err)
	}
}

func TestRuntimeOutcomeRejectsSkipAndFail(t *testing.T) {
	for _, tc := range []struct {
		name string
		json string
	}{
		{"skip", `{"Action":"skip","Test":"TestDODExample"}` + "\n"},
		{"fail", `{"Action":"fail","Test":"TestDODExample"}` + "\n"},
	} {
		passed, skipped, failed := parseTestOutcome(commandResult{Stdout: tc.json}, "TestDODExample")
		if passed || (tc.name == "skip" && !skipped) || (tc.name == "fail" && !failed) {
			t.Errorf("%s outcome accepted: pass=%v skip=%v fail=%v", tc.name, passed, skipped, failed)
		}
	}
}

func TestRuntimeFailureDetailUsesBoundedGoTestJSONWhenStderrIsEmpty(t *testing.T) {
	prefix := strings.Repeat("x", 5000)
	detail := runtimeFailureDetail(commandResult{Stdout: prefix + "\n" +
		`{"Action":"build-output","Output":"compile error\n"}` + "\n" +
		`{"Action":"fail","Test":"TestDODExample"}`})
	if !strings.Contains(detail, "compile error") || !strings.Contains(detail, "TestDODExample failed") {
		t.Fatalf("runtime failure detail omits test failure: %q", detail)
	}
	if strings.Contains(detail, strings.Repeat("x", 2049)) {
		t.Fatalf("runtime failure detail is not bounded: %d bytes", len(detail))
	}
}

func TestRuntimeFailureDetailRetainsFirstFailureBeforeLongCrashTail(t *testing.T) {
	var raw strings.Builder
	raw.WriteString(`{"Action":"run","Test":"TestDODExample"}` + "\n")
	raw.WriteString(`{"Action":"output","Test":"TestDODExample","Output":"    proof.go:77: signer failed to start: exact first failure\\n"}` + "\n")
	for range 80 {
		raw.WriteString(`{"Action":"output","Test":"TestDODExample","Output":"register 0xdeadbeef\\n"}` + "\n")
	}
	raw.WriteString(`{"Action":"fail","Test":"TestDODExample"}` + "\n")
	detail := runtimeFailureDetail(commandResult{Stdout: raw.String()})
	if !strings.Contains(detail, "exact first failure") || !strings.Contains(detail, "TestDODExample failed") {
		t.Fatalf("runtime detail discarded the causal failure: %q", detail)
	}
	if len(detail) > 2200 {
		t.Fatalf("runtime failure detail is not bounded: %d bytes", len(detail))
	}
}

func TestRuntimeBindingRejectsHTTptestAndHandBuiltDeps(t *testing.T) {
	repo := t.TempDir()
	writeGateFixture(t, repo, true)
	manifest := validManifest(t, repo, enforcementRequired)
	entry := manifest.Entries[0]
	if evidence := inspectRuntimeBinding(repo, entry, manifest.Substrates); evidence.OK || (!strings.Contains(evidence.Detail, "hand-constructs") && !strings.Contains(evidence.Detail, "not bound")) {
		t.Fatalf("httptest/hand-built evidence was accepted: %+v", evidence)
	}
}

func TestRuntimeASTAuditIncludesDedicatedTaggedProof(t *testing.T) {
	repo := t.TempDir()
	writeGateFixture(t, repo, false)
	manifest := validManifest(t, repo, enforcementRequired)
	if evidence := inspectRuntimeBinding(repo, manifest.Entries[0], manifest.Substrates); !evidence.OK {
		t.Fatalf("AST audit ignored or rejected the dedicated tagged runtime proof: %+v", evidence)
	}
}

// TestCommittedRequiredRuntimeBindingsStayProductionBound runs the same static
// source proof used by the real census against every currently required manifest
// row. Fixture-only tests prove individual attacks are rejected; this test makes
// sure an actual shipped proof cannot accidentally add httptest, hand-built Deps,
// or an unrelated handler and remain green until the expensive runtime gate.
func TestCommittedRequiredRuntimeBindingsStayProductionBound(t *testing.T) {
	manifest, err := loadManifest("manifest.json")
	if err != nil {
		t.Fatal(err)
	}
	repo, err := filepath.Abs(filepath.Join("..", ".."))
	if err != nil {
		t.Fatal(err)
	}
	fullGroups := groupRuntimeEntries(manifest, "", false)
	for _, entry := range manifest.Entries {
		entry := entry
		if entry.Enforcement != enforcementRequired || !runtimeConfigured(entry.Runtime) {
			continue
		}
		t.Run(entry.ID, func(t *testing.T) {
			profileName, profile := resolvedProfile(manifest, entry)
			group := fullGroups[runtimeCacheKey(profileName, entry)]
			evidence := inspectRuntimeBindingForGroup(repo, entry, manifest.Substrates, group, profile)
			if !evidence.OK {
				t.Fatalf("committed required runtime binding is red: %+v", evidence)
			}
		})
	}
}

func TestRuntimeBindingRejectsUnrelatedHandlerSession(t *testing.T) {
	repo := t.TempDir()
	writeGateFixture(t, repo, false)
	manifest := validManifest(t, repo, enforcementRequired)
	path := filepath.Join(repo, "internal/server/dod_nginx_served_test.go")
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	bad := strings.Replace(string(data), "session := proof.Start(t, \"connector.nginx\", srv.Handler(), req)", "fake := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusAccepted) })\n    session := proof.Start(t, \"connector.nginx\", fake, req)", 1)
	if err := os.WriteFile(path, []byte(bad), 0o600); err != nil {
		t.Fatal(err)
	}
	if evidence := inspectRuntimeBinding(repo, manifest.Entries[0], manifest.Substrates); evidence.OK {
		t.Fatalf("unrelated handler minted a bound Session: %+v", evidence)
	}
}

func TestRuntimeBindingRejectsDeadProofPathAndExcludedSibling(t *testing.T) {
	t.Run("dead constant-false path", func(t *testing.T) {
		repo := t.TempDir()
		writeGateFixture(t, repo, false)
		manifest := validManifest(t, repo, enforcementRequired)
		path := filepath.Join(repo, "internal/server/dod_nginx_served_test.go")
		raw, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		source := strings.Replace(string(raw), "func TestDODConnectorNginxServed(t *testing.T) {", "func TestDODConnectorNginxServed(t *testing.T) {\nif false {", 1)
		source = strings.Replace(source, "\n}\n", "\n}\n}\n", 1)
		if err := os.WriteFile(path, []byte(source), 0o600); err != nil {
			t.Fatal(err)
		}
		if evidence := inspectRuntimeBinding(repo, manifest.Entries[0], manifest.Substrates); evidence.OK {
			t.Fatalf("constant-false proof path was accepted: %+v", evidence)
		}
	})

	t.Run("excluded sibling cannot own manifest test", func(t *testing.T) {
		repo := t.TempDir()
		writeGateFixture(t, repo, false)
		manifest := validManifest(t, repo, enforcementRequired)
		root := filepath.Join(repo, "internal/server/dod_nginx_served_test.go")
		raw, err := os.ReadFile(root)
		if err != nil {
			t.Fatal(err)
		}
		weak := strings.Replace(string(raw), "TestDODConnectorNginxServed", "TestDODUnrelated", 1)
		if err := os.WriteFile(root, []byte(weak), 0o600); err != nil {
			t.Fatal(err)
		}
		excluded := strings.Replace(string(raw), "//go:build trstctl_dodproof", "//go:build trstctl_dodproof && never_enabled", 1)
		writeFile(t, repo, "internal/server/zz_excluded_proof_test.go", excluded, 0o600)
		if evidence := inspectRuntimeBinding(repo, manifest.Entries[0], manifest.Substrates); evidence.OK {
			t.Fatalf("build-excluded sibling supplied the manifest test: %+v", evidence)
		}
	})
}

func TestRuntimeBindingRejectsProofOnOnlyOneUnknownEnvironmentBranch(t *testing.T) {
	repo := t.TempDir()
	writeGateFixture(t, repo, false)
	manifest := validManifest(t, repo, enforcementRequired)
	path := filepath.Join(repo, "internal/server/dod_nginx_served_test.go")
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	source := strings.Replace(string(raw), `"net/http"`, "\"net/http\"\n    \"os\"", 1)
	source = strings.Replace(source, "func TestDODConnectorNginxServed(t *testing.T) {", "func TestDODConnectorNginxServed(t *testing.T) {\nif os.Getenv(\"ATTACKER_BRANCH\") == \"legitimate\" {", 1)
	closing := strings.LastIndex(source, "\n}\n")
	if closing < 0 {
		t.Fatal("fixture has no root closing brace")
	}
	source = source[:closing] + "\n} else {\n    _ = os.Getenv(\"ATTACKER_BRANCH\")\n}" + source[closing:]
	if err := os.WriteFile(path, []byte(source), 0o600); err != nil {
		t.Fatal(err)
	}
	evidence := inspectRuntimeBinding(repo, manifest.Entries[0], manifest.Substrates, manifest.BuildProfiles["static"])
	if evidence.OK || !strings.Contains(evidence.Detail, "only one viable side") {
		t.Fatalf("environment-selected proof/forgery branch was accepted: %+v", evidence)
	}
}

func TestRuntimeBindingDoesNotModelInjectedDODExpectationAsEmpty(t *testing.T) {
	repo := t.TempDir()
	writeGateFixture(t, repo, false)
	manifest := validManifest(t, repo, enforcementRequired)
	path := filepath.Join(repo, "internal/server/dod_nginx_served_test.go")
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	source := strings.Replace(string(raw), `"net/http"`, "\"net/http\"\n    \"os\"", 1)
	const declaration = "func TestDODConnectorNginxServed(t *testing.T) {"
	source = strings.Replace(source, declaration, declaration+`
    if os.Getenv("TRSTCTL_DOD_EXPECTATIONS") != "" {
        dodFakeInjectedExpectation()
        return
    }`, 1)
	source += `
func dodFakeInjectedExpectation() {
    _ = Deps{ConnectorRegistry: newRegistry()}
}
`
	if err := os.WriteFile(path, []byte(source), 0o600); err != nil {
		t.Fatal(err)
	}
	evidence := inspectRuntimeBinding(repo, manifest.Entries[0], manifest.Substrates, manifest.BuildProfiles["static"])
	if evidence.OK || !strings.Contains(evidence.Detail, "hand-constructs Deps") {
		t.Fatalf("gate-injected expectation environment hid test-only assembly: %+v", evidence)
	}
}

func TestRuntimeBindingModelsOnlyExpectationAsInspectedEntry(t *testing.T) {
	t.Run("exact selected entry", func(t *testing.T) {
		repo := t.TempDir()
		writeGateFixture(t, repo, false)
		manifest := validManifest(t, repo, enforcementRequired)
		path := filepath.Join(repo, "internal/server/dod_nginx_served_test.go")
		raw, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		source := strings.Replace(string(raw), "func TestDODConnectorNginxServed(t *testing.T) {", "func TestDODConnectorNginxServed(t *testing.T) {\nif proof.OnlyExpectation(t) == \"connector.nginx\" {", 1)
		closing := strings.LastIndex(source, "\n}\n")
		if closing < 0 {
			t.Fatal("fixture has no root closing brace")
		}
		source = source[:closing] + "\n}" + source[closing:]
		if err := os.WriteFile(path, []byte(source), 0o600); err != nil {
			t.Fatal(err)
		}
		if evidence := inspectRuntimeBindingForGroup(repo, manifest.Entries[0], manifest.Substrates, manifest.Entries, manifest.BuildProfiles["static"]); !evidence.OK {
			t.Fatalf("exact gate-owned expectation branch was rejected: %+v", evidence)
		}
	})

	t.Run("different entry remains dead", func(t *testing.T) {
		repo := t.TempDir()
		writeGateFixture(t, repo, false)
		manifest := validManifest(t, repo, enforcementRequired)
		path := filepath.Join(repo, "internal/server/dod_nginx_served_test.go")
		raw, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		source := strings.Replace(string(raw), "func TestDODConnectorNginxServed(t *testing.T) {", "func TestDODConnectorNginxServed(t *testing.T) {\nif proof.OnlyExpectation(t) == \"connector.apache\" {", 1)
		closing := strings.LastIndex(source, "\n}\n")
		if closing < 0 {
			t.Fatal("fixture has no root closing brace")
		}
		source = source[:closing] + "\n}" + source[closing:]
		if err := os.WriteFile(path, []byte(source), 0o600); err != nil {
			t.Fatal(err)
		}
		if evidence := inspectRuntimeBinding(repo, manifest.Entries[0], manifest.Substrates, manifest.BuildProfiles["static"]); evidence.OK {
			t.Fatalf("a different entry's expectation branch was accepted: %+v", evidence)
		}
	})

	t.Run("shared focused and full modes are independently valid", func(t *testing.T) {
		repo := t.TempDir()
		writeSharedRuntimeFixture(t, repo)
		manifest := validManifest(t, repo, enforcementRequired)
		manifest.Entries[0].Runtime.Test = "TestDODSharedConnectors"
		second := manifest.Entries[0]
		second.ID = "connector.apache"
		second.CardID = "WIRE-CONN-102"
		second.Runtime.Path = "/api/v1/connectors/apache"
		manifest.Entries = append(manifest.Entries, second)
		group := groupRuntimeEntries(manifest, "", false)[runtimeCacheKey("static", manifest.Entries[0])]
		for _, entry := range manifest.Entries {
			evidence := inspectRuntimeBindingForGroup(repo, entry, manifest.Substrates, group, manifest.BuildProfiles["static"])
			if !evidence.OK || !strings.Contains(evidence.Detail, "full-group trace") {
				t.Fatalf("shared focused/full trace for %s = %+v", entry.ID, evidence)
			}
		}
	})
}

func TestRuntimeBindingRejectsFakeFullGroupBranchDuringExactSelection(t *testing.T) {
	repo := t.TempDir()
	writeGateFixture(t, repo, false)
	manifest := validManifest(t, repo, enforcementRequired)
	second := manifest.Entries[0]
	second.ID = "connector.apache"
	second.CardID = "WIRE-CONN-102"
	second.Runtime.Path = "/api/v1/connectors/apache"
	manifest.Entries = append(manifest.Entries, second)

	path := filepath.Join(repo, "internal/server/dod_nginx_served_test.go")
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	const declaration = "func TestDODConnectorNginxServed(t *testing.T) {"
	source := strings.Replace(string(raw), declaration, declaration+`
    if proof.OnlyExpectation(t) == "" {
        dodFakeFullGroup()
        return
    }`, 1)
	source += `
func dodFakeFullGroup() {
    _ = Deps{ConnectorRegistry: newRegistry()}
}
`
	if err := os.WriteFile(path, []byte(source), 0o600); err != nil {
		t.Fatal(err)
	}

	// The focused-only model deliberately demonstrates the former hole: the fake
	// helper is dead when the gate issues this exact entry ID.
	if evidence := inspectRuntimeBinding(repo, manifest.Entries[0], manifest.Substrates, manifest.BuildProfiles["static"]); !evidence.OK {
		t.Fatalf("regression fixture's honest focused branch is invalid: %+v", evidence)
	}
	group := groupRuntimeEntries(manifest, "", false)[runtimeCacheKey("static", manifest.Entries[0])]
	if evidence := inspectRuntimeBindingForGroup(repo, manifest.Entries[0], manifest.Substrates, group, manifest.BuildProfiles["static"]); evidence.OK || !strings.Contains(evidence.Detail, "full-group runtime source") || !strings.Contains(evidence.Detail, "hand-constructs Deps") {
		t.Fatalf("fake full-only branch escaped independent group tracing: %+v", evidence)
	}

	runner := &scriptedRunner{results: []commandResult{{Stdout: "trstctl.com/trstctl/internal/server\ntrstctl.com/trstctl/internal/connector/nginx\n"}}}
	report, err := evaluate(context.Background(), repo, manifest, runner, selection{Capability: "connector.nginx"})
	if err != nil {
		t.Fatalf("evaluate exact selection: %v", err)
	}
	selected := report.Entries["connector.nginx"]
	if selected.Status == statusServed || !strings.Contains(selected.Evidence.Runtime.Detail, "full-group runtime source") {
		t.Fatalf("exact selection certified a test-only full branch: %+v", selected)
	}
	for _, call := range runner.calls {
		if len(call.Args) > 0 && call.Args[0] == "test" {
			t.Fatalf("rejected full-group source still executed a runtime test: %+v", runner.calls)
		}
	}
}

func TestLaunchedRuntimeBindingRejectsFakeHTTPServerAndAcceptsOpaqueProcessPath(t *testing.T) {
	repo := t.TempDir()
	writeGateFixture(t, repo, false)
	manifest := validManifest(t, repo, enforcementRequired)
	entry := manifest.Entries[0]
	entry.Runtime.Mode = "launched-binary"
	manifest.Entries[0] = entry
	path := filepath.Join(repo, "internal/server/dod_nginx_served_test.go")
	positive := `//go:build trstctl_dodproof

package server
import (
    "net/http"
    "testing"
    "trstctl.com/trstctl/internal/crypto"
    "trstctl.com/trstctl/tools/dodcensus/proof"
)
func TestDODConnectorNginxServed(t *testing.T) {
    external := proof.StartCommand(t, "connector.nginx")
    endpoint := external.Endpoint()
    _ = endpoint
    _, publicKey, _ := crypto.GenerateEd25519KeyPEM()
    shipped := proof.BuildShippedProcess(t, "connector.nginx", publicKey)
    shipped.Start(t.TempDir(), nil)
    req, _ := http.NewRequest("POST", "http://127.0.0.1:19443/api/v1/connectors/nginx", nil)
    response := shipped.Do(req)
    session := proof.StartResponse(t, "connector.nginx", response)
    payload := []byte("external payload with readback")
    executionReceipt := external.StopAndReceipt()
    session.Complete(proof.ExternalWrite(proof.ExternalWriteProbe{Destination: []byte("nginx/configuration/path"), Written: payload, ReadBack: payload, ExecutionReceipt: executionReceipt}))
}
`
	if err := os.WriteFile(path, []byte(positive), 0o600); err != nil {
		t.Fatal(err)
	}
	good := inspectRuntimeBinding(repo, entry, manifest.Substrates, manifest.BuildProfiles["static"])
	if !good.OK || !strings.Contains(good.Detail, "PID-owned listener") || strings.Contains(good.Detail, "buildRunDeps -> Build") {
		t.Fatalf("honest launched-process source was not described/bound correctly: %+v", good)
	}

	fake := strings.Replace(positive,
		`response := shipped.Do(req)`,
		`fakeListener, _ := net.Listen("tcp", "127.0.0.1:19443")
    fakeServer := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusAccepted) })}
    go fakeServer.Serve(fakeListener)
    response, _ := (&http.Client{}).Do(req)`, 1)
	fake = strings.Replace(fake, `"net/http"`, `"net/http"`+"\n    \"net\"", 1)
	if err := os.WriteFile(path, []byte(fake), 0o600); err != nil {
		t.Fatal(err)
	}
	bad := inspectRuntimeBinding(repo, entry, manifest.Substrates, manifest.BuildProfiles["static"])
	if bad.OK || (!strings.Contains(strings.Join(bad.Required, " "), "live ShippedProcess") && !strings.Contains(strings.Join(bad.Required, " "), "StartResponse")) {
		t.Fatalf("test-owned fake HTTP server escaped launched-process binding: %+v", bad)
	}
}

func TestAssemblyRejectsDiscardedConstructorNilFieldAndWrongBuildTag(t *testing.T) {
	for _, tc := range []struct {
		name   string
		source string
	}{
		{"discarded and nil", `package server
type Deps struct { ConnectorRegistry any }
func newRegistry() any { return nil }
func buildRunDeps() Deps { _ = newRegistry(); return Deps{ConnectorRegistry:nil} }
`},
		{"wrong build tag", `//go:build windows
package server
type Deps struct { ConnectorRegistry any }
func newRegistry() any { return nil }
func buildRunDeps() Deps { return Deps{ConnectorRegistry:newRegistry()} }
`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			repo := t.TempDir()
			writeFile(t, repo, "internal/server/run.go", tc.source, 0o600)
			entry := Entry{ID: "connector.nginx", Dependencies: []string{"trstctl.com/trstctl/internal/connector/nginx"}, Assembly: AssemblyProof{File: "internal/server/run.go", Function: "buildRunDeps", Binding: "returned-field", Field: "ConnectorRegistry", Calls: []string{"newRegistry"}}}
			if evidence := inspectAssembly(repo, entry, testStaticProfile()); evidence.OK {
				t.Fatalf("invalid production assembly passed: %+v", evidence)
			}
		})
	}
}

func TestSharedRuntimeExecutionIsCachedButEachEntryNeedsOwnReceipt(t *testing.T) {
	repo := t.TempDir()
	writeSharedRuntimeFixture(t, repo)
	manifest := validManifest(t, repo, enforcementRequired)
	manifest.Entries[0].Runtime.Test = "TestDODSharedConnectors"
	second := manifest.Entries[0]
	second.ID = "connector.apache"
	second.CardID = "WIRE-CONN-102"
	second.Runtime.Path = "/api/v1/connectors/apache"
	manifest.Entries = append(manifest.Entries, second)
	deps := "trstctl.com/trstctl/internal/server\ntrstctl.com/trstctl/internal/connector/nginx\n"
	runner := &scriptedRunner{results: []commandResult{
		{Stdout: deps},
		{Stdout: goTestPass("TestDODSharedConnectors")},
	}}
	runner.hook = func(call commandCall) {
		if !containsArg(call.Args, "^TestDODSharedConnectors$") {
			return
		}
		var expectations []runtimeExpectation
		if err := json.Unmarshal([]byte(call.Profile.RuntimeEnv["TRSTCTL_DOD_EXPECTATIONS"]), &expectations); err != nil {
			t.Fatalf("decode runtime env: %v", err)
		}
		for _, expected := range expectations {
			if expected.ID == "connector.nginx" {
				broker := call.Profile.RuntimeBroker
				broker.mu.Lock()
				parentExpected := broker.expect[expected.ID]
				broker.mu.Unlock()
				candidate := receiptFor(parentExpected)
				candidate.MAC = ""
				writeJSON(t, parentExpected.EvidenceFile, candidate)
				broker.mu.Lock()
				broker.receipts[expected.ID] = append([]byte(nil), candidate.ExecutionReceipt...)
				broker.mu.Unlock()
			}
		}
	}
	report, err := evaluate(context.Background(), repo, manifest, runner, selection{})
	if err != nil {
		t.Fatalf("evaluate: %v", err)
	}
	if report.Entries["connector.nginx"].Status != statusServed {
		t.Fatalf("first exact receipt did not serve: %+v", report.Entries["connector.nginx"])
	}
	if report.Entries["connector.apache"].Status == statusServed {
		t.Fatalf("second entry inherited first entry's cached receipt: %+v", report.Entries["connector.apache"])
	}
	goTests := 0
	for _, call := range runner.calls {
		if len(call.Args) > 0 && call.Args[0] == "test" {
			goTests++
			if call.Profile.HostRuntime || !call.Profile.RuntimeExecution {
				t.Fatal("runtime Go test was not pinned to the shipped execution profile")
			}
		}
	}
	if goTests != 1 {
		t.Fatalf("shared profile/package/test executed %d times, want one raw execution", goTests)
	}
}

func TestDODCommandEnvironmentPinsArtifactAndRuntimeToShippedPlatform(t *testing.T) {
	base := []string{"PATH=/bin", "GOOS=fake", "GOARCH=fake", "TRSTCTL_DOD_EXPECTATIONS=forged"}
	artifact := strings.Join(dodCommandEnvironment(base, "/tmp/artifact", BuildProfile{CGOEnabled: "0", GOOS: "linux", GOARCH: "amd64"}), "\n")
	runtimeProfile := BuildProfile{CGOEnabled: "0", GOOS: "linux", GOARCH: "amd64", RuntimeExecution: true, RuntimeEnv: map[string]string{"TRSTCTL_DOD_EXPECTATIONS": "issued"}}
	host := strings.Join(dodCommandEnvironment(base, "/tmp/runtime", runtimeProfile), "\n")
	if !strings.Contains(artifact, "GOOS=linux") || !strings.Contains(artifact, "GOARCH=amd64") {
		t.Fatalf("artifact dependency graph is not pinned: %s", artifact)
	}
	if !strings.Contains(host, "GOOS=linux") || !strings.Contains(host, "GOARCH=amd64") {
		t.Fatalf("runtime proof is not pinned to the shipped platform: %s", host)
	}
	if !strings.Contains(host, "TRSTCTL_DOD_EXPECTATIONS=issued") || strings.Contains(host, "forged") {
		t.Fatalf("gate runtime environment was not isolated: %s", host)
	}
}

func TestDODGoInvocationAllowsOnlyClosedListAndReceiptTestShapes(t *testing.T) {
	accepted := []struct {
		name string
		args []string
	}{
		{name: "go", args: []string{"list", "-deps", "./cmd/trstctl"}},
		{name: "go", args: []string{"list", "-tags=pkcs11cgo", "-deps", "./cmd/trstctl-signer"}},
		{name: "go", args: []string{"test", "-tags=trstctl_dodproof", "-json", "-count=1", "-run", "^TestDODConnectorNginxServed$", "./internal/server"}},
		{name: "go", args: []string{"test", "-tags=pkcs11cgo,trstctl_dodproof", "-json", "-count=1", "-run", "^TestDODManagedKeyProductionAssembly$", "./internal/server"}},
	}
	for _, test := range accepted {
		if err := validateDODGoInvocation(test.name, test.args); err != nil {
			t.Errorf("validateDODGoInvocation(%q, %q): %v", test.name, test.args, err)
		}
	}

	rejected := []struct {
		name string
		args []string
	}{
		{name: "sh", args: []string{"-c", "true"}},
		{name: "go", args: []string{"env"}},
		{name: "go", args: []string{"list", "-exec=/tmp/attacker", "-deps", "./cmd/trstctl"}},
		{name: "go", args: []string{"list", "-tags=trstctl_dodproof", "-deps", "./cmd/trstctl"}},
		{name: "go", args: []string{"list", "-tags=pkcs11cgo,trstctl_dodproof", "-deps", "./cmd/trstctl-signer"}},
		{name: "go", args: []string{"test", "-json", "-count=1", "-run", "TestDOD", "./internal/server"}},
		{name: "go", args: []string{"test", "-tags=pkcs11cgo", "-json", "-count=1", "-run", "TestDOD", "./internal/server"}},
		{name: "go", args: []string{"test", "-json", "-count=1", "-run", "TestDOD", "./internal/server", "-exec=/tmp/attacker"}},
		{name: "go", args: []string{"test", "-json", "-count=1", "-run", "TestDOD", "../outside"}},
	}
	for _, test := range rejected {
		if err := validateDODGoInvocation(test.name, test.args); err == nil {
			t.Errorf("validateDODGoInvocation(%q, %q) unexpectedly accepted unsafe argv", test.name, test.args)
		}
	}
}

func TestRuntimeExecutionAlwaysAddsReservedProofTag(t *testing.T) {
	repo := t.TempDir()
	manifest := validManifest(t, repo, enforcementRequired)
	entry := manifest.Entries[0]
	substrate := manifest.Substrates[entry.Runtime.SubstrateID]
	launched, err := launchedBinarySpecForManifest(repo, manifest)
	if err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name    string
		profile BuildProfile
		wantTag string
	}{
		{name: "static", profile: testStaticProfile(), wantTag: "-tags=trstctl_dodproof"},
		{name: "pkcs11_cgo", profile: BuildProfile{CGOEnabled: "1", GOOS: "linux", GOARCH: "amd64", Tags: []string{"pkcs11cgo"}}, wantTag: "-tags=pkcs11cgo,trstctl_dodproof"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			runner := &scriptedRunner{results: []commandResult{{Stdout: goTestPass(entry.Runtime.Test)}}}
			execution, err := executeRuntimeTest(context.Background(), repo, tc.name, tc.profile, launched, substrate, []Entry{entry}, runner)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = os.RemoveAll(execution.receiptDir) })
			if len(runner.calls) != 1 || len(runner.calls[0].Args) < 2 || runner.calls[0].Args[1] != tc.wantTag {
				t.Fatalf("runtime argv = %+v, want reserved proof tag %q", runner.calls, tc.wantTag)
			}
			if runner.calls[0].Profile.HostRuntime || !runner.calls[0].Profile.RuntimeExecution {
				t.Fatal("dedicated proof test was not configured for shipped-profile execution")
			}
			expected := execution.expectations[entry.ID]
			if expected.RuntimeTestPackage != entry.Runtime.Package || expected.RuntimeCGOEnabled != tc.profile.CGOEnabled || expected.RuntimeGOOS != tc.profile.GOOS || expected.RuntimeGOARCH != tc.profile.GOARCH || strings.Join(expected.RuntimeTags, ",") != strings.Join(tc.profile.Tags, ",") {
				t.Fatalf("runtime expectation profile = cgo=%q %s/%s tags=%v, want cgo=%q %s/%s tags=%v", expected.RuntimeCGOEnabled, expected.RuntimeGOOS, expected.RuntimeGOARCH, expected.RuntimeTags, tc.profile.CGOEnabled, tc.profile.GOOS, tc.profile.GOARCH, tc.profile.Tags)
			}
		})
	}
}

func TestOSRunnerRequiresPinnedRuntimeEvenOnNativeLinuxProfile(t *testing.T) {
	profile := BuildProfile{CGOEnabled: "0", GOOS: runtime.GOOS, GOARCH: runtime.GOARCH, RuntimeExecution: true}
	runner := osRunner{CacheDir: t.TempDir()}
	if _, err := runner.PrepareRuntime(context.Background(), t.TempDir(), profile); err == nil || !strings.Contains(err.Error(), "pinned Linux runner") {
		t.Fatalf("native-matching runtime profile bypassed pinned preparation: %v", err)
	}
	result := runner.Run(context.Background(), t.TempDir(), profile,
		"go", "test", "-tags=trstctl_dodproof", "-json", "-count=1", "-run", "^TestDODExample$", "./internal/server")
	if result.Err == nil || !strings.Contains(result.Err.Error(), "pinned Linux runner") {
		t.Fatalf("native-matching runtime proof fell back to host Go: %+v", result)
	}

	profile.GOOS = "definitely-not-" + runtime.GOOS
	result = runner.Run(context.Background(), t.TempDir(), profile,
		"go", "test", "-tags=trstctl_dodproof", "-json", "-count=1", "-run", "^TestDODExample$", "./internal/server")
	if result.Err == nil || !strings.Contains(result.Err.Error(), "pinned Linux runner") {
		t.Fatalf("cross-host runtime profile bypassed pinned runner: %+v", result)
	}
}

func TestCommandSubstrateIdentityFilesRejectMissingDuplicateAndTraversal(t *testing.T) {
	base := Substrate{
		Kind: "vendor-emulator", Verifier: "external-write", Execution: "command",
		Command: []string{"testdata/emulator"}, IdentityFiles: []string{"testdata/emulator"},
		Identity:     "vendor/emulator@sha256:" + strings.Repeat("a", 64),
		ContractFile: "testdata/contract.json", ContractSHA256: "sha256:" + strings.Repeat("b", 64),
	}
	tests := []struct {
		name   string
		mutate func(*Substrate)
	}{
		{name: "missing closure", mutate: func(value *Substrate) { value.IdentityFiles = nil }},
		{name: "duplicate", mutate: func(value *Substrate) { value.IdentityFiles = []string{"testdata/emulator", "testdata/emulator"} }},
		{name: "traversal", mutate: func(value *Substrate) { value.IdentityFiles = []string{"testdata/emulator", "../outside"} }},
		{name: "missing command", mutate: func(value *Substrate) { value.IdentityFiles = []string{"testdata/helper"} }},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			candidate := base
			candidate.IdentityFiles = append([]string(nil), base.IdentityFiles...)
			tc.mutate(&candidate)
			if err := validateSubstrate("substrates.vendor_emulator", candidate); err == nil {
				t.Fatal("invalid command identity closure was accepted")
			}
		})
	}

	container := Substrate{
		Kind: "testcontainer", Verifier: "external-write", Execution: "container",
		Image: "vendor/image@sha256:" + strings.Repeat("c", 64), Identity: "vendor/image@sha256:" + strings.Repeat("c", 64),
		IdentityFiles: []string{"testdata/emulator"}, ContractFile: "testdata/contract.json", ContractSHA256: "sha256:" + strings.Repeat("d", 64),
	}
	if err := validateSubstrate("substrates.container", container); err == nil {
		t.Fatal("non-command substrate accepted identity_files")
	}
}

func TestCommandIdentityDigestIsSortedAndLengthFramed(t *testing.T) {
	repo := t.TempDir()
	writeFile(t, repo, "proof/a", "alpha", 0o600)
	writeFile(t, repo, "proof/b", "beta", 0o600)
	forward, err := commandIdentityDigest(repo, []string{"proof/a", "proof/b"})
	if err != nil {
		t.Fatal(err)
	}
	reverse, err := commandIdentityDigest(repo, []string{"proof/b", "proof/a"})
	if err != nil {
		t.Fatal(err)
	}
	if forward != reverse {
		t.Fatalf("closure digest depends on manifest order: forward=%s reverse=%s", forward, reverse)
	}

	left := t.TempDir()
	right := t.TempDir()
	writeFile(t, left, "a", "bc", 0o600)
	writeFile(t, right, "ab", "c", 0o600)
	leftDigest, err := commandIdentityDigest(left, []string{"a"})
	if err != nil {
		t.Fatal(err)
	}
	rightDigest, err := commandIdentityDigest(right, []string{"ab"})
	if err != nil {
		t.Fatal(err)
	}
	if leftDigest == rightDigest {
		t.Fatal("length-framed path/content tuples collapsed an ambiguous raw concatenation")
	}
}

func TestOldSelfCertifyingProofAPIsAreImpossible(t *testing.T) {
	parsed, err := parser.ParseFile(token.NewFileSet(), "proof/proof.go", nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	exported := map[string]*ast.FuncDecl{}
	for _, declaration := range parsed.Decls {
		if fn, ok := declaration.(*ast.FuncDecl); ok && fn.Recv == nil && ast.IsExported(fn.Name.Name) {
			exported[fn.Name.Name] = fn
		}
	}
	for _, forbidden := range []string{"HTTPServed", "HTTPResponseIsServed", "ExternalReceipt", "ExternalReceiptIsServed", "InteropServed", "NewEvidence", "EvidenceFromObservations"} {
		if exported[forbidden] != nil {
			t.Errorf("old self-certifying API %s still exists", forbidden)
		}
	}
	for name, fn := range exported {
		if fn.Type.Results == nil {
			continue
		}
		returnsEvidence := false
		for _, field := range fn.Type.Results.List {
			returnsEvidence = returnsEvidence || expressionName(field.Type) == "Evidence"
		}
		if returnsEvidence {
			allowed := false
			for _, constructor := range verifierConstructor {
				allowed = allowed || name == constructor
			}
			if !allowed {
				t.Errorf("generic exported evidence constructor %s is not in the closed verifier set", name)
			}
		}
	}
}

func TestManifestIsVersionedGranularAndCoversEveryDoDCard(t *testing.T) {
	manifest, err := loadManifest("manifest.json")
	if err != nil {
		t.Fatalf("load committed manifest: %v", err)
	}
	if len(manifest.Entries) != 81 {
		t.Fatalf("manifest entries = %d, want one exact row for each of the 81 DoD-gated backlog cards", len(manifest.Entries))
	}
	seen := map[string]bool{}
	for _, entry := range manifest.Entries {
		if seen[entry.CardID] {
			t.Errorf("duplicate card %s", entry.CardID)
		}
		seen[entry.CardID] = true
	}
	for _, card := range []string{"WIRE-CONN-000", "WIRE-CONN-124", "WIRE-EXTCA-114", "WIRE-DYNSEC-108", "WIRE-SYNC-108", "WIRE-HSM-106", "WIRE-CODESIGN-001", "WIRE-RIGHTSIZE-001", "WIRE-K8SDESC-102"} {
		if !seen[card] {
			t.Errorf("manifest missing %s", card)
		}
	}
}

func TestExactlyThirteenManifestRuntimeProofFilesUseDedicatedBuildConstraint(t *testing.T) {
	manifest, err := loadManifest("manifest.json")
	if err != nil {
		t.Fatal(err)
	}
	repo, err := filepath.Abs(filepath.Join("..", ".."))
	if err != nil {
		t.Fatal(err)
	}
	seen := map[string]bool{}
	for _, entry := range manifest.Entries {
		if !runtimeConfigured(entry.Runtime) || seen[entry.Runtime.File] {
			continue
		}
		seen[entry.Runtime.File] = true
		if err := requireDODProofBuildConstraint(repo, entry.Runtime.File); err != nil {
			t.Errorf("%s: %v", entry.Runtime.File, err)
		}
	}
	if len(seen) != 13 {
		t.Fatalf("unique manifest runtime proof files = %d, want exactly 13", len(seen))
	}

	proofDirs := map[string]bool{}
	for name := range seen {
		proofDirs[filepath.Dir(filepath.Join(repo, filepath.FromSlash(name)))] = true
	}
	tagged := map[string]bool{}
	for dir := range proofDirs {
		paths, globErr := filepath.Glob(filepath.Join(dir, "*_test.go"))
		if globErr != nil {
			t.Fatal(globErr)
		}
		for _, path := range paths {
			raw, readErr := os.ReadFile(path)
			if readErr != nil {
				t.Fatal(readErr)
			}
			firstLine := strings.SplitN(string(raw), "\n", 2)[0]
			if strings.Contains(firstLine, dodProofBuildTag) {
				relative, relErr := filepath.Rel(repo, path)
				if relErr != nil {
					t.Fatal(relErr)
				}
				tagged[filepath.ToSlash(relative)] = true
			}
		}
	}
	if len(tagged) != 13 {
		t.Fatalf("manifest proof-package files carrying reserved proof tag = %d, want exactly 13: %v", len(tagged), tagged)
	}

	ordinary := build.Default
	ordinary.BuildTags = withoutString(ordinary.BuildTags, dodProofBuildTag)
	proofBuild := ordinary
	proofBuild.BuildTags = append(append([]string(nil), ordinary.BuildTags...), dodProofBuildTag)
	for name := range seen {
		if !tagged[name] {
			t.Errorf("manifest runtime file %s does not exclusively own the reserved proof tag", name)
		}
		dir, base := filepath.Split(filepath.Join(repo, filepath.FromSlash(name)))
		matched, matchErr := ordinary.MatchFile(dir, base)
		if matchErr != nil {
			t.Errorf("ordinary build match %s: %v", name, matchErr)
		} else if matched {
			t.Errorf("ordinary internal/server test compilation includes receipt file %s", name)
		}
		matched, matchErr = proofBuild.MatchFile(dir, base)
		if matchErr != nil {
			t.Errorf("proof build match %s: %v", name, matchErr)
		} else if !matched {
			t.Errorf("reserved proof-tag compilation excludes manifest file %s", name)
		}
	}
	for name := range tagged {
		if !seen[name] {
			t.Errorf("reserved proof tag is used by non-manifest runtime file %s", name)
		}
	}
}

func withoutString(values []string, unwanted string) []string {
	out := make([]string, 0, len(values))
	for _, value := range values {
		if value != unwanted {
			out = append(out, value)
		}
	}
	return out
}

func validManifest(t *testing.T, repo, enforcement string) Manifest {
	t.Helper()
	contract := []byte(`{"protocol":"vendor-emulator-v1"}`)
	command := []byte("#!/bin/sh\nexit 0\n")
	writeFile(t, repo, "testdata/vendor-contract.json", string(contract), 0o600)
	writeFile(t, repo, "testdata/vendor-emulator", string(command), 0o700)
	identityFiles := []string{"testdata/vendor-emulator"}
	identityDigest, err := commandIdentityDigest(repo, identityFiles)
	if err != nil {
		t.Fatal(err)
	}
	writeFile(t, repo, "go.mod", "module fixture.example/runtime\n\ngo 1.26\ntoolchain go1.26.4\n", 0o600)
	writeFile(t, repo, "go.sum", "", 0o600)
	writeFile(t, repo, "tools/dodcensus/Dockerfile.runtime-runner", runtimeRunnerFixture(), 0o600)
	writeFile(t, repo, runtimeRunnerBaseFile, "golang:1.26.4-bookworm@sha256:"+strings.Repeat("b", 64)+"\n", 0o600)
	runnerFiles := []string{"go.mod", "go.sum", "tools/dodcensus/Dockerfile.runtime-runner", runtimeRunnerBaseFile}
	runnerDigest, err := commandIdentityDigest(repo, runnerFiles)
	if err != nil {
		t.Fatal(err)
	}
	profile := testStaticProfile()
	profile.RuntimeRunner.Identity = "fixture/runtime-runner@" + runnerDigest
	return Manifest{
		SchemaVersion: 1, ManifestVersion: 1, BinaryPackage: "./cmd/trstctl", DefaultBuildProfile: "static",
		BuildProfiles: map[string]BuildProfile{"static": profile},
		Substrates: map[string]Substrate{"vendor_emulator": {
			Kind: "vendor-emulator", Verifier: "external-write", Execution: "command",
			Command: []string{"testdata/vendor-emulator"}, IdentityFiles: identityFiles, Identity: "vendor/emulator@" + identityDigest,
			ContractFile: "testdata/vendor-contract.json", ContractSHA256: "sha256:" + internalcrypto.SHA256Hex(contract),
		}},
		Entries: []Entry{{
			ID: "connector.nginx", CardID: "WIRE-CONN-101", Capability: "connector", Inventory: boolPtr(true), Enforcement: enforcement,
			Dependencies: []string{"trstctl.com/trstctl/internal/connector/nginx"},
			Assembly:     AssemblyProof{File: "internal/server/run.go", Function: "buildRunDeps", Binding: "returned-field", Field: "ConnectorRegistry", Calls: []string{"newRegistry"}},
			Runtime:      RuntimeProof{Package: "./internal/server", Test: "TestDODConnectorNginxServed", File: "internal/server/dod_nginx_served_test.go", Mode: "assembled-handler", Method: "POST", Path: "/api/v1/connectors/nginx", SubstrateID: "vendor_emulator"},
		}},
	}
}

func testStaticProfile() BuildProfile {
	return BuildProfile{
		BinaryPackage: "./cmd/trstctl", CGOEnabled: "0", GOOS: "linux", GOARCH: "amd64", Release: releaseShipped,
		Artifact: ArtifactProof{
			Workflow: ".github/workflows/release.yml", Job: "image", Dockerfile: "deploy/docker/Dockerfile",
			BuilderAction: "docker/build-push-action@10e90e3645eae34f1e60eeb005ba3a3d33f178e8",
			BuilderOutput: "type=image,rewrite-timestamp=true", BuildOutput: "/out/trstctl",
			BuilderTags: "${{ steps.tags.outputs.tags }}",
			BinaryPath:  "/usr/local/bin/trstctl", Platform: "linux/amd64",
			Companions: []CompanionArtifact{{BinaryPackage: "./cmd/trstctl-signer", BuildOutput: "/out/trstctl-signer", BinaryPath: "/usr/local/bin/trstctl-signer"}},
		},
		RuntimeRunner: RuntimeRunnerProof{
			Dockerfile: "tools/dodcensus/Dockerfile.runtime-runner", Platform: "linux/amd64",
			Identity:      "fixture/runtime-runner@sha256:" + strings.Repeat("a", 64),
			IdentityFiles: []string{"go.mod", "go.sum", "tools/dodcensus/Dockerfile.runtime-runner", runtimeRunnerBaseFile},
		},
	}
}

func writeGateFixture(t *testing.T, repo string, adversarial bool) {
	t.Helper()
	writeFile(t, repo, ".github/workflows/release.yml", releaseFixture(), 0o600)
	writeFile(t, repo, "deploy/docker/Dockerfile", dockerfileFixture(), 0o600)
	writeFile(t, repo, "internal/server/run.go", `package server
import "net/http"
type Deps struct { ConnectorRegistry any }
func newRegistry() any { return nil }
func buildRunDeps() Deps { return Deps{ConnectorRegistry: newRegistry()} }
type Server struct{}
func Build(any, Deps) (*Server, error) { return &Server{}, nil }
func (*Server) Handler() http.Handler { return http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusAccepted) }) }
`, 0o600)
	testSource := `//go:build trstctl_dodproof

package server
import (
    "net/http"
    "testing"
    "trstctl.com/trstctl/tools/dodcensus/proof"
)
func TestDODConnectorNginxServed(t *testing.T) {
    external := proof.StartCommand(t, "connector.nginx")
    endpoint := external.Endpoint()
    _ = endpoint
    deps := buildRunDeps()
    srv, _ := Build(nil, deps)
    req, _ := http.NewRequest("POST", "/api/v1/connectors/nginx", nil)
    session := proof.Start(t, "connector.nginx", srv.Handler(), req)
    payload := []byte("external payload with readback")
    executionReceipt := external.StopAndReceipt()
    session.Complete(proof.ExternalWrite(proof.ExternalWriteProbe{Destination: []byte("nginx/configuration/path"), Written: payload, ReadBack: payload, ExecutionReceipt: executionReceipt}))
}
`
	if adversarial {
		testSource = strings.Replace(testSource, `"net/http"`, `"net/http/httptest"`, 1)
		testSource = strings.Replace(testSource, `deps := buildRunDeps()`, `deps := Deps{ConnectorRegistry: newRegistry()}`, 1)
	}
	writeFile(t, repo, "internal/server/dod_nginx_served_test.go", testSource, 0o600)
}

func writeSharedRuntimeFixture(t *testing.T, repo string) {
	writeGateFixture(t, repo, false)
	source := `//go:build trstctl_dodproof

package server
import (
    "net/http"
    "testing"
    "trstctl.com/trstctl/tools/dodcensus/proof"
)
func exerciseConnector(t *testing.T, id, path string) {
    external := proof.StartCommand(t, id)
    endpoint := external.Endpoint()
    _ = endpoint
    deps := buildRunDeps()
    srv, _ := Build(nil, deps)
    req, _ := http.NewRequest("POST", path, nil)
    session := proof.Start(t, id, srv.Handler(), req)
    payload := []byte("external payload with readback")
    executionReceipt := external.StopAndReceipt()
    session.Complete(proof.ExternalWrite(proof.ExternalWriteProbe{Destination: []byte("connector/configuration/path"), Written: payload, ReadBack: payload, ExecutionReceipt: executionReceipt}))
}
func TestDODSharedConnectors(t *testing.T) {
    only := proof.OnlyExpectation(t)
    if only == "" || only == "connector.nginx" {
        exerciseConnector(t, "connector.nginx", "/api/v1/connectors/nginx")
    }
    if only == "" || only == "connector.apache" {
        exerciseConnector(t, "connector.apache", "/api/v1/connectors/apache")
    }
}
`
	writeFile(t, repo, "internal/server/dod_nginx_served_test.go", source, 0o600)
}

func releaseFixture() string {
	return `name: Release
jobs:
  image:
    permissions:
      packages: write
    steps:
      - name: publish
        uses: docker/build-push-action@10e90e3645eae34f1e60eeb005ba3a3d33f178e8
        with:
          file: deploy/docker/Dockerfile
          platforms: linux/amd64,linux/arm64
          push: true
          outputs: type=image,rewrite-timestamp=true
          tags: ${{ steps.tags.outputs.tags }}
`
}

func dockerfileFixture() string {
	return `FROM golang:1.26 AS build
ENV CGO_ENABLED=0 GOOS=${TARGETOS} GOARCH=${TARGETARCH}
RUN go build -trimpath -o /out/trstctl ./cmd/trstctl
RUN go build -trimpath -o /out/trstctl-signer ./cmd/trstctl-signer
FROM scratch
COPY --from=build /out/trstctl /usr/local/bin/trstctl
COPY --from=build /out/trstctl-signer /usr/local/bin/trstctl-signer
ENTRYPOINT ["/usr/local/bin/trstctl"]
`
}

func runtimeRunnerFixture() string {
	return `ARG BASE_IMAGE
FROM ${BASE_IMAGE}
RUN printf '%s\n' 'snapshot.debian.org/archive/debian/20260701T000000Z' 'snapshot.debian.org/archive/debian-security/20260701T000000Z' 'check-valid-until=no' \
 && rm -f /etc/apt/sources.list.d/debian.sources \
 && apt-get update \
 && apt-get install -y ca-certificates docker.io git openssl python3
ARG KIND_VERSION=v0.31.0
ARG KIND_LINUX_AMD64_SHA256=eb244cbafcc157dff60cf68693c14c9a75c4e6e6fedaf9cd71c58117cb93e3fa
ARG OPENSSL_VERSION=3.5.7
ARG OPENSSL_SOURCE_SHA256=a8c0d28a529ca480f9f36cf5792e2cd21984552a3c8e4aa11a24aa31aeac98e8
RUN /usr/local/bin/openssl list -signature-algorithms
ENV OPENSSL_CONF=/dev/null
COPY go.mod go.sum /runtime-modules/
RUN cd /runtime-modules && GOFLAGS=-mod=readonly go mod download all \
 && chown -R 0:0 /go \
 && chmod -R a-w /go
ENTRYPOINT ["/usr/local/go/bin/go"]
`
}

func testExpectation(path string) runtimeExpectation {
	return runtimeExpectation{
		SchemaVersion: 1, Nonce: strings.Repeat("a", 64), ID: "connector.nginx", BuildProfile: "static",
		Method: "POST", Path: "/api/v1/connectors/nginx", RuntimeMode: "assembled-handler", SubstrateID: "vendor_emulator",
		SubstrateKind: "vendor-emulator", SubstrateIdentity: "vendor/emulator@sha256:" + strings.Repeat("b", 64),
		ContractDigest: "sha256:" + strings.Repeat("c", 64), Verifier: "external-write", ReceiptFile: path,
		EvidenceFile: path + ".evidence", RuntimeRunnerIdentity: "runner@sha256:" + strings.Repeat("e", 64),
		RuntimeRunnerImage: "sha256:" + strings.Repeat("a", 64),
		ReceiptMACKey:      []byte("0123456789abcdef0123456789abcdef"),
	}
}

func receiptFor(expected runtimeExpectation) runtimeReceipt {
	observations := map[string]string{}
	for _, key := range requiredObservations[expected.Verifier] {
		observations[key] = "sha256:" + strings.Repeat("d", 64)
	}
	execution, err := json.Marshal(brokerReceipt{
		SchemaVersion: 1, Challenge: expected.Nonce, EntryID: expected.ID,
		Identity: expected.SubstrateIdentity, ContractDigest: expected.ContractDigest,
		PID: os.Getpid() + 1000, Passed: true,
	})
	if err != nil {
		panic(err)
	}
	observations["execution_receipt_digest"] = "sha256:" + internalcrypto.SHA256Hex(execution)
	receipt := runtimeReceipt{
		SchemaVersion: 1, Nonce: expected.Nonce, ID: expected.ID, BuildProfile: expected.BuildProfile,
		Method: expected.Method, Path: expected.Path, RuntimeMode: expected.RuntimeMode, SubstrateID: expected.SubstrateID,
		SubstrateKind: expected.SubstrateKind, SubstrateIdentity: expected.SubstrateIdentity,
		ContractDigest: expected.ContractDigest, Verifier: expected.Verifier,
		Passed: true, Skipped: false, Observations: observations, ExecutionReceipt: execution,
		RuntimeRunnerIdentity: expected.RuntimeRunnerIdentity, RuntimeRunnerImage: expected.RuntimeRunnerImage,
	}
	if expected.RuntimeMode == "launched-binary" {
		receipt.LaunchedProcess = &launchedProcessReceipt{
			PID: os.Getpid() + 2000, ProcessStartTicks: "1234", ProcessMode: "native",
			BinaryModulePath: expected.LaunchedModulePath, BinaryPackage: expected.LaunchedBinaryPackage,
			BinaryCGOEnabled: expected.LaunchedCGOEnabled, BinaryGOOS: expected.LaunchedGOOS,
			BinaryGOARCH: expected.LaunchedGOARCH, BinaryTags: append([]string(nil), expected.LaunchedTags...),
			BinaryDigest: "sha256:" + strings.Repeat("f", 64),
			BinaryDevice: "42", BinaryInode: "84", Address: "127.0.0.1:19443",
			ListenerInode: "123456", AcceptedConnectionInode: "123457",
		}
	}
	payload, err := runtimeReceiptMACPayload(receipt)
	if err != nil {
		panic(err)
	}
	receipt.MAC = "hmac-sha256:" + hex.EncodeToString(internalcrypto.HMACSHA256(expected.ReceiptMACKey, payload))
	return receipt
}

func writeFile(t *testing.T, repo, name, body string, mode os.FileMode) {
	t.Helper()
	path := filepath.Join(repo, filepath.FromSlash(name))
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(body), mode); err != nil {
		t.Fatal(err)
	}
}

func writeJSON(t *testing.T, path string, value any) {
	t.Helper()
	data, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
}

func cloneStrings(source map[string]string) map[string]string {
	out := make(map[string]string, len(source))
	for key, value := range source {
		out[key] = value
	}
	return out
}

func boolPtr(value bool) *bool { return &value }

func containsArg(args []string, want string) bool {
	for _, arg := range args {
		if arg == want {
			return true
		}
	}
	return false
}

func goTestPass(name string) string {
	return `{"Action":"pass","Test":"` + name + `"}` + "\n"
}
