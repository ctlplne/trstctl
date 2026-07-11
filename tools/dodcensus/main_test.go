// SPDX-License-Identifier: MPL-2.0

package main

import (
	"context"
	"encoding/json"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strings"
	"testing"

	internalcrypto "trstctl.com/trstctl/internal/crypto"
)

type scriptedRunner struct {
	results []commandResult
	calls   []commandCall
	hook    func(commandCall)
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
	if manifest.BuildProfiles["pkcs11_cgo"].Release != releasePlanned || artifactConfigured(manifest.BuildProfiles["pkcs11_cgo"].Artifact) {
		t.Fatal("PKCS#11 profile must remain explicitly planned without a fictional release target/job")
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

func TestRuntimeBindingRejectsHTTptestAndHandBuiltDeps(t *testing.T) {
	repo := t.TempDir()
	writeGateFixture(t, repo, true)
	manifest := validManifest(t, repo, enforcementRequired)
	entry := manifest.Entries[0]
	if evidence := inspectRuntimeBinding(repo, entry, manifest.Substrates); evidence.OK || (!strings.Contains(evidence.Detail, "hand-constructs") && !strings.Contains(evidence.Detail, "not bound")) {
		t.Fatalf("httptest/hand-built evidence was accepted: %+v", evidence)
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
				writeJSON(t, expected.ReceiptFile, receiptFor(expected))
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
			if !call.Profile.HostRuntime {
				t.Fatal("runtime Go test was cross-compiled instead of executed on the host")
			}
		}
	}
	if goTests != 1 {
		t.Fatalf("shared profile/package/test executed %d times, want one raw execution", goTests)
	}
}

func TestDODCommandEnvironmentSeparatesArtifactFromHostRuntime(t *testing.T) {
	base := []string{"PATH=/bin", "GOOS=fake", "GOARCH=fake", "TRSTCTL_DOD_EXPECTATIONS=forged"}
	artifact := strings.Join(dodCommandEnvironment(base, "/tmp/artifact", BuildProfile{CGOEnabled: "0", GOOS: "linux", GOARCH: "amd64"}), "\n")
	runtimeProfile := BuildProfile{CGOEnabled: "0", GOOS: "linux", GOARCH: "amd64", HostRuntime: true, RuntimeEnv: map[string]string{"TRSTCTL_DOD_EXPECTATIONS": "issued"}}
	host := strings.Join(dodCommandEnvironment(base, "/tmp/runtime", runtimeProfile), "\n")
	if !strings.Contains(artifact, "GOOS=linux") || !strings.Contains(artifact, "GOARCH=amd64") {
		t.Fatalf("artifact dependency graph is not pinned: %s", artifact)
	}
	if strings.Contains(host, "GOOS=") || strings.Contains(host, "GOARCH=") {
		t.Fatalf("host runtime test was cross-compiled: %s", host)
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
		{name: "go", args: []string{"test", "-json", "-count=1", "-run", "^TestDODConnectorNginxServed$", "./internal/server"}},
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
		{name: "go", args: []string{"test", "-json", "-count=1", "-run", "TestDOD", "./internal/server", "-exec=/tmp/attacker"}},
		{name: "go", args: []string{"test", "-json", "-count=1", "-run", "TestDOD", "../outside"}},
	}
	for _, test := range rejected {
		if err := validateDODGoInvocation(test.name, test.args); err == nil {
			t.Errorf("validateDODGoInvocation(%q, %q) unexpectedly accepted unsafe argv", test.name, test.args)
		}
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
		t.Fatalf("manifest entries = %d, want 81", len(manifest.Entries))
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

func validManifest(t *testing.T, repo, enforcement string) Manifest {
	t.Helper()
	contract := []byte(`{"protocol":"vendor-emulator-v1"}`)
	command := []byte("#!/bin/sh\nexit 0\n")
	writeFile(t, repo, "testdata/vendor-contract.json", string(contract), 0o600)
	writeFile(t, repo, "testdata/vendor-emulator", string(command), 0o700)
	return Manifest{
		SchemaVersion: 1, ManifestVersion: 1, BinaryPackage: "./cmd/trstctl", DefaultBuildProfile: "static",
		BuildProfiles: map[string]BuildProfile{"static": testStaticProfile()},
		Substrates: map[string]Substrate{"vendor_emulator": {
			Kind: "vendor-emulator", Verifier: "external-write", Execution: "command",
			Command: []string{"testdata/vendor-emulator"}, Identity: "vendor/emulator@sha256:" + internalcrypto.SHA256Hex(command),
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
	testSource := `package server
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
	source := `package server
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
    exerciseConnector(t, "connector.nginx", "/api/v1/connectors/nginx")
    exerciseConnector(t, "connector.apache", "/api/v1/connectors/apache")
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
FROM scratch
COPY --from=build /out/trstctl /usr/local/bin/trstctl
ENTRYPOINT ["/usr/local/bin/trstctl"]
`
}

func testExpectation(path string) runtimeExpectation {
	return runtimeExpectation{
		SchemaVersion: 1, Nonce: strings.Repeat("a", 64), ID: "connector.nginx", BuildProfile: "static",
		Method: "POST", Path: "/api/v1/connectors/nginx", SubstrateID: "vendor_emulator",
		SubstrateKind: "vendor-emulator", SubstrateIdentity: "vendor/emulator@sha256:" + strings.Repeat("b", 64),
		ContractDigest: "sha256:" + strings.Repeat("c", 64), Verifier: "external-write", ReceiptFile: path,
	}
}

func receiptFor(expected runtimeExpectation) runtimeReceipt {
	observations := map[string]string{}
	for _, key := range requiredObservations[expected.Verifier] {
		observations[key] = "sha256:" + strings.Repeat("d", 64)
	}
	return runtimeReceipt{
		SchemaVersion: 1, Nonce: expected.Nonce, ID: expected.ID, BuildProfile: expected.BuildProfile,
		Method: expected.Method, Path: expected.Path, SubstrateID: expected.SubstrateID,
		SubstrateKind: expected.SubstrateKind, SubstrateIdentity: expected.SubstrateIdentity,
		ContractDigest: expected.ContractDigest, Verifier: expected.Verifier,
		Passed: true, Skipped: false, Observations: observations,
	}
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
