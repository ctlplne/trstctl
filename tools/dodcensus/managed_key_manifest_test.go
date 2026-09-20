// SPDX-License-Identifier: BUSL-1.1

package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

func TestManagedKeyManifestMatchesEnterpriseSignerAssemblyAndRuntimeBinding(t *testing.T) {
	repo, err := filepath.Abs(filepath.Join("..", ".."))
	if err != nil {
		t.Fatal(err)
	}
	manifest, err := loadManifest(filepath.Join(repo, "tools", "dodcensus", "manifest.json"))
	if err != nil {
		t.Fatal(err)
	}
	checked := 0
	for _, entry := range manifest.Entries {
		if !strings.HasPrefix(entry.ID, "hsm_kms.") {
			continue
		}
		checked++
		if entry.Enforcement != enforcementRequired {
			t.Errorf("%s enforcement=%q, want required", entry.ID, entry.Enforcement)
		}
		if entry.ID == "hsm_kms.runtime" {
			if entry.Assembly.File != "cmd/trstctl-signer/ee_attach.go" {
				t.Errorf("%s must root assembly at the tagged signer attach seam, got %s", entry.ID, entry.Assembly.File)
			}
		} else if entry.Assembly.File != "ee/managedkeys/signerwiring/wiring.go" {
			t.Errorf("%s provider construction escaped the ee/ fence: %s", entry.ID, entry.Assembly.File)
		}
		_, profile := resolvedProfile(manifest, entry)
		if evidence := inspectAssembly(repo, entry, profile); !evidence.OK {
			t.Errorf("%s assembly: %s; required=%v found=%v", entry.ID, evidence.Detail, evidence.Required, evidence.Found)
		}
		if evidence := inspectRuntimeBinding(repo, entry, manifest.Substrates); !evidence.OK {
			t.Errorf("%s runtime: %s; required=%v found=%v", entry.ID, evidence.Detail, evidence.Required, evidence.Found)
		}
	}
	if checked != 7 {
		t.Fatalf("managed-key manifest entries = %d, want runtime + six providers", checked)
	}
}

func TestManagedKeySubstrateIdentityCoversExactRuntimeClosure(t *testing.T) {
	repo, manifest := loadManagedKeyManifest(t)
	substrate := manifest.Substrates["managed_key_custody"]
	want := append([]string(nil), managedKeyIdentityClosure...)
	got := append([]string(nil), substrate.IdentityFiles...)
	sort.Strings(want)
	sort.Strings(got)
	if strings.Join(got, "\n") != strings.Join(want, "\n") {
		t.Fatalf("managed-key identity closure = %v, want exact proof runtime closure %v", got, want)
	}
	digest, err := commandIdentityDigest(repo, substrate.IdentityFiles)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasSuffix(substrate.Identity, "@"+digest) {
		t.Fatalf("managed-key identity %q does not bind closure digest %s", substrate.Identity, digest)
	}
	if evidence := inspectSubstrate(repo, "managed_key_custody", substrate); !evidence.OK {
		t.Fatalf("committed managed-key identity closure: %+v", evidence)
	}
}

func TestManagedKeySubstrateIdentityRejectsEveryMutatedOrMissingRuntimeFile(t *testing.T) {
	repo, manifest := loadManagedKeyManifest(t)
	substrate := manifest.Substrates["managed_key_custody"]
	for _, target := range managedKeyIdentityClosure {
		t.Run("mutated_"+filepath.Base(target), func(t *testing.T) {
			fixture := copyManagedKeyIdentityFixture(t, repo, substrate, "")
			path := filepath.Join(fixture, filepath.FromSlash(target))
			file, err := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0) // #nosec G304 -- test reads its own fixture/tempdir path (CWE-22)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := file.WriteString("\n# identity mutation\n"); err != nil {
				_ = file.Close()
				t.Fatal(err)
			}
			if err := file.Close(); err != nil {
				t.Fatal(err)
			}
			if evidence := inspectSubstrate(fixture, "managed_key_custody", substrate); evidence.OK {
				t.Fatalf("mutation of %s retained trusted substrate identity", target)
			}
		})
		t.Run("missing_"+filepath.Base(target), func(t *testing.T) {
			fixture := copyManagedKeyIdentityFixture(t, repo, substrate, target)
			if evidence := inspectSubstrate(fixture, "managed_key_custody", substrate); evidence.OK {
				t.Fatalf("missing identity file %s retained trusted substrate identity", target)
			}
		})
	}
}

func TestManagedKeyClosureRejectsRehashedMutableBuildInputs(t *testing.T) {
	repo, manifest := loadManagedKeyManifest(t)
	base := manifest.Substrates["managed_key_custody"]
	tests := []struct {
		name        string
		file        string
		old         string
		replacement string
	}{
		{"default builder tag", "deploy/docker/Dockerfile.signer-hsm", "ARG BUILD_IMAGE\n", "ARG BUILD_IMAGE=golang:latest\n"},
		{"default signer parent tag", "tools/dodcensus/Dockerfile.managed-key-runtime", "ARG SIGNER_IMAGE\n", "ARG SIGNER_IMAGE=trstctl-signer-hsm:dod\n"},
		{"moving apt repository", "deploy/docker/Dockerfile.signer-hsm", "http://snapshot.debian.org/archive/debian/20260701T000000Z", "http://deb.debian.org/debian"},
		{"release drops pinned builder", ".github/workflows/release.yml", "BUILD_IMAGE=${{ steps.hsm_basedigest.outputs.build_ref }}", "BUILD_IMAGE=golang:latest"},
		{"runtime uses signer tag", "internal/server/dod_managed_key_runtime_test.go", `"SIGNER_IMAGE="+signerImage`, `"SIGNER_IMAGE=trstctl-signer-hsm:dod"`},
		{"runtime changes shipped platform", "internal/server/dod_managed_key_runtime_test.go", `"linux/amd64"`, `"linux/arm64"`},
		{"runtime image inspection drops platform", "internal/server/dod_managed_key_runtime_test.go", `"--format={{.Id}} {{.Os}}/{{.Architecture}}"`, `"--format={{.Id}}"`},
		{"base pull drops platform", "internal/server/dod_managed_key_runtime_test.go", `"docker", "pull", "--platform", dodManagedKeyRuntimePlatform, taggedImage`, `"docker", "pull", taggedImage`},
		{"runtime restores embedded postgres sibling", "internal/server/dod_managed_key_runtime_test.go", `postgresDSN: dodManagedKeyPostgresDSN(t)`, `postgresDSN: serverTestPostgresDSN(t)`},
		{"postgres image becomes mutable", "internal/server/dod_managed_key_runtime_test.go", `postgres:16.15-alpine@sha256:cf78e76683b9ca8c5733cbbdce6c9262b45b6767934dd0a95e671f9a0fc20685`, `postgres:16.15-alpine`},
		{"postgres publishes on every interface", "internal/server/dod_managed_key_runtime_test.go", `fmt.Sprintf("127.0.0.1:%d:5432", port)`, `fmt.Sprintf("0.0.0.0:%d:5432", port)`},
		{"postgres runs as root", "internal/server/dod_managed_key_runtime_test.go", `postgresUser := strconv.Itoa(uid) + ":" + strconv.Itoa(gid)`, `postgresUser := "0:0"`},
		{"postgres shares host PID namespace", "internal/server/dod_managed_key_runtime_test.go", `"--network", route.network, "--pids-limit", "256", "--memory", "512m"`, `"--network", route.network, "--pid", "host", "--pids-limit", "256", "--memory", "512m"`},
		{"inner emulator run drops platform", "tools/dodcensus/substrates/managed_keys.py", `"docker", "run", "--rm", "--platform", "linux/amd64", "--name"`, `"docker", "run", "--rm", "--name"`},
		{"receipt omits runtime image id", "tools/dodcensus/substrates/managed_keys.py", `"runtime_identity": image`, `"runtime_identity": "mutable"`},
		{"signer drops nonroot uid", "internal/server/dod_managed_key_runtime_test.go", `"--user", strconv.Itoa(uid) + ":" + strconv.Itoa(gid)`, `"--user", "0:0"`},
		{"signer drops no-new-privileges", "internal/server/dod_managed_key_runtime_test.go", `"--security-opt", "no-new-privileges"`, `"--security-opt", "seccomp=unconfined"`},
		{"signer restores ambient capabilities", "internal/server/dod_managed_key_runtime_test.go", `"--cap-drop", "ALL"`, `"--cap-add", "ALL"`},
		{"signer bypasses host mount translation", "internal/server/dod_managed_key_runtime_test.go", `runtimeMountSource := proof.DockerHostMountSource(r.t, r.dir)`, `runtimeMountSource := r.dir`},
		{"signer drops scoped nss", "internal/server/dod_managed_key_runtime_test.go", `"--mount", "type=bind,src="+passwdMountSource+",dst=/etc/passwd,readonly"`, `"--mount", "type=bind,src="+runtimeMountSource+",dst=/etc,readonly"`},
		{"signer nss loses exclusive mode", "internal/server/dod_managed_key_runtime_test.go", `os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600`, `os.O_WRONLY|os.O_CREATE, 0o666`},
		{"swtpm re-enables incompatible internal seccomp", "tools/dodcensus/substrates/managed_key_signer_entrypoint.sh", `--seccomp action=none`, `--seccomp action=kill`},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			fixture := copyManagedKeyIdentityFixture(t, repo, base, "")
			path := filepath.Join(fixture, filepath.FromSlash(tc.file))
			raw, err := os.ReadFile(path) // #nosec G304 -- test reads its own fixture/tempdir path (CWE-22)
			if err != nil {
				t.Fatal(err)
			}
			mutated := strings.Replace(string(raw), tc.old, tc.replacement, 1)
			if mutated == string(raw) {
				t.Fatalf("mutation anchor %q is absent from %s", tc.old, tc.file)
			}
			if err := os.WriteFile(path, []byte(mutated), 0o600); err != nil { // #nosec G703 -- test path inside its own tempdir/checkout (CWE-22)
				t.Fatal(err)
			}
			candidate := base
			digest, err := commandIdentityDigest(fixture, candidate.IdentityFiles)
			if err != nil {
				t.Fatal(err)
			}
			prefix, _, ok := strings.Cut(candidate.Identity, "@")
			if !ok {
				t.Fatal("managed-key identity has no digest separator")
			}
			candidate.Identity = prefix + "@" + digest
			if evidence := inspectSubstrate(fixture, "managed_key_custody", candidate); evidence.OK {
				t.Fatalf("rehashed mutable managed-key build input passed: %+v", evidence)
			}
		})
	}
}

func TestManagedKeyClosureRejectsRehashedTPMRestartSpoofs(t *testing.T) {
	repo, manifest := loadManagedKeyManifest(t)
	base := manifest.Substrates["managed_key_custody"]
	tests := []struct {
		name        string
		old         string
		replacement string
		suffix      string
	}{
		{
			name:        "restart anchors survive only in comments",
			old:         `r.dockerExecTPM(true, "shutdown TPM emulator before signer restart", "tpm2_shutdown", "-c")`,
			replacement: `_ = key`,
			suffix: `

// Spoofed legacy source anchors: "shutdown TPM emulator before signer restart".
// tpm2_shutdown -c
// did not survive signer restart
`,
		},
		{
			name:        "signature survives only in dead helper",
			old:         `r.assertTPMPostRestartSignature(key)`,
			replacement: `_ = key`,
			suffix: `

func dodDeadTPMRestartSpoof(r *dodManagedKeyRuntime, key dodManagedKeyWire) {
	r.assertTPMPostRestartSignature(key)
}
`,
		},
		{
			name:        "managed-key approval survives only in dead helper",
			old:         `runtime.approveManagedKeyAction(generated.KeyID, "rotate")`,
			replacement: `_ = generated.KeyID`,
			suffix: `

func dodDeadManagedKeyApprovalSpoof(runtime *dodManagedKeyRuntime, generated dodManagedKeyWire) {
	runtime.approveManagedKeyAction(generated.KeyID, "rotate")
}
`,
		},
		{
			name:        "one approval retry reuses the zero approval response",
			old:         `oneApproval := dodManagedKeyRequest(r, http.MethodPost, path, action, map[string]string{"key_id": keyID})`,
			replacement: `oneApproval := denied`,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			fixture := copyManagedKeyIdentityFixture(t, repo, base, "")
			path := filepath.Join(fixture, "internal", "server", "dod_managed_key_runtime_test.go")
			raw, err := os.ReadFile(path) // #nosec G304 -- test reads its own fixture/tempdir path (CWE-22)
			if err != nil {
				t.Fatal(err)
			}
			mutated := strings.Replace(string(raw), tc.old, tc.replacement, 1) + tc.suffix
			if !strings.Contains(string(raw), tc.old) {
				t.Fatalf("mutation anchor %q is absent", tc.old)
			}
			if err := os.WriteFile(path, []byte(mutated), 0o600); err != nil { // #nosec G703 -- test path inside its own tempdir/checkout (CWE-22)
				t.Fatal(err)
			}
			candidate := rehashedManagedKeyCandidate(t, fixture, base)
			evidence := inspectSubstrate(fixture, "managed_key_custody", candidate)
			if evidence.OK {
				t.Fatalf("rehashed TPM restart spoof passed: %+v", evidence)
			}
			if !strings.Contains(evidence.Detail, "managed-key TPM restart proof") {
				t.Fatalf("spoof failed outside the TPM restart AST closure: %+v", evidence)
			}
		})
	}
}

func TestManagedKeyTPMRestartClosureFollowsProductionPath(t *testing.T) {
	repo, _ := loadManagedKeyManifest(t)
	path := filepath.Join(repo, "internal", "server", "dod_managed_key_runtime_test.go")
	raw, err := os.ReadFile(path) // #nosec G304 -- test reads its own fixture/tempdir path (CWE-22)
	if err != nil {
		t.Fatal(err)
	}
	if err := inspectManagedKeyTPMRestartClosure(path, string(raw)); err != nil {
		t.Fatal(err)
	}
}

func rehashedManagedKeyCandidate(t *testing.T, repo string, candidate Substrate) Substrate {
	t.Helper()
	digest, err := commandIdentityDigest(repo, candidate.IdentityFiles)
	if err != nil {
		t.Fatal(err)
	}
	prefix, _, ok := strings.Cut(candidate.Identity, "@")
	if !ok {
		t.Fatal("managed-key identity has no digest separator")
	}
	candidate.Identity = prefix + "@" + digest
	return candidate
}

func TestManagedKeyRuntimeUsesContentAddressedImageAtBothRunSites(t *testing.T) {
	repo, _ := loadManagedKeyManifest(t)
	runtimeSource, err := os.ReadFile(filepath.Join(repo, "internal", "server", "dod_managed_key_runtime_test.go")) // #nosec G304 -- test reads its own fixture/tempdir path (CWE-22)
	if err != nil {
		t.Fatal(err)
	}
	source := string(runtimeSource)
	for _, required := range []string{
		`buildBase := dodPinnedBaseImage(t, "golang:"+goVersion+"-bookworm", "golang")`,
		`runtimeBase := dodPinnedBaseImage(t, "debian:bookworm-slim", "debian")`,
		`"docker", "pull", "--platform", dodManagedKeyRuntimePlatform, taggedImage`,
		`"--format={{json .RepoDigests}}"`,
		`"docker", "build", "--platform", dodManagedKeyRuntimePlatform, "-f", "deploy/docker/Dockerfile.signer-hsm"`,
		`signerImage := dodBuiltImageID(t, "trstctl-signer-hsm:dod", dodManagedKeyRuntimePlatform)`,
		`"docker", "build", "--platform", dodManagedKeyRuntimePlatform, "-f", "tools/dodcensus/Dockerfile.managed-key-runtime"`,
		`"SIGNER_IMAGE="+signerImage`,
		`runtimeImage := dodBuiltImageID(t, "trstctl-managed-key-runtime:dod", dodManagedKeyRuntimePlatform)`,
		`"--format={{.Id}} {{.Os}}/{{.Architecture}}"`,
		`len(fields) != 2 || fields[1] != platform`,
		`t.Setenv("TRSTCTL_HSM_PROOF_IMAGE", runtimeImage)`,
		`runtimeImage: runtimeImage`,
		`r.artifacts.runtimeImage`,
		`"--user", strconv.Itoa(uid) + ":" + strconv.Itoa(gid)`,
		`"--security-opt", "no-new-privileges", "--cap-drop", "ALL"`,
		`runtimeMountSource := proof.DockerHostMountSource(r.t, r.dir)`,
		`passwdMountSource := proof.DockerHostMountSource(r.t, passwdFile)`,
		`groupMountSource := proof.DockerHostMountSource(r.t, groupFile)`,
		`"--mount", "type=bind,src="+runtimeMountSource+",dst=/runtime"`,
		`"--mount", "type=bind,src="+passwdMountSource+",dst=/etc/passwd,readonly"`,
		`"--mount", "type=bind,src="+groupMountSource+",dst=/etc/group,readonly"`,
		`os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)`,
	} {
		if !strings.Contains(source, required) {
			t.Errorf("managed-key runtime source omits content-addressed image dataflow %q", required)
		}
	}
	if count := strings.Count(source, `"--platform", dodManagedKeyRuntimePlatform`); count != 4 {
		t.Errorf("managed-key runtime pins exact shipped pull/build/run platform %d times, want four", count)
	}
	for _, forbidden := range []string{
		`t.Setenv("TRSTCTL_HSM_PROOF_IMAGE", "trstctl-managed-key-runtime:dod")`,
		`"trstctl-managed-key-runtime:dod",\n\t\t"--mtls-listen"`,
		`"SIGNER_IMAGE=trstctl-signer-hsm:dod"`,
		`"docker", "image", "inspect", "--format={{.Id}}", image`,
		`"--privileged"`,
		`"seccomp=unconfined"`,
		`"--user", "0:0"`,
		`"-v", r.dir+":/runtime"`,
	} {
		if strings.Contains(source, forbidden) {
			t.Errorf("managed-key runtime still runs mutable image tag via %q", forbidden)
		}
	}

	pythonSource, err := os.ReadFile(filepath.Join(repo, "tools", "dodcensus", "substrates", "managed_keys.py")) // #nosec G304 -- test reads its own fixture/tempdir path (CWE-22)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(pythonSource), "image = required_image_id()") ||
		!strings.Contains(string(pythonSource), `"docker", "run", "--rm", "--platform", "linux/amd64"`) ||
		!strings.Contains(string(pythonSource), `"runtime_identity": image`) ||
		strings.Contains(string(pythonSource), `os.environ.get(IMAGE_ENV, "trstctl-managed-key-runtime:dod")`) {
		t.Fatal("managed-key substrate does not fail closed on a content-addressed inner image id")
	}

	entrypointSource, err := os.ReadFile(filepath.Join(repo, "tools", "dodcensus", "substrates", "managed_key_signer_entrypoint.sh")) // #nosec G304 -- test reads its own fixture/tempdir path (CWE-22)
	if err != nil {
		t.Fatal(err)
	}
	if count := strings.Count(string(entrypointSource), "--seccomp action=none"); count != 1 {
		t.Fatalf("managed-key signer swtpm internal seccomp exception count = %d, want one", count)
	}
}

func TestManagedKeyRuntimeClosureRejectsTestToProductInjectionPrimitives(t *testing.T) {
	repo, manifest := loadManagedKeyManifest(t)
	base := manifest.Substrates["managed_key_custody"]
	for _, primitive := range []string{
		`process_vm_writev`,
		`ptrace`,
		`/proc/123/mem`,
		`"--cap-add"`,
		`"docker", "exec"`,
		`/var/run/docker.sock`,
	} {
		t.Run(strings.NewReplacer("/", "_", `"`, "").Replace(primitive), func(t *testing.T) {
			fixture := copyManagedKeyIdentityFixture(t, repo, base, "")
			path := filepath.Join(fixture, "internal", "server", "dod_managed_key_runtime_test.go")
			raw, err := os.ReadFile(path) // #nosec G304 -- test reads its own fixture/tempdir path (CWE-22)
			if err != nil {
				t.Fatal(err)
			}
			mutated := append(raw, []byte("\n// adversarial runtime primitive: "+primitive+"\n")...)
			if err := os.WriteFile(path, mutated, 0o600); err != nil { // #nosec G703 -- test path inside its own tempdir/checkout (CWE-22)
				t.Fatal(err)
			}
			candidate := rehashedManagedKeyCandidate(t, fixture, base)
			if evidence := inspectSubstrate(fixture, "managed_key_custody", candidate); evidence.OK || !strings.Contains(evidence.Detail, "managed-key runtime retains mutable image input") {
				t.Fatalf("rehashed runtime-injection primitive %q was not rejected exactly: %+v", primitive, evidence)
			}
		})
	}
}

func TestManagedKeyClosureRejectsRehashedControlEndpointBypasses(t *testing.T) {
	repo, manifest := loadManagedKeyManifest(t)
	base := manifest.Substrates["managed_key_custody"]
	for _, test := range []struct {
		name, old, replacement string
	}{
		{
			name:        "control plane dials Docker host directly",
			old:         `control["TRSTCTL_MANAGED_KEYS_AWS_ENDPOINT"] = controlEndpoint`,
			replacement: `control["TRSTCTL_MANAGED_KEYS_AWS_ENDPOINT"] = endpoint`,
		},
		{
			name:        "relay listens beyond runner loopback",
			old:         `listener, err := net.Listen("tcp4", "127.0.0.1:0")`,
			replacement: `listener, err := net.Listen("tcp4", "0.0.0.0:0")`,
		},
		{
			name:        "relay accepts arbitrary upstream host",
			old:         `parsed.Hostname() != allowedHost`,
			replacement: `false`,
		},
		{
			name:        "signer endpoint loses Docker routing seam",
			old:         `signerAddress := dodManagedKeySignerAddress(r.t, r.signerPort)`,
			replacement: `signerAddress := net.JoinHostPort("127.0.0.1", strconv.Itoa(r.signerPort))`,
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			fixture := copyManagedKeyIdentityFixture(t, repo, base, "")
			path := filepath.Join(fixture, "internal", "server", "dod_managed_key_runtime_test.go")
			raw, err := os.ReadFile(path) // #nosec G304 -- test reads its own fixture/tempdir path (CWE-22)
			if err != nil {
				t.Fatal(err)
			}
			mutated := strings.Replace(string(raw), test.old, test.replacement, 1)
			if mutated == string(raw) {
				t.Fatalf("mutation anchor %q is absent", test.old)
			}
			if err := os.WriteFile(path, []byte(mutated), 0o600); err != nil { // #nosec G703 -- test path inside its own tempdir/checkout (CWE-22)
				t.Fatal(err)
			}
			candidate := rehashedManagedKeyCandidate(t, fixture, base)
			if evidence := inspectSubstrate(fixture, "managed_key_custody", candidate); evidence.OK {
				t.Fatalf("rehashed managed-key endpoint bypass passed: %+v", evidence)
			}
		})
	}
}

func TestManagedKeyCloudEmulatorCoversDurableLifecyclePreflights(t *testing.T) {
	repo, _ := loadManagedKeyManifest(t)
	path := filepath.Join(repo, "tools", "dodcensus", "substrates", "managed_keys.py")
	program := `
import importlib.util, sys, tempfile
from pathlib import Path

spec = importlib.util.spec_from_file_location("managed_keys", sys.argv[1])
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)

class FakeKey:
    def __init__(self, key_id, tags=None, state="active"):
        self.key_id = key_id
        self.tags = dict(tags or {})
        self.state = state
        self.public_der = b"d" * 256
        self.public_pem = Path(tempfile.mkdtemp()) / "public.pem"
        self.public_pem.write_text("PUBLIC")

def handler(entry_id):
    state = module.State(entry_id, Path(tempfile.mkdtemp()))
    instance = object.__new__(module.handler_for(state))
    responses = []
    instance.send_json = lambda status, value: responses.append((status, value))
    return state, instance, responses

def fake_create(state, key_id):
    def create(*_args, **_kwargs):
        key = FakeKey(key_id, _kwargs.get("tags") or (_args[1] if len(_args) > 1 else None))
        state.keys[key_id] = key
        state.create_count += 1
        return key
    return create

# AWS durable create first inventories keys, then inventories exact key tags.
state, request, responses = handler("hsm_kms.aws_kms")
state.keys["aws-key-1"] = FakeKey("aws-key-1", {"trstctl-managed-key-operation": "digest"})
request.headers = {"X-Amz-Target": "TrentService.ListKeys"}
request.aws({})
assert responses.pop() == (200, {"Keys": [{"KeyId": "aws-key-1", "KeyArn": "arn:aws:kms:us-east-1:123456789012:key/aws-key-1"}], "Truncated": False})
request.headers = {"X-Amz-Target": "TrentService.ListResourceTags"}
request.aws({"KeyId": "aws-key-1"})
assert responses.pop() == (200, {"Tags": [{"TagKey": "trstctl-managed-key-operation", "TagValue": "digest"}], "Truncated": False})
state.create = fake_create(state, "aws-key-2")
request.headers = {"X-Amz-Target": "TrentService.CreateKey"}
request.aws({"KeySpec": "RSA_2048", "KeyUsage": "SIGN_VERIFY", "Tags": [{"TagKey": "trstctl-managed-key-operation", "TagValue": "next"}]})
status, created = responses.pop()
assert status == 200 and created["KeyMetadata"]["KeyId"] == "aws-key-2"
assert state.keys["aws-key-2"].tags == {"trstctl-managed-key-operation": "next"}
for local_state, provider_state in (("active", "Enabled"), ("revoked", "Disabled"), ("zeroized", "PendingDeletion")):
    state.keys["aws-key-2"].state = local_state
    request.headers = {"X-Amz-Target": "TrentService.DescribeKey"}
    request.aws({"KeyId": "aws-key-2"})
    status, described = responses.pop()
    assert status == 200 and described["KeyMetadata"]["KeyState"] == provider_state
state.observe_provider_request("POST", "/", "TrentService.ListKeys")
diagnostics = state.diagnostics()
assert diagnostics["provider_requests"] == 1 and diagnostics["auth_failures"] == 0
assert diagnostics["last_provider_request"]["target"] == "TrentService.ListKeys"

# Azure uses deterministic GET-before-create and needs enabled state for replay.
state, request, responses = handler("hsm_kms.azure_key_vault")
request.command = "GET"
request.path = "/keys/trstctl-generate-proof?api-version=7.4"
request.headers = {"Authorization": "Bearer " + module.AZURE_TOKEN}
request.do_GET()
assert responses.pop()[0] == 404
state.create_named = fake_create(state, "trstctl-generate-proof")
request.path = "/keys/trstctl-generate-proof/create?api-version=7.4"
request.azure({"kty": "RSA", "key_size": 2048})
status, created = responses.pop()
assert status == 200 and "/keys/trstctl-generate-proof/v1" in created["key"]["kid"]
request.path = "/keys/trstctl-generate-proof/v1?api-version=7.4"
request.do_GET()
status, found = responses.pop()
assert status == 200 and found["attributes"]["enabled"] is True
state.keys["trstctl-generate-proof"].state = "revoked"
request.do_GET()
assert responses.pop()[1]["attributes"]["enabled"] is False

# GCP uses deterministic crypto-key GET and version-state GET around mutations.
state, request, responses = handler("hsm_kms.gcp_kms")
request.command = "GET"
request.headers = {"Authorization": "Bearer " + module.GCP_TOKEN}
request.path = "/v1/" + module.GCP_PARENT + "/cryptoKeys/trstctl-g-proof"
request.do_GET()
assert responses.pop()[0] == 404
state.create_named = fake_create(state, "trstctl-g-proof")
request.path = "/v1/" + module.GCP_PARENT + "/cryptoKeys?cryptoKeyId=trstctl-g-proof"
request.gcp({"purpose": "ASYMMETRIC_SIGN", "versionTemplate": {"algorithm": "RSA_SIGN_PKCS1_2048_SHA256"}})
status, created = responses.pop()
assert status == 200 and created["name"].endswith("/cryptoKeys/trstctl-g-proof")
request.path = "/v1/" + module.GCP_PARENT + "/cryptoKeys/trstctl-g-proof"
request.do_GET()
assert responses.pop()[1]["name"].endswith("/cryptoKeys/trstctl-g-proof")
request.path += "/cryptoKeyVersions/1"
for local_state, provider_state in (("active", "ENABLED"), ("revoked", "DISABLED"), ("zeroized", "DESTROY_SCHEDULED")):
    state.keys["trstctl-g-proof"].state = local_state
    request.do_GET()
    status, version = responses.pop()
    assert status == 200 and version["state"] == provider_state
`
	command := exec.Command("python3", "-c", program, path) // #nosec G204 -- test executes a fixed local tool or fixture it built itself (CWE-78)
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("managed-key cloud durable-lifecycle protocol self-test: %v output=%s", err, output)
	}
}

func TestManagedKeyInnerReceiptValidationRejectsIdentityAndPIDForgery(t *testing.T) {
	repo, _ := loadManagedKeyManifest(t)
	path := filepath.Join(repo, "tools", "dodcensus", "substrates", "managed_keys.py")
	program := `
import importlib.util, os, sys
spec = importlib.util.spec_from_file_location("managed_keys", sys.argv[1])
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)
expected = dict(challenge="nonce", entry_id="hsm_kms.aws_kms", identity="identity", contract="sha256:contract", outer_pid=44)
valid = {"schema_version": 1, "challenge": "nonce", "entry_id": "hsm_kms.aws_kms", "identity": "identity", "contract_digest": "sha256:contract", "pid": 55, "ready": True}
assert module.inner_envelope_matches(valid, flag="ready", **expected)
for field, value in (("schema_version", 2), ("challenge", "wrong"), ("entry_id", "wrong"), ("identity", "wrong"), ("contract_digest", "wrong"), ("pid", 0), ("pid", 44), ("pid", True), ("ready", 1)):
    candidate = dict(valid)
    candidate[field] = value
    assert not module.inner_envelope_matches(candidate, flag="ready", **expected), (field, value)
final = dict(valid)
final.pop("ready")
final["passed"] = True
assert module.inner_envelope_matches(final, flag="passed", expected_pid=55, **expected)
assert not module.inner_envelope_matches(final, flag="passed", expected_pid=56, **expected)
os.environ[module.IMAGE_ENV] = "trstctl-managed-key-runtime:dod"
try:
    module.required_image_id()
except SystemExit:
    pass
else:
    raise AssertionError("mutable image tag accepted")
os.environ[module.IMAGE_ENV] = "sha256:" + "a" * 64
assert module.required_image_id() == os.environ[module.IMAGE_ENV]
`
	command := exec.Command("python3", "-c", program, path) // #nosec G204 -- test executes a fixed local tool or fixture it built itself (CWE-78)
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("managed-key inner receipt validation self-test: %v output=%s", err, output)
	}
}

func loadManagedKeyManifest(t *testing.T) (string, Manifest) {
	t.Helper()
	repo, err := filepath.Abs(filepath.Join("..", ".."))
	if err != nil {
		t.Fatal(err)
	}
	manifest, err := loadManifest(filepath.Join(repo, "tools", "dodcensus", "manifest.json"))
	if err != nil {
		t.Fatal(err)
	}
	return repo, manifest
}

func copyManagedKeyIdentityFixture(t *testing.T, repo string, substrate Substrate, omit string) string {
	t.Helper()
	fixture := t.TempDir()
	paths := append([]string(nil), substrate.IdentityFiles...)
	paths = append(paths, substrate.ContractFile)
	for _, name := range paths {
		if name == omit {
			continue
		}
		source := filepath.Join(repo, filepath.FromSlash(name))
		content, err := os.ReadFile(source) // #nosec G304 -- test reads its own fixture/tempdir path (CWE-22)
		if err != nil {
			t.Fatal(err)
		}
		info, err := os.Stat(source)
		if err != nil {
			t.Fatal(err)
		}
		destination := filepath.Join(fixture, filepath.FromSlash(name))
		if err := os.MkdirAll(filepath.Dir(destination), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(destination, content, info.Mode().Perm()); err != nil { // #nosec G703 -- test path inside its own tempdir/checkout (CWE-22)
			t.Fatal(err)
		}
	}
	return fixture
}
