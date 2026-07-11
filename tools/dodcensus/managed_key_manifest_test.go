// SPDX-License-Identifier: MPL-2.0

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
			file, err := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0)
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
		{"inner emulator run drops platform", "tools/dodcensus/substrates/managed_keys.py", `"docker", "run", "--rm", "--platform", "linux/amd64", "--name"`, `"docker", "run", "--rm", "--name"`},
		{"receipt omits runtime image id", "tools/dodcensus/substrates/managed_keys.py", `"runtime_identity": image`, `"runtime_identity": "mutable"`},
		{"signer drops nonroot uid", "internal/server/dod_managed_key_runtime_test.go", `"--user", strconv.Itoa(uid) + ":" + strconv.Itoa(gid)`, `"--user", "0:0"`},
		{"signer drops no-new-privileges", "internal/server/dod_managed_key_runtime_test.go", `"--security-opt", "no-new-privileges"`, `"--security-opt", "seccomp=unconfined"`},
		{"signer restores ambient capabilities", "internal/server/dod_managed_key_runtime_test.go", `"--cap-drop", "ALL"`, `"--cap-add", "ALL"`},
		{"signer drops scoped nss", "internal/server/dod_managed_key_runtime_test.go", `"-v", passwdFile+":/etc/passwd:ro", "-v", groupFile+":/etc/group:ro"`, `"-v", r.dir+":/etc:ro"`},
		{"signer nss loses exclusive mode", "internal/server/dod_managed_key_runtime_test.go", `os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600`, `os.O_WRONLY|os.O_CREATE, 0o666`},
		{"swtpm re-enables incompatible internal seccomp", "tools/dodcensus/substrates/managed_key_signer_entrypoint.sh", `--seccomp action=none`, `--seccomp action=kill`},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			fixture := copyManagedKeyIdentityFixture(t, repo, base, "")
			path := filepath.Join(fixture, filepath.FromSlash(tc.file))
			raw, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			mutated := strings.Replace(string(raw), tc.old, tc.replacement, 1)
			if mutated == string(raw) {
				t.Fatalf("mutation anchor %q is absent from %s", tc.old, tc.file)
			}
			if err := os.WriteFile(path, []byte(mutated), 0o600); err != nil {
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

func TestManagedKeyRuntimeUsesContentAddressedImageAtBothRunSites(t *testing.T) {
	repo, _ := loadManagedKeyManifest(t)
	runtimeSource, err := os.ReadFile(filepath.Join(repo, "internal", "server", "dod_managed_key_runtime_test.go"))
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
		`"-v", passwdFile+":/etc/passwd:ro", "-v", groupFile+":/etc/group:ro"`,
		`os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)`,
	} {
		if !strings.Contains(source, required) {
			t.Errorf("managed-key runtime source omits content-addressed image dataflow %q", required)
		}
	}
	if count := strings.Count(source, `"--platform", dodManagedKeyRuntimePlatform`); count != 4 {
		t.Errorf("managed-key runtime pins exact pull/build/run platform %d times, want four", count)
	}
	for _, forbidden := range []string{
		`t.Setenv("TRSTCTL_HSM_PROOF_IMAGE", "trstctl-managed-key-runtime:dod")`,
		`"trstctl-managed-key-runtime:dod",\n\t\t"--mtls-listen"`,
		`"SIGNER_IMAGE=trstctl-signer-hsm:dod"`,
		`"docker", "image", "inspect", "--format={{.Id}}", image`,
		`"--privileged"`,
		`"seccomp=unconfined"`,
		`"--user", "0:0"`,
	} {
		if strings.Contains(source, forbidden) {
			t.Errorf("managed-key runtime still runs mutable image tag via %q", forbidden)
		}
	}

	pythonSource, err := os.ReadFile(filepath.Join(repo, "tools", "dodcensus", "substrates", "managed_keys.py"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(pythonSource), "image = required_image_id()") ||
		!strings.Contains(string(pythonSource), `"docker", "run", "--rm", "--platform", "linux/amd64"`) ||
		!strings.Contains(string(pythonSource), `"runtime_identity": image`) ||
		strings.Contains(string(pythonSource), `os.environ.get(IMAGE_ENV, "trstctl-managed-key-runtime:dod")`) {
		t.Fatal("managed-key substrate does not fail closed on a content-addressed inner image id")
	}

	entrypointSource, err := os.ReadFile(filepath.Join(repo, "tools", "dodcensus", "substrates", "managed_key_signer_entrypoint.sh"))
	if err != nil {
		t.Fatal(err)
	}
	if count := strings.Count(string(entrypointSource), "--seccomp action=none"); count != 1 {
		t.Fatalf("managed-key signer swtpm internal seccomp exception count = %d, want one", count)
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
	command := exec.Command("python3", "-c", program, path)
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
		content, err := os.ReadFile(source)
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
		if err := os.WriteFile(destination, content, info.Mode().Perm()); err != nil {
			t.Fatal(err)
		}
	}
	return fixture
}
