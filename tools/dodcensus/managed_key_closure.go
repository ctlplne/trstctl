// SPDX-License-Identifier: MPL-2.0

package main

import (
	"fmt"
	"os"
	"sort"
	"strings"
)

const managedKeyRuntimePlatform = "linux/amd64"

var managedKeyIdentityClosure = []string{
	".github/workflows/release.yml",
	"deploy/docker/Dockerfile.signer-hsm",
	"go.mod",
	"go.sum",
	"internal/server/dod_managed_key_runtime_test.go",
	"tools/dodcensus/Dockerfile.managed-key-runtime",
	"tools/dodcensus/substrates/managed_key_signer_entrypoint.sh",
	"tools/dodcensus/substrates/managed_keys.py",
}

// inspectManagedKeyRuntimeClosure makes the dynamic image bytes part of the
// gate, not merely a convention in a runtime test. The committed identity must
// bind every file which chooses the builder/runtime bases, apt package universe,
// signer parent image, and final container image ID reported in the receipt.
func inspectManagedKeyRuntimeClosure(repo string, substrate Substrate) error {
	want := append([]string(nil), managedKeyIdentityClosure...)
	got := append([]string(nil), substrate.IdentityFiles...)
	sort.Strings(want)
	sort.Strings(got)
	if strings.Join(got, "\n") != strings.Join(want, "\n") {
		return fmt.Errorf("managed-key identity_files = %v, want exact base/package/runtime closure %v", got, want)
	}

	read := func(name string) (string, error) {
		path, err := safeRepoPath(repo, name)
		if err != nil {
			return "", err
		}
		raw, err := os.ReadFile(path)
		if err != nil {
			return "", fmt.Errorf("read %s: %w", name, err)
		}
		return string(raw), nil
	}

	signerDockerfile, err := read("deploy/docker/Dockerfile.signer-hsm")
	if err != nil {
		return err
	}
	if err := requireNoDefaultDockerArg(signerDockerfile, "BUILD_IMAGE"); err != nil {
		return fmt.Errorf("HSM signer builder base: %w", err)
	}
	if err := requireNoDefaultDockerArg(signerDockerfile, "BASE_IMAGE"); err != nil {
		return fmt.Errorf("HSM signer runtime base: %w", err)
	}
	if err := requirePinnedAptSnapshot(signerDockerfile); err != nil {
		return fmt.Errorf("HSM signer packages: %w", err)
	}

	overlayDockerfile, err := read("tools/dodcensus/Dockerfile.managed-key-runtime")
	if err != nil {
		return err
	}
	if err := requireNoDefaultDockerArg(overlayDockerfile, "SIGNER_IMAGE"); err != nil {
		return fmt.Errorf("managed-key verifier parent: %w", err)
	}
	if err := requirePinnedAptSnapshot(overlayDockerfile); err != nil {
		return fmt.Errorf("managed-key verifier packages: %w", err)
	}

	workflow, err := read(".github/workflows/release.yml")
	if err != nil {
		return err
	}
	for _, required := range []string{
		"id: hsm_basedigest",
		`docker buildx imagetools inspect "${build_base}" --format '{{.Manifest.Digest}}'`,
		`docker buildx imagetools inspect "${runtime_base}" --format '{{.Manifest.Digest}}'`,
		`echo "build_ref=golang@${build_digest}"`,
		`echo "runtime_ref=debian@${runtime_digest}"`,
		"BUILD_IMAGE=${{ steps.hsm_basedigest.outputs.build_ref }}",
		"BASE_IMAGE=${{ steps.hsm_basedigest.outputs.runtime_ref }}",
	} {
		if !strings.Contains(workflow, required) {
			return fmt.Errorf("HSM release workflow omits immutable base-image dataflow %q", required)
		}
	}

	runtimeSource, err := read("internal/server/dod_managed_key_runtime_test.go")
	if err != nil {
		return err
	}
	platformDeclared := false
	for _, line := range strings.Split(runtimeSource, "\n") {
		if strings.Join(strings.Fields(line), " ") == `dodManagedKeyRuntimePlatform = "linux/amd64"` {
			platformDeclared = true
			break
		}
	}
	if !platformDeclared {
		return fmt.Errorf("managed-key runtime does not freeze its shipped platform to linux/amd64")
	}
	for _, required := range []string{
		`buildBase := dodPinnedBaseImage(t, "golang:"+goVersion+"-bookworm", "golang")`,
		`runtimeBase := dodPinnedBaseImage(t, "debian:bookworm-slim", "debian")`,
		`"docker", "pull", "--platform", dodManagedKeyRuntimePlatform, taggedImage`,
		`"--format={{json .RepoDigests}}"`,
		`"docker", "build", "--platform", dodManagedKeyRuntimePlatform, "-f", "deploy/docker/Dockerfile.signer-hsm"`,
		`"BUILD_IMAGE="+buildBase`,
		`"BASE_IMAGE="+runtimeBase`,
		`signerImage := dodBuiltImageID(t, "trstctl-signer-hsm:dod", dodManagedKeyRuntimePlatform)`,
		`t.Setenv("DOCKER_BUILDKIT", "0")`,
		`"docker", "build", "--platform", dodManagedKeyRuntimePlatform, "-f", "tools/dodcensus/Dockerfile.managed-key-runtime"`,
		`"SIGNER_IMAGE="+signerImage`,
		`runtimeImage := dodBuiltImageID(t, "trstctl-managed-key-runtime:dod", dodManagedKeyRuntimePlatform)`,
		`"--format={{.Id}} {{.Os}}/{{.Architecture}}"`,
		`len(fields) != 2 || fields[1] != platform`,
		`t.Setenv("TRSTCTL_HSM_PROOF_IMAGE", runtimeImage)`,
		`"--user", strconv.Itoa(uid) + ":" + strconv.Itoa(gid)`,
		`"--security-opt", "no-new-privileges", "--cap-drop", "ALL"`,
		`"-v", passwdFile+":/etc/passwd:ro", "-v", groupFile+":/etc/group:ro"`,
		`os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)`,
	} {
		if !strings.Contains(runtimeSource, required) {
			return fmt.Errorf("managed-key runtime omits content-addressed image dataflow %q", required)
		}
	}
	if count := strings.Count(runtimeSource, `"--platform", dodManagedKeyRuntimePlatform`); count != 4 {
		return fmt.Errorf("managed-key runtime pins linux/amd64 at %d pull/build/run sites, want four", count)
	}
	for _, forbidden := range []string{
		`"BUILD_IMAGE=golang:`, `"BASE_IMAGE=debian:`,
		`"SIGNER_IMAGE=trstctl-signer-hsm:dod"`,
		`t.Setenv("TRSTCTL_HSM_PROOF_IMAGE", "trstctl-managed-key-runtime:dod")`,
		`"docker", "image", "inspect", "--format={{.Id}}", image`,
		`"docker", "build", "-f", "deploy/docker/Dockerfile.signer-hsm"`,
		`"docker", "build", "-f", "tools/dodcensus/Dockerfile.managed-key-runtime"`,
		`"--privileged"`,
		`"seccomp=unconfined"`,
		`"--user", "0:0"`,
	} {
		if strings.Contains(runtimeSource, forbidden) {
			return fmt.Errorf("managed-key runtime retains mutable image input %q", forbidden)
		}
	}

	entrypointSource, err := read("tools/dodcensus/substrates/managed_key_signer_entrypoint.sh")
	if err != nil {
		return err
	}
	if count := strings.Count(entrypointSource, "--seccomp action=none"); count != 1 {
		return fmt.Errorf("managed-key signer disables swtpm internal seccomp %d times, want exactly once for Docker-seccomp compatibility", count)
	}

	substrateSource, err := read("tools/dodcensus/substrates/managed_keys.py")
	if err != nil {
		return err
	}
	for _, required := range []string{
		"image = required_image_id()",
		`"docker", "run", "--rm", "--platform", "linux/amd64"`,
	} {
		if !strings.Contains(substrateSource, required) {
			return fmt.Errorf("managed-key substrate omits image-ID receipt binding %q", required)
		}
	}
	if strings.Contains(substrateSource, `"docker", "run", "--rm", "--name"`) {
		return fmt.Errorf("managed-key substrate retains an unpinned inner runtime platform")
	}
	if count := strings.Count(substrateSource, `"runtime_identity": image`); count != 2 {
		return fmt.Errorf("managed-key substrate image-ID binding appears %d times, want READY and final receipt", count)
	}
	return nil
}

func requireNoDefaultDockerArg(source, name string) error {
	found := false
	for _, instruction := range dockerInstructions(source) {
		if !strings.HasPrefix(strings.ToUpper(instruction), "ARG ") {
			continue
		}
		declaration := strings.TrimSpace(instruction[len("ARG "):])
		if declaration == name {
			found = true
		}
		if strings.HasPrefix(declaration, name+"=") {
			return fmt.Errorf("ARG %s has a default and can silently accept a mutable reference", name)
		}
	}
	if !found {
		return fmt.Errorf("ARG %s is not required without a default", name)
	}
	return nil
}

func requirePinnedAptSnapshot(source string) error {
	instructions := dockerInstructions(source)
	aptRuns := 0
	for _, instruction := range instructions {
		if !strings.HasPrefix(strings.ToUpper(instruction), "RUN ") || !strings.Contains(instruction, "apt-get") {
			continue
		}
		aptRuns++
		for _, required := range []string{
			"snapshot.debian.org/archive/debian/20260701T000000Z",
			"snapshot.debian.org/archive/debian-security/20260701T000000Z",
			"check-valid-until=no",
			"rm -f /etc/apt/sources.list.d/debian.sources",
		} {
			if !strings.Contains(instruction, required) {
				return fmt.Errorf("apt RUN omits immutable repository input %q", required)
			}
		}
		if strings.Contains(instruction, "deb.debian.org") || strings.Contains(instruction, "security.debian.org") {
			return fmt.Errorf("apt RUN retains a moving Debian repository")
		}
	}
	if aptRuns != 1 {
		return fmt.Errorf("dockerfile has %d apt RUN instructions, want one fully pinned transaction", aptRuns)
	}
	return nil
}
