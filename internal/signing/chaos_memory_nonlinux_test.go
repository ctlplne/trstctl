//go:build chaos && !linux

// SPDX-License-Identifier: MPL-2.0

package signing_test

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// TestChaosRealSignerAddressSpaceCapShedsWithoutWrongAnswers keeps the real
// RLIMIT_AS scenario mandatory on kernels such as Darwin that expose the
// constant but reject changing it. The host test launches the exact Linux test
// in the digest-pinned Go image, with the repository and module cache mounted
// read-only and networking disabled. Missing Docker, missing cached modules, or
// a red Linux fault test is a hard failure, never a skip.
func TestChaosRealSignerAddressSpaceCapShedsWithoutWrongAnswers(t *testing.T) {
	docker, err := exec.LookPath("docker")
	if err != nil {
		t.Fatalf("real Linux RLIMIT_AS chaos proof requires Docker on %s: %v", runtimeGOOS(), err)
	}
	repo := chaosRepoRoot()
	baseRaw, err := os.ReadFile(filepath.Join(repo, "tools", "dodcensus", "runtime-runner-base.txt"))
	if err != nil {
		t.Fatalf("read pinned Linux chaos image: %v", err)
	}
	base := strings.TrimSpace(string(baseRaw))
	if !strings.Contains(base, "@sha256:") {
		t.Fatalf("Linux chaos image is not digest-pinned: %q", base)
	}
	moduleCacheRaw, err := exec.Command("go", "env", "GOMODCACHE").Output()
	if err != nil {
		t.Fatalf("resolve host Go module cache: %v", err)
	}
	moduleCache := strings.TrimSpace(string(moduleCacheRaw))
	buildCache := t.TempDir()

	command := exec.Command(docker,
		"run", "--rm", "--network=none", "--platform=linux/amd64",
		"-e", "CGO_ENABLED=0", "-e", "GOFLAGS=-mod=readonly",
		"-e", "GOCACHE=/chaos-cache", "-e", "GOMODCACHE=/go/pkg/mod",
		"-v", repo+":/src:ro", "-v", moduleCache+":/go/pkg/mod:ro",
		"-v", buildCache+":/chaos-cache", "-w", "/src", base,
		"go", "test", "-tags=chaos", "-count=1",
		"-run", "^TestChaosRealSignerAddressSpaceCapShedsWithoutWrongAnswers$",
		"./internal/signing",
	)
	output, err := command.CombinedOutput()
	if err != nil {
		t.Fatalf("pinned Linux RLIMIT_AS chaos proof failed: %v\n%s", err, output)
	}
	t.Logf("pinned Linux RLIMIT_AS chaos proof passed:\n%s", output)
}

func runtimeGOOS() string {
	output, err := exec.Command("go", "env", "GOOS").Output()
	if err != nil {
		return "non-Linux host"
	}
	return strings.TrimSpace(string(output))
}
