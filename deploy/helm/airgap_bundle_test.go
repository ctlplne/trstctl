// SPDX-License-Identifier: BUSL-1.1

package helm

import (
	"archive/tar"
	"compress/gzip"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

const airgapCanarySecret = "password=airgap-local-canary-must-not-ship"

func TestAirGapBundleUsesOnlyTrackedChartFiles(t *testing.T) {
	repo, err := filepath.Abs(filepath.Join("..", ".."))
	if err != nil {
		t.Fatal(err)
	}
	chartDir := filepath.Join(repo, "deploy", "helm", "trstctl")
	for _, name := range []string{".fuse_hidden_airgap_test", "operator-secret.tmp"} {
		path := filepath.Join(chartDir, name)
		if err := os.WriteFile(path, []byte(airgapCanarySecret+"\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = os.Remove(path) })
	}

	trackedOutput, err := exec.Command("git", "-C", repo, "ls-files", "--", "deploy/helm/trstctl").Output() // #nosec G204 -- test executes a fixed local tool or fixture it built itself (CWE-78)
	if err != nil {
		t.Fatalf("list tracked chart files: %v", err)
	}
	tracked := map[string]bool{}
	for _, path := range strings.Fields(string(trackedOutput)) {
		tracked[strings.TrimPrefix(path, "deploy/helm/trstctl/")] = true
	}
	if len(tracked) == 0 {
		t.Fatal("tracked chart allowlist is empty")
	}

	var manifests [][]string
	for build := 0; build < 2; build++ {
		out := filepath.Join(t.TempDir(), "airgap")
		cmd := exec.Command(filepath.Join(repo, "scripts", "airgap-bundle.sh")) // #nosec G204 -- test executes a fixed local tool or fixture it built itself (CWE-78)
		cmd.Dir = repo
		cmd.Env = append(os.Environ(),
			"VERSION=v0.5.0",
			"PLATFORM=linux/amd64",
			"IMAGE=ghcr.io/ctlplne/trstctl:v0.5.0",
			"OUT_DIR="+out,
			"TRSTCTL_AIRGAP_SKIP_IMAGES=1",
		)
		if output, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("build %d: %v\n%s", build+1, err, output)
		}
		bundle := filepath.Join(out, "trstctl-0.5.0-linux-amd64-airgap")
		manifest, err := os.ReadFile(filepath.Join(bundle, "MANIFEST.txt")) // #nosec G304 -- bundle is created inside this test's TempDir (CWE-22).
		if err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(string(manifest), "platform: linux/amd64") {
			t.Fatalf("bundle manifest does not bind its image platform:\n%s", manifest)
		}
		platform, err := os.ReadFile(filepath.Join(bundle, "images", "trstctl-image.platform")) // #nosec G304 -- bundle is created inside this test's TempDir (CWE-22).
		if err != nil {
			t.Fatal(err)
		}
		if strings.TrimSpace(string(platform)) != "linux/amd64" {
			t.Fatalf("image platform receipt = %q, want linux/amd64", platform)
		}
		exploded := filepath.Join(bundle, "charts", "trstctl")
		assertTrackedTree(t, exploded, tracked)
		assertNoCanary(t, exploded)

		packages, err := filepath.Glob(filepath.Join(bundle, "charts", "trstctl-*.tgz"))
		if err != nil {
			t.Fatal(err)
		}
		if len(packages) == 0 {
			packages = []string{filepath.Join(bundle, "charts", "trstctl-chart.tar.gz")}
		}
		assertTrackedTar(t, packages[0], tracked)

		check := exec.Command("shasum", "-a", "256", "-c", "CHECKSUMS.txt")
		check.Dir = bundle
		if output, err := check.CombinedOutput(); err != nil {
			t.Fatalf("checksum verification: %v\n%s", err, output)
		}
		manifests = append(manifests, tarManifest(t, filepath.Join(out, "trstctl-0.5.0-linux-amd64-airgap.tar.gz")))
	}
	if strings.Join(manifests[0], "\n") != strings.Join(manifests[1], "\n") {
		t.Fatalf("same-commit air-gap file manifests differ:\nfirst=%v\nsecond=%v", manifests[0], manifests[1])
	}
}

func TestAirGapBundleRequiresSupportedPlatform(t *testing.T) {
	repo, err := filepath.Abs(filepath.Join("..", ".."))
	if err != nil {
		t.Fatal(err)
	}
	for name, platform := range map[string]string{
		"missing":     "",
		"unsupported": "linux/s390x",
	} {
		t.Run(name, func(t *testing.T) {
			cmd := exec.Command(filepath.Join(repo, "scripts", "airgap-bundle.sh")) // #nosec G204 -- test executes a fixed local tool (CWE-78).
			cmd.Dir = repo
			cmd.Env = append(os.Environ(),
				"VERSION=v0.5.0",
				"PLATFORM="+platform,
				"OUT_DIR="+t.TempDir(),
				"TRSTCTL_AIRGAP_SKIP_IMAGES=1",
			)
			if output, err := cmd.CombinedOutput(); err == nil {
				t.Fatalf("bundle accepted PLATFORM=%q:\n%s", platform, output)
			}
		})
	}
}

func TestAirGapBundleUsesPinnedLocalImageWithoutPull(t *testing.T) {
	repo, err := filepath.Abs(filepath.Join("..", ".."))
	if err != nil {
		t.Fatal(err)
	}
	bin := t.TempDir()
	log := filepath.Join(bin, "docker.log")
	const imageID = "sha256:9538a65497203467f056d2b9e89c13cf856bdd49bd827fd45ed40020c0929372"
	fakeDocker := `#!/bin/sh
set -eu
printf '%s\n' "$*" >> "$AIRGAP_DOCKER_LOG"
case "$*" in
  *'image inspect'*'{{.Id}}'*) printf '%s\n' "$AIRGAP_DOCKER_IMAGE_ID" ;;
  *'image inspect'*'{{.Os}}/{{.Architecture}}'*) printf '%s\n' "$AIRGAP_DOCKER_PLATFORM" ;;
  *'image save'*)
    while [ "$#" -gt 0 ]; do
      if [ "$1" = '-o' ]; then shift; printf 'saved pinned image\n' > "$1"; exit 0; fi
      shift
    done
    exit 42 ;;
  *) exit 43 ;;
esac
`
	if err := os.WriteFile(filepath.Join(bin, "docker"), []byte(fakeDocker), 0o755); err != nil { // #nosec G306 -- the executable is a disposable fake Docker client inside this test's private temporary directory.
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name     string
		pinned   string
		platform string
		ok       bool
	}{
		{"exact image", imageID, "linux/arm64", true},
		{"wrong image id", "sha256:0000000000000000000000000000000000000000000000000000000000000000", "linux/arm64", false},
		{"missing pin", "", "linux/arm64", false},
		{"wrong platform", imageID, "linux/amd64", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if err := os.WriteFile(log, nil, 0o600); err != nil {
				t.Fatal(err)
			}
			out := t.TempDir()
			cmd := exec.Command(filepath.Join(repo, "scripts", "airgap-bundle.sh")) // #nosec G204 -- fixed repository script under test.
			cmd.Dir = repo
			cmd.Env = append(os.Environ(),
				"PATH="+bin+string(os.PathListSeparator)+os.Getenv("PATH"),
				"AIRGAP_DOCKER_LOG="+log,
				"AIRGAP_DOCKER_IMAGE_ID="+imageID,
				"AIRGAP_DOCKER_PLATFORM="+tc.platform,
				"VERSION=v0.5.4-qa-local",
				"PLATFORM=linux/arm64",
				"IMAGE=trstctl-goal-airgap-backup:local",
				"OUT_DIR="+out,
				"TRSTCTL_AIRGAP_IMAGE_SOURCE=local",
				"TRSTCTL_AIRGAP_IMAGE_ID="+tc.pinned,
			)
			output, err := cmd.CombinedOutput()
			if (err == nil) != tc.ok {
				t.Fatalf("bundle result = %v, want success %v:\n%s", err, tc.ok, output)
			}
			calls, err := os.ReadFile(log) // #nosec G304 -- the call log path is created inside this test's private temporary directory.
			if err != nil {
				t.Fatal(err)
			}
			if strings.Contains(string(calls), "pull") {
				t.Fatalf("local artifact path attempted a pull:\n%s", calls)
			}
			if !tc.ok {
				if strings.Contains(string(calls), "image save") {
					t.Fatalf("wrong image was saved:\n%s", calls)
				}
				return
			}
			bundle := filepath.Join(out, "trstctl-0.5.4-qa-local-linux-arm64-airgap")
			manifest, err := os.ReadFile(filepath.Join(bundle, "MANIFEST.txt")) // #nosec G304 -- the bundle path is created inside this test's private temporary directory.
			if err != nil {
				t.Fatal(err)
			}
			if !strings.Contains(string(manifest), "image_id: "+imageID) || !strings.Contains(string(manifest), "image_source: local") ||
				!strings.Contains(string(manifest), "image_id_scope: build-host tag before platform-specific docker save") {
				t.Fatalf("bundle does not bind its local source image:\n%s", manifest)
			}
			if _, err := os.Stat(filepath.Join(bundle, "images", "trstctl-image.tar")); err != nil {
				t.Fatal(err)
			}
			// A copied archive must verify with its build-host directory absent.
			// Checking only beside the original file would miss absolute paths in
			// the outer checksum and falsely qualify a disconnected transfer.
			archiveName := "trstctl-0.5.4-qa-local-linux-arm64-airgap.tar.gz"
			checksumName := archiveName + ".sha256"
			receiver := t.TempDir()
			for _, name := range []string{archiveName, checksumName} {
				body, err := os.ReadFile(filepath.Join(out, name)) // #nosec G304 -- the archive is produced inside this test's private temporary directory.
				if err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(filepath.Join(receiver, name), body, 0o600); err != nil { // #nosec G703 -- receiver is a private test directory and name ranges over two fixed archive basenames.
					t.Fatal(err)
				}
			}
			original := filepath.Join(out, archiveName)
			held := original + ".held"
			if err := os.Rename(original, held); err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = os.Rename(held, original) })
			verify := exec.Command("shasum", "-a", "256", "-c", checksumName) // #nosec G204 -- fixed stock checksum command over test-owned archive names.
			verify.Dir = receiver
			if output, err := verify.CombinedOutput(); err != nil {
				t.Fatalf("received archive did not verify without staging path: %v\n%s", err, output)
			}
		})
	}
}

func assertTrackedTree(t *testing.T, root string, tracked map[string]bool) {
	t.Helper()
	seen := map[string]bool{}
	err := filepath.WalkDir(root, func(path string, entry os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if entry.IsDir() {
			return nil
		}
		rel, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}
		rel = filepath.ToSlash(rel)
		if !tracked[rel] {
			t.Errorf("exploded chart contains non-tracked file %q", rel)
		}
		seen[rel] = true
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	for path := range tracked {
		if !seen[path] {
			t.Errorf("exploded chart omitted tracked file %q", path)
		}
	}
}

func assertNoCanary(t *testing.T, root string) {
	t.Helper()
	err := filepath.WalkDir(root, func(path string, entry os.DirEntry, err error) error {
		if err != nil || entry.IsDir() {
			return err
		}
		body, err := os.ReadFile(path) // #nosec G122 G304 -- test reads its own fixture/tempdir path (CWE-22, CWE-367)
		if err != nil {
			return err
		}
		if strings.Contains(string(body), airgapCanarySecret) {
			t.Errorf("secret-shaped canary shipped in %s", path)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}

func assertTrackedTar(t *testing.T, path string, tracked map[string]bool) {
	t.Helper()
	file, err := os.Open(path) // #nosec G304 -- test reads its own fixture/tempdir path (CWE-22)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := file.Close(); err != nil {
			t.Errorf("close packaged chart: %v", err)
		}
	}()
	zr, err := gzip.NewReader(file)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := zr.Close(); err != nil {
			t.Errorf("close packaged chart gzip reader: %v", err)
		}
	}()
	tr := tar.NewReader(zr)
	for {
		header, err := tr.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		rel := strings.TrimPrefix(header.Name, "trstctl/")
		if rel == "" || strings.HasSuffix(rel, "/") {
			continue
		}
		if !tracked[rel] {
			t.Errorf("packaged chart contains non-tracked file %q", rel)
		}
		body, err := io.ReadAll(tr)
		if err != nil {
			t.Fatal(err)
		}
		if strings.Contains(string(body), airgapCanarySecret) {
			t.Fatalf("secret-shaped canary shipped in packaged chart file %q", rel)
		}
	}
}

func tarManifest(t *testing.T, path string) []string {
	t.Helper()
	file, err := os.Open(path) // #nosec G304 -- test reads its own fixture/tempdir path (CWE-22)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := file.Close(); err != nil {
			t.Errorf("close packaged chart: %v", err)
		}
	}()
	zr, err := gzip.NewReader(file)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := zr.Close(); err != nil {
			t.Errorf("close packaged chart gzip reader: %v", err)
		}
	}()
	tr := tar.NewReader(zr)
	var names []string
	for {
		header, err := tr.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		names = append(names, header.Name)
	}
	sort.Strings(names)
	return names
}
