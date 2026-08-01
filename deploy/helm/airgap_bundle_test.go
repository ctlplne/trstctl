// SPDX-License-Identifier: MPL-2.0

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
			"IMAGE=ghcr.io/ctlplne/trstctl:v0.5.0",
			"OUT_DIR="+out,
			"TRSTCTL_AIRGAP_SKIP_IMAGES=1",
		)
		if output, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("build %d: %v\n%s", build+1, err, output)
		}
		bundle := filepath.Join(out, "trstctl-0.5.0-airgap")
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
		manifests = append(manifests, tarManifest(t, filepath.Join(out, "trstctl-0.5.0-airgap.tar.gz")))
	}
	if strings.Join(manifests[0], "\n") != strings.Join(manifests[1], "\n") {
		t.Fatalf("same-commit air-gap file manifests differ:\nfirst=%v\nsecond=%v", manifests[0], manifests[1])
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
