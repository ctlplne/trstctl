// SPDX-License-Identifier: BUSL-1.1

package docker

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"

	"trstctl.com/trstctl/internal/crypto"
)

const alpineMirrorDefault = "ARG ALPINE_MIRROR=https://dl-cdn.alpinelinux.org/alpine"

type alpinePackages struct {
	Schema   string `json:"schema"`
	Upstream string `json:"upstream"`
	Packages []struct {
		Path   string `json:"path"`
		SHA256 string `json:"sha256"`
	} `json:"packages"`
}

func readAlpinePackages(t *testing.T, path string) alpinePackages {
	t.Helper()
	var m alpinePackages
	if err := json.Unmarshal([]byte(readArtifact(t, path)), &m); err != nil {
		t.Fatal(err)
	}
	return m
}

// TestAlpinePackageInputsAreTheManifestFetchedThroughTheMirrorArgTOOLO1: every
// Alpine package an image build fetches is in deploy/supply-chain/
// alpine-packages.json with its digest, and is fetched as ADD --checksum=
// sha256:<digest> ${ALPINE_MIRROR}/<path> in a stage that declares
// ALPINE_MIRROR with the Alpine CDN as its default. A build with the
// default fetches exactly what it did; a mirror kept by
// scripts/supply-chain/alpine-mirror.py serves the same paths, and the
// checksum holds whichever serves them. No Dockerfile names the CDN anywhere
// else, and the manifest lists nothing no build fetches.
func TestAlpinePackageInputsAreTheManifestFetchedThroughTheMirrorArgTOOLO1(t *testing.T) {
	manifest := readAlpinePackages(t, "../supply-chain/alpine-packages.json")
	if manifest.Schema != "trstctl.alpine-packages.v1" || manifest.Upstream != "https://dl-cdn.alpinelinux.org/alpine" {
		t.Fatalf("manifest schema %q upstream %q", manifest.Schema, manifest.Upstream)
	}
	pinned := map[string]string{}
	for _, p := range manifest.Packages {
		if !regexp.MustCompile(`^[0-9a-f]{64}$`).MatchString(p.SHA256) || pinned[p.Path] != "" {
			t.Fatalf("manifest entry %+v is malformed or repeated", p)
		}
		pinned[p.Path] = p.SHA256
	}
	files, err := filepath.Glob("Dockerfile*")
	if err != nil {
		t.Fatal(err)
	}
	files = append(files, "../demo/Dockerfile.seed")
	add := regexp.MustCompile(`^ADD --checksum=sha256:([0-9a-f]{64}) \$\{ALPINE_MIRROR\}/(\S+\.apk) \S+$`)
	used := map[string]bool{}
	for _, file := range files {
		inStage, declared := false, false
		for n, line := range strings.Split(readArtifact(t, file), "\n") {
			switch {
			case strings.HasPrefix(line, "FROM "):
				inStage, declared = true, false
			case line == alpineMirrorDefault:
				declared = inStage
			case strings.Contains(line, "dl-cdn.alpinelinux.org"):
				t.Errorf("%s:%d names the Alpine CDN outside the ALPINE_MIRROR default: %s", file, n+1, line)
			case strings.Contains(line, "${ALPINE_MIRROR}"):
				m := add.FindStringSubmatch(line)
				if m == nil {
					t.Errorf("%s:%d fetches from ALPINE_MIRROR without a pinned checksum: %s", file, n+1, line)
					continue
				}
				if !declared {
					t.Errorf("%s:%d fetches before its stage declares %q", file, n+1, alpineMirrorDefault)
				}
				if pinned[m[2]] != m[1] {
					t.Errorf("%s:%d pins %s at %s; the manifest has %q", file, n+1, m[2], m[1], pinned[m[2]])
				}
				used[m[2]] = true
			}
		}
	}
	var unused []string
	for path := range pinned {
		if !used[path] {
			unused = append(unused, path)
		}
	}
	sort.Strings(unused)
	if len(unused) != 0 || len(used) != len(pinned) {
		t.Fatalf("the manifest lists packages no build fetches: %v", unused)
	}
}

// TestAlpineMirrorFetchVerifiesDigestsAndFallsBackTOOLO1: the mirror tool
// keeps every pinned package at its Alpine path: from the mirror when it has
// the pinned bytes, else from the upstream; a download that is not the
// pinned SHA-256 is refused and never written; a kept copy needs no network;
// and a damaged copy fails verification and cannot be repaired offline.
func TestAlpineMirrorFetchVerifiesDigestsAndFallsBackTOOLO1(t *testing.T) {
	python, err := exec.LookPath("python3")
	if err != nil {
		t.Skipf("python3 is required: %v", err)
	}
	good := map[string][]byte{
		"v3.24/main/x86_64/alpha-1.0-r0.apk":  []byte("alpha package bytes"),
		"v3.24/main/aarch64/bravo-2.0-r1.apk": []byte("bravo package bytes"),
	}
	serving := func(files map[string][]byte) *httptest.Server {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			body, ok := files[strings.TrimPrefix(r.URL.Path, "/alpine/")]
			if !ok {
				http.NotFound(w, r)
				return
			}
			_, _ = w.Write(body)
		}))
		t.Cleanup(srv.Close)
		return srv
	}
	// The mirror has alpha, and a bravo whose bytes are not the pinned ones;
	// the upstream has the pinned bravo.
	mirror := serving(map[string][]byte{"v3.24/main/x86_64/alpha-1.0-r0.apk": good["v3.24/main/x86_64/alpha-1.0-r0.apk"], "v3.24/main/aarch64/bravo-2.0-r1.apk": []byte("a rebuilt bravo")})
	upstream := serving(map[string][]byte{"v3.24/main/aarch64/bravo-2.0-r1.apk": good["v3.24/main/aarch64/bravo-2.0-r1.apk"]})
	dir := t.TempDir()
	manifestPath := filepath.Join(dir, "alpine-packages.json")
	var entries []map[string]string
	for path, body := range good {
		entries = append(entries, map[string]string{"path": path, "sha256": crypto.SHA256Hex(body)})
	}
	raw, err := json.Marshal(map[string]any{"schema": "trstctl.alpine-packages.v1", "upstream": upstream.URL + "/alpine", "packages": entries})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(manifestPath, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	store := filepath.Join(dir, "mirror")
	run := func(args ...string) (string, error) {
		t.Helper()
		out, err := exec.Command(python, append([]string{"-I", "../../scripts/supply-chain/alpine-mirror.py", "--manifest", manifestPath}, args...)...).CombinedOutput() // #nosec G204 -- fixed interpreter and the repository's own script (CWE-78)
		return string(out), err
	}
	out, err := run("fetch", store, "--mirror", mirror.URL+"/alpine")
	if err != nil {
		t.Fatalf("fetch: %v\n%s", err, out)
	}
	if !strings.Contains(out, "fetched  v3.24/main/x86_64/alpha-1.0-r0.apk from "+mirror.URL) ||
		!strings.Contains(out, "refused  v3.24/main/aarch64/bravo-2.0-r1.apk from "+mirror.URL) ||
		!strings.Contains(out, "fetched  v3.24/main/aarch64/bravo-2.0-r1.apk from "+upstream.URL) {
		t.Fatalf("fetch did not take alpha from the mirror and bravo from the upstream after refusing the mirror's:\n%s", out)
	}
	for path, body := range good {
		got, err := os.ReadFile(filepath.Join(store, path)) // #nosec G304 -- the test's own temp directory (CWE-22)
		if err != nil || string(got) != string(body) {
			t.Fatalf("%s holds %q (%v)", path, got, err)
		}
	}
	mirror.Close()
	upstream.Close()
	if out, err := run("fetch", store); err != nil || strings.Count(out, "kept     ") != 2 {
		t.Fatalf("a kept mirror needed the network: %v\n%s", err, out)
	}
	if out, err := run("verify", store); err != nil || !strings.Contains(out, "2 of 2 pinned packages match") {
		t.Fatalf("verify: %v\n%s", err, out)
	}
	if err := os.WriteFile(filepath.Join(store, "v3.24/main/x86_64/alpha-1.0-r0.apk"), []byte("damaged"), 0o600); err != nil {
		t.Fatal(err)
	}
	if out, err := run("verify", store); err == nil || !strings.Contains(out, "differs  v3.24/main/x86_64/alpha-1.0-r0.apk") {
		t.Fatalf("a damaged copy verified: %v\n%s", err, out)
	}
	if out, err := run("fetch", store); err == nil || !strings.Contains(out, "1 pinned package(s) could not be fetched") {
		t.Fatalf("a damaged copy was kept or repaired offline: %v\n%s", err, out)
	}
	if out, err := run("fetch", store, "--mirror", "http://mirror.example.test/alpine"); err == nil || !strings.Contains(out, "must be an https URL") {
		t.Fatalf("a plain-http mirror off loopback was used: %v\n%s", err, out)
	}
}
