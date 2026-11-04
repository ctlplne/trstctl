// SPDX-License-Identifier: BUSL-1.1

package registry

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"compress/gzip"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/crypto"
)

func writeTree(t *testing.T, root string, files map[string]string) []string {
	t.Helper()
	var list []string
	for name, body := range files {
		p := filepath.Join(root, filepath.FromSlash(name))
		if err := os.MkdirAll(filepath.Dir(p), 0o750); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
		list = append(list, name)
	}
	return list
}

func zipFiles(t *testing.T, path string) map[string][]byte {
	t.Helper()
	zr, err := zip.OpenReader(path)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = zr.Close() }()
	out := map[string][]byte{}
	for _, f := range zr.File {
		rc, err := f.Open()
		if err != nil {
			t.Fatal(err)
		}
		data, err := io.ReadAll(rc)
		_ = rc.Close()
		if err != nil {
			t.Fatal(err)
		}
		out[f.Name] = data
	}
	return out
}

// A250: the Go module tree is what the go command fetches: list, info, mod
// and a zip whose every file sits under module@version/, without nested
// modules or vendor/, and only the listed (tracked) files.
func TestGoModuleTree(t *testing.T) {
	repo, out := t.TempDir(), t.TempDir()
	files := writeTree(t, repo, map[string]string{
		"sdk/go/go.mod":             "// header\nmodule example.test/sdk\n\ngo 1.22\n",
		"sdk/go/client.go":          "package sdk\n",
		"sdk/go/nested/go.mod":      "module example.test/sdk/nested\n",
		"sdk/go/nested/x.go":        "package nested\n",
		"sdk/go/vendor/v/v.go":      "package v\n",
		"sdk/go/models/models.go":   "package models\n",
		"other/ignored/elsewhere.g": "x",
	})
	writeTree(t, repo, map[string]string{"sdk/go/untracked.go": "package sdk\n"})
	at := time.Date(2026, 11, 4, 0, 0, 0, 0, time.UTC)
	pkg, err := GoModule(repo, files, "sdk/go", "example.test/sdk", "v1.2.3", at, out)
	if err != nil {
		t.Fatal(err)
	}
	if pkg.File != "go/example.test/sdk/@v/v1.2.3.zip" || pkg.Ecosystem != "go" || pkg.Version != "v1.2.3" {
		t.Fatalf("package = %+v", pkg)
	}
	got := zipFiles(t, filepath.Join(out, filepath.FromSlash(pkg.File)))
	want := []string{"example.test/sdk@v1.2.3/client.go", "example.test/sdk@v1.2.3/go.mod", "example.test/sdk@v1.2.3/models/models.go"}
	if len(got) != len(want) {
		t.Fatalf("zip holds %d files: %v", len(got), keys(got))
	}
	for _, name := range want {
		if _, ok := got[name]; !ok {
			t.Fatalf("zip lacks %s: %v", name, keys(got))
		}
	}
	for name, body := range map[string]string{"list": "v1.2.3\n", "v1.2.3.mod": "// header\nmodule example.test/sdk\n\ngo 1.22\n",
		"v1.2.3.info": `{"Time":"2026-11-04T00:00:00Z","Version":"v1.2.3"}`} {
		raw, err := os.ReadFile(filepath.Join(out, "go", "example.test", "sdk", "@v", name)) // #nosec G304 -- the test reads files it wrote under its own temp dir (CWE-22)
		if err != nil || string(raw) != body {
			t.Fatalf("%s = %q, %v", name, raw, err)
		}
	}
	if _, err := GoModule(repo, files, "sdk/go", "example.test/other", "v1.2.3", at, out); err == nil {
		t.Fatal("a module path the go.mod does not declare was packaged")
	}
	if _, err := GoModule(repo, files, "sdk/go", "example.test/sdk", "1.2.3", at, out); err == nil {
		t.Fatal("a Go version without its v was packaged")
	}
}

func keys(m map[string][]byte) []string {
	var out []string
	for k := range m {
		out = append(out, k)
	}
	return out
}

// A250: the wheel carries the package, METADATA from pyproject.toml, and a
// RECORD whose digests match every file, as pip checks them.
func TestWheel(t *testing.T) {
	repo, out := t.TempDir(), t.TempDir()
	files := writeTree(t, repo, map[string]string{
		"sdk/py/pyproject.toml": `[build-system]
requires = ["setuptools>=68"]

[project]
name = "demo-sdk"
version = "0.0.0"
description = "A demo"
requires-python = ">=3.9"
license = { text = "MPL-2.0" }
authors = [{ name = "demo maintainers" }]
keywords = ["a", "b"]
classifiers = [
  "Programming Language :: Python :: 3",
  "Typing :: Typed",
]

[tool.setuptools.packages.find]
where = ["src"]
`,
		"sdk/py/README.md":                               "# demo\n",
		"sdk/py/src/demo_sdk/__init__.py":                "X = 1\n",
		"sdk/py/src/demo_sdk/py.typed":                   "",
		"sdk/py/src/demo_sdk/__pycache__/x.cpython.pyc":  "junk",
		"sdk/py/src/demo_sdk.egg-info/PKG-INFO":          "not packaged",
		"sdk/py/src/demo_sdk/sub/mod.py":                 "Y = 2\n",
		"sdk/py/tests/test_demo.py":                      "not packaged",
		"sdk/py/scripts/gen.py":                          "not packaged",
		"sdk/py/src/demo_sdk/sub/__init__.py":            "",
		"sdk/py/src/demo_sdk/sub/data/template.json.txt": "{}",
	})
	pkg, err := Wheel(repo, files, "sdk/py", "1.4.0", out)
	if err != nil {
		t.Fatal(err)
	}
	if pkg.File != "pypi/packages/demo_sdk-1.4.0-py3-none-any.whl" || pkg.Name != "demo-sdk" {
		t.Fatalf("package = %+v", pkg)
	}
	got := zipFiles(t, filepath.Join(out, filepath.FromSlash(pkg.File)))
	meta := string(got["demo_sdk-1.4.0.dist-info/METADATA"])
	for _, line := range []string{"Name: demo-sdk", "Version: 1.4.0", "Summary: A demo", "Requires-Python: >=3.9", "License: MPL-2.0",
		"Classifier: Typing :: Typed", "Keywords: a,b", "Author: demo maintainers", "\n\n# demo\n"} {
		if !strings.Contains(meta, line) {
			t.Fatalf("METADATA lacks %q:\n%s", line, meta)
		}
	}
	record := strings.Split(strings.TrimSpace(string(got["demo_sdk-1.4.0.dist-info/RECORD"])), "\n")
	if len(record) != len(got) {
		t.Fatalf("RECORD lists %d of %d files", len(record), len(got))
	}
	for _, line := range record {
		parts := strings.Split(line, ",")
		if parts[0] == "demo_sdk-1.4.0.dist-info/RECORD" {
			if parts[1] != "" || parts[2] != "" {
				t.Fatalf("RECORD lists itself with a digest: %s", line)
			}
			continue
		}
		data, ok := got[parts[0]]
		if !ok || parts[1] != "sha256="+base64.RawURLEncoding.EncodeToString(crypto.SHA256Sum(data)) {
			t.Fatalf("RECORD line %q does not match the file", line)
		}
	}
	for name := range got {
		if strings.Contains(name, "__pycache__") || strings.Contains(name, "egg-info") || strings.Contains(name, "tests/") {
			t.Fatalf("the wheel carries %s", name)
		}
	}
	page, err := os.ReadFile(filepath.Join(out, "pypi", "simple", "demo-sdk", "index.html")) // #nosec G304 -- the test reads files it wrote under its own temp dir (CWE-22)
	if err != nil || !strings.Contains(string(page), "../../packages/demo_sdk-1.4.0-py3-none-any.whl#sha256="+pkg.SHA256) ||
		!strings.Contains(string(page), `data-requires-python="&gt;=3.9"`) {
		t.Fatalf("simple page = %s, %v", page, err)
	}
}

func npmTarball(t *testing.T, packageJSON string) []byte {
	t.Helper()
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)
	for name, body := range map[string]string{"package/package.json": packageJSON, "package/dist/index.js": "export {};\n"} {
		if err := tw.WriteHeader(&tar.Header{Name: name, Mode: 0o644, Size: int64(len(body))}); err != nil {
			t.Fatal(err)
		}
		if _, err := tw.Write([]byte(body)); err != nil {
			t.Fatal(err)
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := gz.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

// A250: the npm document carries the tarball's sha512 integrity, the handler
// makes its tarball address absolute, and the registry serves only reads.
func TestNPMDocumentAndHandler(t *testing.T) {
	out := t.TempDir()
	raw := npmTarball(t, `{"name":"@demo/sdk","version":"2.0.1","main":"./dist/index.js","scripts":{"x":"y"},"devDependencies":{"z":"1"}}`)
	tarball := filepath.Join(t.TempDir(), "demo-sdk-2.0.1.tgz")
	if err := os.WriteFile(tarball, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	pkg, err := NPM(tarball, out)
	if err != nil {
		t.Fatal(err)
	}
	if err := AddToManifest(out, pkg); err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(&Handler{Dir: out})
	defer srv.Close()
	resp, err := srv.Client().Get(srv.URL + "/npm/@demo%2fsdk")
	if err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Versions map[string]struct {
			Name    string         `json:"name"`
			Scripts map[string]any `json:"scripts"`
			Dist    struct {
				Integrity, Tarball string
			} `json:"dist"`
		} `json:"versions"`
		DistTags map[string]string `json:"dist-tags"`
	}
	err = json.NewDecoder(resp.Body).Decode(&doc)
	_ = resp.Body.Close()
	if err != nil {
		t.Fatal(err)
	}
	v := doc.Versions["2.0.1"]
	sum, err := crypto.Digest(crypto.SHA512, raw)
	if err != nil {
		t.Fatal(err)
	}
	if doc.DistTags["latest"] != "2.0.1" || v.Name != "@demo/sdk" || v.Scripts != nil ||
		v.Dist.Integrity != "sha512-"+base64.StdEncoding.EncodeToString(sum) || v.Dist.Tarball != srv.URL+"/npm/tarballs/demo-sdk-2.0.1.tgz" {
		t.Fatalf("document = %+v", doc)
	}
	got, err := srv.Client().Get(v.Dist.Tarball)
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(got.Body)
	_ = got.Body.Close()
	if !bytes.Equal(body, raw) {
		t.Fatal("the served tarball is not the packed one")
	}
	for _, c := range []struct{ method, path string }{{http.MethodPut, "/npm/@demo%2fsdk"}, {http.MethodGet, "/npm/..%2fmanifest.json"}, {http.MethodGet, "/elsewhere"}} {
		req, _ := http.NewRequest(c.method, srv.URL+c.path, nil)
		resp, err := srv.Client().Do(req)
		if err != nil {
			t.Fatal(err)
		}
		_ = resp.Body.Close()
		if resp.StatusCode == http.StatusOK {
			t.Fatalf("%s %s was served", c.method, c.path)
		}
	}
	m, err := ReadManifest(out)
	if found, ok := m.Find("npm", "2.0.1"); err != nil || len(m.Packages) != 1 || !ok || found.SHA256 != crypto.SHA256Hex(raw) {
		t.Fatalf("manifest = %+v, %v", m, err)
	}
	sums, err := os.ReadFile(filepath.Join(out, "SHA256SUMS")) // #nosec G304 -- the test reads files it wrote under its own temp dir (CWE-22)
	if err != nil || string(sums) != crypto.SHA256Hex(raw)+"  npm/tarballs/demo-sdk-2.0.1.tgz\n" {
		t.Fatalf("SHA256SUMS = %q, %v", sums, err)
	}

	// A registry holds versions side by side: a later one joins the document
	// and becomes latest; an earlier one added afterwards does not.
	for _, version := range []string{"2.0.10", "2.0.2"} {
		next := filepath.Join(t.TempDir(), "demo-sdk-"+version+".tgz")
		if err := os.WriteFile(next, npmTarball(t, `{"name":"@demo/sdk","version":"`+version+`"}`), 0o600); err != nil {
			t.Fatal(err)
		}
		p, err := NPM(next, out)
		if err != nil {
			t.Fatal(err)
		}
		if err := AddToManifest(out, p); err != nil {
			t.Fatal(err)
		}
	}
	resp, err = srv.Client().Get(srv.URL + "/npm/@demo%2fsdk")
	if err != nil {
		t.Fatal(err)
	}
	doc.Versions, doc.DistTags = nil, nil
	err = json.NewDecoder(resp.Body).Decode(&doc)
	_ = resp.Body.Close()
	if err != nil || len(doc.Versions) != 3 || doc.DistTags["latest"] != "2.0.10" {
		t.Fatalf("after two more versions: %d versions, latest %q, %v", len(doc.Versions), doc.DistTags["latest"], err)
	}
	if m, err := ReadManifest(out); err != nil || len(m.Packages) != 3 {
		t.Fatalf("manifest = %+v, %v", m, err)
	}
}

// A250: the Go list, the PyPI page and the Maven metadata each hold every
// version the directory has, oldest first.
func TestRegistriesHoldSeveralVersions(t *testing.T) {
	repo, out := t.TempDir(), t.TempDir()
	files := writeTree(t, repo, map[string]string{
		"g/go.mod": "module example.test/m\n", "g/a.go": "package m\n",
		"p/pyproject.toml": "[project]\nname = \"demo-sdk\"\nrequires-python = \">=3.9\"\n", "p/README.md": "# d\n", "p/src/demo_sdk/__init__.py": "\n",
	})
	jar := filepath.Join(repo, "x.jar")
	pom := filepath.Join(repo, "x.pom")
	writeTree(t, repo, map[string]string{"x.jar": "jar", "x.pom": "<project/>"})
	at := time.Date(2026, 11, 4, 0, 0, 0, 0, time.UTC)
	for _, v := range []string{"1.10.0", "1.2.0", "1.9.3"} {
		if _, err := GoModule(repo, files, "g", "example.test/m", "v"+v, at, out); err != nil {
			t.Fatal(err)
		}
		if _, err := Wheel(repo, files, "p", v, out); err != nil {
			t.Fatal(err)
		}
		if _, err := Maven(jar, pom, "com.example", "demo", v, at, out); err != nil {
			t.Fatal(err)
		}
	}
	list, err := os.ReadFile(filepath.Join(out, "go", "example.test", "m", "@v", "list")) // #nosec G304 -- the test reads files it wrote under its own temp dir (CWE-22)
	if err != nil || string(list) != "v1.2.0\nv1.9.3\nv1.10.0\n" {
		t.Fatalf("Go list = %q, %v", list, err)
	}
	page, err := os.ReadFile(filepath.Join(out, "pypi", "simple", "demo-sdk", "index.html")) // #nosec G304 -- the test reads files it wrote under its own temp dir (CWE-22)
	if err != nil || strings.Count(string(page), "<a href=") != 3 {
		t.Fatalf("PyPI page = %s, %v", page, err)
	}
	meta, err := os.ReadFile(filepath.Join(out, "maven", "com", "example", "demo", "maven-metadata.xml")) // #nosec G304 -- the test reads files it wrote under its own temp dir (CWE-22)
	if err != nil || !strings.Contains(string(meta), "<latest>1.10.0</latest>") ||
		!strings.Contains(string(meta), "<version>1.2.0</version>\n      <version>1.9.3</version>\n      <version>1.10.0</version>") {
		t.Fatalf("Maven metadata = %s, %v", meta, err)
	}
}
