// SPDX-License-Identifier: BUSL-1.1

package registry

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"

	"trstctl.com/trstctl/internal/crypto"
)

func writeFile(p string, data []byte) error {
	if err := os.MkdirAll(filepath.Dir(p), 0o750); err != nil {
		return err
	}
	return os.WriteFile(p, data, 0o600) // #nosec G703 -- a path under the operator's registry output directory (CWE-22)
}

// ---- Go module proxy --------------------------------------------------------

// GoModule writes module@version as a GOPROXY tree under out/go: @v/list, the
// .info, the .mod and the module zip, built from the listed files under src
// (the module's root, holding its go.mod). Files of nested modules are left
// out, as the go command leaves them out.
func GoModule(repo string, files []string, src, module, version string, at time.Time, out string) (Package, error) {
	if !strings.HasPrefix(version, "v") {
		return Package{}, fmt.Errorf("registry: Go module version %q needs its v", version)
	}
	sources, err := readFiles(repo, files, src)
	if err != nil {
		return Package{}, err
	}
	gomod, ok := sources["go.mod"]
	if !ok {
		return Package{}, fmt.Errorf("registry: %s has no go.mod", src)
	}
	if !bytes.Contains(gomod, []byte("module "+module+"\n")) {
		return Package{}, fmt.Errorf("registry: %s/go.mod does not declare module %s", src, module)
	}
	nested := map[string]bool{}
	for name := range sources {
		if dir := path.Dir(name); path.Base(name) == "go.mod" && dir != "." {
			nested[dir] = true
		}
	}
	var entries []zipEntry
	for name, data := range sources {
		skip := false
		for dir := range nested {
			skip = skip || strings.HasPrefix(name, dir+"/")
		}
		if !skip && !strings.HasPrefix(name, "vendor/") {
			entries = append(entries, zipEntry{module + "@" + version + "/" + name, data})
		}
	}
	root := filepath.Join(out, "go", filepath.FromSlash(module), "@v")
	if err := writeZip(filepath.Join(root, version+".zip"), entries); err != nil {
		return Package{}, err
	}
	info, err := json.Marshal(map[string]string{"Version": version, "Time": at.UTC().Format(time.RFC3339)})
	if err != nil {
		return Package{}, err
	}
	// The list holds every version the directory has; this one joins them.
	versions := []string{version}
	if prior, err := os.ReadFile(filepath.Join(root, "list")); err == nil { // #nosec G304 -- this registry directory's own list (CWE-22)
		for _, v := range strings.Fields(string(prior)) {
			if v != version {
				versions = append(versions, v)
			}
		}
	}
	sortVersions(versions)
	for name, data := range map[string][]byte{"list": []byte(strings.Join(versions, "\n") + "\n"), version + ".info": info, version + ".mod": gomod} {
		if err := writeFile(filepath.Join(root, name), data); err != nil {
			return Package{}, err
		}
	}
	return describe(out, path.Join("go", module, "@v", version+".zip"), "go", module, version)
}

// ---- Python: a pure-Python wheel and a PEP 503 simple index ---------------

// pyproject is the [project] table's fields a wheel's METADATA carries.
type pyproject struct {
	Name, Description, RequiresPython, License, Author string
	Keywords, Classifiers                              []string
}

var (
	pyString = regexp.MustCompile(`^([a-z-]+) = "(.*)"$`)
	pyQuoted = regexp.MustCompile(`"([^"]*)"`)
)

// readPyproject reads the [project] table's simple fields.
func readPyproject(raw []byte) (pyproject, error) {
	var p pyproject
	inProject, inClassifiers := false, false
	for _, line := range strings.Split(string(raw), "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "[") && !inClassifiers {
			inProject = line == "[project]"
			continue
		}
		if !inProject {
			continue
		}
		switch {
		case inClassifiers:
			if line == "]" {
				inClassifiers = false
				continue
			}
			for _, m := range pyQuoted.FindAllStringSubmatch(line, -1) {
				p.Classifiers = append(p.Classifiers, m[1])
			}
		case line == "classifiers = [":
			inClassifiers = true
		case strings.HasPrefix(line, "keywords = ["):
			for _, m := range pyQuoted.FindAllStringSubmatch(line, -1) {
				p.Keywords = append(p.Keywords, m[1])
			}
		case strings.HasPrefix(line, "license = {"):
			if m := pyQuoted.FindStringSubmatch(line); m != nil {
				p.License = m[1]
			}
		case strings.HasPrefix(line, "authors = ["):
			if m := pyQuoted.FindStringSubmatch(line); m != nil {
				p.Author = m[1]
			}
		default:
			if m := pyString.FindStringSubmatch(line); m != nil {
				switch m[1] {
				case "name":
					p.Name = m[2]
				case "description":
					p.Description = m[2]
				case "requires-python":
					p.RequiresPython = m[2]
				}
			}
		}
	}
	if p.Name == "" {
		return p, errors.New("registry: pyproject.toml's [project] table names no package")
	}
	return p, nil
}

// Wheel writes a pure-Python wheel of the package under src/src/<package>
// (the listed files only) to out/pypi/packages, with the simple index pip
// reads at out/pypi/simple.
func Wheel(repo string, files []string, src, version, out string) (Package, error) {
	pyprojectRaw, err := os.ReadFile(filepath.Join(repo, src, "pyproject.toml")) // #nosec G304 -- the SDK's own pyproject.toml in the checkout (CWE-22)
	if err != nil {
		return Package{}, err
	}
	project, err := readPyproject(pyprojectRaw)
	if err != nil {
		return Package{}, err
	}
	readme, err := os.ReadFile(filepath.Join(repo, src, "README.md")) // #nosec G304 -- the SDK's own README in the checkout (CWE-22)
	if err != nil {
		return Package{}, err
	}
	module := strings.ReplaceAll(project.Name, "-", "_")
	sources, err := readFiles(repo, files, path.Join(src, "src", module))
	if err != nil {
		return Package{}, err
	}
	distInfo := module + "-" + version + ".dist-info"
	var meta strings.Builder
	fmt.Fprintf(&meta, "Metadata-Version: 2.1\nName: %s\nVersion: %s\nSummary: %s\n", project.Name, version, project.Description)
	if project.Author != "" {
		fmt.Fprintf(&meta, "Author: %s\n", project.Author)
	}
	if project.License != "" {
		fmt.Fprintf(&meta, "License: %s\n", project.License)
	}
	if len(project.Keywords) > 0 {
		fmt.Fprintf(&meta, "Keywords: %s\n", strings.Join(project.Keywords, ","))
	}
	for _, c := range project.Classifiers {
		fmt.Fprintf(&meta, "Classifier: %s\n", c)
	}
	if project.RequiresPython != "" {
		fmt.Fprintf(&meta, "Requires-Python: %s\n", project.RequiresPython)
	}
	fmt.Fprintf(&meta, "Description-Content-Type: text/markdown\n\n%s", readme)
	contents := map[string][]byte{
		distInfo + "/METADATA":      []byte(meta.String()),
		distInfo + "/WHEEL":         []byte("Wheel-Version: 1.0\nGenerator: trstctl-sdkpack\nRoot-Is-Purelib: true\nTag: py3-none-any\n"),
		distInfo + "/top_level.txt": []byte(module + "\n"),
	}
	for name, data := range sources {
		if strings.Contains(name, "__pycache__/") || strings.HasSuffix(name, ".pyc") {
			continue
		}
		contents[module+"/"+name] = data
	}
	var record strings.Builder
	var entries []zipEntry
	for name, data := range contents {
		entries = append(entries, zipEntry{name, data})
	}
	// RECORD lists every file with its urlsafe, unpadded SHA-256 and size,
	// and itself without either.
	sortEntries(entries)
	for _, e := range entries {
		fmt.Fprintf(&record, "%s,sha256=%s,%d\n", e.name, crypto.SHA256Base64URL(e.data), len(e.data))
	}
	fmt.Fprintf(&record, "%s/RECORD,,\n", distInfo)
	entries = append(entries, zipEntry{distInfo + "/RECORD", []byte(record.String())})
	file := module + "-" + version + "-py3-none-any.whl"
	if err := writeZip(filepath.Join(out, "pypi", "packages", file), entries); err != nil {
		return Package{}, err
	}
	pkg, err := describe(out, path.Join("pypi", "packages", file), "pypi", project.Name, version)
	if err != nil {
		return Package{}, err
	}
	normalized := strings.ToLower(regexp.MustCompile(`[-_.]+`).ReplaceAllString(project.Name, "-"))
	// The project page links every wheel of the project the directory holds.
	wheels, err := filepath.Glob(filepath.Join(out, "pypi", "packages", module+"-*-py3-none-any.whl"))
	if err != nil {
		return Package{}, err
	}
	sort.Strings(wheels)
	var links strings.Builder
	for _, w := range wheels {
		raw, err := os.ReadFile(w) // #nosec G304 -- a wheel in this registry directory (CWE-22)
		if err != nil {
			return Package{}, err
		}
		fmt.Fprintf(&links, "<a href=\"../../packages/%s#sha256=%s\" data-requires-python=\"%s\">%s</a>\n",
			filepath.Base(w), crypto.SHA256Hex(raw), strings.ReplaceAll(project.RequiresPython, ">", "&gt;"), filepath.Base(w))
	}
	page := "<!DOCTYPE html>\n<html><body>\n" + links.String() + "</body></html>\n"
	index := fmt.Sprintf("<!DOCTYPE html>\n<html><body>\n<a href=\"%s/\">%s</a>\n</body></html>\n", normalized, normalized)
	if err := writeFile(filepath.Join(out, "pypi", "simple", normalized, "index.html"), []byte(page)); err != nil {
		return Package{}, err
	}
	return pkg, writeFile(filepath.Join(out, "pypi", "simple", "index.html"), []byte(index))
}

func sortEntries(entries []zipEntry) {
	for i := 1; i < len(entries); i++ {
		for j := i; j > 0 && entries[j].name < entries[j-1].name; j-- {
			entries[j], entries[j-1] = entries[j-1], entries[j]
		}
	}
}

// ---- npm ---------------------------------------------------------------------

// NPM files an `npm pack` tarball under out/npm/tarballs and writes the
// version's registry document (its package.json fields and dist.integrity)
// for the handler to serve with the tarball's address filled in.
func NPM(tarball, out string) (Package, error) {
	raw, err := os.ReadFile(tarball) // #nosec G304 -- the npm pack output the release script names (CWE-22)
	if err != nil {
		return Package{}, err
	}
	manifest, err := tarballPackageJSON(raw)
	if err != nil {
		return Package{}, err
	}
	var fields map[string]any
	if err := json.Unmarshal(manifest, &fields); err != nil {
		return Package{}, fmt.Errorf("registry: %s's package.json: %w", tarball, err)
	}
	name, _ := fields["name"].(string)
	version, _ := fields["version"].(string)
	if name == "" || version == "" {
		return Package{}, fmt.Errorf("registry: %s's package.json names no package or version", tarball)
	}
	file := filepath.Base(tarball)
	if err := writeFile(filepath.Join(out, "npm", "tarballs", file), raw); err != nil {
		return Package{}, err
	}
	sum, err := crypto.Digest(crypto.SHA512, raw)
	if err != nil {
		return Package{}, err
	}
	delete(fields, "scripts")
	delete(fields, "devDependencies")
	fields["dist"] = map[string]any{"integrity": "sha512-" + base64.StdEncoding.EncodeToString(sum), "tarball": "tarballs/" + file}
	// The document holds every version the directory has; latest is the
	// highest of them.
	metaFile := filepath.Join(out, "npm", "meta", url2file(name)+".json")
	versions := map[string]any{}
	if prior, err := os.ReadFile(metaFile); err == nil { // #nosec G304 -- this registry directory's own document (CWE-22)
		var existing struct {
			Versions map[string]any `json:"versions"`
		}
		if err := json.Unmarshal(prior, &existing); err != nil {
			return Package{}, fmt.Errorf("registry: %s: %w", metaFile, err)
		}
		versions = existing.Versions
	}
	versions[version] = fields
	latest := version
	for v := range versions {
		if newerVersion(v, latest) {
			latest = v
		}
	}
	doc, err := json.MarshalIndent(map[string]any{
		"name": name, "dist-tags": map[string]string{"latest": latest}, "versions": versions,
	}, "", "  ")
	if err != nil {
		return Package{}, err
	}
	if err := writeFile(metaFile, doc); err != nil {
		return Package{}, err
	}
	return describe(out, path.Join("npm", "tarballs", file), "npm", name, version)
}

// url2file is a package name as one file name (a scoped name's slash escaped).
func url2file(name string) string { return strings.ReplaceAll(name, "/", "%2f") }

// tarballPackageJSON reads package/package.json from an npm pack tarball.
func tarballPackageJSON(raw []byte) ([]byte, error) {
	gz, err := gzip.NewReader(bytes.NewReader(raw))
	if err != nil {
		return nil, fmt.Errorf("registry: npm tarball: %w", err)
	}
	tr := tar.NewReader(gz)
	for {
		h, err := tr.Next()
		if err == io.EOF {
			return nil, errors.New("registry: npm tarball has no package/package.json")
		}
		if err != nil {
			return nil, fmt.Errorf("registry: npm tarball: %w", err)
		}
		if h.Name == "package/package.json" {
			return io.ReadAll(io.LimitReader(tr, 1<<20))
		}
	}
}

// ---- Maven -------------------------------------------------------------------

// Maven files a jar and its pom in the Maven 2 layout under out/maven, with
// SHA-256 and SHA-512 checksums and the artifact's maven-metadata.xml.
func Maven(jar, pom, groupID, artifactID, version string, at time.Time, out string) (Package, error) {
	dir := path.Join("maven", strings.ReplaceAll(groupID, ".", "/"), artifactID)
	base := path.Join(dir, version, artifactID+"-"+version)
	// The metadata lists every version the directory holds; latest and
	// release are the highest.
	versions := []string{version}
	if entries, err := os.ReadDir(filepath.Join(out, filepath.FromSlash(dir))); err == nil {
		for _, e := range entries {
			if e.IsDir() && e.Name() != version {
				versions = append(versions, e.Name())
			}
		}
	}
	sortVersions(versions)
	var listed strings.Builder
	for _, v := range versions {
		fmt.Fprintf(&listed, "      <version>%s</version>\n", v)
	}
	highest := versions[len(versions)-1]
	metadata := fmt.Sprintf(`<?xml version="1.0" encoding="UTF-8"?>
<metadata>
  <groupId>%s</groupId>
  <artifactId>%s</artifactId>
  <versioning>
    <latest>%s</latest>
    <release>%s</release>
    <versions>
%s    </versions>
    <lastUpdated>%s</lastUpdated>
  </versioning>
</metadata>
`, groupID, artifactID, highest, highest, listed.String(), at.UTC().Format("20060102150405"))
	for src, dst := range map[string]string{jar: base + ".jar", pom: base + ".pom", "": path.Join(dir, "maven-metadata.xml")} {
		data := []byte(metadata)
		if src != "" {
			var err error
			if data, err = os.ReadFile(src); err != nil { // #nosec G304 -- the jar and pom the release script built (CWE-22)
				return Package{}, err
			}
		}
		if err := writeFile(filepath.Join(out, filepath.FromSlash(dst)), data); err != nil {
			return Package{}, err
		}
		sha512, err := crypto.Digest(crypto.SHA512, data)
		if err != nil {
			return Package{}, err
		}
		for ext, sum := range map[string]string{".sha256": crypto.SHA256Hex(data), ".sha512": fmt.Sprintf("%x", sha512)} {
			if err := writeFile(filepath.Join(out, filepath.FromSlash(dst+ext)), []byte(sum)); err != nil {
				return Package{}, err
			}
		}
	}
	return describe(out, base+".jar", "maven", groupID+":"+artifactID, version)
}
