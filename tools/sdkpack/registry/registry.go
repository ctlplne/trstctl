// SPDX-License-Identifier: BUSL-1.1

// Package registry builds the trstctl client SDKs into the files package
// registries serve, and serves them from one directory as local registries
// (A250): a Go module proxy, an npm registry, a PEP 503 simple index and a
// Maven repository. Nothing here publishes anywhere; a package leaves this
// directory only when someone installs it from the local registry.
package registry

import (
	"archive/zip"
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"trstctl.com/trstctl/internal/crypto"
)

// Package is one built package and its digest.
type Package struct {
	Ecosystem string `json:"ecosystem"`
	Name      string `json:"name"`
	Version   string `json:"version"`
	// File is the package's path under the registry directory.
	File   string `json:"file"`
	SHA256 string `json:"sha256"`
	Size   int64  `json:"size"`
}

// Manifest lists every package a registry directory holds.
type Manifest struct {
	Version  string    `json:"version"`
	Packages []Package `json:"packages"`
}

const manifestFile = "manifest.json"

// zipEpoch is the modification time every archive entry carries, so the same
// sources build the same bytes.
var zipEpoch = time.Date(1980, 1, 1, 0, 0, 0, 0, time.UTC)

// describe records the package at dir/rel with its digest.
func describe(dir, rel, ecosystem, name, version string) (Package, error) {
	raw, err := os.ReadFile(filepath.Join(dir, filepath.FromSlash(rel))) // #nosec G304 -- a file this tool just wrote under the operator's output directory (CWE-22)
	if err != nil {
		return Package{}, err
	}
	return Package{Ecosystem: ecosystem, Name: name, Version: version, File: rel, SHA256: crypto.SHA256Hex(raw), Size: int64(len(raw))}, nil
}

// AddToManifest records pkg in dir's manifest, replacing an earlier build of
// the same package, and rewrites SHA256SUMS beside it.
func AddToManifest(dir, version string, pkg Package) error {
	m, err := ReadManifest(dir)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	if m.Version != "" && m.Version != version {
		return fmt.Errorf("registry: %s holds version %s, not %s", dir, m.Version, version)
	}
	m.Version = version
	kept := m.Packages[:0]
	for _, p := range m.Packages {
		if p.Ecosystem != pkg.Ecosystem || p.Name != pkg.Name || p.Version != pkg.Version {
			kept = append(kept, p)
		}
	}
	m.Packages = append(kept, pkg)
	sort.Slice(m.Packages, func(i, j int) bool { return m.Packages[i].File < m.Packages[j].File })
	raw, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(dir, manifestFile), append(raw, '\n'), 0o600); err != nil {
		return err
	}
	var sums bytes.Buffer
	for _, p := range m.Packages {
		fmt.Fprintf(&sums, "%s  %s\n", p.SHA256, p.File)
	}
	return os.WriteFile(filepath.Join(dir, "SHA256SUMS"), sums.Bytes(), 0o600)
}

// ReadManifest reads dir's manifest.
func ReadManifest(dir string) (Manifest, error) {
	raw, err := os.ReadFile(filepath.Join(dir, manifestFile)) // #nosec G304 -- the registry directory's own manifest (CWE-22)
	if err != nil {
		return Manifest{}, err
	}
	var m Manifest
	if err := json.Unmarshal(raw, &m); err != nil {
		return Manifest{}, fmt.Errorf("registry: %s: %w", manifestFile, err)
	}
	return m, nil
}

// zipEntry is one file to archive: its name in the archive and its bytes.
type zipEntry struct {
	name string
	data []byte
}

// writeZip writes entries in name order with fixed times, so a rebuild of the
// same files is byte-identical.
func writeZip(path string, entries []zipEntry) error {
	sort.Slice(entries, func(i, j int) bool { return entries[i].name < entries[j].name })
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	for _, e := range entries {
		w, err := zw.CreateHeader(&zip.FileHeader{Name: e.name, Method: zip.Deflate, Modified: zipEpoch})
		if err != nil {
			return err
		}
		if _, err := w.Write(e.data); err != nil {
			return err
		}
	}
	if err := zw.Close(); err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		return err
	}
	return os.WriteFile(path, buf.Bytes(), 0o600)
}

// readFiles reads repo-relative files (the tracked files a build is given)
// that sit under prefix, keyed by their path below prefix.
func readFiles(repo string, files []string, prefix string) (map[string][]byte, error) {
	prefix = strings.TrimSuffix(filepath.ToSlash(prefix), "/") + "/"
	out := map[string][]byte{}
	for _, f := range files {
		f = filepath.ToSlash(strings.TrimSpace(f))
		if f == "" || !strings.HasPrefix(f, prefix) {
			continue
		}
		raw, err := os.ReadFile(filepath.Join(repo, filepath.FromSlash(f))) // #nosec G304 -- a tracked file the release script listed (CWE-22)
		if err != nil {
			return nil, err
		}
		out[strings.TrimPrefix(f, prefix)] = raw
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("registry: no listed files under %s", prefix)
	}
	return out, nil
}

// ReadFileList reads a newline-separated list of repo-relative paths, as
// `git ls-files` prints them.
func ReadFileList(path string) ([]string, error) {
	f, err := os.Open(path) // #nosec G304 -- the operator's file list (CWE-22)
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()
	raw, err := io.ReadAll(io.LimitReader(f, 16<<20))
	if err != nil {
		return nil, err
	}
	var out []string
	for _, line := range strings.Split(string(raw), "\n") {
		if line = strings.TrimSpace(line); line != "" {
			out = append(out, line)
		}
	}
	return out, nil
}
