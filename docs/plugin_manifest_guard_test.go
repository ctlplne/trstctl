// SPDX-License-Identifier: BUSL-1.1

package docs

// PLUGIN-001: a shipped plugin manifest must be load-bearing or absent.
//
// The served plugin surface is filename-driven: internal/server/plugins.go
// loadDir admits every `<name>.wasm` that has a sibling `<name>.wasm.sig`, takes
// the plugin's identity from the filename, and runs it under the single grant
// internal/server/run.go buildPluginConfig assembles from `plugins.capabilities`
// and `plugins.path_prefixes`. Nothing in that path opens a manifest. So a
// `plugin.json` sitting next to a reference plugin that declares
// `"capabilities": ["fs.write"]` reads like a least-privilege request and is not
// one — the host never sees it, never intersects it with the operator grant, and
// the module gets whatever the deployment configured. That is the false-comfort
// class this guard closes: ship a manifest only once a Go source actually reads
// it.

import (
	"io/fs"
	"path/filepath"
	"strings"
	"testing"
)

// pluginManifestSkipDirs are directories whose Go files are not this
// repository's own source: dependency trees and analyzer fixtures.
var pluginManifestSkipDirs = map[string]bool{
	".git":         true,
	"node_modules": true,
	"vendor":       true,
	"testdata":     true,
}

// pluginManifestGuardFile is this file, excluded from the reader scan below so
// the guard can never satisfy itself by naming the manifest in its own prose.
const pluginManifestGuardFile = "plugin_manifest_guard_test.go"

// TestPluginManifestIsEitherWiredOrNotShipped locks PLUGIN-001. ELI5: if the
// repository ships a plugin manifest, some Go code has to actually read it —
// otherwise the manifest is a capability declaration nobody enforces, sitting in
// a tree whose README argues the plugin model is safe by construction. The guard
// is a biconditional, not a ban: wire the manifest into the loader and a Go file
// names it, and this passes.
func TestPluginManifestIsEitherWiredOrNotShipped(t *testing.T) {
	const manifestBase = "plugin.json"

	var manifests []string
	scanned := 0
	err := filepath.WalkDir(filepath.FromSlash("../plugins"), func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}
		scanned++
		if d.Name() == manifestBase {
			manifests = append(manifests, filepath.ToSlash(path))
		}
		return nil
	})
	if err != nil {
		t.Fatalf("PLUGIN-001: walk plugins/: %v", err)
	}
	if scanned == 0 {
		t.Fatal("PLUGIN-001: walked plugins/ and found no files at all; the plugin tree moved — re-point this guard rather than letting it pass vacuously")
	}
	if len(manifests) == 0 {
		return
	}

	readers := goFilesNamingPluginManifest(t, manifestBase)
	if len(readers) == 0 {
		t.Fatalf("PLUGIN-001: %v ship a plugin manifest that no Go source in this repository opens, parses or validates.\n"+
			"internal/server/plugins.go loadDir discovers plugins by filename (<name>.wasm plus a detached <name>.wasm.sig) and\n"+
			"internal/server/run.go buildPluginConfig gives every one of them the operator-configured grant, so the manifest's\n"+
			"capability list is decorative — a module cannot request less than the deployment grants it.\n"+
			"Either wire the manifest into the loader (a Go file will then name it and this guard passes) or stop shipping it.",
			manifests)
	}
}

// goFilesNamingPluginManifest returns the repository's own Go files that mention
// the manifest filename, excluding this guard file.
func goFilesNamingPluginManifest(t *testing.T, manifestBase string) []string {
	t.Helper()
	var out []string
	err := filepath.WalkDir(filepath.FromSlash(".."), func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			if pluginManifestSkipDirs[d.Name()] {
				return fs.SkipDir
			}
			return nil
		}
		name := d.Name()
		if !strings.HasSuffix(name, ".go") || name == pluginManifestGuardFile {
			return nil
		}
		if strings.Contains(read(t, path), manifestBase) {
			out = append(out, filepath.ToSlash(path))
		}
		return nil
	})
	if err != nil {
		t.Fatalf("PLUGIN-001: scan Go sources: %v", err)
	}
	return out
}

// TestPluginsReadmeNamesTheGrantOwner is PLUGIN-001's prose half. ELI5: the page
// that tells third parties how to author a plugin must not tell them they
// declare their own capability grant, because they do not — the operator's
// config does, and there is no manifest format that would let a module ask for
// less.
func TestPluginsReadmeNamesTheGrantOwner(t *testing.T) {
	readme := read(t, "../plugins/README.md")
	for _, want := range []string{
		"The capability grant is the operator's, not the plugin author's.",
		"ships no plugin manifest format",
	} {
		if !strings.Contains(readme, want) {
			t.Errorf("PLUGIN-001: plugins/README.md must state %q — an author reading this page has to learn that the deployment sets the grant", want)
		}
	}
	if strings.Contains(readme, "minimal capability grant it needs") {
		t.Error("PLUGIN-001: plugins/README.md still tells a plugin author to declare the grant their module needs; nothing in the served loader reads such a declaration")
	}
}
