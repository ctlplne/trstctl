// SPDX-License-Identifier: BUSL-1.1

package hostsource

import (
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"trstctl.com/trstctl/internal/safefile"
)

const maxGlobEntries = 4096

var errHostScanLimit = errors.New("CBOM host selector exceeds its file or directory-entry limit")

type confinedFile struct {
	path string
	rel  string
	root *os.Root
}

// expandConfined walks globs through open directory descriptors. A symlink may
// point elsewhere inside an approved root, but os.Root refuses any hop outside
// it. The entry budget bounds work before a large directory becomes a heap
// allocation, and the returned roots stay open until the caller finishes reads.
func expandConfined(ctx context.Context, configuredRoots []string, expected map[string]os.FileInfo, selectors []string, maxFiles int) ([]confinedFile, int, func()) {
	opened := make(map[string]*os.Root, len(configuredRoots))
	closeRoots := func() {
		for _, root := range opened {
			_ = root.Close()
		}
	}
	if len(configuredRoots) == 0 {
		return nil, len(selectors), closeRoots
	}
	for _, path := range configuredRoots {
		if expected != nil && expected[path] == nil {
			continue
		}
		if root, err := os.OpenRoot(path); err == nil {
			if expected != nil {
				info, statErr := root.Stat(".")
				if statErr != nil || !os.SameFile(info, expected[path]) {
					_ = root.Close()
					continue
				}
			}
			opened[path] = root
		}
	}
	out := make([]confinedFile, 0, min(maxFiles, len(selectors)))
	seen := make(map[string]bool)
	failures := 0
	remainingEntries := maxGlobEntries
	for _, selector := range selectors {
		if ctx.Err() != nil {
			failures++
			break
		}
		canonical, displayPrefix, canonicalPrefix, err := canonicalHostSelector(selector)
		if err != nil {
			failures++
			continue
		}
		rootPath := longestContainingRoot(configuredRoots, canonical)
		root := opened[rootPath]
		if root == nil {
			failures++
			continue
		}
		rel, err := filepath.Rel(rootPath, canonical)
		if err != nil || rel == "." || filepath.IsAbs(rel) || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
			failures++
			continue
		}
		parts := strings.Split(filepath.ToSlash(rel), "/")
		if err := walkConfinedGlob(ctx, root, rootPath, displayPrefix, canonicalPrefix, ".", parts, &remainingEntries, maxFiles, seen, &out); err != nil {
			failures++
		}
	}
	return out, failures, closeRoots
}

// Resolve only the directory preceding the first wildcard. The remainder is
// still a selector, not a file to inspect. Keep its original spelling for
// inventory locations while using the resolved spelling for authority checks.
func canonicalHostSelector(selector string) (canonical, displayPrefix, canonicalPrefix string, err error) {
	displayPrefix = filepath.Dir(selector)
	if index := strings.IndexAny(selector, "*?["); index >= 0 {
		displayPrefix = filepath.Dir(selector[:index] + "x")
	}
	canonicalPrefix, err = filepath.EvalSymlinks(displayPrefix)
	if err != nil {
		return "", "", "", err
	}
	suffix, err := filepath.Rel(displayPrefix, selector)
	if err != nil {
		return "", "", "", err
	}
	return filepath.Join(canonicalPrefix, suffix), displayPrefix, canonicalPrefix, nil
}

// CanonicalSelector resolves the non-glob directory prefix for a preview
// authority check. Scanning still resolves and confines every match itself.
func CanonicalSelector(selector string) (canonical, displayPrefix, canonicalPrefix string, err error) {
	return canonicalHostSelector(selector)
}

func longestContainingRoot(roots []string, path string) string {
	var chosen string
	for _, root := range roots {
		if len(root) > len(chosen) && safefile.ContainsPath(root, path) {
			chosen = root
		}
	}
	return chosen
}

func walkConfinedGlob(ctx context.Context, root *os.Root, rootPath, displayPrefix, canonicalPrefix, current string, parts []string,
	remaining *int, maxFiles int, seen map[string]bool, out *[]confinedFile) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if len(parts) == 0 {
		info, err := root.Stat(current)
		if err != nil || !info.Mode().IsRegular() {
			return safefile.ErrNotRegular
		}
		canonicalPath := filepath.Join(rootPath, current)
		if seen[canonicalPath] {
			return nil
		}
		if len(*out) >= maxFiles {
			return errHostScanLimit
		}
		displayRel, err := filepath.Rel(canonicalPrefix, canonicalPath)
		if err != nil {
			return err
		}
		seen[canonicalPath] = true
		*out = append(*out, confinedFile{path: filepath.Join(displayPrefix, displayRel), rel: current, root: root})
		return nil
	}
	part := parts[0]
	if !strings.ContainsAny(part, "*?[") {
		return walkConfinedGlob(ctx, root, rootPath, displayPrefix, canonicalPrefix, filepath.Join(current, part), parts[1:], remaining, maxFiles, seen, out)
	}
	dir, err := safefile.OpenDirectory(ctx, root, current)
	if err != nil {
		return err
	}
	entries, readErr := dir.ReadDir(*remaining + 1)
	_ = dir.Close()
	if readErr != nil && !errors.Is(readErr, io.EOF) {
		return readErr
	}
	if len(entries) > *remaining {
		return errHostScanLimit
	}
	*remaining -= len(entries)
	sort.Slice(entries, func(i, j int) bool { return entries[i].Name() < entries[j].Name() })
	matched := false
	for _, entry := range entries {
		if err := ctx.Err(); err != nil {
			return err
		}
		ok, err := filepath.Match(part, entry.Name())
		if err != nil {
			return err
		}
		if !ok {
			continue
		}
		if err := walkConfinedGlob(ctx, root, rootPath, displayPrefix, canonicalPrefix, filepath.Join(current, entry.Name()), parts[1:], remaining, maxFiles, seen, out); err != nil {
			return err
		}
		matched = true
	}
	if !matched {
		return os.ErrNotExist
	}
	return nil
}
