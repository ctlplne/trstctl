// SPDX-License-Identifier: BUSL-1.1

package safefile

import (
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
)

// ContainsPath reports whether path is root or a descendant of root. Callers
// resolve symbolic links before using this check as filesystem authority.
func ContainsPath(root, path string) bool {
	rel, err := filepath.Rel(root, path)
	return err == nil && rel != ".." && !filepath.IsAbs(rel) &&
		!strings.HasPrefix(rel, ".."+string(filepath.Separator))
}

// ScanRoots resolves operator directories and refuses filesystem roots and
// any root that contains the shared temporary staging directory.
func ScanRoots(configured []string) ([]string, error) {
	if len(configured) == 0 {
		return nil, nil
	}
	temp, err := canonicalPath(os.TempDir())
	if err != nil {
		return nil, fmt.Errorf("resolve process temporary directory: %w", err)
	}
	ancestors, err := directoryLineage(temp)
	if err != nil {
		return nil, fmt.Errorf("check process temporary directory: %w", err)
	}
	roots := make([]string, 0, len(configured))
	for index, value := range configured {
		path := strings.TrimSpace(value)
		if path == "" {
			return nil, fmt.Errorf("entry %d must name a directory", index+1)
		}
		root, err := canonicalPath(path)
		if err != nil {
			return nil, fmt.Errorf("resolve directory for entry %d: %w", index+1, err)
		}
		info, err := os.Stat(root)
		if err != nil {
			return nil, fmt.Errorf("check directory for entry %d: %w", index+1, err)
		}
		if !info.IsDir() {
			return nil, fmt.Errorf("entry %d must name a directory", index+1)
		}
		if filepath.Dir(root) == root || slices.ContainsFunc(ancestors, func(ancestor os.FileInfo) bool {
			return os.SameFile(info, ancestor)
		}) {
			return nil, fmt.Errorf("entry %d cannot be a filesystem root or contain the process temporary directory", index+1)
		}
		roots = append(roots, root)
	}
	return roots, nil
}

func directoryLineage(directory string) ([]os.FileInfo, error) {
	var lineage []os.FileInfo
	for {
		info, err := os.Stat(directory)
		if err != nil {
			return nil, err
		}
		lineage = append(lineage, info)
		parent := filepath.Dir(directory)
		if parent == directory {
			return lineage, nil
		}
		directory = parent
	}
}

func canonicalPath(path string) (string, error) {
	abs, err := filepath.Abs(path)
	if err != nil {
		return "", err
	}
	return filepath.EvalSymlinks(abs)
}
