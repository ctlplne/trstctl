// SPDX-License-Identifier: BUSL-1.1

package drift

import (
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"

	"trstctl.com/trstctl/internal/crypto/secret"
	"trstctl.com/trstctl/internal/safefile"
)

const (
	maxConfinedWatched = 128
	maxConfinedScope   = 16
	maxScanEntries     = 4096
)

var ErrPathNotApproved = errors.New("drift path is outside operator-approved roots")

// ApprovedRoots canonicalizes the distinct operator configuration and refuses
// special kernel/device filesystems even when an operator listed them.
func ApprovedRoots(configured []string) ([]string, error) {
	if len(configured) > 16 {
		return nil, ErrPathNotApproved
	}
	roots, err := safefile.ScanRoots(configured)
	if err != nil {
		return nil, err
	}
	seen := map[string]bool{}
	for _, root := range roots {
		if forbiddenDriftPath(root) || seen[root] {
			return nil, ErrPathNotApproved
		}
		seen[root] = true
	}
	return roots, nil
}

// ValidateConfinedPaths checks the same filesystem authority used by the
// served worker. A tenant may select a file only inside an operator-mounted
// drift root; a missing watched file is valid so deletion remains detectable.
func ValidateConfinedPaths(roots []string, watched []Watched, scope []string) error {
	if len(roots) == 0 || len(watched) == 0 || len(watched) > maxConfinedWatched || len(scope) > maxConfinedScope {
		return ErrPathNotApproved
	}
	seen := make(map[string]bool, len(watched))
	for _, w := range watched {
		canonical, err := canonicalConfinedPath(w.Path)
		if err != nil {
			return err
		}
		if seen[canonical] {
			return errors.New("drift watched paths must be unique")
		}
		seen[canonical] = true
		root, rel, err := openConfinedRoot(roots, w.Path)
		if err != nil || rel == "." {
			if root != nil {
				_ = root.Close()
			}
			return ErrPathNotApproved
		}
		parent, err := root.Stat(filepath.Dir(rel))
		if err != nil || !parent.IsDir() {
			_ = root.Close()
			return ErrPathNotApproved
		}
		_, err = root.Stat(rel)
		_ = root.Close()
		if err != nil && !errors.Is(err, fs.ErrNotExist) {
			return ErrPathNotApproved
		}
	}
	for _, path := range scope {
		root, rel, err := openConfinedRoot(roots, path)
		if err != nil {
			return err
		}
		info, err := root.Stat(rel)
		_ = root.Close()
		if err != nil || !info.IsDir() {
			return ErrPathNotApproved
		}
	}
	return nil
}

// DetectConfined is the served variant of Detect. It opens every path from an
// approved directory descriptor, so a symlink substituted after source creation
// cannot send the worker outside the approved tree.
func DetectConfined(ctx context.Context, roots []string, watched []Watched, scope ...string) ([]Finding, error) {
	if err := ValidateConfinedPaths(roots, watched, scope); err != nil {
		return nil, err
	}
	findings := make([]Finding, 0, len(watched))
	for _, w := range watched {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		root, rel, err := openConfinedRoot(roots, w.Path)
		if err != nil {
			return nil, err
		}
		f, err := detectOneConfined(ctx, root, rel, w, roots, scope)
		_ = root.Close()
		if err != nil {
			return nil, err
		}
		if f.Type != None {
			findings = append(findings, f)
		}
	}
	return findings, nil
}

func detectOneConfined(ctx context.Context, root *os.Root, rel string, w Watched, roots, scope []string) (Finding, error) {
	info, err := root.Stat(rel)
	if errors.Is(err, fs.ErrNotExist) {
		at, found, scanErr := scanConfined(ctx, roots, w, append([]string{filepath.Dir(w.Path)}, scope...))
		if scanErr != nil {
			return Finding{}, scanErr
		}
		if found {
			return Finding{Watched: w, Type: Relocated, FoundAt: at}, nil
		}
		return Finding{Watched: w, Type: Deleted}, nil
	}
	if err != nil {
		return Finding{}, ErrPathNotApproved
	}
	data, err := safefile.ReadRegularFile(ctx, root, rel, maxScanFileSize)
	if err != nil {
		return Finding{}, err
	}
	fingerprint := Fingerprint(data)
	secret.Wipe(data)
	if fingerprint != w.Fingerprint {
		return Finding{Watched: w, Type: Replaced}, nil
	}
	if drifted, detail := permissionDriftedConfined(root, rel, info, w); drifted {
		return Finding{Watched: w, Type: PermissionChanged, ActualMode: info.Mode(), Detail: detail}, nil
	}
	return Finding{Watched: w, Type: None}, nil
}

func scanConfined(ctx context.Context, roots []string, w Watched, dirs []string) (string, bool, error) {
	seen := map[string]bool{}
	for _, dir := range dirs {
		if seen[dir] {
			continue
		}
		seen[dir] = true
		root, rel, err := openConfinedRoot(roots, dir)
		if err != nil {
			return "", false, err
		}
		folder, err := root.Open(rel)
		if err != nil {
			_ = root.Close()
			return "", false, ErrPathNotApproved
		}
		entries, readErr := folder.ReadDir(maxScanEntries + 1)
		_ = folder.Close()
		if readErr != nil && !errors.Is(readErr, io.EOF) {
			_ = root.Close()
			return "", false, readErr
		}
		if len(entries) > maxScanEntries {
			_ = root.Close()
			return "", false, fmt.Errorf("drift relocation scan exceeds %d entries", maxScanEntries)
		}
		for _, entry := range entries {
			if err := ctx.Err(); err != nil {
				_ = root.Close()
				return "", false, err
			}
			if !entry.Type().IsRegular() && entry.Type()&os.ModeSymlink == 0 {
				continue
			}
			candidate := filepath.Join(dir, entry.Name())
			if candidate == w.Path {
				continue
			}
			data, err := safefile.ReadRegularFile(ctx, root, filepath.Join(rel, entry.Name()), maxScanFileSize)
			if err == nil {
				fingerprint := Fingerprint(data)
				secret.Wipe(data)
				if fingerprint == w.Fingerprint {
					_ = root.Close()
					return candidate, true, nil
				}
			}
		}
		_ = root.Close()
	}
	return "", false, nil
}

func openConfinedRoot(roots []string, path string) (*os.Root, string, error) {
	resolved, err := canonicalConfinedPath(path)
	if err != nil {
		return nil, "", err
	}
	for _, approved := range roots {
		if !safefile.ContainsPath(approved, resolved) {
			continue
		}
		canonical, err := filepath.EvalSymlinks(approved)
		if err != nil || canonical != approved {
			return nil, "", ErrPathNotApproved
		}
		root, err := os.OpenRoot(approved)
		if err != nil {
			return nil, "", ErrPathNotApproved
		}
		canonical, err = filepath.EvalSymlinks(approved)
		if err != nil || canonical != approved {
			_ = root.Close()
			return nil, "", ErrPathNotApproved
		}
		opened, openErr := root.Stat(".")
		current, statErr := os.Stat(approved)
		if openErr != nil || statErr != nil || !os.SameFile(opened, current) {
			_ = root.Close()
			return nil, "", ErrPathNotApproved
		}
		rel, err := filepath.Rel(approved, resolved)
		if err != nil {
			_ = root.Close()
			return nil, "", ErrPathNotApproved
		}
		return root, rel, nil
	}
	return nil, "", ErrPathNotApproved
}

func canonicalConfinedPath(path string) (string, error) {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path || forbiddenDriftPath(path) {
		return "", ErrPathNotApproved
	}
	resolved, err := filepath.EvalSymlinks(path)
	if errors.Is(err, fs.ErrNotExist) {
		if info, lstatErr := os.Lstat(path); lstatErr == nil && info.Mode()&os.ModeSymlink != 0 {
			return "", ErrPathNotApproved
		}
		parent, parentErr := filepath.EvalSymlinks(filepath.Dir(path))
		if parentErr != nil {
			return "", ErrPathNotApproved
		}
		resolved = filepath.Join(parent, filepath.Base(path))
	} else if err != nil {
		return "", ErrPathNotApproved
	}
	if forbiddenDriftPath(resolved) {
		return "", ErrPathNotApproved
	}
	return resolved, nil
}

func forbiddenDriftPath(path string) bool {
	for _, system := range []string{"/proc", "/dev", "/sys"} {
		if safefile.ContainsPath(system, path) {
			return true
		}
	}
	return false
}
