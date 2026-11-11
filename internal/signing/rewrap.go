// SPDX-License-Identifier: BUSL-1.1

package signing

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"time"

	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/crypto/seal"
	"trstctl.com/trstctl/internal/crypto/secret"
)

// RewrapReport is what a key-store re-wrap did.
type RewrapReport struct {
	// Rewrapped counts the sealed files whose data key moved to the
	// destination wrapper; Keys counts the signer keys among them, each
	// opened under the destination before the swap.
	Rewrapped int
	Keys      int
	// Copied counts the files that are not sealed containers (public kits,
	// tombstones, anchors), carried over byte for byte.
	Copied int
	// Backup is where the original directory was kept: the rollback set,
	// still opened by the source wrapper.
	Backup string
}

// RewrapKeyStore moves a signer key store from one key wrapper to another
// (A200-L2): from the local KEK onto the external KMS/HSM adapter, typically.
// Every sealed container under dir (keys, sign and destruction journals,
// import seeds, KEM custody, the succession mint journal) has its data key
// unwrapped by source and wrapped by destination; the payload is never
// opened and every other byte is kept. The work happens in a staging copy
// beside dir: each moved data key must come back unchanged from destination,
// every signer key must open under destination, and dir must be unchanged
// since the copy began. Only then is dir renamed to
// <dir>.pre-rewrap-<UTC time> (the rollback set) and the copy renamed into
// its place. Any failure leaves dir untouched and removes the copy. The
// signer must be stopped while it runs; a container that source does not
// open stops the re-wrap rather than being carried over unreadable.
func RewrapKeyStore(dir string, source, destination seal.KeyWrapper, now time.Time) (RewrapReport, error) {
	var report RewrapReport
	if source == nil || destination == nil {
		return report, errors.New("signing: re-wrap needs the source and the destination key wrappers")
	}
	dir = filepath.Clean(dir)
	info, err := os.Lstat(dir)
	if err != nil {
		return report, fmt.Errorf("signing: re-wrap the key store: %w", err)
	}
	if !info.IsDir() {
		return report, fmt.Errorf("signing: re-wrap: %s is not a directory", dir)
	}
	parent, base := filepath.Dir(dir), filepath.Base(dir)
	backup := filepath.Join(parent, base+".pre-rewrap-"+now.UTC().Format("20060102T150405Z"))
	if _, err := os.Lstat(backup); err == nil {
		return report, fmt.Errorf("signing: re-wrap: %s already exists", backup)
	}
	staging, err := os.MkdirTemp(parent, base+".rewrap-")
	if err != nil {
		return report, fmt.Errorf("signing: re-wrap staging: %w", err)
	}
	swapped := false
	defer func() {
		if !swapped {
			_ = os.RemoveAll(staging)
		}
	}()
	if err := os.Chmod(staging, info.Mode().Perm()); err != nil {
		return report, fmt.Errorf("signing: re-wrap staging: %w", err)
	}

	before, err := rewrapTree(dir, staging, source, destination, &report)
	if err != nil {
		return report, err
	}
	if err := verifyRewrappedKeys(dir, staging, source, destination, &report); err != nil {
		return report, err
	}
	after, err := fingerprintTree(dir)
	if err != nil {
		return report, err
	}
	if !sameFingerprints(before, after) {
		return report, errors.New("signing: re-wrap: the key store changed while it was copied; stop the signer and run the re-wrap again")
	}
	if err := syncTree(staging); err != nil {
		return report, err
	}
	if err := os.Rename(dir, backup); err != nil {
		return report, fmt.Errorf("signing: re-wrap: keep the original as %s (a key store at a mount point cannot be renamed; use a directory below it): %w", backup, err)
	}
	if err := os.Rename(staging, dir); err != nil {
		if restoreErr := os.Rename(backup, dir); restoreErr != nil {
			return report, fmt.Errorf("signing: re-wrap: put the re-wrapped store in place: %v; the original is at %s: %w", err, backup, restoreErr)
		}
		return report, fmt.Errorf("signing: re-wrap: put the re-wrapped store in place (the original is back): %w", err)
	}
	swapped = true
	if err := syncDirectory(parent); err != nil {
		return report, err
	}
	report.Backup = backup
	return report, nil
}

// fileFingerprint is what change detection compares: the file's size, mode,
// modification time and content digest.
type fileFingerprint struct {
	size    int64
	mode    fs.FileMode
	modTime time.Time
	digest  string
}

// rewrapTree copies dir into staging, moving each sealed container's data
// key, and returns the fingerprints of what it read. Files are read and
// written through roots on the two directories, so nothing swapped in during
// the walk can lead outside them.
func rewrapTree(dir, staging string, source, destination seal.KeyWrapper, report *RewrapReport) (map[string]fileFingerprint, error) {
	src, err := os.OpenRoot(dir)
	if err != nil {
		return nil, err
	}
	defer func() { _ = src.Close() }()
	dst, err := os.OpenRoot(staging)
	if err != nil {
		return nil, err
	}
	defer func() { _ = dst.Close() }()
	seen := map[string]fileFingerprint{}
	err = filepath.WalkDir(dir, func(path string, d fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		rel, err := filepath.Rel(dir, path)
		if err != nil {
			return err
		}
		if rel == "." {
			return nil
		}
		info, err := d.Info()
		if err != nil {
			return err
		}
		switch {
		case info.Mode()&fs.ModeSymlink != 0:
			return fmt.Errorf("signing: re-wrap: %s is a symbolic link; a key store holds none", rel)
		case info.IsDir():
			seen[rel] = fileFingerprint{mode: info.Mode()}
			return dst.Mkdir(rel, info.Mode().Perm())
		case !info.Mode().IsRegular():
			return fmt.Errorf("signing: re-wrap: %s is not a regular file", rel)
		}
		raw, err := src.ReadFile(rel)
		if err != nil {
			return err
		}
		defer secret.Wipe(raw)
		seen[rel] = fileFingerprint{size: info.Size(), mode: info.Mode(), modTime: info.ModTime(), digest: crypto.SHA256Hex(raw)}
		out := raw
		if _, _, notSealed := seal.ContainerWrappedDEK(raw); notSealed == nil {
			moved, _, err := seal.RewrapContainerDEK(raw, func(wrapped []byte) ([]byte, bool, error) {
				return moveDataKey(rel, wrapped, source, destination)
			})
			if err != nil {
				return err
			}
			out = moved
			report.Rewrapped++
		} else {
			report.Copied++
		}
		return writeStagedFile(dst, rel, out, info.Mode().Perm())
	})
	if err != nil {
		return nil, err
	}
	return seen, nil
}

// moveDataKey unwraps one container's data key with source, wraps it with
// destination, and checks destination gives back the same bytes.
func moveDataKey(rel string, wrapped []byte, source, destination seal.KeyWrapper) ([]byte, bool, error) {
	dek, err := source.UnwrapDEK(wrapped)
	if err != nil {
		return nil, false, fmt.Errorf("signing: re-wrap: %s is not sealed under the source key: %w", rel, err)
	}
	defer secret.Wipe(dek)
	next, err := destination.WrapDEK(dek)
	if err != nil {
		return nil, false, fmt.Errorf("signing: re-wrap %s under the destination: %w", rel, err)
	}
	check, err := destination.UnwrapDEK(next)
	if err != nil {
		return nil, false, fmt.Errorf("signing: re-wrap: the destination does not open %s's new data key: %w", rel, err)
	}
	defer secret.Wipe(check)
	if !crypto.ConstantTimeEqual(check, dek) {
		return nil, false, fmt.Errorf("signing: re-wrap: the destination gave back a different data key for %s", rel)
	}
	return next, true, nil
}

// verifyRewrappedKeys opens every signer key file under destination in the
// staging copy (and under source in the original), so the swap happens only
// when each key still decrypts.
func verifyRewrappedKeys(dir, staging string, source, destination seal.KeyWrapper, report *RewrapReport) error {
	entries, err := os.ReadDir(staging)
	if err != nil {
		return err
	}
	for _, entry := range entries {
		name := entry.Name()
		if entry.IsDir() || !strings.HasSuffix(name, keyFileExt) {
			continue
		}
		stem := strings.TrimSuffix(name, keyFileExt)
		for _, check := range []struct {
			root    string
			wrapper seal.KeyWrapper
			label   string
		}{{dir, source, "the source"}, {staging, destination, "the destination"}} {
			sealed, err := os.ReadFile(filepath.Join(check.root, name)) // #nosec G304 -- the operator's own key store and its staging copy (CWE-22)
			if err != nil {
				return err
			}
			plaintext, err := seal.Open(check.wrapper, sealed, []byte(stem))
			secret.Wipe(sealed)
			if err != nil {
				return fmt.Errorf("signing: re-wrap: key %q does not open under %s: %w", stem, check.label, err)
			}
			secret.Wipe(plaintext)
		}
		report.Keys++
	}
	return nil
}

func fingerprintTree(dir string) (map[string]fileFingerprint, error) {
	root, err := os.OpenRoot(dir)
	if err != nil {
		return nil, err
	}
	defer func() { _ = root.Close() }()
	seen := map[string]fileFingerprint{}
	err = filepath.WalkDir(dir, func(path string, d fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		rel, err := filepath.Rel(dir, path)
		if err != nil || rel == "." {
			return err
		}
		info, err := d.Info()
		if err != nil {
			return err
		}
		if info.IsDir() || !info.Mode().IsRegular() {
			seen[rel] = fileFingerprint{mode: info.Mode()}
			return nil
		}
		raw, err := root.ReadFile(rel)
		if err != nil {
			return err
		}
		seen[rel] = fileFingerprint{size: info.Size(), mode: info.Mode(), modTime: info.ModTime(), digest: crypto.SHA256Hex(raw)}
		secret.Wipe(raw)
		return nil
	})
	return seen, err
}

func sameFingerprints(a, b map[string]fileFingerprint) bool {
	if len(a) != len(b) {
		return false
	}
	for rel, fa := range a {
		fb, ok := b[rel]
		if !ok || fa.size != fb.size || fa.mode != fb.mode || !fa.modTime.Equal(fb.modTime) || fa.digest != fb.digest {
			return false
		}
	}
	return true
}

func writeStagedFile(root *os.Root, name string, data []byte, perm fs.FileMode) error {
	file, err := root.OpenFile(name, os.O_CREATE|os.O_EXCL|os.O_WRONLY, perm)
	if err != nil {
		return err
	}
	if _, err := file.Write(data); err != nil {
		_ = file.Close()
		return err
	}
	if err := file.Sync(); err != nil {
		_ = file.Close()
		return err
	}
	return file.Close()
}

// syncTree flushes every directory of the staging copy, so the swap never
// exposes entries the disk has not recorded.
func syncTree(root string) error {
	return filepath.WalkDir(root, func(path string, d fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if !d.IsDir() {
			return nil
		}
		return syncDirectory(path)
	})
}
