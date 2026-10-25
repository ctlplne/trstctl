// SPDX-License-Identifier: BUSL-1.1

package backup

import (
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/objectstore"
)

// Full backup sets live in the object store as backups/<set name>/ beneath the
// deployment prefix. A set holds every tenant's data (its sensitive artifacts
// encrypted), so it is a deployment object and carries no tenant prefix.
const objectSetRoot = "backups/"

// maxObjectSetFiles bounds the listing of one set.
const maxObjectSetFiles = 10000

var setNamePattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$`)

// ObjectSet describes a set in the object store.
type ObjectSet struct {
	Name     string `json:"name"`
	Location string `json:"location"`
	Objects  int    `json:"objects"`
	Bytes    int64  `json:"bytes"`
	// Resumed counts objects an earlier, interrupted upload had already stored
	// with the same bytes.
	Resumed int `json:"resumed"`
}

// ObjectSetName is the name a set directory uploads under: its base name.
func ObjectSetName(dir string) (string, error) {
	name := filepath.Base(filepath.Clean(dir))
	if !setNamePattern.MatchString(name) {
		return "", fmt.Errorf("backup: %q is not a usable set name (letters, digits, '.', '_' and '-', at most 128)", name)
	}
	return name, nil
}

// UploadFullBackup copies the finished full backup set in dir to the object
// store as backups/<name>/. Every object is created once with its SHA-256:
// every file except the manifest first, then the manifest, so a set whose
// manifest is in the store is complete. A complete set is never replaced. An
// interrupted upload is resumed: an object already stored is kept when its
// checksum matches the local file and refused when it does not.
func UploadFullBackup(ctx context.Context, store objectstore.Store, dir string) (ObjectSet, error) {
	name, err := ObjectSetName(dir)
	if err != nil {
		return ObjectSet{}, err
	}
	if _, err := ReadFullManifest(filepath.Join(dir, FullManifestName)); err != nil {
		return ObjectSet{}, fmt.Errorf("backup: %s is not a finished full backup set: %w", dir, err)
	}
	prefix := objectSetRoot + name + "/"
	if _, err := store.Head(ctx, prefix+FullManifestName); err == nil {
		return ObjectSet{}, fmt.Errorf("backup: the object store already holds a complete set named %q", name)
	} else if !errors.Is(err, objectstore.ErrNotFound) {
		return ObjectSet{}, err
	}
	files, err := setFiles(dir)
	if err != nil {
		return ObjectSet{}, err
	}
	set := ObjectSet{Name: name, Location: store.Location(prefix)}
	for _, rel := range append(files, FullManifestName) {
		size, resumed, err := uploadSetFile(ctx, store, prefix+rel, filepath.Join(dir, filepath.FromSlash(rel)))
		if err != nil {
			return set, err
		}
		set.Objects++
		set.Bytes += size
		if resumed {
			set.Resumed++
		}
	}
	return set, nil
}

// setFiles lists the regular files of a set directory, slash-separated and
// sorted, without the manifest. Anything other than a regular file or a
// directory is refused: a set never carries links.
func setFiles(dir string) ([]string, error) {
	var files []string
	err := filepath.WalkDir(dir, func(path string, entry fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if entry.IsDir() {
			return nil
		}
		if !entry.Type().IsRegular() {
			return fmt.Errorf("backup: %s is not a regular file", path)
		}
		rel, err := filepath.Rel(dir, path)
		if err != nil {
			return err
		}
		rel = filepath.ToSlash(rel)
		if rel != FullManifestName {
			files = append(files, rel)
		}
		return nil
	})
	sort.Strings(files)
	return files, err
}

func uploadSetFile(ctx context.Context, store objectstore.Store, name, path string) (int64, bool, error) {
	f, err := os.Open(path) // #nosec G304 -- a file inside the operator's own backup set directory (CWE-22)
	if err != nil {
		return 0, false, err
	}
	defer func() { _ = f.Close() }()
	info, err := f.Stat()
	if err != nil {
		return 0, false, err
	}
	digest := crypto.NewSHA256HMACDigest(nil)
	if _, err := io.Copy(digest, f); err != nil {
		return 0, false, fmt.Errorf("backup: hash %s: %w", path, err)
	}
	err = store.Create(ctx, name, f, info.Size(), digest.SHA256Sum())
	if errors.Is(err, objectstore.ErrExists) {
		stored, headErr := store.Head(ctx, name)
		if headErr != nil {
			return 0, false, headErr
		}
		if stored.SHA256 != digest.SHA256Hex() || stored.Size != info.Size() {
			return 0, false, fmt.Errorf("backup: %s already holds different bytes", store.Location(name))
		}
		return info.Size(), true, nil
	}
	if err != nil {
		return 0, false, fmt.Errorf("backup: upload %s: %w", path, err)
	}
	return info.Size(), false, nil
}

// DownloadFullBackup fetches the set backups/<name>/ into dir, which must be
// absent or empty, then re-hashes every artifact against the downloaded
// manifest (VerifyFullBackup). A set without its manifest is an upload that
// did not finish and is refused. Every object is checked against its stored
// SHA-256 as it arrives.
func DownloadFullBackup(ctx context.Context, store objectstore.Store, name, dir string) (VerifyReport, error) {
	if !setNamePattern.MatchString(name) {
		return VerifyReport{}, fmt.Errorf("backup: %q is not a set name", name)
	}
	prefix := objectSetRoot + name + "/"
	listed, err := store.List(ctx, prefix, maxObjectSetFiles)
	if err != nil {
		return VerifyReport{}, err
	}
	complete := false
	for _, obj := range listed {
		complete = complete || obj.Name == prefix+FullManifestName
	}
	if !complete {
		return VerifyReport{}, fmt.Errorf("backup: the object store holds no complete set named %q (no manifest)", name)
	}
	if err := ensureEmptyDirectory(dir); err != nil {
		return VerifyReport{}, err
	}
	for _, obj := range listed {
		if err := downloadSetFile(ctx, store, obj.Name, dir, strings.TrimPrefix(obj.Name, prefix)); err != nil {
			return VerifyReport{}, err
		}
	}
	return VerifyFullBackup(dir)
}

func ensureEmptyDirectory(dir string) error {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		return err
	}
	if len(entries) != 0 {
		return fmt.Errorf("backup: %s is not empty; download a set into a new directory", dir)
	}
	return nil
}

func downloadSetFile(ctx context.Context, store objectstore.Store, name, dir, rel string) error {
	if err := objectstore.ValidName(rel, false); err != nil {
		return err
	}
	target := filepath.Join(dir, filepath.FromSlash(rel))
	if inside, err := filepath.Rel(dir, target); err != nil || inside == ".." || strings.HasPrefix(inside, ".."+string(filepath.Separator)) {
		return fmt.Errorf("backup: object %s would land outside %s", name, dir)
	}
	if err := os.MkdirAll(filepath.Dir(target), 0o700); err != nil {
		return err
	}
	f, err := os.OpenFile(target, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600) // #nosec G304 -- a validated name inside the operator's new download directory (CWE-22)
	if err != nil {
		return err
	}
	_, getErr := store.Get(ctx, name, f, objectstore.MaxObjectBytes)
	closeErr := f.Close()
	if err := errors.Join(getErr, closeErr); err != nil {
		return fmt.Errorf("backup: download %s: %w", store.Location(name), err)
	}
	return nil
}
