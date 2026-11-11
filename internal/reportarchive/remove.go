// SPDX-License-Identifier: BUSL-1.1

package reportarchive

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"trstctl.com/trstctl/internal/objectstore"
)

// The report retention (A206) removes a report its run no longer keeps and
// then confirms it is gone. Removal is by the run's reference, so it reaches
// the directory or the object store wherever the report was written.

// Remove deletes a run's report from where its reference says. A report that
// is already gone is not an error; an object store that refuses the delete
// returns its error and the report stays.
func (a Archive) Remove(ctx context.Context, ref, tenantID, runID, digest string) error {
	if !ValidReference(ref, tenantID, runID, digest) {
		return errors.New("reportarchive: reference does not match the run")
	}
	if IsDirectoryReference(ref) {
		path, missing, err := a.Dir.reportFile(tenantID, runID, digest)
		if err != nil || missing {
			return err
		}
		if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("reportarchive: remove report: %w", err)
		}
		return syncDirectory(filepath.Dir(path))
	}
	if a.Objects == nil {
		return errors.New("reportarchive: the report is in the object store, which is not configured")
	}
	// A206-L2: a bucket that keeps versions keeps a report's data after a
	// plain delete, so remove every version the store lists.
	if versioned, ok := a.Objects.(objectstore.Versioned); ok {
		removed, err := removeVersions(ctx, versioned, ref)
		if err != nil || removed {
			return err
		}
	}
	return a.removeCurrent(ctx, ref)
}

// removeCurrent deletes the report's current version, as a store without
// versions keeps only that one.
func (a Archive) removeCurrent(ctx context.Context, ref string) error {
	// A208: on a bucket with S3 Object Lock a plain delete only hides a
	// locked version behind a delete marker, so read the lock first and
	// leave a protected report in place.
	if locker, ok := a.Objects.(objectstore.Locker); ok {
		state, err := locker.Lock(ctx, ref)
		switch {
		case errors.Is(err, objectstore.ErrNotFound):
			return nil
		case err != nil:
			return fmt.Errorf("reportarchive: read the report's Object Lock: %w", err)
		case state.Locked(time.Now()):
			locked := &objectstore.ErrLocked{Name: ref, LegalHold: state.LegalHold}
			if state.RetainUntil != nil {
				locked.Until = *state.RetainUntil
			}
			return locked
		}
	}
	return a.Objects.Delete(ctx, ref)
}

// Gone reports whether a run's report is absent from where its reference
// says. An archive that cannot be read, including an archive root that is not
// there (an unmounted volume), is an error, never "gone".
func (a Archive) Gone(ctx context.Context, ref, tenantID, runID, digest string) (bool, error) {
	if !ValidReference(ref, tenantID, runID, digest) {
		return false, errors.New("reportarchive: reference does not match the run")
	}
	if IsDirectoryReference(ref) {
		path, missing, err := a.Dir.reportFile(tenantID, runID, digest)
		if err != nil || missing {
			return missing, err
		}
		if _, err := os.Lstat(path); errors.Is(err, os.ErrNotExist) {
			return true, nil
		} else if err != nil {
			return false, err
		}
		return false, nil
	}
	if a.Objects == nil {
		return false, errors.New("reportarchive: the report is in the object store, which is not configured")
	}
	_, err := a.Objects.Head(ctx, ref)
	switch {
	case errors.Is(err, objectstore.ErrNotFound):
	case err != nil:
		return false, err
	default:
		return false, nil
	}
	// A206-L2: HEAD answers 404 once a delete marker hides the report, so a
	// store that keeps versions must list none of the report's data.
	if versioned, ok := a.Objects.(objectstore.Versioned); ok {
		versions, err := versioned.Versions(ctx, ref)
		switch {
		case errors.Is(err, objectstore.ErrVersionsUnsupported):
		case err != nil:
			return false, fmt.Errorf("reportarchive: list the report's versions: %w", err)
		default:
			for _, version := range versions {
				if !version.DeleteMarker {
					return false, nil
				}
			}
		}
	}
	return true, nil
}

// removeVersions deletes every version of a report the store lists, its data
// first and then the delete markers earlier plain deletes left. It reads each
// version's Object Lock first: if the lock protects any version, nothing is
// deleted and the error says until when. removed is false when the store does
// not list versions or lists none, and the caller deletes the current version
// as before.
func removeVersions(ctx context.Context, store objectstore.Versioned, ref string) (removed bool, err error) {
	versions, err := store.Versions(ctx, ref)
	switch {
	case errors.Is(err, objectstore.ErrVersionsUnsupported):
		return false, nil
	case err != nil:
		return false, fmt.Errorf("reportarchive: list the report's versions: %w", err)
	case len(versions) == 0:
		return false, nil
	}
	now := time.Now()
	var locked *objectstore.ErrLocked
	for _, version := range versions {
		if version.DeleteMarker {
			continue
		}
		state, err := store.LockVersion(ctx, ref, version.ID)
		switch {
		case errors.Is(err, objectstore.ErrNotFound):
			continue
		case err != nil:
			return false, fmt.Errorf("reportarchive: read the Object Lock of a version of the report: %w", err)
		case !state.Locked(now):
			continue
		}
		if locked == nil {
			locked = &objectstore.ErrLocked{Name: ref}
		}
		locked.LegalHold = locked.LegalHold || state.LegalHold
		if until := state.RetainUntil; until != nil && now.Before(*until) && until.After(locked.Until) {
			locked.Until = *until
		}
	}
	if locked != nil {
		return false, locked
	}
	for _, markers := range []bool{false, true} {
		for _, version := range versions {
			if version.DeleteMarker != markers {
				continue
			}
			if err := store.DeleteVersion(ctx, ref, version.ID); err != nil {
				return false, fmt.Errorf("reportarchive: remove a version of the report: %w", err)
			}
		}
	}
	return true, nil
}

// reportFile resolves a run's report under the archive root, checking every
// directory on the way as Read does, so a removal never follows a link out of
// the archive. The root and its reports directory must exist; a missing tenant
// or run directory means the report is not there (missing).
func (d Dir) reportFile(tenantID, runID, digest string) (path string, missing bool, err error) {
	ref, err := Reference(tenantID, runID, digest)
	if err != nil {
		return "", false, err
	}
	if d.Root == "" {
		return "", false, errors.New("reportarchive: archive root is required")
	}
	root, err := filepath.Abs(d.Root)
	if err != nil {
		return "", false, err
	}
	for _, dir := range []string{root, filepath.Join(root, "reports")} {
		if err := checkPrivateDirectory(dir); err != nil {
			return "", false, err
		}
	}
	for _, dir := range []string{filepath.Join(root, "reports", tenantID), filepath.Join(root, "reports", tenantID, runID)} {
		if err := checkPrivateDirectory(dir); errors.Is(err, os.ErrNotExist) {
			return "", true, nil
		} else if err != nil {
			return "", false, err
		}
	}
	return filepath.Join(root, filepath.FromSlash(ref)), false, nil
}
