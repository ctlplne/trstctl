// SPDX-License-Identifier: BUSL-1.1

package reportarchive_test

import (
	"context"
	"errors"
	"slices"
	"sync"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/objectstore"
	"trstctl.com/trstctl/internal/objectstore/s3test"
	"trstctl.com/trstctl/internal/reportarchive"
)

// versionedStore is an object store that keeps versions, as an S3 bucket with
// versioning (or Object Lock) does: the fake S3 holds the current object and
// this store lists the versions and delete markers beside it.
type versionedStore struct {
	objectstore.Store
	mu       sync.Mutex
	versions map[string][]objectstore.Version
	locks    map[string]objectstore.LockState
	deleted  []string
	// keep acknowledges a version's deletion without applying it;
	// unsupported answers as a store that lists no versions.
	keep, unsupported bool
}

func (s *versionedStore) Versions(_ context.Context, name string) ([]objectstore.Version, error) {
	if s.unsupported {
		return nil, objectstore.ErrVersionsUnsupported
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return slices.Clone(s.versions[name]), nil
}

func (s *versionedStore) LockVersion(_ context.Context, _, version string) (objectstore.LockState, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.locks[version], nil
}

func (s *versionedStore) DeleteVersion(ctx context.Context, name, version string) error {
	s.mu.Lock()
	s.deleted = append(s.deleted, version)
	if s.keep {
		s.mu.Unlock()
		return nil
	}
	s.versions[name] = slices.DeleteFunc(s.versions[name], func(v objectstore.Version) bool { return v.ID == version })
	data := slices.ContainsFunc(s.versions[name], func(v objectstore.Version) bool { return !v.DeleteMarker })
	s.mu.Unlock()
	if data {
		return nil
	}
	// The last version of the data takes the current object with it.
	return s.Delete(ctx, name)
}

// A206-L2: in a store that keeps versions, removing a report deletes every
// version of it, its data before the delete markers, and the report reads
// gone only when no version of its data is left, whatever HEAD answers. A
// version under Object Lock keeps every version in place and says until when.
// A store that lists no versions is removed from as before.
func TestArchiveRemovesEveryVersionOfAReport(t *testing.T) {
	ctx := t.Context()
	setup := func(t *testing.T, versions ...objectstore.Version) (*versionedStore, *s3test.Server, reportarchive.Archive, string, string) {
		t.Helper()
		srv := s3test.NewServer(t)
		store := &versionedStore{Store: srv.Open(t), versions: map[string][]objectstore.Version{}, locks: map[string]objectstore.LockState{}}
		archive := reportarchive.Archive{Objects: store}
		ref, digest, err := archive.Put(ctx, objectTenant, objectRun, signedReport)
		if err != nil {
			t.Fatal(err)
		}
		store.versions[ref] = versions
		return store, srv, archive, ref, digest
	}

	t.Run("a version hidden behind a delete marker", func(t *testing.T) {
		store, srv, archive, ref, digest := setup(t, objectstore.Version{ID: "v1"}, objectstore.Version{ID: "m1", DeleteMarker: true})
		// A plain delete hid the report: HEAD answers 404, the version stays.
		if err := store.Delete(ctx, ref); err != nil {
			t.Fatal(err)
		}
		if gone, err := archive.Gone(ctx, ref, objectTenant, objectRun, digest); err != nil || gone {
			t.Fatalf("a report whose version remains reads gone = %v %v", gone, err)
		}
		if err := archive.Remove(ctx, ref, objectTenant, objectRun, digest); err != nil {
			t.Fatal(err)
		}
		if want := []string{"v1", "m1"}; !slices.Equal(store.deleted, want) {
			t.Fatalf("deleted %v, want the data then the marker %v", store.deleted, want)
		}
		if gone, err := archive.Gone(ctx, ref, objectTenant, objectRun, digest); err != nil || !gone {
			t.Fatalf("a report with no version left reads gone = %v %v", gone, err)
		}
		if _, found := srv.Object(ref); found {
			t.Fatal("the current object is still in the store")
		}
	})

	t.Run("a version under Object Lock keeps them all", func(t *testing.T) {
		store, srv, archive, ref, digest := setup(t, objectstore.Version{ID: "v2"}, objectstore.Version{ID: "v1"}, objectstore.Version{ID: "v0"})
		now := time.Now().UTC().Truncate(time.Second)
		later, earlier, past := now.Add(72*time.Hour), now.Add(24*time.Hour), now.Add(-time.Hour)
		store.locks["v2"] = objectstore.LockState{Mode: "GOVERNANCE", RetainUntil: &earlier}
		store.locks["v1"] = objectstore.LockState{Mode: "COMPLIANCE", RetainUntil: &later}
		store.locks["v0"] = objectstore.LockState{Mode: "GOVERNANCE", RetainUntil: &past}
		err := archive.Remove(ctx, ref, objectTenant, objectRun, digest)
		var locked *objectstore.ErrLocked
		if !errors.As(err, &locked) || locked.LegalHold || !locked.Until.Equal(later) {
			t.Fatalf("removal under retention = %v, want refused until the latest lock's end %v", err, later)
		}
		if len(store.deleted) != 0 {
			t.Fatalf("deleted %v while a version is locked", store.deleted)
		}
		store.locks["v0"] = objectstore.LockState{LegalHold: true}
		if err := archive.Remove(ctx, ref, objectTenant, objectRun, digest); !errors.As(err, &locked) || !locked.LegalHold {
			t.Fatalf("removal under a legal hold = %v", err)
		}
		if _, found := srv.Object(ref); !found || len(store.deleted) != 0 {
			t.Fatalf("a locked report was touched: present %v, deleted %v", found, store.deleted)
		}
		// The locks end: every version goes.
		store.locks = map[string]objectstore.LockState{"v1": {Mode: "COMPLIANCE", RetainUntil: &past}}
		if err := archive.Remove(ctx, ref, objectTenant, objectRun, digest); err != nil {
			t.Fatal(err)
		}
		if gone, err := archive.Gone(ctx, ref, objectTenant, objectRun, digest); err != nil || !gone {
			t.Fatalf("after the locks ended the report reads gone = %v %v", gone, err)
		}
	})

	t.Run("a deletion acknowledged but not applied", func(t *testing.T) {
		store, _, archive, ref, digest := setup(t, objectstore.Version{ID: "v1"})
		store.keep = true
		if err := store.Delete(ctx, ref); err != nil {
			t.Fatal(err)
		}
		if err := archive.Remove(ctx, ref, objectTenant, objectRun, digest); err != nil {
			t.Fatal(err)
		}
		if gone, err := archive.Gone(ctx, ref, objectTenant, objectRun, digest); err != nil || gone {
			t.Fatalf("a report whose version the store kept reads gone = %v %v", gone, err)
		}
	})

	t.Run("a store that lists no versions", func(t *testing.T) {
		store, srv, archive, ref, digest := setup(t)
		store.unsupported = true
		if err := archive.Remove(ctx, ref, objectTenant, objectRun, digest); err != nil {
			t.Fatal(err)
		}
		if _, found := srv.Object(ref); found || len(store.deleted) != 0 {
			t.Fatalf("plain removal: present %v, versions deleted %v", found, store.deleted)
		}
		if gone, err := archive.Gone(ctx, ref, objectTenant, objectRun, digest); err != nil || !gone {
			t.Fatalf("a removed report reads gone = %v %v", gone, err)
		}
	})
}
