// SPDX-License-Identifier: BUSL-1.1

package s3test

import (
	"context"
	"errors"
	"io"
	"slices"
	"strconv"
	"sync"
	"time"

	"trstctl.com/trstctl/internal/objectstore"
)

// VersionedStore is a store that keeps versions, as an S3 bucket with
// versioning or Object Lock does (A206L2-L1): every Create adds a version of
// the object, a plain Delete only adds a delete marker and leaves the data,
// and DeleteVersion removes one version for good, refusing one its Object
// Lock protects. The wrapped store holds each object's current data.
type VersionedStore struct {
	objectstore.Store
	mu       sync.Mutex
	seq      int
	versions map[string][]objectstore.Version
	locks    map[string]objectstore.LockState
}

var (
	_ objectstore.Versioned = (*VersionedStore)(nil)
	_ objectstore.Locker    = (*VersionedStore)(nil)
)

// NewVersionedStore keeps versions of what base stores.
func NewVersionedStore(base objectstore.Store) *VersionedStore {
	return &VersionedStore{Store: base, versions: map[string][]objectstore.Version{}, locks: map[string]objectstore.LockState{}}
}

func (s *VersionedStore) newVersion(name string, marker bool) {
	s.seq++
	s.versions[name] = append(s.versions[name], objectstore.Version{ID: "v" + strconv.Itoa(s.seq), DeleteMarker: marker})
}

// Create writes the object and keeps it as a new version.
func (s *VersionedStore) Create(ctx context.Context, name string, body io.ReadSeeker, size int64, sha256 []byte) error {
	if err := s.Store.Create(ctx, name, body, size, sha256); err != nil {
		return err
	}
	s.mu.Lock()
	s.newVersion(name, false)
	s.mu.Unlock()
	return nil
}

// Delete hides the object behind a delete marker; its versions stay.
func (s *VersionedStore) Delete(ctx context.Context, name string) error {
	s.mu.Lock()
	if len(s.versions[name]) > 0 {
		s.newVersion(name, true)
	}
	s.mu.Unlock()
	return s.Store.Delete(ctx, name)
}

// Versions lists every version of the object and its delete markers.
func (s *VersionedStore) Versions(_ context.Context, name string) ([]objectstore.Version, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return slices.Clone(s.versions[name]), nil
}

// LockVersion reads one version's Object Lock.
func (s *VersionedStore) LockVersion(_ context.Context, name, version string) (objectstore.LockState, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !slices.ContainsFunc(s.versions[name], func(v objectstore.Version) bool { return v.ID == version }) {
		return objectstore.LockState{}, objectstore.ErrNotFound
	}
	return s.locks[version], nil
}

// Lock reads the Object Lock of the object's newest version.
func (s *VersionedStore) Lock(_ context.Context, name string) (objectstore.LockState, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for i := len(s.versions[name]) - 1; i >= 0; i-- {
		if v := s.versions[name][i]; !v.DeleteMarker {
			return s.locks[v.ID], nil
		}
	}
	return objectstore.LockState{}, objectstore.ErrNotFound
}

// SetLegalHold sets or clears the legal hold of the object's newest version.
func (s *VersionedStore) SetLegalHold(_ context.Context, name string, on bool) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	for i := len(s.versions[name]) - 1; i >= 0; i-- {
		if v := s.versions[name][i]; !v.DeleteMarker {
			state := s.locks[v.ID]
			state.LegalHold = on
			s.locks[v.ID] = state
			return nil
		}
	}
	return objectstore.ErrNotFound
}

// Retain puts the object's newest version under Object Lock retention until.
func (s *VersionedStore) Retain(name string, until time.Time) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for i := len(s.versions[name]) - 1; i >= 0; i-- {
		if v := s.versions[name][i]; !v.DeleteMarker {
			s.locks[v.ID] = objectstore.LockState{Mode: "GOVERNANCE", RetainUntil: &until}
			return
		}
	}
}

// DeleteVersion removes one version for good, as S3 refuses for a version its
// Object Lock protects; removing the last version of the data takes the
// current object with it.
func (s *VersionedStore) DeleteVersion(ctx context.Context, name, version string) error {
	s.mu.Lock()
	if s.locks[version].Locked(time.Now()) {
		s.mu.Unlock()
		return errors.New("s3test: AccessDenied: the version is under Object Lock")
	}
	s.versions[name] = slices.DeleteFunc(s.versions[name], func(v objectstore.Version) bool { return v.ID == version })
	data := slices.ContainsFunc(s.versions[name], func(v objectstore.Version) bool { return !v.DeleteMarker })
	if len(s.versions[name]) == 0 {
		delete(s.versions, name)
	}
	s.mu.Unlock()
	if data {
		return nil
	}
	return s.Store.Delete(ctx, name)
}

// VersionCount is how many versions and delete markers the object has.
func (s *VersionedStore) VersionCount(name string) int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.versions[name])
}

// Names lists every object that has a version or delete marker.
func (s *VersionedStore) Names() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]string, 0, len(s.versions))
	for name := range s.versions {
		out = append(out, name)
	}
	slices.Sort(out)
	return out
}
