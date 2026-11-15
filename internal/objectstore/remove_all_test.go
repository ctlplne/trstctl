// SPDX-License-Identifier: BUSL-1.1

package objectstore_test

import (
	"bytes"
	"context"
	"errors"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/objectstore"
	"trstctl.com/trstctl/internal/objectstore/s3test"
)

func putA206L2L1(t *testing.T, store objectstore.Store, name, body string) {
	t.Helper()
	if err := store.Create(context.Background(), name, bytes.NewReader([]byte(body)), int64(len(body)), crypto.SHA256Sum([]byte(body))); err != nil {
		t.Fatal(err)
	}
}

// TestRemoveAllLeavesNoVersionAndHonorsObjectLockA206L2L1: on a store that
// keeps versions, RemoveAll deletes every version of every object it is given
// and the delete markers earlier plain deletes left, where a plain delete
// leaves the data behind a marker; a version under Object Lock keeps all of
// the objects in place (none half removed) and the error says until when,
// and once the lock lapses they go; a store that lists no versions has its
// current objects deleted; a missing object is not an error.
func TestRemoveAllLeavesNoVersionAndHonorsObjectLockA206L2L1(t *testing.T) {
	ctx := context.Background()
	server := s3test.NewServer(t)
	store := s3test.NewVersionedStore(server.Open(t))
	putA206L2L1(t, store, "rec/one", "first")
	if err := store.Delete(ctx, "rec/one"); err != nil {
		t.Fatal(err)
	}
	putA206L2L1(t, store, "rec/one", "second")
	putA206L2L1(t, store, "rec/two", "manifest")
	if store.VersionCount("rec/one") != 3 {
		t.Fatalf("rec/one has %d versions, want two of data and a marker", store.VersionCount("rec/one"))
	}
	// A plain delete is what left the first version behind.
	if err := store.Delete(ctx, "rec/two"); err != nil {
		t.Fatal(err)
	}
	if store.VersionCount("rec/two") != 2 {
		t.Fatal("a plain delete removed the data of a versioned object")
	}

	until := time.Now().Add(400 * time.Millisecond)
	store.Retain("rec/one", until)
	err := objectstore.RemoveAll(ctx, store, "rec/two", "rec/one")
	var locked *objectstore.ErrLocked
	if !errors.As(err, &locked) || locked.Name != "rec/one" || !locked.Until.Equal(until) {
		t.Fatalf("RemoveAll under Object Lock = %v", err)
	}
	if store.VersionCount("rec/two") != 2 || store.VersionCount("rec/one") != 3 {
		t.Fatal("a lock on one object let another be removed")
	}
	time.Sleep(time.Until(until) + 50*time.Millisecond)
	if err := objectstore.RemoveAll(ctx, store, "rec/two", "rec/one", "rec/missing"); err != nil {
		t.Fatalf("RemoveAll after the lock lapsed: %v", err)
	}
	if names := store.Names(); len(names) != 0 {
		t.Fatalf("versions or markers left: %v", names)
	}
	if _, err := store.Head(ctx, "rec/one"); !errors.Is(err, objectstore.ErrNotFound) {
		t.Fatalf("the current object is still there: %v", err)
	}

	plain := server.Open(t)
	putA206L2L1(t, plain, "plain/one", "x")
	if err := objectstore.RemoveAll(ctx, plain, "plain/one", "plain/missing"); err != nil {
		t.Fatal(err)
	}
	if _, err := plain.Head(ctx, "plain/one"); !errors.Is(err, objectstore.ErrNotFound) {
		t.Fatalf("a store without versions kept the object: %v", err)
	}
}
