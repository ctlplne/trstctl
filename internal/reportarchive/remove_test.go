// SPDX-License-Identifier: BUSL-1.1

package reportarchive_test

import (
	"os"
	"path/filepath"
	"testing"

	"trstctl.com/trstctl/internal/objectstore/s3test"
	"trstctl.com/trstctl/internal/reportarchive"
)

// A206: the report retention removes a report where its reference says and
// confirms it is gone. A second removal is not an error. An archive that
// cannot be read, including a root that is not there (an unmounted volume),
// never reads as "gone", and a removal never follows a link out of the
// archive.
func TestArchiveRemovesReportsAndConfirmsThemGone(t *testing.T) {
	ctx := t.Context()
	root := filepath.Join(t.TempDir(), "archive")
	archive := reportarchive.Archive{Dir: reportarchive.Dir{Root: root}}
	ref, digest, err := archive.Dir.Put(objectTenant, objectRun, signedReport)
	if err != nil {
		t.Fatal(err)
	}
	if gone, err := archive.Gone(ctx, ref, objectTenant, objectRun, digest); err != nil || gone {
		t.Fatalf("a kept report reads gone = %v %v", gone, err)
	}
	if err := archive.Remove(ctx, ref, objectTenant, otherRun, digest); err == nil {
		t.Fatal("a removal under another run's identity was accepted")
	}
	for i := 0; i < 2; i++ {
		if err := archive.Remove(ctx, ref, objectTenant, objectRun, digest); err != nil {
			t.Fatalf("removal %d: %v", i+1, err)
		}
	}
	if gone, err := archive.Gone(ctx, ref, objectTenant, objectRun, digest); err != nil || !gone {
		t.Fatalf("a removed report reads gone = %v %v", gone, err)
	}
	if _, err := archive.Read(ctx, ref, objectTenant, objectRun, digest); err == nil {
		t.Fatal("a removed report still reads")
	}

	// A run whose directory was never written is gone; an archive root that
	// is not there is an error.
	if gone, err := archive.Gone(ctx, "reports/"+objectTenant+"/"+otherRun+"/"+digest+".json", objectTenant, otherRun, digest); err != nil || !gone {
		t.Fatalf("a run with no directory reads gone = %v %v", gone, err)
	}
	unmounted := reportarchive.Archive{Dir: reportarchive.Dir{Root: filepath.Join(t.TempDir(), "not-mounted")}}
	if gone, err := unmounted.Gone(ctx, ref, objectTenant, objectRun, digest); err == nil || gone {
		t.Fatalf("a missing archive root reads gone = %v %v", gone, err)
	}

	// A run directory replaced by a link out of the archive is refused.
	linked := filepath.Join(t.TempDir(), "archive")
	linkedArchive := reportarchive.Archive{Dir: reportarchive.Dir{Root: linked}}
	linkedRef, linkedDigest, err := linkedArchive.Dir.Put(objectTenant, objectRun, signedReport)
	if err != nil {
		t.Fatal(err)
	}
	runDir := filepath.Join(linked, "reports", objectTenant, objectRun)
	outside := filepath.Join(t.TempDir(), "outside")
	if err := os.Rename(runDir, outside); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, runDir); err != nil {
		t.Fatal(err)
	}
	if err := linkedArchive.Remove(ctx, linkedRef, objectTenant, objectRun, linkedDigest); err == nil {
		t.Fatal("a removal followed a linked run directory")
	}
	if gone, err := linkedArchive.Gone(ctx, linkedRef, objectTenant, objectRun, linkedDigest); err == nil || gone {
		t.Fatalf("a linked run directory reads gone = %v %v", gone, err)
	}
	if _, err := os.Stat(filepath.Join(outside, linkedDigest+".json")); err != nil {
		t.Fatalf("the report outside the archive was touched: %v", err)
	}
}

// In the object store, the removal deletes the run's object and the
// confirmation is a read of the store.
func TestArchiveRemovesObjectStoreReports(t *testing.T) {
	ctx := t.Context()
	srv := s3test.NewServer(t)
	archive := reportarchive.Archive{Objects: srv.Open(t)}
	ref, digest, err := archive.Put(ctx, objectTenant, objectRun, signedReport)
	if err != nil {
		t.Fatal(err)
	}
	if gone, err := archive.Gone(ctx, ref, objectTenant, objectRun, digest); err != nil || gone {
		t.Fatalf("a kept object reads gone = %v %v", gone, err)
	}
	if err := archive.Remove(ctx, ref, objectTenant, objectRun, digest); err != nil {
		t.Fatal(err)
	}
	if _, found := srv.Object(ref); found {
		t.Fatal("the object is still in the store")
	}
	if gone, err := archive.Gone(ctx, ref, objectTenant, objectRun, digest); err != nil || !gone {
		t.Fatalf("a removed object reads gone = %v %v", gone, err)
	}
	if err := (reportarchive.Archive{}).Remove(ctx, ref, objectTenant, objectRun, digest); err == nil {
		t.Fatal("an archive without the object store removed an object reference")
	}
}
