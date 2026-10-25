// SPDX-License-Identifier: BUSL-1.1

package reportarchive_test

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"trstctl.com/trstctl/internal/objectstore/s3test"
	"trstctl.com/trstctl/internal/reportarchive"
)

const (
	objectTenant = "11111111-1111-4111-8111-111111111111"
	objectRun    = "22222222-2222-4222-8222-222222222222"
	otherRun     = "44444444-4444-4444-8444-444444444444"
)

var signedReport = []byte(`{"manifest":{"payload":{"n":1}},"signature":"AQ==","public_key_der":"AQ=="}`)

// With the object store as the target, a report is kept once under the
// tenant's object prefix, its reference is that object name, and every read
// checks the digest the completion event pins.
func TestArchiveKeepsReportsInTheObjectStoreUnderTheTenantPrefix(t *testing.T) {
	srv := s3test.NewServer(t)
	archive := reportarchive.Archive{Objects: srv.Open(t)}
	if !archive.Configured() || archive.Ready() != nil {
		t.Fatal("an archive with an object store is not ready")
	}
	ctx := t.Context()
	ref, digest, err := archive.Put(ctx, objectTenant, objectRun, signedReport)
	if err != nil {
		t.Fatal(err)
	}
	if want := "tenant/" + objectTenant + "/reports/" + objectRun + "/" + digest + ".json"; ref != want {
		t.Fatalf("reference = %q, want %q", ref, want)
	}
	if !reportarchive.ValidReference(ref, objectTenant, objectRun, digest) {
		t.Fatal("the object reference does not validate for its own run")
	}
	if got, err := archive.Read(ctx, ref, objectTenant, objectRun, digest); err != nil || !bytes.Equal(got, signedReport) {
		t.Fatalf("read = %q %v", got, err)
	}
	if again, _, err := archive.Put(ctx, objectTenant, objectRun, signedReport); err != nil || again != ref {
		t.Fatalf("idempotent put = %q %v", again, err)
	}
	foundRef, foundDigest, found, err := archive.FindRun(ctx, objectTenant, objectRun)
	if err != nil || foundRef != ref || foundDigest != digest || !bytes.Equal(found, signedReport) {
		t.Fatalf("crash-window recovery = %q %q %v", foundRef, foundDigest, err)
	}
	if _, _, _, err := archive.FindRun(ctx, objectTenant, otherRun); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("recovery of a run with no artifact = %v, want os.ErrNotExist", err)
	}
	if _, err := archive.Read(ctx, ref, "33333333-3333-4333-8333-333333333333", objectRun, digest); err == nil {
		t.Fatal("another tenant read the report through its reference")
	}
	srv.Replace(ref, []byte(`{"manifest":"altered"}`))
	if _, err := archive.Read(ctx, ref, objectTenant, objectRun, digest); err == nil {
		t.Fatal("altered stored bytes passed the read")
	}
	if _, _, err := archive.Put(ctx, objectTenant, objectRun, signedReport); err == nil {
		t.Fatal("a put accepted a stored object whose bytes differ")
	}
}

// Moving from the directory to the object store keeps earlier reports
// readable: a read follows the reference the run recorded, while new reports
// go to the object store and leave the directory untouched.
func TestArchiveReadsDirectoryReportsAfterMovingToTheObjectStore(t *testing.T) {
	root := filepath.Join(t.TempDir(), "archive")
	dir := reportarchive.Dir{Root: root}
	dirRef, dirDigest, err := dir.Put(objectTenant, objectRun, signedReport)
	if err != nil {
		t.Fatal(err)
	}
	srv := s3test.NewServer(t)
	archive := reportarchive.Archive{Dir: dir, Objects: srv.Open(t)}
	ctx := t.Context()
	if got, err := archive.Read(ctx, dirRef, objectTenant, objectRun, dirDigest); err != nil || !bytes.Equal(got, signedReport) {
		t.Fatalf("read of a directory report after the move = %q %v", got, err)
	}
	newReport := []byte(`{"manifest":{"payload":{"n":2}},"signature":"AQ==","public_key_der":"AQ=="}`)
	ref, _, err := archive.Put(ctx, objectTenant, otherRun, newReport)
	if err != nil || ref == "" || ref[:7] != "tenant/" {
		t.Fatalf("new report reference = %q %v, want an object reference", ref, err)
	}
	if entries, err := os.ReadDir(filepath.Join(root, "reports", objectTenant)); err != nil || len(entries) != 1 {
		t.Fatalf("the directory gained entries after the move: %v %v", entries, err)
	}
	if _, err := (reportarchive.Archive{Dir: dir}).Read(ctx, ref, objectTenant, otherRun, ref[len(ref)-69:len(ref)-5]); err == nil {
		t.Fatal("a directory-only archive read an object reference")
	}
}

// A reference is valid only for its own tenant, run and digest, in the
// directory form or under the tenant's own object prefix.
func TestValidReferenceAcceptsOnlyTheRunsOwnLocations(t *testing.T) {
	digest := "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	rel := "reports/" + objectRun + "/" + digest + ".json"
	for ref, want := range map[string]bool{
		"reports/" + objectTenant + "/" + objectRun + "/" + digest + ".json":       true,
		"tenant/" + objectTenant + "/" + rel:                                       true,
		"silo/" + objectTenant + "/" + rel:                                         true,
		"tenant/33333333-3333-4333-8333-333333333333/" + rel:                       false,
		"tenant/" + objectTenant + "/reports/" + otherRun + "/" + digest + ".json": false,
		"tenant/" + objectTenant + "/../" + objectTenant + "/" + rel:               false,
		"prod/tenant/" + objectTenant + "/" + rel:                                  false,
		"": false,
	} {
		if got := reportarchive.ValidReference(ref, objectTenant, objectRun, digest); got != want {
			t.Errorf("ValidReference(%q) = %v, want %v", ref, got, want)
		}
	}
}
