// SPDX-License-Identifier: BUSL-1.1

package objectstore_test

import (
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"sync"
	"testing"

	"trstctl.com/trstctl/internal/objectstore"
	"trstctl.com/trstctl/internal/objectstore/s3test"
)

// versionsServer answers ListObjectVersions with the pages a test gives it,
// chosen by the request's key marker, and records DeleteObject requests.
type versionsServer struct {
	mu      sync.Mutex
	pages   map[string]string
	listed  []string
	deleted []string
}

func (s *versionsServer) serve(w http.ResponseWriter, r *http.Request) {
	query := r.URL.Query()
	s.mu.Lock()
	defer s.mu.Unlock()
	switch {
	case r.Method == http.MethodGet && query.Has("versions"):
		s.listed = append(s.listed, query.Get("prefix")+" after "+query.Get("key-marker")+"@"+query.Get("version-id-marker"))
		page, ok := s.pages[query.Get("key-marker")+"@"+query.Get("version-id-marker")]
		if !ok {
			http.Error(w, "no such page", http.StatusBadRequest)
			return
		}
		w.Header().Set("Content-Type", "application/xml")
		_, _ = io.WriteString(w, `<?xml version="1.0" encoding="UTF-8"?><ListVersionsResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/">`+page+`</ListVersionsResult>`)
	case r.Method == http.MethodDelete:
		version := query.Get("versionId")
		s.deleted = append(s.deleted, strings.TrimPrefix(r.URL.Path, "/trstctl-test/")+"@"+version)
		if version == "already-gone" {
			w.Header().Set("Content-Type", "application/xml")
			w.WriteHeader(http.StatusNotFound)
			_, _ = io.WriteString(w, `<Error><Code>NoSuchVersion</Code><Message>gone</Message></Error>`)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	default:
		http.Error(w, "unexpected request", http.StatusBadRequest)
	}
}

func versionEntry(kind, key, id string) string {
	return fmt.Sprintf("<%s><Key>%s</Key><VersionId>%s</VersionId></%s>", kind, key, id, kind)
}

// A206-L2: a store's versions of one object are listed page by page, exactly
// that key's (a longer key sharing its prefix ends the listing), within a
// bound; a version is deleted by its ID, one already gone is not an error,
// and a store that does not list versions says so.
func TestS3ListsAndDeletesAnObjectsVersions(t *testing.T) {
	ctx := t.Context()
	const key = "deployment-a/tenant/reports/run/a.json"
	fake := &versionsServer{pages: map[string]string{
		"@": versionEntry("Version", key, "v3") + versionEntry("DeleteMarker", key, "m1") + versionEntry("Version", key, "v2") +
			"<IsTruncated>true</IsTruncated><NextKeyMarker>" + key + "</NextKeyMarker><NextVersionIdMarker>v2</NextVersionIdMarker>",
		key + "@v2": versionEntry("Version", key, "v1") + versionEntry("Version", key+".bak", "x1") +
			"<IsTruncated>true</IsTruncated><NextKeyMarker>" + key + ".bak</NextKeyMarker><NextVersionIdMarker>x1</NextVersionIdMarker>",
	}}
	srv := httptest.NewServer(http.HandlerFunc(fake.serve))
	t.Cleanup(srv.Close)
	open := func() *objectstore.S3 {
		store, err := objectstore.Open(objectstore.Options{Endpoint: srv.URL, Bucket: "trstctl-test", Prefix: "deployment-a", PathStyle: true,
			AllowInsecureLoopback: true, AccessKeyID: "AKIATRSTCTLTEST", SecretAccessKey: []byte("test-secret-access-key")})
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(store.Destroy)
		return store
	}
	store := open()
	const name = "tenant/reports/run/a.json"
	versions, err := store.Versions(ctx, name)
	want := []objectstore.Version{{ID: "v3"}, {ID: "v2"}, {ID: "m1", DeleteMarker: true}, {ID: "v1"}}
	if err != nil || !slices.Equal(versions, want) {
		t.Fatalf("versions = %+v %v, want %+v", versions, err, want)
	}
	if wantListed := []string{key + " after @", key + " after " + key + "@v2"}; !slices.Equal(fake.listed, wantListed) {
		t.Fatalf("listed %q, want %q", fake.listed, wantListed)
	}
	for _, version := range []string{"v3", "already-gone"} {
		if err := store.DeleteVersion(ctx, name, version); err != nil {
			t.Fatalf("delete version %s: %v", version, err)
		}
	}
	if wantDeleted := []string{key + "@v3", key + "@already-gone"}; !slices.Equal(fake.deleted, wantDeleted) {
		t.Fatalf("deleted %q, want %q", fake.deleted, wantDeleted)
	}
	if err := store.DeleteVersion(ctx, name, ""); err == nil {
		t.Fatal("a deletion without a version ID was sent")
	}
	if _, err := store.LockVersion(ctx, name, ""); err == nil {
		t.Fatal("a lock read without a version ID was sent")
	}

	// A listing cut short without a marker, or longer than the bound, is
	// an error, never a partial answer.
	fake.mu.Lock()
	fake.pages["@"] = versionEntry("Version", key, "v1") + "<IsTruncated>true</IsTruncated>"
	fake.mu.Unlock()
	if _, err := store.Versions(ctx, name); err == nil {
		t.Fatal("a truncated listing without a marker was accepted")
	}
	var many strings.Builder
	for i := 0; i <= 1000; i++ {
		many.WriteString(versionEntry("Version", key, fmt.Sprintf("v%d", i)))
	}
	fake.mu.Lock()
	fake.pages["@"] = many.String()
	fake.mu.Unlock()
	if _, err := store.Versions(ctx, name); err == nil || !strings.Contains(err.Error(), "more than 1000 versions") {
		t.Fatalf("1001 versions = %v", err)
	}

	// The fake S3 does not implement the versions listing.
	unversioned := s3test.NewServer(t).Open(t)
	if _, err := unversioned.Versions(ctx, name); !errors.Is(err, objectstore.ErrVersionsUnsupported) {
		t.Fatalf("a store without versions = %v", err)
	}
}
