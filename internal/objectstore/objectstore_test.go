// SPDX-License-Identifier: BUSL-1.1

package objectstore_test

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/objectstore"
	"trstctl.com/trstctl/internal/objectstore/s3test"
)

func create(t *testing.T, store objectstore.Store, name string, data []byte) error {
	t.Helper()
	return store.Create(t.Context(), name, bytes.NewReader(data), int64(len(data)), crypto.SHA256Sum(data))
}

// Objects are created, never replaced: the write is conditional, the store
// checks the digest it is given, and a second write to the same name is
// refused by the store itself and leaves the first bytes in place.
func TestCreateIsConditionalAndDigestChecked(t *testing.T) {
	srv := s3test.NewServer(t)
	store := srv.Open(t, func(o *objectstore.Options) { o.Prefix = "prod" })
	first := []byte(`{"segment":1}`)
	if err := create(t, store, "audit/a.jws", first); err != nil {
		t.Fatalf("create: %v", err)
	}
	if got := srv.Keys(); len(got) != 1 || got[0] != "prod/audit/a.jws" {
		t.Fatalf("stored keys = %v, want the name under the deployment prefix", got)
	}
	if err := create(t, store, "audit/a.jws", []byte(`{"segment":2}`)); !errors.Is(err, objectstore.ErrExists) {
		t.Fatalf("second create = %v, want ErrExists", err)
	}
	if got, _ := srv.Object("prod/audit/a.jws"); !bytes.Equal(got, first) {
		t.Fatalf("the refused overwrite changed the object to %q", got)
	}
	wrong := crypto.SHA256Sum([]byte("other bytes"))
	if err := store.Create(t.Context(), "audit/b.jws", bytes.NewReader(first), int64(len(first)), wrong); !errors.Is(err, objectstore.ErrDigest) {
		t.Fatalf("create with a digest of other bytes = %v, want ErrDigest", err)
	}
	if _, ok := srv.Object("prod/audit/b.jws"); ok {
		t.Fatal("the store kept an object whose digest did not match")
	}
	var buf bytes.Buffer
	obj, err := store.Get(t.Context(), "audit/a.jws", &buf, 1<<20)
	if err != nil || !bytes.Equal(buf.Bytes(), first) || obj.SHA256 != crypto.SHA256Hex(first) || obj.Size != int64(len(first)) {
		t.Fatalf("get = %+v %q %v", obj, buf.Bytes(), err)
	}
	head, err := store.Head(t.Context(), "audit/a.jws")
	if err != nil || head.SHA256 != crypto.SHA256Hex(first) || head.Size != int64(len(first)) {
		t.Fatalf("head = %+v %v, want the stored size and checksum", head, err)
	}
	if _, err := store.Head(t.Context(), "audit/missing.jws"); !errors.Is(err, objectstore.ErrNotFound) {
		t.Fatalf("head of a missing object = %v, want ErrNotFound", err)
	}
	if err := store.Delete(t.Context(), "audit/a.jws"); err != nil {
		t.Fatal(err)
	}
	if err := store.Delete(t.Context(), "audit/a.jws"); err != nil {
		t.Fatalf("deleting a missing object = %v, want nil", err)
	}
	if location := store.Location("audit/a.jws"); location != "s3://trstctl-test/prod/audit/a.jws" {
		t.Fatalf("location = %q", location)
	}
	if name, err := store.NameOf("s3://trstctl-test/prod/audit/a.jws"); err != nil || name != "audit/a.jws" {
		t.Fatalf("name of the store's own locator = %q %v", name, err)
	}
	for _, foreign := range []string{"s3://other-bucket/prod/audit/a.jws", "s3://trstctl-test/staging/audit/a.jws", "s3://trstctl-test/prod/../x", "/var/archive/a.jws"} {
		if _, err := store.NameOf(foreign); !errors.Is(err, objectstore.ErrName) {
			t.Fatalf("name of %q = %v, want ErrName", foreign, err)
		}
	}
}

// A read refuses an object over the caller's limit, and an object whose bytes
// no longer match the checksum recorded at upload is reported as a digest
// failure, not returned.
func TestGetRefusesOversizedAndAlteredObjects(t *testing.T) {
	srv := s3test.NewServer(t)
	store := srv.Open(t)
	data := bytes.Repeat([]byte("a"), 4096)
	if err := create(t, store, "reports/r.json", data); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Get(t.Context(), "reports/r.json", &bytes.Buffer{}, 1024); !errors.Is(err, objectstore.ErrTooLarge) {
		t.Fatalf("get over the limit = %v, want ErrTooLarge", err)
	}
	srv.Replace("reports/r.json", bytes.Repeat([]byte("b"), 4096))
	if _, err := store.Get(t.Context(), "reports/r.json", &bytes.Buffer{}, 1<<20); !errors.Is(err, objectstore.ErrDigest) {
		t.Fatalf("get of altered bytes = %v, want ErrDigest", err)
	}
}

// A listing follows continuation pages in name order, and refuses to return a
// silently truncated list when more objects match than the caller allowed.
func TestListFollowsPagesAndRefusesTruncation(t *testing.T) {
	srv := s3test.NewServer(t)
	store := srv.Open(t)
	for i := 0; i < 1005; i++ {
		srv.Seed(fmt.Sprintf("backups/set-1/part-%04d", i), []byte{byte(i)})
	}
	srv.Seed("backups/set-2/manifest.json", []byte("{}"))
	listed, err := store.List(t.Context(), "backups/set-1/", 2000)
	if err != nil || len(listed) != 1005 || listed[0].Name != "backups/set-1/part-0000" || listed[1004].Name != "backups/set-1/part-1004" {
		t.Fatalf("list = %d objects, err %v", len(listed), err)
	}
	if _, err := store.List(t.Context(), "backups/set-1/", 10); err == nil || !strings.Contains(err.Error(), "more than 10") {
		t.Fatalf("list over the limit = %v, want a refusal", err)
	}
	for _, bad := range []string{"", "/backups", "backups/../x/", "backups//"} {
		if _, err := store.List(t.Context(), bad, 10); !errors.Is(err, objectstore.ErrName) {
			t.Fatalf("list %q = %v, want ErrName", bad, err)
		}
	}
}

// A tenant view addresses only names inside its tenant's prefix: one tenant's
// listing never shows another's object, and a name that would climb out of
// the prefix is refused before any request is made.
func TestTenantViewIsConfinedToItsPrefix(t *testing.T) {
	srv := s3test.NewServer(t)
	store := srv.Open(t, func(o *objectstore.Options) { o.Prefix = "prod/" })
	const tenantA, tenantB = "11111111-1111-4111-8111-111111111111", "22222222-2222-4222-8222-222222222222"
	viewA, err := objectstore.ForTenant(t.Context(), store, tenantA)
	if err != nil {
		t.Fatal(err)
	}
	viewB, err := objectstore.ForTenant(t.Context(), store, tenantB)
	if err != nil {
		t.Fatal(err)
	}
	if viewA.Prefix() != "tenant/"+tenantA+"/" {
		t.Fatalf("pooled tenant prefix = %q", viewA.Prefix())
	}
	data := []byte("marker")
	name, err := viewA.Create(t.Context(), "doctor/marker", bytes.NewReader(data), int64(len(data)), crypto.SHA256Sum(data))
	if err != nil || name != "tenant/"+tenantA+"/doctor/marker" {
		t.Fatalf("create in A = %q %v", name, err)
	}
	if keys := srv.Keys(); len(keys) != 1 || keys[0] != "prod/tenant/"+tenantA+"/doctor/marker" {
		t.Fatalf("stored keys = %v", keys)
	}
	if listed, err := viewB.List(t.Context(), "", 10); err != nil || len(listed) != 0 {
		t.Fatalf("B's listing = %v %v, want empty", listed, err)
	}
	if _, err := viewB.Get(t.Context(), "doctor/marker", &bytes.Buffer{}, 1024); !errors.Is(err, objectstore.ErrNotFound) {
		t.Fatalf("B reading the same relative name = %v, want ErrNotFound under B's own prefix", err)
	}
	before := len(srv.Requests())
	for _, escape := range []string{"../" + tenantA + "/doctor/marker", "/tenant/" + tenantA + "/doctor/marker", "doctor/../../" + tenantA + "/doctor/marker", "doctor\\marker"} {
		if _, err := viewB.Get(t.Context(), escape, &bytes.Buffer{}, 1024); !errors.Is(err, objectstore.ErrName) {
			t.Fatalf("B reading %q = %v, want ErrName", escape, err)
		}
	}
	if after := len(srv.Requests()); after != before {
		t.Fatalf("refused names still reached the store: %d requests", after-before)
	}
	if viewB.Contains(name) || !viewA.Contains(name) {
		t.Fatal("containment does not follow the tenant prefix")
	}
	for _, bad := range []string{"", "a/b", "..", "."} {
		if _, err := objectstore.ForTenant(t.Context(), store, bad); err == nil {
			t.Fatalf("a view for tenant %q was allowed", bad)
		}
	}
}

// AN-7: a store runs at most MaxInFlight calls and refuses the next one at
// once instead of queueing it behind a stalled endpoint; every call runs under
// its own deadline.
func TestCallsAreBoundedAndTimed(t *testing.T) {
	srv := s3test.NewServer(t)
	store := srv.Open(t, func(o *objectstore.Options) { o.MaxInFlight = 1; o.Timeout = 300 * time.Millisecond })
	srv.Seed("x", []byte("x"))
	release := srv.Stall("HEAD")
	defer release()
	done := make(chan error, 1)
	go func() {
		_, err := store.Head(context.Background(), "x")
		done <- err
	}()
	deadline := time.Now().Add(5 * time.Second)
	for len(srv.Requests()) == 0 && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	start := time.Now()
	if _, err := store.Head(t.Context(), "x"); !errors.Is(err, objectstore.ErrBusy) || time.Since(start) > time.Second {
		t.Fatalf("a call over the bound = %v after %s, want ErrBusy at once", err, time.Since(start))
	}
	if err := <-done; !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("the stalled call = %v, want its deadline to end it", err)
	}
	release()
	if _, err := store.Head(t.Context(), "x"); err != nil {
		t.Fatalf("the store did not recover its slot: %v", err)
	}
}

// Open refuses an unsafe endpoint, a malformed bucket or prefix, and missing
// credentials, and a destroyed store makes no further signed call.
func TestOpenRefusesUnsafeSettingsAndDestroyEndsCalls(t *testing.T) {
	srv := s3test.NewServer(t)
	for name, mutate := range map[string]func(*objectstore.Options){
		"plain http to a non-loopback host": func(o *objectstore.Options) { o.Endpoint = "http://minio.internal:9000" },
		"loopback http without opt-in":      func(o *objectstore.Options) { o.AllowInsecureLoopback = false },
		"endpoint with a path":              func(o *objectstore.Options) { o.Endpoint += "/bucket" },
		"endpoint with userinfo":            func(o *objectstore.Options) { o.Endpoint = strings.Replace(o.Endpoint, "http://", "http://u:p@", 1) },
		"invalid bucket":                    func(o *objectstore.Options) { o.Bucket = "Bad_Bucket" },
		"ip-shaped bucket":                  func(o *objectstore.Options) { o.Bucket = "10.0.0.1" },
		"prefix climbing out":               func(o *objectstore.Options) { o.Prefix = "prod/../other" },
		"ca with plain http":                func(o *objectstore.Options) { o.CAPEM = []byte("-----BEGIN CERTIFICATE-----") },
		"no secret":                         func(o *objectstore.Options) { o.SecretAccessKey = nil },
		"virtual-hosted loopback":           func(o *objectstore.Options) { o.PathStyle = false },
	} {
		opts := srv.Options()
		mutate(&opts)
		if store, err := objectstore.Open(opts); err == nil {
			store.Destroy()
			t.Fatalf("%s: open succeeded", name)
		}
	}
	store := srv.Open(t)
	srv.Seed("x", []byte("x"))
	store.Destroy()
	before := len(srv.Requests())
	if _, err := store.Head(t.Context(), "x"); err == nil {
		t.Fatal("a destroyed store still made a call")
	}
	if after := len(srv.Requests()); after != before {
		t.Fatalf("a destroyed store sent %d requests", after-before)
	}
}

// The configured store reads its secret from a private file only.
func TestFromConfigReadsPrivateCredentialFiles(t *testing.T) {
	srv := s3test.NewServer(t)
	dir := t.TempDir()
	secretPath := filepath.Join(dir, "s3-secret")
	if err := os.WriteFile(secretPath, append(append([]byte(nil), srv.Secret...), '\n'), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg := config.ObjectStore{
		Endpoint: srv.URL, Bucket: srv.Bucket, PathStyle: true, AllowInsecureLoopback: true,
		AccessKeyID: srv.AccessKeyID, SecretAccessKeyFile: secretPath, Prefix: "lab/",
	}
	store, err := objectstore.FromConfig(cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Destroy()
	if err := create(t, store, "probe", []byte("ok")); err != nil {
		t.Fatalf("create through the configured store: %v", err)
	}
	if err := os.Chmod(secretPath, 0o644); err != nil { // #nosec G302 -- the test loosens the mode on purpose to prove a world-readable secret file is refused (CWE-276)
		t.Fatal(err)
	}
	if loose, err := objectstore.FromConfig(cfg); err == nil {
		loose.Destroy()
		t.Fatal("a world-readable secret file was accepted")
	}
	if none, err := objectstore.FromConfig(config.ObjectStore{}); none != nil || err != nil {
		t.Fatalf("an unconfigured store = %v %v, want nil, nil", none, err)
	}
}
