// SPDX-License-Identifier: BUSL-1.1

package objectstore_test

import (
	"bytes"
	"context"
	"encoding/hex"
	"errors"
	"net/http"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"

	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/objectstore"
)

// a208MinIO starts a throwaway MinIO from the image TRSTCTL_TEST_MINIO_IMAGE
// names, with fresh root credentials on a loopback port. MinIO publishes no
// image to pull any more, so the lab builds one from source; without it the
// Object Lock proof is skipped.
func a208MinIO(t *testing.T) (endpoint, user, password string) {
	t.Helper()
	image := os.Getenv("TRSTCTL_TEST_MINIO_IMAGE")
	if image == "" {
		t.Skip("TRSTCTL_TEST_MINIO_IMAGE names no MinIO image; the Object Lock proof needs a real S3 Object Lock implementation")
	}
	random := func() string {
		raw, err := crypto.RandomBytes(12)
		if err != nil {
			t.Fatal(err)
		}
		return hex.EncodeToString(raw)
	}
	user, password = "a208"+random(), random()+random()
	container := "trstctl-a208-minio-" + random()
	out, err := exec.Command("docker", "run", "-d", "--name", container, "-p", "127.0.0.1::9000", // #nosec G204 G702 -- test runs a fixed local tool with the image the operator named (CWE-78)
		"-e", "MINIO_ROOT_USER="+user, "-e", "MINIO_ROOT_PASSWORD="+password, image, "server", "/data").CombinedOutput()
	if err != nil {
		t.Fatalf("docker run MinIO: %v\n%s", err, out)
	}
	t.Cleanup(func() { _ = exec.Command("docker", "rm", "-f", container).Run() }) // #nosec G204 -- test removes the container it started (CWE-78)
	port, err := exec.Command("docker", "port", container, "9000/tcp").Output()   // #nosec G204 -- test inspects the container it started (CWE-78)
	if err != nil {
		t.Fatalf("docker port: %v", err)
	}
	endpoint = "http://" + strings.TrimSpace(strings.Split(string(port), "\n")[0])
	deadline := time.Now().Add(60 * time.Second)
	for {
		resp, err := http.Get(endpoint + "/minio/health/live") // #nosec G107 -- loopback URL of the container this test started (CWE-88)
		if err == nil {
			_ = resp.Body.Close()
			if resp.StatusCode == http.StatusOK {
				return endpoint, user, password
			}
		}
		if time.Now().After(deadline) {
			logs, _ := exec.Command("docker", "logs", container).CombinedOutput() // #nosec G204 -- test reads the container it started (CWE-78)
			t.Fatalf("MinIO did not become live: %v\n%s", err, logs)
		}
		time.Sleep(250 * time.Millisecond)
	}
}

// a208Credentials hands the throwaway MinIO's root credentials to the raw
// client the test uses for what trstctl never does (versioned deletes).
type a208Credentials struct{ id, secret string }

func (c a208Credentials) Retrieve(context.Context) (awssdk.Credentials, error) {
	return awssdk.Credentials{AccessKeyID: c.id, SecretAccessKey: c.secret}, nil
}

func a208Raw(endpoint, user, password string) *s3.Client {
	return s3.New(s3.Options{
		Region: "us-east-1", BaseEndpoint: awssdk.String(endpoint), UsePathStyle: true,
		Credentials: a208Credentials{id: user, secret: password},
	})
}

func a208VersionOf(t *testing.T, raw *s3.Client, bucket, key string) string {
	t.Helper()
	out, err := raw.ListObjectVersions(context.Background(), &s3.ListObjectVersionsInput{Bucket: awssdk.String(bucket), Prefix: awssdk.String(key)})
	if err != nil || len(out.Versions) != 1 {
		t.Fatalf("versions of %s = %+v %v", key, out, err)
	}
	return awssdk.ToString(out.Versions[0].VersionId)
}

// A208: against a real MinIO, an object trstctl writes under Object Lock
// retention cannot be deleted before the retention ends; a plain delete only
// hides it behind a delete marker while the locked version stays. A legal hold
// blocks deleting an object until it is released, and both read back.
func TestObjectLockAgainstMinIO(t *testing.T) {
	endpoint, user, password := a208MinIO(t)
	ctx := context.Background()
	raw := a208Raw(endpoint, user, password)
	const locked, plain = "a208-locked", "a208-plain"
	if _, err := raw.CreateBucket(ctx, &s3.CreateBucketInput{Bucket: awssdk.String(locked), ObjectLockEnabledForBucket: awssdk.Bool(true)}); err != nil {
		t.Fatal(err)
	}
	if _, err := raw.CreateBucket(ctx, &s3.CreateBucketInput{Bucket: awssdk.String(plain)}); err != nil {
		t.Fatal(err)
	}
	open := func(bucket string, lock *objectstore.ObjectLock) *objectstore.S3 {
		store, err := objectstore.Open(objectstore.Options{Endpoint: endpoint, Bucket: bucket, PathStyle: true,
			AllowInsecureLoopback: true, AccessKeyID: user, SecretAccessKey: []byte(password), ObjectLock: lock})
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(store.Destroy)
		return store
	}
	put := func(store *objectstore.S3, name string, body []byte) {
		t.Helper()
		if err := store.Create(ctx, name, bytes.NewReader(body), int64(len(body)), crypto.SHA256Sum(body)); err != nil {
			t.Fatalf("create %s: %v", name, err)
		}
	}
	deleteVersion := func(bucket, key, version string) error {
		_, err := raw.DeleteObject(ctx, &s3.DeleteObjectInput{Bucket: awssdk.String(bucket), Key: awssdk.String(key), VersionId: awssdk.String(version)})
		return err
	}

	// Retention: every object the locked store writes carries it.
	store := open(locked, &objectstore.ObjectLock{Mode: "governance", Retention: 24 * time.Hour})
	if enabled, err := store.BucketLockEnabled(ctx); err != nil || !enabled {
		t.Fatalf("lock-enabled bucket reads %v %v", enabled, err)
	}
	report := "tenant/20800000-0000-4000-8000-000000000001/reports/run/" + strings.Repeat("a", 64) + ".json"
	put(store, report, []byte(`{"signed_export":{"report":"a208"}}`))
	state, err := store.Lock(ctx, report)
	if err != nil || state.Mode != "GOVERNANCE" || state.RetainUntil == nil || state.LegalHold ||
		state.RetainUntil.Before(time.Now().Add(23*time.Hour)) || !state.Locked(time.Now()) {
		t.Fatalf("locked object reads %+v %v", state, err)
	}
	version := a208VersionOf(t, raw, locked, report)
	if err := deleteVersion(locked, report, version); err == nil {
		t.Fatal("a version under retention was deleted")
	}
	// A plain delete only adds a delete marker; the locked version remains,
	// which is why trstctl's own removals read the lock first.
	if err := store.Delete(ctx, report); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Head(ctx, report); !errors.Is(err, objectstore.ErrNotFound) {
		t.Fatalf("head after a plain delete = %v", err)
	}
	if got := a208VersionOf(t, raw, locked, report); got != version {
		t.Fatalf("the locked version went: %s", got)
	}

	// Legal hold: an object written without retention is held, cannot be
	// deleted, and can be once the hold is released.
	unlocked := open(locked, nil)
	segment := "tenant/20800000-0000-4000-8000-000000000001/audit/audit-1.jws"
	put(unlocked, segment, []byte("a208.jws"))
	if err := unlocked.SetLegalHold(ctx, segment, true); err != nil {
		t.Fatalf("place legal hold: %v", err)
	}
	if state, err := unlocked.Lock(ctx, segment); err != nil || !state.LegalHold || state.RetainUntil != nil {
		t.Fatalf("held object reads %+v %v", state, err)
	}
	segmentVersion := a208VersionOf(t, raw, locked, segment)
	if err := deleteVersion(locked, segment, segmentVersion); err == nil {
		t.Fatal("a held version was deleted")
	}
	if err := unlocked.SetLegalHold(ctx, segment, false); err != nil {
		t.Fatalf("release legal hold: %v", err)
	}
	if state, err := unlocked.Lock(ctx, segment); err != nil || state.Locked(time.Now()) {
		t.Fatalf("released object reads %+v %v", state, err)
	}
	if err := deleteVersion(locked, segment, segmentVersion); err != nil {
		t.Fatalf("delete after release: %v", err)
	}

	// A bucket without Object Lock says so, and a locked write to it fails
	// rather than landing unlocked.
	plainStore := open(plain, &objectstore.ObjectLock{Mode: "COMPLIANCE", Retention: 24 * time.Hour})
	if enabled, err := plainStore.BucketLockEnabled(ctx); err != nil || enabled {
		t.Fatalf("plain bucket reads %v %v", enabled, err)
	}
	body := []byte("a208")
	if err := plainStore.Create(ctx, "tenant/x/a208", bytes.NewReader(body), int64(len(body)), crypto.SHA256Sum(body)); err == nil {
		t.Fatal("a locked write to a bucket without Object Lock succeeded")
	}
	// An object in a bucket without Object Lock reads as unlocked, so
	// trstctl's removals keep working there.
	plainUnlocked := open(plain, nil)
	put(plainUnlocked, "tenant/x/a208", body)
	if state, err := plainUnlocked.Lock(ctx, "tenant/x/a208"); err != nil || state.Locked(time.Now()) {
		t.Fatalf("an object in a plain bucket reads %+v %v", state, err)
	}
	// A missing object: the plain bucket answers before it looks at the key
	// (unlocked), a lock-enabled bucket says the object is not there.
	if state, err := plainUnlocked.Lock(ctx, "tenant/x/missing"); err != nil || state.Locked(time.Now()) {
		t.Fatalf("a missing object in a plain bucket reads %+v %v", state, err)
	}
	if _, err := unlocked.Lock(ctx, "tenant/x/missing"); !errors.Is(err, objectstore.ErrNotFound) {
		t.Fatalf("a missing object in a lock-enabled bucket = %v, want not found", err)
	}
}
