// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"context"
	"encoding/hex"
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

type a208Credentials struct{ id, secret string }

func (c a208Credentials) Retrieve(context.Context) (awssdk.Credentials, error) {
	return awssdk.Credentials{AccessKeyID: c.id, SecretAccessKey: c.secret}, nil
}

// a208ServedMinIO starts a throwaway MinIO from the lab image
// TRSTCTL_TEST_MINIO_IMAGE names (MinIO publishes no image to pull) and makes
// a bucket with S3 Object Lock enabled; without the image the proof skips.
func a208ServedMinIO(t *testing.T) (*s3.Client, objectstore.Options) {
	t.Helper()
	image := os.Getenv("TRSTCTL_TEST_MINIO_IMAGE")
	if image == "" {
		t.Skip("TRSTCTL_TEST_MINIO_IMAGE names no MinIO image; this proof needs a real S3 Object Lock implementation")
	}
	random := func() string {
		raw, err := crypto.RandomBytes(12)
		if err != nil {
			t.Fatal(err)
		}
		return hex.EncodeToString(raw)
	}
	user, password, container := "a208"+random(), random()+random(), "trstctl-a208-served-minio-"+random()
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
	endpoint := "http://" + strings.TrimSpace(strings.Split(string(port), "\n")[0])
	deadline := time.Now().Add(60 * time.Second)
	for {
		resp, err := http.Get(endpoint + "/minio/health/live") // #nosec G107 -- loopback URL of the container this test started (CWE-88)
		if err == nil {
			_ = resp.Body.Close()
			if resp.StatusCode == http.StatusOK {
				break
			}
		}
		if time.Now().After(deadline) {
			t.Fatalf("MinIO did not become live: %v", err)
		}
		time.Sleep(250 * time.Millisecond)
	}
	raw := s3.New(s3.Options{Region: "us-east-1", BaseEndpoint: awssdk.String(endpoint), UsePathStyle: true,
		Credentials: a208Credentials{id: user, secret: password}})
	const bucket = "trstctl-a208"
	if _, err := raw.CreateBucket(context.Background(), &s3.CreateBucketInput{Bucket: awssdk.String(bucket), ObjectLockEnabledForBucket: awssdk.Bool(true)}); err != nil {
		t.Fatal(err)
	}
	return raw, objectstore.Options{Endpoint: endpoint, Bucket: bucket, PathStyle: true, AllowInsecureLoopback: true,
		AccessKeyID: user, SecretAccessKey: []byte(password),
		ObjectLock: &objectstore.ObjectLock{Mode: "GOVERNANCE", Retention: 24 * time.Hour}}
}

// A208 against a real MinIO through the served product: scheduled reports
// land under the deployment's Object Lock retention, so their versions cannot
// be deleted early; a person's report legal hold also sets an S3 legal hold
// the bucket reads back; releasing it clears that hold while the retention
// still protects the report; and the report retention defers the report until
// its retention ends instead of hiding it behind a delete marker.
func TestServedArchiveObjectLockAgainstMinIO(t *testing.T) {
	raw, opts := a208ServedMinIO(t)
	store, err := objectstore.Open(opts)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(store.Destroy)
	r := newA206Retention(t, store, 24*time.Hour, 1)
	run := r.runs[0]
	ctx := context.Background()
	state, err := store.Lock(ctx, run.ArtifactRef)
	if err != nil || state.Mode != "GOVERNANCE" || state.RetainUntil == nil || !state.Locked(time.Now()) {
		t.Fatalf("the scheduled report's object reads %+v %v", state, err)
	}
	versions, err := raw.ListObjectVersions(ctx, &s3.ListObjectVersionsInput{Bucket: awssdk.String(opts.Bucket), Prefix: awssdk.String(opts.Prefix + run.ArtifactRef)})
	if err != nil || len(versions.Versions) != 1 {
		t.Fatalf("report versions = %+v %v", versions, err)
	}
	deleteVersion := func() error {
		_, err := raw.DeleteObject(ctx, &s3.DeleteObjectInput{Bucket: awssdk.String(opts.Bucket),
			Key: awssdk.String(opts.Prefix + run.ArtifactRef), VersionId: versions.Versions[0].VersionId})
		return err
	}
	if err := deleteVersion(); err == nil {
		t.Fatal("a report under retention was deleted early")
	}

	if status, body := r.hold(t, run.ID, "litigation hold 2026-208"); status != http.StatusOK {
		t.Fatalf("report hold = %d %s", status, body)
	}
	r.drain(t)
	if state, err := store.Lock(ctx, run.ArtifactRef); err != nil || !state.LegalHold {
		t.Fatalf("after the hold the object reads %+v %v", state, err)
	}
	if status, body := r.release(t, run.ID); status != http.StatusOK {
		t.Fatalf("report release = %d %s", status, body)
	}
	r.drain(t)
	if state, err := store.Lock(ctx, run.ArtifactRef); err != nil || state.LegalHold || !state.Locked(time.Now()) {
		t.Fatalf("after the release the object reads %+v %v", state, err)
	}
	if err := deleteVersion(); err == nil {
		t.Fatal("the released report was deleted while its retention lasts")
	}

	if n := r.expire(t, 25*time.Hour); n != 1 {
		t.Fatalf("sweep queued %d", n)
	}
	r.drain(t)
	got := r.run(t, run.ID).Retention
	if got.ArtifactExpiredAt != nil || got.StorageLockedUntil == nil || !got.StorageLockedUntil.Equal(*state.RetainUntil) {
		t.Fatalf("the retention's run reads %+v, want deferred until %v", got, state.RetainUntil)
	}
	if status, _ := r.download(t, run.ID); status != http.StatusOK {
		t.Fatalf("download of the protected report = %d", status)
	}
}
