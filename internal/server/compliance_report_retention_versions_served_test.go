// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os/exec"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/objectstore"
)

// A206-L2: on a bucket that keeps versions (S3 Object Lock turns versioning
// on), a plain delete only adds a delete marker; HEAD then answers 404 while
// the report's version stays in the bucket. Against LocalStack's S3, which
// enforces Object Lock, the report retention removes every version of a
// report, including one an earlier plain delete hid behind a marker, and
// records the run expired only once the bucket lists nothing for it. A
// version under Object Lock keeps the report, its run deferred until the
// lock's end, and after it the report goes entirely.
func TestServedReportRetentionRemovesEveryVersionA206L2(t *testing.T) {
	if testing.Short() {
		t.Skip("container acceptance test")
	}
	if out, err := exec.Command("docker", "image", "inspect", a202LocalStackImage).CombinedOutput(); err != nil { // #nosec G204 -- fixed local Docker tool and approved fixture image (CWE-78)
		t.Skipf("approved LocalStack image unavailable: %v %s", err, out)
	}
	target, address := a201Container(t, "4566", "-e", "SERVICES=s3", a202LocalStackImage)
	endpoint := "http://" + address
	a201Await(t, "LocalStack S3", func() bool {
		response, err := http.Get(endpoint + "/_localstack/health")
		if err != nil {
			return false
		}
		defer func() { _ = response.Body.Close() }()
		var health struct{ Services map[string]string }
		if json.NewDecoder(response.Body).Decode(&health) != nil {
			return false
		}
		return health.Services["s3"] == "running" || health.Services["s3"] == "available"
	})
	s3api := func(args ...string) string {
		t.Helper()
		out, err := a201Exec(target, append([]string{"awslocal", "s3api"}, args...)...)
		if err != nil {
			t.Fatalf("s3api %v: %v %s", args, err, out)
		}
		return out
	}
	const bucket, prefix = "a206-versions", "deployment-a"
	s3api("create-bucket", "--bucket", bucket, "--object-lock-enabled-for-bucket")
	objects, err := objectstore.Open(objectstore.Options{
		Endpoint: endpoint, Region: "us-east-1", Bucket: bucket, Prefix: prefix, PathStyle: true,
		AllowInsecureLoopback: true, AccessKeyID: "test", SecretAccessKey: []byte("test"),
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(objects.Destroy)
	// listed reads the bucket itself: every version and delete marker of
	// the report's exact key.
	listed := func(ref string) []string {
		t.Helper()
		key := prefix + "/" + ref
		var out struct {
			Versions, DeleteMarkers []struct{ Key, VersionId string }
		}
		if raw := s3api("list-object-versions", "--bucket", bucket, "--prefix", key, "--output", "json"); raw != "" {
			if err := json.Unmarshal([]byte(raw), &out); err != nil {
				t.Fatalf("list-object-versions: %v %s", err, raw)
			}
		}
		var entries []string
		for _, v := range out.Versions {
			if v.Key == key {
				entries = append(entries, "version "+v.VersionId)
			}
		}
		for _, m := range out.DeleteMarkers {
			if m.Key == key {
				entries = append(entries, "delete marker "+m.VersionId)
			}
		}
		return entries
	}

	r := newA206Retention(t, objects, 24*time.Hour, 3)
	plain, hidden, locked := r.runs[0], r.runs[1], r.runs[2]
	for _, run := range r.runs {
		if got := listed(run.ArtifactRef); len(got) != 1 {
			t.Fatalf("the report of %s is stored as %v, want one version", run.ID, got)
		}
	}
	// An earlier plain delete hid one report behind a delete marker; HEAD
	// reads it gone while its version remains.
	s3api("delete-object", "--bucket", bucket, "--key", prefix+"/"+hidden.ArtifactRef)
	if got := listed(hidden.ArtifactRef); len(got) != 2 {
		t.Fatalf("the hidden report is stored as %v, want its version and a delete marker", got)
	}
	// Another report's version is under Object Lock for a few seconds.
	lockEnd := time.Now().UTC().Add(10 * time.Second).Truncate(time.Second)
	s3api("put-object-retention", "--bucket", bucket, "--key", prefix+"/"+locked.ArtifactRef,
		"--retention", fmt.Sprintf(`{"Mode":"GOVERNANCE","RetainUntilDate":%q}`, lockEnd.Format(time.RFC3339)))

	if n := r.expire(t, 25*time.Hour); n != 3 {
		t.Fatalf("sweep queued %d, want 3", n)
	}
	r.drain(t)
	for _, run := range []struct {
		name string
		id   string
		ref  string
	}{{"plain", plain.ID, plain.ArtifactRef}, {"hidden", hidden.ID, hidden.ArtifactRef}} {
		if got := listed(run.ref); len(got) != 0 {
			t.Fatalf("the %s report's run was swept (recorded expired: %t), but the bucket still lists %v",
				run.name, r.run(t, run.id).Retention.ArtifactExpiredAt != nil, got)
		}
		if got := r.run(t, run.id).Retention; got.ArtifactExpiredAt == nil {
			t.Fatalf("the %s report is gone but its run reads %+v", run.name, got)
		}
	}
	got := r.run(t, locked.ID).Retention
	if got.ArtifactExpiredAt != nil || got.StorageLockedUntil == nil || !got.StorageLockedUntil.Equal(lockEnd) {
		t.Fatalf("the locked report's run reads %+v, want it deferred until %v", got, lockEnd)
	}
	if got := listed(locked.ArtifactRef); len(got) != 1 {
		t.Fatalf("the locked report is stored as %v, want its version untouched", got)
	}

	// Past the lock's end the report goes, every version of it.
	time.Sleep(time.Until(lockEnd) + time.Second)
	if n := r.expire(t, 25*time.Hour); n != 1 {
		t.Fatalf("sweep after the lock's end queued %d, want 1", n)
	}
	r.drain(t)
	if got := listed(locked.ArtifactRef); len(got) != 0 {
		t.Fatalf("the lock ended and the run was swept (recorded expired: %t), but the bucket still lists %v",
			r.run(t, locked.ID).Retention.ArtifactExpiredAt != nil, got)
	}
	if got := r.run(t, locked.ID).Retention; got.ArtifactExpiredAt == nil {
		t.Fatalf("the unlocked report is gone but its run reads %+v", got)
	}
	if status, _ := r.download(t, locked.ID); status != http.StatusGone {
		t.Fatalf("download of the removed report = %d, want 410", status)
	}
}
