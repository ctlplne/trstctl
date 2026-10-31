// SPDX-License-Identifier: LicenseRef-trstctl-EE
package auditcompliance_test

import (
	"context"
	"encoding/hex"
	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"net/http"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"
	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/objectstore"
)

type protectedArchiveCredentials struct{ id, secret string }

func (c protectedArchiveCredentials) Retrieve(context.Context) (awssdk.Credentials, error) {
	return awssdk.Credentials{AccessKeyID: c.id, SecretAccessKey: c.secret}, nil
}

// protectedArchiveMinIO starts a throwaway MinIO from the lab image
// TRSTCTL_TEST_MINIO_IMAGE names (MinIO publishes no image to pull) and makes
// a bucket with S3 Object Lock enabled; without the image the proof skips.
func protectedArchiveMinIO(t *testing.T) (*s3.Client, objectstore.Options) {
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
	user, password, container := "a233archive"+random(), random()+random(), "trstctl-a233archive-served-minio-"+random()
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
		Credentials: protectedArchiveCredentials{id: user, secret: password}})
	const bucket = "trstctl-a233archive"
	if _, err := raw.CreateBucket(context.Background(), &s3.CreateBucketInput{Bucket: awssdk.String(bucket), ObjectLockEnabledForBucket: awssdk.Bool(true)}); err != nil {
		t.Fatal(err)
	}
	return raw, objectstore.Options{Endpoint: endpoint, Bucket: bucket, PathStyle: true, AllowInsecureLoopback: true,
		AccessKeyID: user, SecretAccessKey: []byte(password),
		ObjectLock: &objectstore.ObjectLock{Mode: "GOVERNANCE", Retention: 24 * time.Hour}}
}
