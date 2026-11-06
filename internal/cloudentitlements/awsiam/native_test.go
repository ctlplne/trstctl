// SPDX-License-Identifier: BUSL-1.1
package awsiam

import (
	"context"
	"os"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/cloudentitlements/awspolicy"
)

func TestAWSIAMNativeInventoryA264(t *testing.T) {
	endpoint := os.Getenv("TRSTCTL_A264_IAM_ENDPOINT")
	sessionPath := os.Getenv("TRSTCTL_A264_IAM_SESSION_FILE")
	if endpoint == "" || sessionPath == "" {
		t.Skip("set owned LocalStack endpoint and private STS response file")
	}
	client, err := New(Config{Endpoint: endpoint, AllowInsecureLoopback: true, UseCredentials: SessionFile(sessionPath, time.Now)})
	if err != nil {
		t.Fatal(err)
	}
	capture, err := client.Collect(context.Background(), []Selection{{Kind: awspolicy.IAMUser, Name: "a264-workload"}, {Kind: awspolicy.IAMRole, Name: "a264-reader"}})
	if err != nil {
		t.Fatal(err)
	}
	if len(capture.Identities) != 2 || len(capture.Identities[0].Keys) != 1 || len(capture.Identities[0].PolicyReceipts) != 3 || len(capture.Identities[0].Evidence.Identity.Documents) != 2 || capture.Identities[0].Evidence.Boundary.Coverage != awspolicy.Complete || len(capture.Identities[1].TrustDocument) == 0 {
		t.Fatalf("native policy/group/key/trust capture incomplete: identities=%d calls=%d", len(capture.Identities), capture.Calls)
	}
	t.Logf("native selected identities=%d user policies=%d keys=%d calls=%d; LocalStack IAM metadata only, enforcement unproven", len(capture.Identities), len(capture.Identities[0].PolicyReceipts), len(capture.Identities[0].Keys), capture.Calls)
}
