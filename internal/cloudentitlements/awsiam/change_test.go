// SPDX-License-Identifier: BUSL-1.1
package awsiam

import (
	"context"
	"fmt"
	"net/url"
	"strings"
	"testing"
	"trstctl.com/trstctl/internal/cloudentitlements/awspolicy"
)

func TestAWSIAMChangePrincipalDriftReadbackAndReplayA264(t *testing.T) {
	target := ChangeTarget{ARN: "arn:aws:iam::111122223333:user/workload", NativeID: "AIDAEXAMPLE", Name: "workload", Kind: awspolicy.IAMUser}
	for _, mode := range []string{"id_drift", "key_reappears", "success"} {
		t.Run(mode, func(t *testing.T) {
			deletes := 0
			server := fixtureIAM(t, func(action string, _ url.Values) (string, bool) {
				if action == "GetUser" && mode == "id_drift" {
					return `<GetUserResponse><GetUserResult><User><Arn>` + target.ARN + `</Arn><UserId>AIDAREPLACED</UserId></User></GetUserResult></GetUserResponse>`, true
				}
				if action == "DeleteAccessKey" {
					deletes++
					return `<DeleteAccessKeyResponse><ResponseMetadata><RequestId>owned</RequestId></ResponseMetadata></DeleteAccessKeyResponse>`, true
				}
				if action == "ListAccessKeys" && deletes > 0 && mode == "success" {
					return `<ListAccessKeysResponse><ListAccessKeysResult><AccessKeyMetadata/><IsTruncated>false</IsTruncated></ListAccessKeysResult></ListAccessKeysResponse>`, true
				}
				return "", false
			})
			defer server.Close()
			writer := &ChangeClient{client: fixtureClient(t, server.URL)}
			result, err := writer.RevokeKey(context.Background(), target, "AKIAEXAMPLE")
			switch mode {
			case "id_drift":
				if err == nil || deletes != 0 {
					t.Fatal("identity drift allowed a native effect")
				}
			case "key_reappears":
				if err == nil || deletes != 1 {
					t.Fatal("failed readback claimed completion")
				}
			case "success":
				if err != nil || !result.KeyAbsent || deletes != 1 {
					t.Fatalf("native change: %+v %v", result, err)
				}
				again, err := writer.RevokeKey(context.Background(), target, "AKIAEXAMPLE")
				if err != nil || again.Postcondition != "already_absent" || deletes != 1 {
					t.Fatal("replay executed native deletion again")
				}
			}
		})
	}
}
func TestAWSIAMWriterRefusesGrantOrOwnedPolicyOverwriteA264(t *testing.T) {
	server := fixtureIAM(t, func(action string, _ url.Values) (string, bool) {
		if strings.HasPrefix(action, "Put") {
			t.Error("unreviewed native write")
			return fmt.Sprintf("<%sResponse/>", action), true
		}
		return "", false
	})
	defer server.Close()
	writer := &ChangeClient{client: fixtureClient(t, server.URL)}
	target := ChangeTarget{ARN: "arn:aws:iam::111122223333:user/workload", NativeID: "AIDAEXAMPLE", Name: "workload", Kind: awspolicy.IAMUser}
	for _, document := range []string{fixturePolicy, `{"Version":"2012-10-17","Statement":[{"Effect":"Deny","Action":"s3:GetObject","Resource":"arn:aws:s3:::owned/report"}]}`} {
		if _, err := writer.PutOwnedDeny(context.Background(), target, "trstctl-tighten-owned", []byte(document)); err == nil {
			t.Fatal("grant or existing different policy accepted")
		}
	}
	session := &captureSession{c: writer.client}
	if _, err := session.call(context.Background(), "DeleteAccessKey", url.Values{}); err == nil {
		t.Fatal("read-only collector accepted mutation")
	}
}
