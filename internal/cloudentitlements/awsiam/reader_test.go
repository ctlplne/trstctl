// SPDX-License-Identifier: BUSL-1.1
package awsiam

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/cloudentitlements/awspolicy"
	"trstctl.com/trstctl/internal/crypto/awssignin"
)

const fixtureAccount = "111122223333"
const fixturePolicy = `{"Version":"2012-10-17","Statement":{"Sid":"Read","Effect":"Allow","Action":"s3:GetObject","Resource":"arn:aws:s3:::owned/report+name"}}`

func fixtureIAM(t *testing.T, mutate func(string, url.Values) (string, bool)) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "POST" || r.URL.Path != "/" || r.Header.Get("Authorization") == "" || r.Header.Get("X-Amz-Security-Token") == "" {
			t.Error("missing fixed signed IAM request")
			http.Error(w, "refused", http.StatusForbidden)
			return
		}
		raw, err := io.ReadAll(io.LimitReader(r.Body, 1<<20))
		if err != nil {
			t.Error(err)
			return
		}
		values, err := url.ParseQuery(string(raw))
		if err != nil {
			t.Error(err)
			return
		}
		action := values.Get("Action")
		if values.Get("Version") != "2010-05-08" {
			t.Error("IAM version")
		}
		if mutate != nil {
			if body, ok := mutate(action, values); ok {
				_, _ = fmt.Fprint(w, body)
				return
			}
		}
		var body string
		switch action {
		case "GetUser":
			body = `<User><UserName>workload</UserName><UserId>AIDAEXAMPLE</UserId><Arn>arn:aws:iam::111122223333:user/workload</Arn><CreateDate>2020-01-01T00:00:00Z</CreateDate><PermissionsBoundary><PermissionsBoundaryArn>arn:aws:iam::111122223333:policy/bound</PermissionsBoundaryArn></PermissionsBoundary></User>`
		case "ListUserPolicies":
			body = `<PolicyNames><member>inline</member></PolicyNames><IsTruncated>false</IsTruncated>`
		case "GetUserPolicy":
			body = `<PolicyDocument>` + url.PathEscape(fixturePolicy) + `</PolicyDocument>`
		case "ListAttachedUserPolicies":
			body = `<AttachedPolicies><member><PolicyName>read</PolicyName><PolicyArn>arn:aws:iam::111122223333:policy/read</PolicyArn></member></AttachedPolicies><IsTruncated>false</IsTruncated>`
		case "GetPolicy":
			body = `<Policy><Arn>` + values.Get("PolicyArn") + `</Arn><DefaultVersionId>v7</DefaultVersionId></Policy>`
		case "GetPolicyVersion":
			body = `<PolicyVersion><VersionId>v7</VersionId><Document>` + url.PathEscape(fixturePolicy) + `</Document></PolicyVersion>`
		case "ListGroupsForUser":
			body = `<Groups><member><GroupName>workload-readers</GroupName></member></Groups><IsTruncated>false</IsTruncated>`
		case "ListGroupPolicies":
			body = `<PolicyNames><member>group-inline</member></PolicyNames><IsTruncated>false</IsTruncated>`
		case "GetGroupPolicy":
			body = `<PolicyDocument>` + url.PathEscape(fixturePolicy) + `</PolicyDocument>`
		case "ListAttachedGroupPolicies":
			body = `<AttachedPolicies></AttachedPolicies><IsTruncated>false</IsTruncated>`
		case "ListAccessKeys":
			body = `<AccessKeyMetadata><member><UserName>workload</UserName><AccessKeyId>AKIAEXAMPLE</AccessKeyId><Status>Active</Status><CreateDate>2020-01-01T00:00:00Z</CreateDate></member></AccessKeyMetadata><IsTruncated>false</IsTruncated>`
		case "GetAccessKeyLastUsed":
			body = `<UserName>workload</UserName><AccessKeyLastUsed><LastUsedDate>2020-01-02T00:00:00Z</LastUsedDate><ServiceName>s3</ServiceName><Region>us-east-1</Region></AccessKeyLastUsed>`
		case "GetRole":
			body = `<Role><RoleName>workload-role</RoleName><RoleId>AROAEXAMPLE</RoleId><Arn>arn:aws:iam::111122223333:role/workload-role</Arn><CreateDate>2020-01-01T00:00:00Z</CreateDate><AssumeRolePolicyDocument>` + url.PathEscape(`{"Version":"2012-10-17","Statement":{"Effect":"Allow","Principal":{"Service":"ec2.amazonaws.com"},"Action":"sts:AssumeRole"}}`) + `</AssumeRolePolicyDocument><RoleLastUsed><LastUsedDate>2026-11-01T00:00:00Z</LastUsedDate></RoleLastUsed></Role>`
		case "ListRolePolicies":
			body = `<PolicyNames></PolicyNames><IsTruncated>false</IsTruncated>`
		case "ListAttachedRolePolicies":
			body = `<AttachedPolicies></AttachedPolicies><IsTruncated>false</IsTruncated>`
		default:
			t.Errorf("unexpected API action %q", action)
			http.Error(w, "unsupported", http.StatusBadRequest)
			return
		}
		w.Header().Set("Content-Type", "text/xml")
		_, _ = fmt.Fprintf(w, "<%sResponse><%sResult>%s</%sResult></%sResponse>", action, action, body, action, action)
	}))
}
func fixtureClient(t *testing.T, endpoint string) *Client {
	t.Helper()
	c, err := New(Config{Endpoint: endpoint, Region: "us-east-1", AllowInsecureLoopback: true, UseCredentials: func(_ context.Context, fn func(awssignin.Credentials) error) error {
		return fn(awssignin.Credentials{AccessKeyID: []byte("ASIAEXAMPLE"), SecretAccessKey: []byte("fixture-signing-material"), SessionToken: []byte("fixture-temporary-token")})
	}, Now: func() time.Time { return time.Date(2026, 11, 5, 0, 0, 0, 0, time.UTC) }})
	if err != nil {
		t.Fatal(err)
	}
	return c
}
func TestAWSIAMSelectedInventoryA264(t *testing.T) {
	server := fixtureIAM(t, nil)
	defer server.Close()
	client := fixtureClient(t, server.URL)
	capture, err := client.Collect(context.Background(), []Selection{{Kind: awspolicy.IAMUser, Name: "workload"}, {Kind: awspolicy.IAMRole, Name: "workload-role"}})
	if err != nil {
		t.Fatal(err)
	}
	if len(capture.Identities) != 2 || capture.Calls < 15 {
		t.Fatalf("incomplete capture: %+v", capture)
	}
	user := capture.Identities[0]
	if user.Principal.AccountID != fixtureAccount || len(user.PolicyReceipts) != 4 || user.Evidence.Identity.Coverage != awspolicy.Complete || user.Evidence.Boundary.Coverage != awspolicy.Complete || len(user.Evidence.Identity.Documents) != 3 {
		t.Fatalf("identity policy/group/boundary capture: %+v", user)
	}
	if len(user.Keys) != 1 || user.Keys[0].LastUsed == nil || user.Keys[0].LastUseCoverage != awspolicy.Complete || user.Keys[0].LastUsedService != "s3" {
		t.Fatalf("key provenance absent: %+v", user.Keys)
	}
	if user.Evidence.SCPCoverage != awspolicy.Unavailable || user.Evidence.RCPCoverage != awspolicy.Unavailable || user.Evidence.Resource.Coverage != awspolicy.Unavailable || len(user.Gaps) < 3 {
		t.Fatal("missing guardrails became absent")
	}
	if !bytes.Contains(user.PolicyReceipts[0].Document, []byte("report+name")) {
		t.Fatal("RFC3986 policy decode replaced literal plus")
	}
	role := capture.Identities[1]
	if role.LastUsed == nil || !bytes.Contains(role.TrustDocument, []byte("ec2.amazonaws.com")) || role.Evidence.Boundary.Coverage != awspolicy.Absent {
		t.Fatalf("role/trust capture missing: %+v", role)
	}
	for _, receipt := range user.PolicyReceipts {
		if len(receipt.SHA256) != 64 || !xmlSafe(receipt.Document) {
			t.Fatal("policy receipt missing parsed evidence")
		}
	}
}
func xmlSafe(raw []byte) bool {
	return len(raw) > 0 && !strings.Contains(string(raw), "<PolicyDocument>")
}
