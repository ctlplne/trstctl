// SPDX-License-Identifier: BUSL-1.1
package awsiam

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"trstctl.com/trstctl/internal/cloudentitlements/awspolicy"
)

func TestAWSIAMPaginationAndPartialEvidenceA264(t *testing.T) {
	for _, test := range []struct{ name, action, body string }{
		{"repeated marker", "ListUserPolicies", `<PolicyNames/><IsTruncated>true</IsTruncated><Marker>same</Marker>`},
		{"missing marker", "ListUserPolicies", `<PolicyNames/><IsTruncated>true</IsTruncated>`},
		{"missing group coverage", "ListGroupsForUser", `<IsTruncated>false</IsTruncated>`},
		{"duplicate policy version", "GetPolicy", `<Policy><Arn>arn:aws:iam::111122223333:policy/read</Arn><DefaultVersionId>v7</DefaultVersionId><DefaultVersionId>v8</DefaultVersionId></Policy>`},
		{"wrong identity", "GetUser", `<User><UserName>another-workload</UserName></User>`},
		{"malformed policy", "GetUserPolicy", `<PolicyDocument>%7Bbroken</PolicyDocument>`},
		{"duplicate key identity", "GetAccessKeyLastUsed", `<UserName>another-workload</UserName><AccessKeyLastUsed/>`},
	} {
		t.Run(test.name, func(t *testing.T) {
			server := fixtureIAM(t, func(action string, _ url.Values) (string, bool) {
				if action != test.action {
					return "", false
				}
				return "<" + action + "Response><" + action + "Result>" + test.body + "</" + action + "Result></" + action + "Response>", true
			})
			defer server.Close()
			capture, err := fixtureClient(t, server.URL).Collect(context.Background(), []Selection{{Kind: awspolicy.IAMUser, Name: "workload"}})
			if err == nil || len(capture.Identities) != 0 {
				t.Fatalf("partial policy evidence became a complete identity: %+v %v", capture, err)
			}
		})
	}
}
func TestAWSIAMEndpointAndSelectionBoundsA264(t *testing.T) {
	for _, endpoint := range []string{"http://169.254.169.254/", "https://user:password@iam.amazonaws.com/", "https://iam.amazonaws.com/?x=y", "https://iam.amazonaws.com/extra", "file:///owned", "http://example.org/"} {
		if _, err := New(Config{Endpoint: endpoint, AllowInsecureLoopback: true, UseCredentials: fixtureClient(t, "http://127.0.0.1").cfg.UseCredentials}); err == nil {
			t.Errorf("accepted endpoint %q", endpoint)
		}
	}
	server := fixtureIAM(t, nil)
	defer server.Close()
	client := fixtureClient(t, server.URL)
	for _, selection := range [][]Selection{nil, {{Kind: awspolicy.IAMUser, Name: "../../other"}}, {{Kind: awspolicy.RoleSession, Name: "workload"}}, {{Kind: awspolicy.IAMUser, Name: "workload"}, {Kind: awspolicy.IAMUser, Name: "workload"}}, make([]Selection, MaxPrincipals+1)} {
		if _, err := client.Collect(context.Background(), selection); err == nil {
			t.Fatal("invalid selection accepted")
		}
	}
}
func TestAWSIAMTLSFailureClosesBeforeCredentialsA264(t *testing.T) {
	// The fixture's self-signed certificate is intentionally not trusted. Its
	// handler must never receive signed application bytes.
	server := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { t.Error("untrusted TLS received application data") }))
	defer server.Close()
	client := fixtureClient(t, server.URL)
	// Private test egress is explicit; TLS trust remains absent.
	client.dialer.Control = nil
	_, err := client.Collect(context.Background(), []Selection{{Kind: awspolicy.IAMUser, Name: "workload"}})
	if err == nil || !strings.Contains(err.Error(), "TLS identity verification failed") {
		t.Fatalf("expected TLS refusal, got %v", err)
	}
}
func TestAWSIAMXMLBoundariesA264(t *testing.T) {
	for _, raw := range []string{`<GetUserResponse><GetUserResult/><GetUserResult/></GetUserResponse>`, `<!DOCTYPE x><GetUserResponse><GetUserResult/></GetUserResponse>`, `<OtherResponse><GetUserResult/></OtherResponse>`, strings.Repeat("<a>", 25) + strings.Repeat("</a>", 25)} {
		if _, err := parseResponse([]byte(raw), "GetUser"); err == nil {
			t.Fatal("accepted ambiguous or unbounded XML")
		}
	}
}
func FuzzAWSIAMResponse(f *testing.F) {
	f.Add([]byte(`<GetUserResponse><GetUserResult><User><UserName>workload</UserName></User></GetUserResult></GetUserResponse>`))
	f.Fuzz(func(t *testing.T, raw []byte) {
		if len(raw) > maxResponse {
			return
		}
		_, _ = parseResponse(raw, "GetUser")
	})
}
func FuzzAWSIAMPolicyDecode(f *testing.F) {
	f.Add(`%7B%22Version%22%3A%222012-10-17%22%7D`)
	f.Fuzz(func(t *testing.T, value string) {
		if len(value) > 3*(64<<10) {
			return
		}
		raw, err := decodePolicy(value)
		if err == nil && len(raw) > 64<<10 {
			t.Fatal("decoded policy exceeds bound")
		}
	})
}

func TestAWSIAMRetainedPolicyBudgetStopsCaptureA264(t *testing.T) {
	server := fixtureIAM(t, nil)
	defer server.Close()
	session := &captureSession{c: fixtureClient(t, server.URL), policyBytes: 8<<20 - 1}
	if _, err := session.identity(context.Background(), Selection{Kind: awspolicy.IAMUser, Name: "workload"}); err == nil || session.calls > 3 {
		t.Fatalf("oversized cumulative policy capture continued: calls=%d err=%v", session.calls, err)
	}
}
