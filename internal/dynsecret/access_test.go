// SPDX-License-Identifier: BUSL-1.1

package dynsecret

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"
)

// iamStandIn answers the two IAM reads ResolveAccess makes, paging the
// attached policies, and refuses everything else.
type iamStandIn struct {
	mu      sync.Mutex
	status  int
	actions []string
}

func (s *iamStandIn) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "invalid form", http.StatusBadRequest)
		return
	}
	s.mu.Lock()
	s.actions = append(s.actions, r.Form.Get("Action")+" "+r.Form.Get("Marker"))
	status := s.status
	s.mu.Unlock()
	if !strings.Contains(r.Header.Get("Authorization"), "/us-east-1/iam/aws4_request") {
		http.Error(w, "not signed for IAM", http.StatusBadRequest)
		return
	}
	if status != 0 {
		w.WriteHeader(status)
		_, _ = fmt.Fprint(w, `<ErrorResponse><Error><Code>AccessDenied</Code></Error></ErrorResponse>`)
		return
	}
	if r.Form.Get("RoleName") != "deploy" {
		w.WriteHeader(http.StatusNotFound)
		_, _ = fmt.Fprint(w, `<ErrorResponse><Error><Code>NoSuchEntity</Code></Error></ErrorResponse>`)
		return
	}
	switch r.Form.Get("Action") + "/" + r.Form.Get("Marker") {
	case "ListAttachedRolePolicies/":
		_, _ = fmt.Fprint(w, `<ListAttachedRolePoliciesResponse><ListAttachedRolePoliciesResult><AttachedPolicies><member><PolicyName>ci-deploy</PolicyName><PolicyArn>arn:aws:iam::123456789012:policy/ci-deploy</PolicyArn></member></AttachedPolicies><IsTruncated>true</IsTruncated><Marker>page-2</Marker></ListAttachedRolePoliciesResult></ListAttachedRolePoliciesResponse>`)
	case "ListAttachedRolePolicies/page-2":
		_, _ = fmt.Fprint(w, `<ListAttachedRolePoliciesResponse><ListAttachedRolePoliciesResult><AttachedPolicies><member><PolicyName>AmazonS3ReadOnlyAccess</PolicyName><PolicyArn>arn:aws:iam::aws:policy/AmazonS3ReadOnlyAccess</PolicyArn></member></AttachedPolicies><IsTruncated>false</IsTruncated></ListAttachedRolePoliciesResult></ListAttachedRolePoliciesResponse>`)
	case "ListRolePolicies/":
		_, _ = fmt.Fprint(w, `<ListRolePoliciesResponse><ListRolePoliciesResult><PolicyNames><member>s3-write-artifacts</member><member>kms-decrypt</member></PolicyNames><IsTruncated>false</IsTruncated></ListRolePoliciesResult></ListRolePoliciesResponse>`)
	default:
		http.Error(w, "unexpected IAM call", http.StatusBadRequest)
	}
}

func newAccessSTSBackend(t *testing.T, iam *httptest.Server) *AWSSTSBackend {
	t.Helper()
	backend, err := NewAWSSTSBackend(AWSSTSConfig{
		Endpoint: "https://sts.us-west-2.amazonaws.com", Region: "us-west-2",
		AccessKeyID: "AKID", SecretAccessKey: []byte("admin-secret"),
		RoleARNs:    map[string]string{"deploy": "arn:aws:iam::123456789012:role/ci/deploy"},
		IAMEndpoint: iam.URL, IAMHTTPClient: iam.Client(),
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(backend.Close)
	return backend
}

func stsLeaseRef(t *testing.T, roleARN string) string {
	t.Helper()
	raw, err := json.Marshal(awsSTSRef{
		RoleARN: roleARN, SessionName: "trstctl-deploy-lease", AssumedRoleID: "AROADEPLOY:trstctl-deploy-lease",
		AccessKeyID: "ASIAEXAMPLE", Expiration: time.Now().Add(time.Hour),
	})
	if err != nil {
		t.Fatal(err)
	}
	return string(raw)
}

// G2: an STS lease reaches the IAM role it assumed, with every managed policy
// attached to that role (across pages) and every inline policy, read from IAM
// with requests signed for IAM's home region whatever the STS region is.
func TestAWSSTSLeaseAccessListsTheRolesPoliciesG2(t *testing.T) {
	standIn := &iamStandIn{}
	iam := httptest.NewServer(standIn)
	defer iam.Close()
	backend := newAccessSTSBackend(t, iam)

	access, err := backend.ResolveAccess(context.Background(), stsLeaseRef(t, "arn:aws:iam::123456789012:role/ci/deploy"))
	if err != nil {
		t.Fatal(err)
	}
	want := []string{
		"inline policy kms-decrypt",
		"inline policy s3-write-artifacts",
		"managed policy AmazonS3ReadOnlyAccess (arn:aws:iam::aws:policy/AmazonS3ReadOnlyAccess)",
		"managed policy ci-deploy (arn:aws:iam::123456789012:policy/ci-deploy)",
	}
	if access.TargetKind != AccessTargetAWSIAMRole || access.TargetRef != "arn:aws:iam::123456789012:role/ci/deploy" ||
		access.Login != "AROADEPLOY:trstctl-deploy-lease" || !slices.Equal(access.Grants, want) || access.Truncated != 0 {
		t.Fatalf("access = %+v", access)
	}
	if got := AccessGrantsSummary(access); !strings.HasPrefix(got, "inline policy kms-decrypt; ") {
		t.Fatalf("summary = %q", got)
	}
	if !slices.Equal(standIn.actions, []string{"ListAttachedRolePolicies ", "ListAttachedRolePolicies page-2", "ListRolePolicies "}) {
		t.Fatalf("IAM calls = %v", standIn.actions)
	}

	// The role is gone: the login is missing, not "no policies".
	_, err = backend.ResolveAccess(context.Background(), stsLeaseRef(t, "arn:aws:iam::123456789012:role/retired"))
	if !errors.Is(err, ErrAccessLoginMissing) || AccessReason(err) != "login_missing" {
		t.Fatalf("missing role = %v", err)
	}
	// IAM refuses the provider's credentials: unknown, and the target is still named.
	standIn.mu.Lock()
	standIn.status = http.StatusForbidden
	standIn.mu.Unlock()
	access, err = backend.ResolveAccess(context.Background(), stsLeaseRef(t, "arn:aws:iam::123456789012:role/ci/deploy"))
	if !errors.Is(err, ErrAccessDenied) || AccessReason(err) != "access_denied" ||
		access.TargetRef != "arn:aws:iam::123456789012:role/ci/deploy" || len(access.Grants) != 0 {
		t.Fatalf("refused read = %+v, %v", access, err)
	}
	// IAM cannot be reached at all.
	iam.Close()
	if _, err := backend.ResolveAccess(context.Background(), stsLeaseRef(t, "arn:aws:iam::123456789012:role/ci/deploy")); !errors.Is(err, ErrAccessUnreachable) {
		t.Fatalf("unreachable IAM = %v", err)
	}
}

func TestAccessTargetsNameNoCredentialsG2(t *testing.T) {
	for dsn, want := range map[string]string{
		"postgres://admin:s3cret@db.example:5433/app?sslmode=require":                "postgresql://db.example:5433/app",
		"postgresql://admin:s3cret@db.example/app":                                   "postgresql://db.example/app",
		"host=db.internal port=5432 user=admin password=s3cret dbname=app":           "postgresql://db.internal:5432/app",
		"host='db.internal' user=admin password='s3cret' dbname=app sslmode=disable": "postgresql://db.internal/app",
		"user=admin password=s3cret dbname=app":                                      "postgresql://localhost/app",
	} {
		if got := postgresTargetRef([]byte(dsn), "app"); got != want || strings.Contains(got, "s3cret") || strings.Contains(got, "admin") {
			t.Errorf("postgresTargetRef(%q) = %q, want %q", dsn, got, want)
		}
	}
	for arn, want := range map[string]string{
		"arn:aws:iam::123456789012:role/deploy":         "deploy",
		"arn:aws:iam::123456789012:role/ci/team/deploy": "deploy",
		"arn:aws-us-gov:iam::123456789012:role/reader":  "reader",
	} {
		if got, ok := awsRoleNameFromARN(arn); !ok || got != want {
			t.Errorf("awsRoleNameFromARN(%q) = %q, %t", arn, got, ok)
		}
	}
	for _, arn := range []string{"arn:aws:iam::123456789012:user/deploy", "role/deploy", "arn:aws:iam::123456789012:role/"} {
		if _, ok := awsRoleNameFromARN(arn); ok {
			t.Errorf("awsRoleNameFromARN(%q) accepted a non-role ARN", arn)
		}
	}
	for region, want := range map[string][2]string{
		"eu-west-1":      {"https://iam.amazonaws.com", "us-east-1"},
		"us-gov-east-1":  {"https://iam.us-gov.amazonaws.com", "us-gov-west-1"},
		"cn-northwest-1": {"https://iam.cn-north-1.amazonaws.com.cn", "cn-north-1"},
	} {
		if endpoint, signing := AWSIAMEndpointFor(region, ""); endpoint != want[0] || signing != want[1] {
			t.Errorf("AWSIAMEndpointFor(%q) = %s, %s", region, endpoint, signing)
		}
	}
	if endpoint, signing := AWSIAMEndpointFor("eu-west-1", " http://127.0.0.1:4566 "); endpoint != "http://127.0.0.1:4566" || signing != "us-east-1" {
		t.Errorf("configured IAM endpoint = %s, %s", endpoint, signing)
	}
}
