// SPDX-License-Identifier: BUSL-1.1

package dynsecret

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
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
	// refuseDocuments answers every policy document read 403 (G2-L1).
	refuseDocuments bool
}

// iamPolicyDocuments are the stand-in's policy documents (G2-L1), by managed
// policy ARN or inline policy name, as IAM's documented JSON grammar has them.
var iamPolicyDocuments = map[string]string{
	"arn:aws:iam::123456789012:policy/ci-deploy": `{"Version":"2012-10-17","Statement":[` +
		`{"Effect":"Allow","Action":["s3:PutObject","s3:GetObject"],"Resource":"arn:aws:s3:::artifacts/*"},` +
		`{"Effect":"Allow","Action":"ecr:*","Resource":"*","Condition":{"StringEquals":{"aws:RequestedRegion":"us-east-1"}}}]}`,
	"arn:aws:iam::aws:policy/AmazonS3ReadOnlyAccess": `{"Version":"2012-10-17","Statement":{"Effect":"Allow","Action":["s3:Get*","s3:List*"],"Resource":"*"}}`,
	"arn:aws:iam::aws:policy/AdministratorAccess":    `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"*","Resource":"*"}]}`,
	"s3-write-artifacts": `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"s3:DeleteObject","Resource":"*"},` +
		`{"Effect":"Deny","Action":"s3:Delete*","Resource":"*"}]}`,
	"kms-decrypt": `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"kms:Decrypt","NotResource":"arn:aws:kms:us-east-1:123456789012:key/admin"}]}`,
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
	switch action := r.Form.Get("Action"); action {
	case "GetPolicy", "GetPolicyVersion", "GetRolePolicy":
		s.mu.Lock()
		refuse := s.refuseDocuments
		s.mu.Unlock()
		if refuse {
			w.WriteHeader(http.StatusForbidden)
			_, _ = fmt.Fprint(w, `<ErrorResponse><Error><Code>AccessDenied</Code></Error></ErrorResponse>`)
			return
		}
		key := r.Form.Get("PolicyArn")
		if action == "GetRolePolicy" {
			key = r.Form.Get("PolicyName")
		}
		doc, ok := iamPolicyDocuments[key]
		if !ok {
			w.WriteHeader(http.StatusNotFound)
			_, _ = fmt.Fprint(w, `<ErrorResponse><Error><Code>NoSuchEntity</Code></Error></ErrorResponse>`)
			return
		}
		switch action {
		case "GetPolicy":
			_, _ = fmt.Fprintf(w, `<GetPolicyResponse><GetPolicyResult><Policy><Arn>%s</Arn><DefaultVersionId>v3</DefaultVersionId></Policy></GetPolicyResult></GetPolicyResponse>`, key) // #nosec G705 -- test writes fixture bytes to its own local server (CWE-79)
		case "GetPolicyVersion":
			if r.Form.Get("VersionId") != "v3" {
				http.Error(w, "not the default version", http.StatusBadRequest)
				return
			}
			_, _ = fmt.Fprintf(w, `<GetPolicyVersionResponse><GetPolicyVersionResult><PolicyVersion><Document>%s</Document><VersionId>v3</VersionId><IsDefaultVersion>true</IsDefaultVersion></PolicyVersion></GetPolicyVersionResult></GetPolicyVersionResponse>`, url.QueryEscape(doc))
		default:
			_, _ = fmt.Fprintf(w, `<GetRolePolicyResponse><GetRolePolicyResult><RoleName>%s</RoleName><PolicyName>%s</PolicyName><PolicyDocument>%s</PolicyDocument></GetRolePolicyResult></GetRolePolicyResponse>`, r.Form.Get("RoleName"), key, url.QueryEscape(doc)) // #nosec G705 -- test writes fixture bytes to its own local server (CWE-79)
		}
		return
	}
	if r.Form.Get("RoleName") == "admin" {
		switch r.Form.Get("Action") {
		case "ListAttachedRolePolicies":
			_, _ = fmt.Fprint(w, `<ListAttachedRolePoliciesResponse><ListAttachedRolePoliciesResult><AttachedPolicies><member><PolicyName>AdministratorAccess</PolicyName><PolicyArn>arn:aws:iam::aws:policy/AdministratorAccess</PolicyArn></member></AttachedPolicies><IsTruncated>false</IsTruncated></ListAttachedRolePoliciesResult></ListAttachedRolePoliciesResponse>`)
		case "ListRolePolicies":
			_, _ = fmt.Fprint(w, `<ListRolePoliciesResponse><ListRolePoliciesResult><PolicyNames></PolicyNames><IsTruncated>false</IsTruncated></ListRolePoliciesResult></ListRolePoliciesResponse>`)
		default:
			http.Error(w, "unexpected IAM call", http.StatusBadRequest)
		}
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
		"effective: inline policy s3-write-artifacts's allow of s3:DeleteObject is overridden by inline policy s3-write-artifacts's deny",
		"inline policy kms-decrypt",
		"inline policy kms-decrypt: allow kms:Decrypt on every resource except arn:aws:kms:us-east-1:123456789012:key/admin",
		"inline policy s3-write-artifacts",
		"inline policy s3-write-artifacts: allow s3:DeleteObject on every resource",
		"inline policy s3-write-artifacts: deny s3:Delete* on every resource",
		"managed policy AmazonS3ReadOnlyAccess (arn:aws:iam::aws:policy/AmazonS3ReadOnlyAccess)",
		"managed policy AmazonS3ReadOnlyAccess: allow s3:Get*, s3:List* on every resource",
		"managed policy ci-deploy (arn:aws:iam::123456789012:policy/ci-deploy)",
		"managed policy ci-deploy: allow ecr:* on every resource when StringEquals aws:RequestedRegion",
		"managed policy ci-deploy: allow s3:GetObject, s3:PutObject on arn:aws:s3:::artifacts/*",
	}
	if access.TargetKind != AccessTargetAWSIAMRole || access.TargetRef != "arn:aws:iam::123456789012:role/ci/deploy" ||
		access.Login != "AROADEPLOY:trstctl-deploy-lease" || !slices.Equal(access.Grants, want) || access.Truncated != 0 {
		t.Fatalf("access = %+v", access)
	}
	if got := AccessGrantsSummary(access); !strings.HasPrefix(got, "effective: inline policy s3-write-artifacts's allow") {
		t.Fatalf("summary = %q", got)
	}
	if !slices.Equal(standIn.actions, []string{"ListAttachedRolePolicies ", "ListAttachedRolePolicies page-2", "ListRolePolicies ",
		"GetPolicy ", "GetPolicyVersion ", "GetPolicy ", "GetPolicyVersion ", "GetRolePolicy ", "GetRolePolicy "}) {
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
		"postgres://admin:s3cret@db.example:5433/app?sslmode=require":                "postgresql://db.example:5433/app", // #nosec G101 -- test fixture DSNs with a dummy password; the test asserts it never reaches the target ref (CWE-798)
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

// G2-L1: a role's policies are read statement by statement and weighed as
// IAM decides a request. An unconditional allow of every action on every
// resource with no deny reads as a full administrator; a document IAM
// refuses to show names the policy and says its statements are unreadable,
// while the role's policy names are still recorded.
func TestAWSSTSLeaseAccessWeighsPolicyStatementsG2L1(t *testing.T) {
	standIn := &iamStandIn{}
	iam := httptest.NewServer(standIn)
	defer iam.Close()
	backend := newAccessSTSBackend(t, iam)

	access, err := backend.ResolveAccess(context.Background(), stsLeaseRef(t, "arn:aws:iam::123456789012:role/admin"))
	if err != nil {
		t.Fatal(err)
	}
	want := []string{
		"effective: full administrator (managed policy AdministratorAccess allows every action on every resource with no condition, and no statement denies)",
		"managed policy AdministratorAccess (arn:aws:iam::aws:policy/AdministratorAccess)",
		"managed policy AdministratorAccess: allow every action on every resource",
	}
	if !slices.Equal(access.Grants, want) {
		t.Fatalf("administrator grants = %q", access.Grants)
	}

	standIn.mu.Lock()
	standIn.refuseDocuments = true
	standIn.mu.Unlock()
	access, err = backend.ResolveAccess(context.Background(), stsLeaseRef(t, "arn:aws:iam::123456789012:role/ci/deploy"))
	if err != nil {
		t.Fatalf("a refused document read failed the whole resolution: %v", err)
	}
	want = []string{
		"inline policy kms-decrypt",
		"inline policy kms-decrypt: statements unreadable (access_denied)",
		"inline policy s3-write-artifacts",
		"inline policy s3-write-artifacts: statements unreadable (access_denied)",
		"managed policy AmazonS3ReadOnlyAccess (arn:aws:iam::aws:policy/AmazonS3ReadOnlyAccess)",
		"managed policy AmazonS3ReadOnlyAccess: statements unreadable (access_denied)",
		"managed policy ci-deploy (arn:aws:iam::123456789012:policy/ci-deploy)",
		"managed policy ci-deploy: statements unreadable (access_denied)",
	}
	if !slices.Equal(access.Grants, want) {
		t.Fatalf("refused documents = %q", access.Grants)
	}
}

// G2-L1: the statement grammar — a statement or a list, a string or a list
// of actions and resources, NotAction and NotResource, condition keys — and
// a document that is not one is refused.
func TestParseAWSPolicyDocumentG2L1(t *testing.T) {
	doc := url.QueryEscape(`{"Statement":{"Effect":"Deny","NotAction":["iam:*","sts:AssumeRole"],"Resource":["arn:a","arn:b"],` +
		`"Condition":{"Bool":{"aws:MultiFactorAuthPresent":"false"},"IpAddress":{"aws:SourceIp":["10.0.0.0/8"]}}}}`)
	statements, err := parseAWSPolicyDocument(doc)
	if err != nil || len(statements) != 1 {
		t.Fatalf("parse = %+v, %v", statements, err)
	}
	got := statementGrant(policyStatement{label: "inline policy guard", awsPolicyStatement: statements[0]})
	if got != "inline policy guard: deny every action except iam:*, sts:AssumeRole on arn:a, arn:b when Bool aws:MultiFactorAuthPresent, IpAddress aws:SourceIp" {
		t.Fatalf("grant = %q", got)
	}
	for _, bad := range []string{"", "%zz", url.QueryEscape(`{"Statement":[{"Effect":"Maybe","Action":"*","Resource":"*"}]}`), url.QueryEscape(`{"Statement":7}`)} {
		if _, err := parseAWSPolicyDocument(bad); err == nil {
			t.Fatalf("%q parsed", bad)
		}
	}
	if !actionCovered("s3:Delete*", "s3:DeleteObject") || !actionCovered("S3:get?bject", "s3:GetObject") || actionCovered("s3:Get*", "s3:PutObject") {
		t.Fatal("action patterns match wrongly")
	}
}
