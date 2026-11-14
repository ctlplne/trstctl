// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/dynsecret"
)

const n3l2RoleARN = "arn:aws:iam::123456789012:role/n3l2-deployer"

// n3l2AWSStandIn answers STS AssumeRole and IAM's role-policy and
// managed-policy calls for the n3l2-deployer role, written from the API
// references: the role's inline policies are already at their size quota (its
// own policy fills it), so PutRolePolicy is LimitExceeded; managed policies
// are created under their path and attached to the role.
type n3l2AWSStandIn struct {
	*httptest.Server
	mu       sync.Mutex
	inline   map[string]string
	managed  map[string]string
	attached map[string]bool
	issued   int
}

func newN3L2AWSStandIn(t *testing.T) *n3l2AWSStandIn {
	t.Helper()
	s := &n3l2AWSStandIn{managed: map[string]string{}, attached: map[string]bool{},
		inline: map[string]string{"n3l2-app": `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"s3:GetObject","Resource":"*"}]}`}}
	s.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil || n3l3Credential.FindStringSubmatch(r.Header.Get("Authorization")) == nil {
			http.Error(w, "unsigned or invalid request", http.StatusForbidden)
			return
		}
		s.mu.Lock()
		defer s.mu.Unlock()
		fail := func(status int, code string) {
			w.WriteHeader(status)
			_, _ = fmt.Fprintf(w, "<ErrorResponse><Error><Code>%s</Code></Error></ErrorResponse>", code) // #nosec G705 -- test writes fixture bytes to its own local server (CWE-79)
		}
		name, arn := r.Form.Get("PolicyName"), r.Form.Get("PolicyArn")
		switch r.Form.Get("Action") {
		case "AssumeRole":
			seconds, _ := strconv.Atoi(r.Form.Get("DurationSeconds"))
			s.issued++
			expires := time.Now().UTC().Add(time.Duration(seconds) * time.Second).Truncate(time.Second).Format(time.RFC3339)
			_, _ = fmt.Fprintf(w, `<AssumeRoleResponse><AssumeRoleResult><Credentials><AccessKeyId>ASIAN3L2SESSION%04d</AccessKeyId><SecretAccessKey>n3l2-session-value-%d</SecretAccessKey><SessionToken>n3l2-session-token-%d</SessionToken><Expiration>%s</Expiration></Credentials><AssumedRoleUser><AssumedRoleId>AROAN3L2:%s</AssumedRoleId></AssumedRoleUser></AssumeRoleResult></AssumeRoleResponse>`,
				s.issued, s.issued, s.issued, expires, r.Form.Get("RoleSessionName")) // #nosec G705 -- test writes fixture bytes to its own local server (CWE-79)
		case "PutRolePolicy":
			if _, exists := s.inline[name]; !exists {
				fail(http.StatusConflict, "LimitExceeded")
				return
			}
			s.inline[name] = r.Form.Get("PolicyDocument")
			_, _ = fmt.Fprint(w, `<PutRolePolicyResponse/>`)
		case "ListRolePolicies":
			var names []string
			for n := range s.inline {
				names = append(names, n)
			}
			_, _ = fmt.Fprintf(w, `<ListRolePoliciesResponse><ListRolePoliciesResult><PolicyNames><member>%s</member></PolicyNames><IsTruncated>false</IsTruncated></ListRolePoliciesResult></ListRolePoliciesResponse>`, strings.Join(names, "</member><member>")) // #nosec G705 -- test writes fixture bytes to its own local server (CWE-79)
		case "CreatePolicy":
			created := "arn:aws:iam::123456789012:policy" + r.Form.Get("Path") + name
			if _, ok := s.managed[created]; ok {
				fail(http.StatusConflict, "EntityAlreadyExists")
				return
			}
			s.managed[created] = r.Form.Get("PolicyDocument")
			_, _ = fmt.Fprintf(w, `<CreatePolicyResponse><CreatePolicyResult><Policy><Arn>%s</Arn></Policy></CreatePolicyResult></CreatePolicyResponse>`, created) // #nosec G705 -- test writes fixture bytes to its own local server (CWE-79)
		case "AttachRolePolicy":
			if _, ok := s.managed[arn]; !ok {
				fail(http.StatusNotFound, "NoSuchEntity")
				return
			}
			s.attached[arn] = true
			_, _ = fmt.Fprint(w, `<AttachRolePolicyResponse/>`)
		case "ListAttachedRolePolicies":
			var b strings.Builder
			for a := range s.attached {
				b.WriteString("<member><PolicyName>" + a[strings.LastIndex(a, "/")+1:] + "</PolicyName><PolicyArn>" + a + "</PolicyArn></member>")
			}
			_, _ = fmt.Fprintf(w, `<ListAttachedRolePoliciesResponse><ListAttachedRolePoliciesResult><AttachedPolicies>%s</AttachedPolicies><IsTruncated>false</IsTruncated></ListAttachedRolePoliciesResult></ListAttachedRolePoliciesResponse>`, b.String()) // #nosec G705 -- test writes fixture bytes to its own local server (CWE-79)
		case "GetPolicy":
			_, _ = fmt.Fprint(w, `<GetPolicyResponse><GetPolicyResult><Policy><DefaultVersionId>v1</DefaultVersionId></Policy></GetPolicyResult></GetPolicyResponse>`)
		case "GetPolicyVersion":
			_, _ = fmt.Fprintf(w, `<GetPolicyVersionResponse><GetPolicyVersionResult><PolicyVersion><Document>%s</Document></PolicyVersion></GetPolicyVersionResult></GetPolicyVersionResponse>`, url.PathEscape(s.managed[arn])) // #nosec G705 -- test writes fixture bytes to its own local server (CWE-79)
		default:
			fail(http.StatusBadRequest, "InvalidAction")
		}
	}))
	t.Cleanup(s.Close)
	return s
}

// N3-L2: an aws-sts provider with revoke_with_deny_policy and
// deny_quota_fallback token_issue_time revokes a lease whose role's inline
// policies are at IAM's quota: instead of failing, it attaches a managed
// policy denying every session of the role issued before the revocation, reads
// it back, and completes as deny_policy; the role's own policy is untouched.
func TestServedSTSRevocationFallsBackToACutoffWhenTheQuotaIsFullN3L2(t *testing.T) {
	aws := newN3L2AWSStandIn(t)
	h := newOperatingServedHarness(t, config.Protocols{}, func(d *Deps) {
		d.EnableSecretsAPI = true
		resolver := integrationCredentialResolver{store: d.Store, kek: d.KEK, crypto: d.TenantCrypto}
		cfg := config.DynamicSecretProviderConfig{
			TenantID: servedTestTenant, ID: "aws-n3l2", Type: "aws-sts", Endpoint: aws.URL, IAMEndpoint: aws.URL,
			AllowInsecureLoopback: true, Region: "us-east-1", AccessKeyID: "AKIAN3L2ISSUER",
			SecretAccessRef:      writeServedCredentialFile(t, "n3l2-issuer", "n3l2-issuer-signing"),
			RevokeWithDenyPolicy: true, DenyQuotaFallback: "token_issue_time",
			AllowedRoles: []string{"deployer"}, RoleBindings: map[string]string{"deployer": n3l2RoleARN}, MaxTTL: "1h",
		}
		if err := config.ValidateSecretIntegrations(config.SecretIntegrationsConfig{DynamicProviders: []config.DynamicSecretProviderConfig{cfg}}, true); err != nil {
			t.Fatalf("the provider as configured: %v", err)
		}
		d.TenantDynamicSecretProviders = DynamicSecretProviderRegistry{servedTestTenant: {
			newConfiguredDynamicProvider(cfg, map[string]bool{"deployer": true}, time.Hour, resolver, nil),
		}}
	})
	startServedExternalCADispatcher(t, h)
	tok := seedScopedTokenSubject(t, h.store, h.tenant, "n3l2-issuer", "secrets:read", "secrets:write")

	issuedAt := time.Now().UTC()
	status, body := secretsReqKey(t, h, http.MethodPost, "/api/v1/secrets/leases", tok, "n3l2-issue",
		map[string]any{"provider": "aws-n3l2", "role": "deployer", "ttl_seconds": 900})
	var lease struct {
		ID string `json:"id"`
	}
	if status != http.StatusCreated || json.Unmarshal(body, &lease) != nil || lease.ID == "" {
		t.Fatalf("issue the lease: HTTP %d", status)
	}
	if status, body := secretsReqKey(t, h, http.MethodPost, "/api/v1/secrets/leases/"+lease.ID+"/revoke", tok, "n3l2-revoke", map[string]any{}); status != http.StatusOK && status != http.StatusAccepted {
		t.Fatalf("revoke the lease: HTTP %d %s", status, body)
	}
	var revoked struct {
		RevocationStatus string `json:"revocation_status"`
		RevocationMethod string `json:"revocation_method"`
	}
	for deadline := time.Now().Add(30 * time.Second); ; {
		status, body := secretsReq(t, h, http.MethodGet, "/api/v1/secrets/leases/"+lease.ID, tok, nil)
		if status == http.StatusOK && json.Unmarshal(body, &revoked) == nil && revoked.RevocationStatus == "completed" {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("the revocation did not complete: HTTP %d", status)
		}
		time.Sleep(100 * time.Millisecond)
	}
	aws.mu.Lock()
	defer aws.mu.Unlock()
	var cutoffPolicy string
	for arn := range aws.attached {
		cutoffPolicy = aws.managed[arn]
	}
	var doc struct {
		Statement []struct {
			Effect    string
			Condition map[string]map[string]string
		}
	}
	if err := json.Unmarshal([]byte(cutoffPolicy), &doc); err != nil || len(aws.attached) != 1 || len(doc.Statement) != 1 || doc.Statement[0].Effect != "Deny" {
		t.Fatalf("attached %v, the cutoff policy %q", aws.attached, cutoffPolicy)
	}
	cutoff, err := time.Parse(time.RFC3339, doc.Statement[0].Condition["DateLessThan"]["aws:TokenIssueTime"])
	if err != nil || !cutoff.After(issuedAt) || revoked.RevocationMethod != dynsecret.RevocationMethodDenyPolicy {
		t.Fatalf("cutoff %v (session issued %v) %v, revocation method %q", cutoff, issuedAt, err, revoked.RevocationMethod)
	}
	if len(aws.inline) != 1 || aws.inline["n3l2-app"] == "" {
		t.Fatalf("the role's inline policies = %v; want its own policy untouched", aws.inline)
	}
	t.Logf("N3L2_CUTOFF_OK cutoff=%s method=%s", cutoff.Format(time.RFC3339), revoked.RevocationMethod)
}
