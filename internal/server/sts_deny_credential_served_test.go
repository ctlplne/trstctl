// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"context"
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

const (
	n3l1RoleARN = "arn:aws:iam::123456789012:role/n3l1-deployer"
	n3l1Issuer  = "AKIAN3L1ISSUER"
	n3l1Denier  = "AKIAN3L1DENIER"
)

// n3l1AWSStandIn answers STS AssumeRole for the issuing identity and IAM's
// role-policy calls (Put, Get, List, Delete; written from IAM's API
// reference) for the n3l1-deployer role, with AWS's authorization split: only
// the denial identity may write or delete the role's policies, so the issuing
// identity holds no IAM write permission. It notes who signed each call.
type n3l1AWSStandIn struct {
	*httptest.Server
	mu       sync.Mutex
	policies map[string]string
	signers  map[string][]string
	issued   int
}

func newN3L1AWSStandIn(t *testing.T) *n3l1AWSStandIn {
	t.Helper()
	s := &n3l1AWSStandIn{policies: map[string]string{}, signers: map[string][]string{}}
	s.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil {
			http.Error(w, "invalid form", http.StatusBadRequest)
			return
		}
		match := n3l3Credential.FindStringSubmatch(r.Header.Get("Authorization"))
		if match == nil {
			http.Error(w, "unsigned request", http.StatusForbidden)
			return
		}
		signer, action := match[1], r.Form.Get("Action")
		s.mu.Lock()
		defer s.mu.Unlock()
		s.signers[action] = append(s.signers[action], signer)
		denied := func() {
			w.WriteHeader(http.StatusForbidden)
			_, _ = fmt.Fprint(w, `<ErrorResponse><Error><Type>Sender</Type><Code>AccessDenied</Code><Message>not authorized</Message></Error></ErrorResponse>`)
		}
		name := r.Form.Get("PolicyName")
		switch action {
		case "AssumeRole":
			if signer != n3l1Issuer {
				denied()
				return
			}
			seconds, _ := strconv.Atoi(r.Form.Get("DurationSeconds"))
			s.issued++
			expires := time.Now().UTC().Add(time.Duration(seconds) * time.Second).Truncate(time.Second).Format(time.RFC3339)
			_, _ = fmt.Fprintf(w, `<AssumeRoleResponse><AssumeRoleResult><Credentials><AccessKeyId>ASIAN3L1SESSION%04d</AccessKeyId><SecretAccessKey>n3l1-session-value-%d</SecretAccessKey><SessionToken>n3l1-session-token-%d</SessionToken><Expiration>%s</Expiration></Credentials><AssumedRoleUser><AssumedRoleId>AROAN3L1:%s</AssumedRoleId></AssumedRoleUser></AssumeRoleResult></AssumeRoleResponse>`,
				s.issued, s.issued, s.issued, expires, r.Form.Get("RoleSessionName")) // #nosec G705 -- test writes fixture bytes to its own local server (CWE-79)
		case "PutRolePolicy", "DeleteRolePolicy":
			if signer != n3l1Denier {
				denied()
				return
			}
			if action == "PutRolePolicy" {
				s.policies[name] = r.Form.Get("PolicyDocument")
			} else {
				delete(s.policies, name)
			}
			_, _ = fmt.Fprintf(w, `<%sResponse><ResponseMetadata/></%sResponse>`, action, action) // #nosec G705 -- test writes fixture bytes to its own local server (CWE-79)
		case "GetRolePolicy":
			stored, ok := s.policies[name]
			if !ok {
				http.Error(w, "<Error><Code>NoSuchEntity</Code></Error>", http.StatusNotFound)
				return
			}
			_, _ = fmt.Fprintf(w, `<GetRolePolicyResponse><GetRolePolicyResult><RoleName>n3l1-deployer</RoleName><PolicyName>%s</PolicyName><PolicyDocument>%s</PolicyDocument></GetRolePolicyResult></GetRolePolicyResponse>`,
				name, url.PathEscape(stored)) // #nosec G705 -- test writes fixture bytes to its own local server (CWE-79)
		case "ListRolePolicies":
			var b strings.Builder
			for n := range s.policies {
				b.WriteString("<member>" + n + "</member>")
			}
			_, _ = fmt.Fprintf(w, `<ListRolePoliciesResponse><ListRolePoliciesResult><PolicyNames>%s</PolicyNames><IsTruncated>false</IsTruncated></ListRolePoliciesResult></ListRolePoliciesResponse>`, b.String()) // #nosec G705 -- test writes fixture bytes to its own local server (CWE-79)
		default:
			http.Error(w, "unexpected action "+action, http.StatusBadRequest)
		}
	}))
	t.Cleanup(s.Close)
	return s
}

func (s *n3l1AWSStandIn) signedBy(action string) []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]string(nil), s.signers[action]...)
}

// N3-L1: an aws-sts provider with revoke_with_deny_policy and a denial
// credential issues sessions with its own identity, which holds no IAM write
// permission, and writes, reads back and prunes each revoked session's denial
// with the denial identity. Against an STS and IAM stand-in that lets only the
// denial identity write the role's policies, a lease's revocation completes
// as deny_policy, the role holds the session's own denial, and every IAM
// role-policy call was signed by the denial identity, AssumeRole by the
// issuing one.
func TestServedSTSDenialsUseTheirOwnCredentialN3L1(t *testing.T) {
	aws := newN3L1AWSStandIn(t)
	h := newOperatingServedHarness(t, config.Protocols{}, func(d *Deps) {
		d.EnableSecretsAPI = true
		resolver := integrationCredentialResolver{store: d.Store, kek: d.KEK, crypto: d.TenantCrypto}
		cfg := config.DynamicSecretProviderConfig{
			TenantID: servedTestTenant, ID: "aws-n3l1", Type: "aws-sts", Endpoint: aws.URL, IAMEndpoint: aws.URL,
			AllowInsecureLoopback: true, Region: "us-east-1", AccessKeyID: n3l1Issuer,
			SecretAccessRef:      writeServedCredentialFile(t, "n3l1-issuer", "n3l1-issuer-signing"),
			RevokeWithDenyPolicy: true, DenyAccessKeyID: n3l1Denier,
			DenySecretAccessRef: writeServedCredentialFile(t, "n3l1-denier", "n3l1-denier-signing"),
			AllowedRoles:        []string{"deployer"}, RoleBindings: map[string]string{"deployer": n3l1RoleARN}, MaxTTL: "1h",
		}
		if err := config.ValidateSecretIntegrations(config.SecretIntegrationsConfig{DynamicProviders: []config.DynamicSecretProviderConfig{cfg}}, true); err != nil {
			t.Fatalf("the provider as configured: %v", err)
		}
		d.TenantDynamicSecretProviders = DynamicSecretProviderRegistry{servedTestTenant: {
			newConfiguredDynamicProvider(cfg, map[string]bool{"deployer": true}, time.Hour, resolver, nil),
		}}
	})
	startServedExternalCADispatcher(t, h)
	tok := seedScopedTokenSubject(t, h.store, h.tenant, "n3l1-issuer", "secrets:read", "secrets:write")

	status, body := secretsReqKey(t, h, http.MethodPost, "/api/v1/secrets/leases", tok, "n3l1-issue",
		map[string]any{"provider": "aws-n3l1", "role": "deployer", "ttl_seconds": 900})
	var lease struct {
		ID string `json:"id"`
	}
	if status != http.StatusCreated || json.Unmarshal(body, &lease) != nil || lease.ID == "" {
		t.Fatalf("issue the lease: HTTP %d", status)
	}
	if status, body := secretsReqKey(t, h, http.MethodPost, "/api/v1/secrets/leases/"+lease.ID+"/revoke", tok, "n3l1-revoke", map[string]any{}); status != http.StatusOK && status != http.StatusAccepted {
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
			t.Fatalf("the revocation did not complete: HTTP %d %s", status, body)
		}
		time.Sleep(100 * time.Millisecond)
	}
	record, err := h.store.GetDynamicSecretLease(context.Background(), h.tenant, lease.ID)
	if err != nil {
		t.Fatal(err)
	}
	var ref struct {
		AssumedRoleID string    `json:"assumed_role_id"`
		Expiration    time.Time `json:"expiration"`
	}
	if err := json.Unmarshal([]byte(record.BackendRef), &ref); err != nil {
		t.Fatal(err)
	}
	aws.mu.Lock()
	denial := aws.policies[dynsecret.AWSSTSDenyPolicyName(ref.AssumedRoleID, ref.Expiration)]
	aws.mu.Unlock()
	if revoked.RevocationMethod != dynsecret.RevocationMethodDenyPolicy || !strings.Contains(denial, `"aws:userid":"`+ref.AssumedRoleID+`"`) {
		t.Fatalf("revocation method %q, the role's denial %q", revoked.RevocationMethod, denial)
	}
	for _, action := range []string{"PutRolePolicy", "GetRolePolicy", "ListRolePolicies"} {
		signers := aws.signedBy(action)
		if len(signers) == 0 {
			t.Fatalf("no %s call", action)
		}
		for _, signer := range signers {
			if signer != n3l1Denier {
				t.Fatalf("%s signed by %s; want the denial identity", action, signer)
			}
		}
	}
	if signers := aws.signedBy("AssumeRole"); len(signers) != 1 || signers[0] != n3l1Issuer {
		t.Fatalf("AssumeRole signed by %v; want the issuing identity once", signers)
	}
	t.Logf("N3L1_DENY_CREDENTIAL_OK method=%s put_by=%s assume_by=%s", revoked.RevocationMethod, n3l1Denier, n3l1Issuer)
}
