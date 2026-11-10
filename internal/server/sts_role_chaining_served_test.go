// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/dynsecret"
)

const (
	n3l3LeaseRoleARN   = "arn:aws:iam::123456789012:role/n3l3-deployer"
	n3l3ChainedRoleARN = "arn:aws:iam::123456789012:role/n3l3-production-admin"
)

// n3l3STSStandIn is an STS authorization stand-in: it issues sessions for
// AssumeRole, keeps each session's session policy, and evaluates it when a
// session signs an AssumeRole itself (role chaining), as AWS evaluates a
// session policy's explicit Deny for every request the session makes.
type n3l3STSStandIn struct {
	*httptest.Server
	mu       sync.Mutex
	sessions map[string]string // access key ID -> its session policy ("" = none)
	issued   int
	denied   int // AssumeRole calls a session's own policy refused
}

var n3l3Credential = regexp.MustCompile(`Credential=([A-Z0-9]+)/`)

func newN3L3STSStandIn(t *testing.T) *n3l3STSStandIn {
	t.Helper()
	s := &n3l3STSStandIn{sessions: map[string]string{}}
	s.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil || r.Form.Get("Action") != "AssumeRole" {
			http.Error(w, "not an AssumeRole request", http.StatusBadRequest)
			return
		}
		match := n3l3Credential.FindStringSubmatch(r.Header.Get("Authorization"))
		if match == nil {
			http.Error(w, "unsigned request", http.StatusForbidden)
			return
		}
		s.mu.Lock()
		defer s.mu.Unlock()
		if policy, isSession := s.sessions[match[1]]; isSession {
			if r.Header.Get("X-Amz-Security-Token") == "" {
				http.Error(w, "a session key without its token", http.StatusForbidden)
				return
			}
			if n3l3PolicyDeniesAssumeRole(policy) {
				s.denied++
				w.WriteHeader(http.StatusForbidden)
				_, _ = fmt.Fprint(w, `<ErrorResponse><Error><Type>Sender</Type><Code>AccessDenied</Code><Message>explicit deny in a session policy</Message></Error></ErrorResponse>`)
				return
			}
		} else if match[1] != "AKIAN3L3ADMIN" {
			http.Error(w, "unknown caller", http.StatusForbidden)
			return
		}
		seconds, err := strconv.Atoi(r.Form.Get("DurationSeconds"))
		if err != nil {
			http.Error(w, "no duration", http.StatusBadRequest)
			return
		}
		s.issued++
		key := fmt.Sprintf("ASIAN3L3SESSION%04d", s.issued)
		s.sessions[key] = r.Form.Get("Policy")
		expires := time.Now().UTC().Add(time.Duration(seconds) * time.Second).Truncate(time.Second).Add(time.Second).Format(time.RFC3339)
		_, _ = fmt.Fprintf(w, `<AssumeRoleResponse><AssumeRoleResult><Credentials><AccessKeyId>%s</AccessKeyId><SecretAccessKey>n3l3-session-secret-%d</SecretAccessKey><SessionToken>n3l3-session-token-%d</SessionToken><Expiration>%s</Expiration></Credentials><AssumedRoleUser><AssumedRoleId>AROAN3L3:%s</AssumedRoleId></AssumedRoleUser></AssumeRoleResult></AssumeRoleResponse>`,
			key, s.issued, s.issued, expires, r.Form.Get("RoleSessionName")) // #nosec G705 -- test writes fixture bytes to its own local server (CWE-79)
	}))
	t.Cleanup(s.Close)
	return s
}

// n3l3PolicyDeniesAssumeRole evaluates the statements this stand-in needs: an
// explicit Deny whose action covers sts:AssumeRole on every resource.
func n3l3PolicyDeniesAssumeRole(policy string) bool {
	if policy == "" {
		return false
	}
	var doc struct {
		Statement []struct {
			Effect   string
			Action   any
			Resource any
		}
	}
	if json.Unmarshal([]byte(policy), &doc) != nil {
		return true // AWS refuses a malformed session policy outright
	}
	covers := func(value any, want ...string) bool {
		var values []string
		switch v := value.(type) {
		case string:
			values = []string{v}
		case []any:
			for _, item := range v {
				if s, ok := item.(string); ok {
					values = append(values, s)
				}
			}
		}
		for _, v := range values {
			for _, w := range want {
				if v == w {
					return true
				}
			}
		}
		return false
	}
	for _, s := range doc.Statement {
		if s.Effect == "Deny" && covers(s.Action, "sts:AssumeRole", "sts:*", "*") && covers(s.Resource, "*", n3l3ChainedRoleARN) {
			return true
		}
	}
	return false
}

// n3l3Lease is the lease's metadata and its STS credential.
type n3l3Lease struct {
	ID              string     `json:"id"`
	NativeExpiresAt *time.Time `json:"native_expires_at"`
	RoleChaining    bool       `json:"role_chaining"`
	Credential      string     `json:"credential"`
}

func issueN3L3Lease(t *testing.T, h *servedHarness, token, key, provider string) (n3l3Lease, map[string]string) {
	t.Helper()
	status, body := secretsReqKey(t, h, http.MethodPost, "/api/v1/secrets/leases", token, key,
		map[string]any{"provider": provider, "role": "deployer", "ttl_seconds": 900})
	if status != http.StatusCreated {
		t.Fatalf("issue %s lease: HTTP %d %s", provider, status, body)
	}
	var lease n3l3Lease
	if err := json.Unmarshal(body, &lease); err != nil || lease.ID == "" || lease.Credential == "" {
		t.Fatalf("issue %s lease: %v %s", provider, err, body)
	}
	var credential map[string]string
	if err := json.Unmarshal([]byte(lease.Credential), &credential); err != nil || credential["access_key_id"] == "" {
		t.Fatalf("the %s lease's credential is not an STS session: %v", provider, err)
	}
	return lease, credential
}

// chainFrom assumes the chained role signed with a lease's own session, as a
// workload holding the lease would.
func (s *n3l3STSStandIn) chainFrom(t *testing.T, credential map[string]string) error {
	t.Helper()
	backend, err := dynsecret.NewAWSSTSBackend(dynsecret.AWSSTSConfig{
		Endpoint: s.URL, HTTPClient: s.Client(), Region: "us-east-1",
		AccessKeyID: credential["access_key_id"], SecretAccessKey: []byte(credential["secret_access_key"]),
		SessionToken: []byte(credential["session_token"]),
		RoleARNs:     map[string]string{"admin": n3l3ChainedRoleARN},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer backend.Close()
	_, raw, err := backend.CreateCredential(context.Background(), dynsecret.GenerateRequest{Role: "admin", TTL: time.Hour, LeaseID: "n3l3-chained"})
	clear(raw)
	return err
}

// N3-L3: a lease's AWS session can't chain into another role. A chained
// session runs as the other role, which neither a denial on the lease's role
// nor the lease's expiry reaches, so it outlived the lease's revocation.
// Against an STS authorization stand-in that evaluates session policies, a
// workload holding a lease is refused when it assumes another role with the
// lease's session, and the lease's native expiry is the session's own. A
// provider with allow_role_chaining issues a session that can chain, and its
// lease says so and waits an hour past the session's expiry.
func TestServedSTSLeaseCannotChainIntoAnotherRoleN3L3(t *testing.T) {
	sts := newN3L3STSStandIn(t)
	h := newOperatingServedHarness(t, config.Protocols{}, func(d *Deps) {
		d.EnableSecretsAPI = true
		resolver := integrationCredentialResolver{store: d.Store, kek: d.KEK, crypto: d.TenantCrypto}
		base := config.DynamicSecretProviderConfig{
			TenantID: servedTestTenant, Type: "aws-sts", Endpoint: sts.URL,
			AllowInsecureLoopback: true, Region: "us-east-1", AccessKeyID: "AKIAN3L3ADMIN",
			SecretAccessRef: writeServedCredentialFile(t, "n3l3-aws-secret", "n3l3-admin-secret"),
			AllowedRoles:    []string{"deployer"}, RoleBindings: map[string]string{"deployer": n3l3LeaseRoleARN}, MaxTTL: "1h",
		}
		bounded := base
		bounded.ID = "aws-bounded"
		chaining := base
		chaining.ID, chaining.AllowRoleChaining = "aws-chaining", true
		d.TenantDynamicSecretProviders = DynamicSecretProviderRegistry{servedTestTenant: {
			newConfiguredDynamicProvider(bounded, map[string]bool{"deployer": true}, time.Hour, resolver, nil),
			newConfiguredDynamicProvider(chaining, map[string]bool{"deployer": true}, time.Hour, resolver, nil),
		}}
	})
	startServedExternalCADispatcher(t, h)
	issuer := seedScopedTokenSubject(t, h.store, h.tenant, "n3l3-issuer", "secrets:read", "secrets:write")

	lease, credential := issueN3L3Lease(t, h, issuer, "n3l3-bounded", "aws-bounded")
	err := sts.chainFrom(t, credential)
	sts.mu.Lock()
	denied := sts.denied
	sts.mu.Unlock()
	if err == nil || !strings.Contains(err.Error(), "status 403") || denied != 1 {
		t.Fatalf("assuming another role with the lease's session = %v (session-policy denials %d), want refused by its session policy", err, denied)
	}
	if lease.RoleChaining || lease.NativeExpiresAt == nil {
		t.Fatalf("the bounded lease reads role_chaining=%v native_expires_at=%v", lease.RoleChaining, lease.NativeExpiresAt)
	}
	sessionExpiry, err := time.Parse(time.RFC3339, credential["expiration"])
	if err != nil || !lease.NativeExpiresAt.Equal(sessionExpiry) {
		t.Fatalf("the bounded lease's native expiry %v is not its session's %q (%v)", lease.NativeExpiresAt, credential["expiration"], err)
	}

	chained, chainedCredential := issueN3L3Lease(t, h, issuer, "n3l3-chaining", "aws-chaining")
	if err := sts.chainFrom(t, chainedCredential); err != nil {
		t.Fatalf("a lease of a provider that allows role chaining could not chain: %v", err)
	}
	chainedExpiry, err := time.Parse(time.RFC3339, chainedCredential["expiration"])
	if err != nil || !chained.RoleChaining || chained.NativeExpiresAt == nil ||
		!chained.NativeExpiresAt.Equal(chainedExpiry.Add(dynsecret.AWSSTSChainedSessionMaxDuration)) {
		t.Fatalf("the chaining lease reads role_chaining=%v native_expires_at=%v, want an hour past %q", chained.RoleChaining, chained.NativeExpiresAt, chainedCredential["expiration"])
	}
	// The lease read back by its ID says the same.
	status, body := secretsReq(t, h, http.MethodGet, "/api/v1/secrets/leases/"+chained.ID, issuer, nil)
	var read n3l3Lease
	if status != http.StatusOK || json.Unmarshal(body, &read) != nil || !read.RoleChaining || read.Credential != "" {
		t.Fatalf("read the chaining lease: HTTP %d %s", status, body)
	}
}
