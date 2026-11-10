// SPDX-License-Identifier: BUSL-1.1

package dynsecret

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/crypto/secret"
)

// awsSTSChainingStandIn answers AssumeRole and records each request's session
// policy, so a test can see what a lease's session may do.
type awsSTSChainingStandIn struct {
	server     *httptest.Server
	expiration time.Time
	policies   []string
	hasPolicy  []bool
}

func newAWSSTSChainingStandIn(t *testing.T, expiration time.Time) *awsSTSChainingStandIn {
	t.Helper()
	s := &awsSTSChainingStandIn{expiration: expiration}
	s.server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil || r.Form.Get("Action") != "AssumeRole" {
			http.Error(w, "not an AssumeRole request", http.StatusBadRequest)
			return
		}
		_, has := r.Form["Policy"]
		s.policies = append(s.policies, r.Form.Get("Policy"))
		s.hasPolicy = append(s.hasPolicy, has)
		_, _ = fmt.Fprintf(w, `<AssumeRoleResponse><AssumeRoleResult><Credentials><AccessKeyId>ASIACHAIN%d</AccessKeyId><SecretAccessKey>ephemeral-secret</SecretAccessKey><SessionToken>ephemeral-session</SessionToken><Expiration>%s</Expiration></Credentials><AssumedRoleUser><AssumedRoleId>AROAREADER:lease-%d</AssumedRoleId></AssumedRoleUser></AssumeRoleResult></AssumeRoleResponse>`,
			len(s.policies), s.expiration.Format(time.RFC3339), len(s.policies))
	}))
	t.Cleanup(s.server.Close)
	return s
}

func (s *awsSTSChainingStandIn) backend(t *testing.T, cfg AWSSTSConfig) *AWSSTSBackend {
	t.Helper()
	cfg.Endpoint, cfg.HTTPClient, cfg.Region = s.server.URL, s.server.Client(), "us-east-1"
	cfg.AccessKeyID, cfg.SecretAccessKey = "AKID", []byte("admin-secret")
	cfg.RoleARNs = map[string]string{"reader": "arn:aws:iam::123456789012:role/trstctl-reader"}
	backend, err := NewAWSSTSBackend(cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(backend.Close)
	return backend
}

// N3-L3: a lease's session is issued unable to assume another role. A chained
// session runs as the other role, which neither a denial on the lease's role
// nor the lease's expiry reaches, so it would outlive the lease's revocation.
func TestAWSSTSLeaseSessionCannotChainRolesN3L3(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	standIn := newAWSSTSChainingStandIn(t, now.Add(time.Hour))
	backend := standIn.backend(t, AWSSTSConfig{})
	ref, raw, err := backend.CreateCredential(context.Background(), GenerateRequest{Role: "reader", TTL: time.Hour, LeaseID: "lease-n3l3"})
	if err != nil {
		t.Fatal(err)
	}
	secret.Wipe(raw)
	if len(standIn.policies) != 1 || !standIn.hasPolicy[0] {
		t.Fatal("the lease's AssumeRole passed no session policy, so the session can assume other roles")
	}
	var policy struct {
		Version   string
		Statement []struct {
			Sid, Effect, Action, Resource string
		}
	}
	if err := json.Unmarshal([]byte(standIn.policies[0]), &policy); err != nil {
		t.Fatalf("session policy %q: %v", standIn.policies[0], err)
	}
	var allowsTheRole, deniesChaining bool
	for _, s := range policy.Statement {
		switch {
		case s.Effect == "Allow" && s.Action == "*" && s.Resource == "*":
			allowsTheRole = true
		case s.Effect == "Deny" && s.Action == "sts:AssumeRole" && s.Resource == "*":
			deniesChaining = true
		default:
			t.Fatalf("unexpected session policy statement %+v", s)
		}
	}
	if policy.Version != "2012-10-17" || !allowsTheRole || !deniesChaining {
		t.Fatalf("session policy %s must keep the role's permissions and deny sts:AssumeRole", standIn.policies[0])
	}
	// The revocation waits for the session's own expiry only.
	if expiration, ok := AWSSTSExpiration(ref); !ok || !expiration.Equal(standIn.expiration) || AWSSTSRoleChaining(ref) {
		t.Fatalf("native expiry = %v %v (chaining %v), want the session's %v", expiration, ok, AWSSTSRoleChaining(ref), standIn.expiration)
	}
}

// N3-L3: allow_role_chaining issues the session without the policy, and its
// revocation then waits an hour past the session's expiry, the longest a
// session chained from it can run.
func TestAWSSTSRoleChainingOptInWaitsForAChainedSessionN3L3(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	standIn := newAWSSTSChainingStandIn(t, now.Add(time.Hour))
	backend := standIn.backend(t, AWSSTSConfig{AllowRoleChaining: true})
	ref, raw, err := backend.CreateCredential(context.Background(), GenerateRequest{Role: "reader", TTL: time.Hour, LeaseID: "lease-n3l3-chain"})
	if err != nil {
		t.Fatal(err)
	}
	secret.Wipe(raw)
	if len(standIn.hasPolicy) != 1 || standIn.hasPolicy[0] {
		t.Fatalf("an opted-in lease passed a session policy %q", standIn.policies)
	}
	wantUntil := standIn.expiration.Add(time.Hour)
	if until, ok := AWSSTSExpiration(ref); !ok || !until.Equal(wantUntil) || !AWSSTSRoleChaining(ref) {
		t.Fatalf("native expiry = %v %v (chaining %v), want %v", until, ok, AWSSTSRoleChaining(ref), wantUntil)
	}
	backend.query.now = func() time.Time { return standIn.expiration.Add(time.Second) }
	if err := backend.Revoke(context.Background(), ref); !errors.Is(err, ErrAWSSTSSessionActive) {
		t.Fatalf("revoke just past the session's expiry = %v, want pending while a chained session can run", err)
	}
	if err := CheckNativeExpiration(ref, wantUntil.Add(-time.Second)); !errors.Is(err, ErrNativeExpiryPending) {
		t.Fatalf("native expiration just before the chained hour ends = %v, want pending", err)
	}
	backend.query.now = func() time.Time { return wantUntil.Add(time.Second) }
	if err := backend.Revoke(context.Background(), ref); err != nil {
		t.Fatalf("revoke after the chained hour = %v", err)
	}
	if len(standIn.policies) != 1 {
		t.Fatalf("passive revocation made AWS calls: %d", len(standIn.policies))
	}

	// A denial on the lease's role can't reach a chained session, so the two
	// options don't combine.
	if _, err := NewAWSSTSBackend(AWSSTSConfig{
		Endpoint: standIn.server.URL, HTTPClient: standIn.server.Client(), Region: "us-east-1",
		AccessKeyID: "AKID", SecretAccessKey: []byte("admin-secret"),
		RoleARNs:          map[string]string{"reader": "arn:aws:iam::123456789012:role/trstctl-reader"},
		AllowRoleChaining: true, RevokeWithDenyPolicy: true,
	}); err == nil || !strings.Contains(err.Error(), "allow_role_chaining") {
		t.Fatalf("role chaining with deny-policy revocation = %v, want refused", err)
	}
}
