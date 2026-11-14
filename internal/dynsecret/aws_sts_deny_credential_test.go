// SPDX-License-Identifier: BUSL-1.1

package dynsecret

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

// signerRecorder notes which access key signed each IAM call, then lets the
// role-policy double answer it.
type signerRecorder struct {
	next http.Handler
	mu   sync.Mutex
	keys map[string][]string
}

func (s *signerRecorder) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	_ = r.ParseForm()
	key := ""
	if _, rest, ok := strings.Cut(r.Header.Get("Authorization"), "Credential="); ok {
		key, _, _ = strings.Cut(rest, "/")
	}
	s.mu.Lock()
	s.keys[r.Form.Get("Action")] = append(s.keys[r.Form.Get("Action")], key)
	s.mu.Unlock()
	s.next.ServeHTTP(w, r)
}

func (s *signerRecorder) signers(action string) []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]string(nil), s.keys[action]...)
}

// N3-L1: with a denial credential, every call that writes, reads back or
// prunes a session's denial is signed by it, never by the credential that
// issues sessions, which then needs no IAM write permission; without one the
// issuing credential signs them, as before. A denial credential without
// revoke_with_deny_policy is refused.
func TestAWSSTSDenialsUseTheirOwnCredentialN3L1(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	for name, c := range map[string]struct {
		denyKey string
		want    string
	}{
		"a denial credential": {"AKIDDENYWRITER", "AKIDDENYWRITER"},
		"none":                {"", "AKIDISSUER"},
	} {
		stale := awsSTSDenyPolicyPrefix + "1000000000-0123456789ab"
		double := &iamRolePolicyDouble{t: t, role: "trstctl-reader", policies: map[string]string{stale: `{"Version":"2012-10-17","Statement":[]}`}}
		rec := &signerRecorder{next: double, keys: map[string][]string{}}
		server := httptest.NewServer(rec)
		cfg := AWSSTSConfig{
			Endpoint: server.URL, HTTPClient: server.Client(), Region: "us-east-1",
			AccessKeyID: "AKIDISSUER", SecretAccessKey: []byte("issuer-signing-value"),
			RoleARNs:    map[string]string{"reader": "arn:aws:iam::123456789012:role/trstctl-reader"},
			IAMEndpoint: server.URL, RevokeWithDenyPolicy: true,
		}
		if c.denyKey != "" {
			cfg.DenyAccessKeyID, cfg.DenySecretAccessKey = c.denyKey, []byte("deny-signing-value")
		}
		backend, err := NewAWSSTSBackend(cfg)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		backend.query.now = func() time.Time { return now }
		method, err := backend.RevokeMethod(context.Background(), stsSessionRef(t, "AROAREADER:trstctl-reader-lease", now.Add(time.Hour)))
		if err != nil || method != RevocationMethodDenyPolicy {
			t.Fatalf("%s: revoke = %q %v", name, method, err)
		}
		for _, action := range []string{"ListRolePolicies", "DeleteRolePolicy", "PutRolePolicy", "GetRolePolicy"} {
			signers := rec.signers(action)
			if len(signers) == 0 {
				t.Fatalf("%s: no %s call", name, action)
			}
			for _, key := range signers {
				if key != c.want {
					t.Fatalf("%s: %s signed by %q; want %q", name, action, key, c.want)
				}
			}
		}
		backend.Close()
		server.Close()
	}
	if _, err := NewAWSSTSBackend(AWSSTSConfig{
		Endpoint: "https://sts.us-east-1.amazonaws.com", Region: "us-east-1",
		AccessKeyID: "AKIDISSUER", SecretAccessKey: []byte("issuer-signing-value"),
		RoleARNs:        map[string]string{"reader": "arn:aws:iam::123456789012:role/trstctl-reader"},
		DenyAccessKeyID: "AKIDDENYWRITER", DenySecretAccessKey: []byte("deny-signing-value"),
	}); err == nil || !strings.Contains(err.Error(), "needs revoke_with_deny_policy") {
		t.Fatalf("a denial credential without revoke_with_deny_policy = %v", err)
	}
}
