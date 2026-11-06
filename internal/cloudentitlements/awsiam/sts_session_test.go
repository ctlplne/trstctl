// SPDX-License-Identifier: BUSL-1.1
package awsiam

import (
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
	"trstctl.com/trstctl/internal/crypto/awssignin"
)

func leaseFixture() []byte {
	return []byte(`{"access_key_id":"ASIAEXAMPLE","secret_access_key":"fixture-signing-material","session_token":"fixture-session-material","expiration":"2026-11-05T01:00:00Z"}`)
}
func TestSTSLeaseByteCustodyAndAmbiguityA264(t *testing.T) {
	now := time.Date(2026, 11, 5, 0, 0, 0, 0, time.UTC)
	var borrowed awssignin.Credentials
	if err := UseLeaseCredential(leaseFixture(), now, func(c awssignin.Credentials) error {
		borrowed = c
		if !bytes.Equal(c.SessionToken, []byte("fixture-session-material")) {
			t.Fatal("credential changed")
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	for _, raw := range [][]byte{borrowed.AccessKeyID, borrowed.SecretAccessKey, borrowed.SessionToken} {
		if !bytes.Equal(raw, make([]byte, len(raw))) {
			t.Fatal("borrowed credential remained after callback")
		}
	}
	for _, raw := range [][]byte{bytes.Replace(leaseFixture(), []byte(`"expiration"`), []byte(`"session_token":"other","expiration"`), 1), bytes.Replace(leaseFixture(), []byte("session_token"), []byte("SESSION_TOKEN"), 1), bytes.Replace(leaseFixture(), []byte("2026-11-05T01"), []byte("2026-11-04T01"), 1), bytes.Replace(leaseFixture(), []byte("fixture-session-material"), []byte(""), 1), append(leaseFixture(), []byte(` {}`)...)} {
		if err := UseLeaseCredential(raw, now, func(awssignin.Credentials) error { t.Error("invalid temporary credential reached signer"); return nil }); err == nil {
			t.Fatal("ambiguous, expired or incomplete credential accepted")
		}
	}
}
func TestSTSSigningScopeAndExactCallerA264(t *testing.T) {
	for _, mode := range []string{"allowed", "wrong_role", "wrong_native_session", "redirect"} {
		t.Run(mode, func(t *testing.T) {
			calls := 0
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				calls++
				if r.Method != "POST" || r.URL.Path != "/" {
					t.Error("not a fixed native STS query")
				}
				if err := r.ParseForm(); err != nil {
					t.Error(err)
				}
				if r.PostForm.Get("Action") != "GetCallerIdentity" || r.PostForm.Get("Version") != "2011-06-15" || !strings.Contains(r.Header.Get("Authorization"), "/us-east-1/sts/aws4_request") || r.Header.Get("X-Amz-Security-Token") == "" {
					t.Error("wrong STS protocol/signing scope")
				}
				if mode == "redirect" {
					w.Header().Set("Location", "http://127.0.0.1:1/")
					w.WriteHeader(http.StatusTemporaryRedirect)
					return
				}
				role, session := "workload-role", "owned-session"
				if mode == "wrong_role" {
					role = "other"
				}
				if mode == "wrong_native_session" {
					session = "different"
				}
				_, _ = w.Write([]byte(`<GetCallerIdentityResponse><GetCallerIdentityResult><UserId>AROAEXAMPLE:` + session + `</UserId><Account>111122223333</Account><Arn>arn:aws:sts::111122223333:assumed-role/` + role + `/owned-session</Arn></GetCallerIdentityResult></GetCallerIdentityResponse>`))
			}))
			defer server.Close()
			cfg := fixtureClient(t, server.URL).cfg
			identity, err := VerifyAssumedRole(context.Background(), cfg, []string{"arn:aws:iam::111122223333:role/path/workload-role"})
			if mode == "allowed" {
				if err != nil || identity.UserID != "AROAEXAMPLE:owned-session" {
					t.Fatalf("caller readback: %+v %v", identity, err)
				}
			} else if err == nil {
				t.Fatal("non-matching native caller or redirect accepted")
			}
			if calls != 1 {
				t.Fatal("credential-bearing verification followed redirect or retried")
			}
		})
	}
}
func FuzzSTSLeaseCredential(f *testing.F) {
	f.Add(leaseFixture())
	f.Fuzz(func(t *testing.T, raw []byte) {
		if len(raw) > 64<<10 {
			return
		}
		calls := 0
		var borrowed awssignin.Credentials
		err := UseLeaseCredential(raw, time.Date(2026, 11, 5, 0, 0, 0, 0, time.UTC), func(c awssignin.Credentials) error {
			calls++
			borrowed = c
			if len(c.AccessKeyID) == 0 || len(c.SecretAccessKey) == 0 || len(c.SessionToken) == 0 {
				t.Fatal("incomplete temporary credential")
			}
			return nil
		})
		if err == nil && calls != 1 {
			t.Fatal("successful borrow did not invoke exactly once")
		}
		for _, value := range [][]byte{borrowed.AccessKeyID, borrowed.SecretAccessKey, borrowed.SessionToken} {
			if !bytes.Equal(value, make([]byte, len(value))) {
				t.Fatal("borrow survived callback")
			}
		}
	})
}
