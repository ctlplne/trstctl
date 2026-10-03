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

func TestAWSSTSAssumeRoleUsesNativeExpiryAndNeverCreatesIAMKey(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	expiration := now.Add(time.Hour)
	var actions []string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil {
			t.Error(err)
			http.Error(w, "invalid form", http.StatusBadRequest)
			return
		}
		actions = append(actions, r.Form.Get("Action"))
		if r.Form.Get("Action") != "AssumeRole" ||
			r.Form.Get("RoleArn") != "arn:aws:iam::123456789012:role/trstctl-reader" ||
			r.Form.Get("DurationSeconds") != "3600" ||
			!strings.Contains(r.Header.Get("Authorization"), "/sts/aws4_request") {
			http.Error(w, "not a signed bounded AssumeRole request", http.StatusBadRequest)
			return
		}
		_, _ = fmt.Fprintf(w, `<AssumeRoleResponse><AssumeRoleResult><Credentials><AccessKeyId>ASIAEXAMPLE123456</AccessKeyId><SecretAccessKey>ephemeral-secret</SecretAccessKey><SessionToken>ephemeral-session</SessionToken><Expiration>%s</Expiration></Credentials><AssumedRoleUser><AssumedRoleId>AROAREADER:trstctl-reader-lease</AssumedRoleId></AssumedRoleUser></AssumeRoleResult></AssumeRoleResponse>`, expiration.Format(time.RFC3339))
	}))
	defer server.Close()

	backend, err := NewAWSSTSBackend(AWSSTSConfig{
		Endpoint: server.URL, HTTPClient: server.Client(), Region: "us-east-1",
		AccessKeyID: "AKID", SecretAccessKey: []byte("admin-secret"),
		RoleARNs: map[string]string{"reader": "arn:aws:iam::123456789012:role/trstctl-reader"},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer backend.Close()
	ref, raw, err := backend.CreateCredential(context.Background(), GenerateRequest{Role: "reader", TTL: time.Hour, LeaseID: "lease-sts-test"})
	if err != nil {
		t.Fatal(err)
	}
	defer secret.Wipe(raw)
	var issued struct {
		AccessKeyID     string `json:"access_key_id"`
		SecretAccessKey string `json:"secret_access_key"`
		SessionToken    string `json:"session_token"`
		Expiration      string `json:"expiration"`
	}
	if err := json.Unmarshal(raw, &issued); err != nil {
		t.Fatal(err)
	}
	if issued.AccessKeyID != "ASIAEXAMPLE123456" || issued.SecretAccessKey == "" || issued.SessionToken == "" || issued.Expiration != expiration.Format(time.RFC3339) {
		t.Fatalf("incomplete STS credential: key=%q secret=%t session=%t expiry=%q", issued.AccessKeyID, issued.SecretAccessKey != "", issued.SessionToken != "", issued.Expiration)
	}
	if len(actions) != 1 || actions[0] != "AssumeRole" || strings.Contains(ref, issued.SecretAccessKey) || strings.Contains(ref, issued.SessionToken) {
		t.Fatalf("unsafe STS operation or reference: actions=%v", actions)
	}
	if err := backend.Revoke(context.Background(), ref); !errors.Is(err, ErrAWSSTSSessionActive) {
		t.Fatalf("early revoke = %v; AWS session must remain visibly pending", err)
	}
	backend.query.now = func() time.Time { return expiration.Add(time.Second) }
	if err := backend.Revoke(context.Background(), ref); err != nil {
		t.Fatalf("native expiry did not complete passive revocation: %v", err)
	}
	if len(actions) != 1 {
		t.Fatalf("passive revocation unexpectedly made AWS API calls: %v", actions)
	}
}

func TestAWSSTSRefusesUnboundedOrUnknownRoleWithoutRemoteCall(t *testing.T) {
	calls := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		calls++
		http.Error(w, "unexpected", http.StatusInternalServerError)
	}))
	defer server.Close()
	backend, err := NewAWSSTSBackend(AWSSTSConfig{
		Endpoint: server.URL, HTTPClient: server.Client(), Region: "us-east-1", AccessKeyID: "AKID",
		SecretAccessKey: []byte("admin-secret"),
		RoleARNs:        map[string]string{"reader": "arn:aws:iam::123456789012:role/trstctl-reader"},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer backend.Close()
	for _, req := range []GenerateRequest{
		{Role: "writer", TTL: time.Hour, LeaseID: "lease"},
		{Role: "reader", TTL: 14 * time.Minute, LeaseID: "lease"},
		{Role: "reader", TTL: 13 * time.Hour, LeaseID: "lease"},
		{Role: "reader", TTL: time.Hour},
	} {
		if _, raw, err := backend.CreateCredential(context.Background(), req); err == nil || len(raw) != 0 {
			t.Fatalf("unsafe STS request %+v returned credential or no error", req)
		}
	}
	if calls != 0 {
		t.Fatalf("invalid request reached AWS %d times", calls)
	}
	if _, err := NewAWSSTSBackend(AWSSTSConfig{Region: "us-east-1", AccessKeyID: "AKID", SecretAccessKey: []byte("admin-secret"), RoleARNs: map[string]string{"reader": "arn:aws:iam::123456789012:policy/ReadOnlyAccess"}}); err == nil {
		t.Fatal("managed-policy ARN was accepted as an assumable role")
	}
}
