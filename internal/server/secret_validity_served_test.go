// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/authz"
	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/secretscan/validity"
	"trstctl.com/trstctl/internal/store"
)

// P14: a secret posted in a Slack channel is found and linked to its owner,
// and an AWS key pair found beside it is checked where it was found — a live
// key marked valid, a deactivated one invalid — with only a SigV4 signature
// reaching the provider, never the secret.
func TestServedSlackLeakIsCheckedAndLinkedToItsOwnerP14(t *testing.T) {
	const (
		// Fabricated key IDs in AWS's shape, built from two literals so secret
		// scanners do not take the fixtures for credentials.
		liveKey    = "AKIA" + "Q7TESTACTIVEKEY2"
		liveSecret = "p14LiveSecretAccessKeyValue000000000abc/"
		deadKey    = "AKIA" + "Q7TESTREVOKEDK3Z"
		deadSecret = "p14DeadSecretAccessKeyValue000000000xyz+"
	)
	var mu sync.Mutex
	var seen []string
	sts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		mu.Lock()
		seen = append(seen, fmt.Sprint(r.Header)+string(body))
		mu.Unlock()
		auth := r.Header.Get("Authorization")
		switch {
		case strings.HasPrefix(auth, "AWS4-HMAC-SHA256 Credential="+liveKey+"/"):
			_, _ = io.WriteString(w, `<GetCallerIdentityResponse><GetCallerIdentityResult><Account>111122223333</Account><Arn>arn:aws:iam::111122223333:user/ci</Arn></GetCallerIdentityResult></GetCallerIdentityResponse>`)
		default:
			w.WriteHeader(http.StatusForbidden)
			_, _ = io.WriteString(w, `<ErrorResponse><Error><Code>InvalidClientTokenId</Code></Error></ErrorResponse>`)
		}
	}))
	t.Cleanup(sts.Close)
	slack := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer p14-slack-token" {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		switch r.URL.Path {
		case "/api/conversations.history":
			messages := []map[string]string{
				{"ts": "1762246800.000100", "user": "U0P14OWNER", "text": "use aws_access_key_id=" + liveKey + " aws_secret_access_key=" + liveSecret},
				{"ts": "1762250400.000200", "user": "U0P14OTHER", "text": "old one: AWS_ACCESS_KEY_ID=" + deadKey + " AWS_SECRET_ACCESS_KEY=" + deadSecret},
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"ok": true, "messages": messages, "has_more": false})
		case "/api/users.info":
			emails := map[string]string{"U0P14OWNER": "p14-owner@example.test", "U0P14OTHER": "nobody@example.test"}
			id := r.URL.Query().Get("user")
			_ = json.NewEncoder(w).Encode(map[string]any{"ok": true, "user": map[string]any{"id": id, "profile": map[string]string{"email": emails[id]}}})
		default:
			http.Error(w, "unexpected", http.StatusNotFound)
		}
	}))
	t.Cleanup(slack.Close)
	t.Setenv("TRSTCTL_P14_SLACK", "p14-slack-token")
	checker := validity.New(validity.Config{Endpoints: map[string]string{validity.ProviderAWS: sts.URL},
		Allowlist: []string{sts.URL}, Rates: map[string]float64{validity.ProviderAWS: 50}, Client: sts.Client()})
	h := newOperatingServedHarness(t, config.Protocols{}, withSecretsEnabled(t, nil), allowOutboundEnvCredentialRefs("env:TRSTCTL_P14_SLACK"),
		func(d *Deps) {
			d.SecretScanner = &a174MarkerScanner{marker: "AKIA", rule: "aws-access-token"}
			d.SecretValidity = checker
		})
	owner, err := h.store.CreateOwner(context.Background(), store.Owner{TenantID: h.tenant, Kind: store.OwnerWorkload, Name: "p14 platform", Email: "p14-owner@example.test"})
	if err != nil {
		t.Fatal(err)
	}
	tok := seedScopedToken(t, h.store, h.tenant, "secrets:read", "secrets:write", "discovery:read", string(authz.PrivateEgress))
	status, body := secretsReqKey(t, h, http.MethodPost, "/api/v1/secrets/scans/third-party/slack/ingest", tok, "p14-slack",
		map[string]any{"source": "ops-slack-p14", "event": "p14", "collect": map[string]any{"base_url": slack.URL, "token_ref": "env:TRSTCTL_P14_SLACK", // #nosec G101 -- an env: reference to a test-only value (CWE-798)
			"channels": []string{"C0OPS"}, "allow_private_endpoint": true, "private_egress_cidrs": []string{"127.0.0.1/32"}}})
	var receipt struct {
		RunID string `json:"run_id"`
	}
	if status != http.StatusAccepted || json.Unmarshal(body, &receipt) != nil || receipt.RunID == "" {
		t.Fatalf("ingest = %d %s", status, body)
	}
	deadline := time.Now().Add(30 * time.Second)
	for {
		h.srv.dispatchOnce(context.Background())
		var runStatus string
		_ = h.store.SystemPool().QueryRow(t.Context(), `SELECT status FROM discovery_runs WHERE tenant_id = $1 AND id = $2`, h.tenant, receipt.RunID).Scan(&runStatus)
		if runStatus == "succeeded" || runStatus == "failed" {
			if runStatus != "succeeded" {
				t.Fatalf("the collection run %s", runStatus)
			}
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("the collection did not finish")
		}
		time.Sleep(100 * time.Millisecond)
	}
	var metas []string
	rows, err := h.store.SystemPool().Query(t.Context(), `SELECT metadata::text FROM discovery_findings WHERE tenant_id = $1 AND run_id = $2`, h.tenant, receipt.RunID)
	if err != nil {
		t.Fatal(err)
	}
	for rows.Next() {
		var m string
		if err := rows.Scan(&m); err != nil {
			t.Fatal(err)
		}
		metas = append(metas, m)
	}
	rows.Close()
	if len(metas) != 2 {
		t.Fatalf("findings = %d %v", len(metas), metas)
	}
	type meta struct {
		OwnerID  string `json:"owner_id"`
		Validity struct {
			State  string `json:"state"`
			Detail string `json:"detail"`
		} `json:"validity"`
		Object map[string]string `json:"provider_object"`
	}
	byUser := map[string]meta{}
	for _, raw := range metas {
		if strings.Contains(raw, liveSecret) || strings.Contains(raw, deadSecret) {
			t.Fatal("a finding carries the secret")
		}
		var m meta
		if err := json.Unmarshal([]byte(raw), &m); err != nil {
			t.Fatal(err)
		}
		byUser[m.Object["user"]] = m
	}
	if got := byUser["U0P14OWNER"]; got.Validity.State != validity.StateValid || got.OwnerID != owner.ID ||
		got.Object["user_email"] != "p14-owner@example.test" || !strings.Contains(got.Validity.Detail, "111122223333") {
		t.Fatalf("the live key's finding = %+v", got)
	}
	if got := byUser["U0P14OTHER"]; got.Validity.State != validity.StateInvalid || got.OwnerID != "" {
		t.Fatalf("the deactivated key's finding = %+v", got)
	}
	mu.Lock()
	defer mu.Unlock()
	if len(seen) != 2 {
		t.Fatalf("STS saw %d checks, want 2", len(seen))
	}
	for _, request := range seen {
		if strings.Contains(request, liveSecret) || strings.Contains(request, deadSecret) {
			t.Fatal("a secret left the scanning host")
		}
	}
}
