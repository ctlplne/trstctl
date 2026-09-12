// SPDX-License-Identifier: MPL-2.0

package server

import (
	"context"
	"encoding/json"
	"fmt"
	"sync"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"net/http"
	"testing"

	"trstctl.com/trstctl/internal/agent/transport"
	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/crypto/mtls"
)

// Exercise product-generated host work: API preview and authorization, actual
// dispatcher handoff, then an operator's revocation before the host may sign.
func TestServedRevokedIdentityStopsPendingHostIssuance(t *testing.T) {
	for _, heldBeforeRevocation := range []bool{false, true} {
		name := "unclaimed"
		if heldBeforeRevocation {
			name = "already held"
		}
		t.Run(name, func(t *testing.T) {
			h, token, identityID := servedHostRevocationFixture(t)
			ctx := t.Context()
			var job transport.ClaimedJob
			if heldBeforeRevocation {
				job = claimOneRenewal(t, ctx, h)
			}
			servedHostLifecycleTransition(t, h, token, identityID, "revoked", "revoke-host", http.StatusOK)
			current, err := h.store.GetIdentity(ctx, h.tenant, identityID)
			if err != nil || current.Status != "revoked" {
				t.Fatalf("revocation was not accepted: identity=%+v err=%v", current, err)
			}
			if !heldBeforeRevocation {
				claimed, err := h.client.ClaimJobs(ctx, &transport.ClaimJobsRequest{Kinds: []string{agentJobKindEndpointRenew}, Limit: 5, LeaseSeconds: 120})
				if err != nil || len(claimed.Jobs) != 0 {
					t.Fatalf("revoked identity handed out host issuance: jobs=%d err=%v", len(claimed.Jobs), err)
				}
				return
			}
			key, err := crypto.GenerateHostSubjectKey("mail.revocation.test", []string{"mail.revocation.test"})
			if err != nil {
				t.Fatal(err)
			}
			defer key.Destroy()
			signed, err := h.client.SignJobCSR(ctx, &transport.SignJobCSRRequest{JobID: job.JobID, Attempt: job.Attempt, CSRDER: key.CSRDER})
			if status.Code(err) != codes.PermissionDenied {
				t.Fatalf("revoked identity signing result: response=%v err=%v; want PermissionDenied", signed != nil, err)
			}
		})
	}
}

func servedHostRevocationFixture(t *testing.T) (*roleHarness, string, string) {
	t.Helper()
	h := newRoleHarness(t, []string{mtls.AgentRoleHost}, agentJobKindEndpointRenew)
	ctx := t.Context()
	token := seedScopedToken(t, h.store, h.tenant, "owners:write", "connectors:write", "certs:issue", "certs:revoke", "identities:write")
	post := func(path string, input any, expected int) map[string]json.RawMessage {
		t.Helper()
		code, body := secretsReq(t, h.servedHarness, http.MethodPost, path, token, input)
		if code != expected {
			t.Fatalf("POST %s: status=%d body=%s", path, code, body)
		}
		var result map[string]json.RawMessage
		if err := json.Unmarshal(body, &result); err != nil {
			t.Fatal(err)
		}
		return result
	}
	str := func(raw json.RawMessage) string {
		t.Helper()
		var result string
		if err := json.Unmarshal(raw, &result); err != nil {
			t.Fatal(err)
		}
		return result
	}
	owner := str(post("/api/v1/owners", map[string]any{"kind": "workload", "name": "Host revocation QA"}, http.StatusCreated)["id"])
	target := str(post("/api/v1/connectors/targets", map[string]any{
		"name": "revocation-mail", "connector": "postfix", "enabled": true,
		"config": map[string]any{"executor": "agent", "required_agent_role": "host",
			"postfix_cert_path": "/mail/tls/smtp.crt", "postfix_key_path": "/mail/tls/smtp.key",
			"dovecot_cert_path": "/mail/tls/imap.crt", "dovecot_key_path": "/mail/tls/imap.key",
			"verify_address": "127.0.0.1:1465", "verify_server_name": "mail.revocation.test"},
	}, http.StatusCreated)["id"])
	request := map[string]any{"owner_id": owner, "identity_name": "mail.revocation.test", "target_id": target,
		"issuer": map[string]any{"source": "platform", "id": "trstctl-issuing-ca"}, "reason": "QA host revocation fence"}
	preview := post("/api/v1/lifecycle/endpoint-bindings/preview", request, http.StatusOK)
	request["preview_fingerprint"] = str(preview["request_fingerprint"])
	binding := post("/api/v1/lifecycle/endpoint-bindings", request, http.StatusCreated)
	var identity struct{ ID string }
	if err := json.Unmarshal(binding["identity"], &identity); err != nil {
		t.Fatal(err)
	}
	if dispatched, err := h.srv.DispatchIssuanceOnce(ctx); err != nil || !dispatched {
		t.Fatalf("dispatch authorized first issuance: dispatched=%v err=%v", dispatched, err)
	}
	return h, token, identity.ID
}

func servedHostLifecycleTransition(t *testing.T, h *roleHarness, token, identityID, to, key string, expected int) {
	t.Helper()
	code, body := secretsReqKey(t, h.servedHarness, http.MethodPost, "/api/v1/identities/"+identityID+"/transitions", token, key, map[string]any{"to": to, "reason": "cessationOfOperation"})
	if code != expected {
		t.Fatalf("transition %s: HTTP %d, want %d: %s", to, code, expected, body)
	}
}

// Pause at the real signer seam after the identity and claim checks, then race
// the public revocation command. A mere state precheck cannot pass this test.
func TestServedHostSignatureAndRevocationAreOrdered(t *testing.T) {
	h, token, identityID := servedHostRevocationFixture(t)
	ctx := t.Context()
	job := claimOneRenewal(t, ctx, h)
	key, err := crypto.GenerateHostSubjectKey("mail.revocation.test", []string{"mail.revocation.test"})
	if err != nil {
		t.Fatal(err)
	}
	defer key.Destroy()
	d := h.srv.obHandler.(*issuanceDispatcher)
	delegate := d.issue
	entered, release := make(chan struct{}), make(chan struct{})
	var once sync.Once
	unblock := func() { once.Do(func() { close(release) }) }
	defer unblock()
	d.issue = func(ctx context.Context, csr []byte, ttl time.Duration, profile crypto.LeafProfile) (crypto.IssuedLeaf, error) {
		close(entered)
		select {
		case <-release:
			return delegate(ctx, csr, ttl, profile)
		case <-ctx.Done():
			return crypto.IssuedLeaf{}, ctx.Err()
		}
	}
	req := &transport.SignJobCSRRequest{JobID: job.JobID, Attempt: job.Attempt, CSRDER: key.CSRDER}
	signed := make(chan error, 1)
	go func() {
		response, err := h.client.SignJobCSR(ctx, req)
		if err == nil && (response == nil || len(response.CertificatePEM) == 0) {
			err = fmt.Errorf("signing returned no certificate")
		}
		signed <- err
	}()
	select {
	case <-entered:
	case err := <-signed:
		t.Fatalf("signing ended before reaching real signer: %v", err)
	case <-time.After(10 * time.Second):
		t.Fatal("signer did not start")
	}
	servedHostLifecycleTransition(t, h, token, identityID, "revoked", "ordered-revocation", http.StatusConflict)
	current, err := h.store.GetIdentity(ctx, h.tenant, identityID)
	if err != nil || current.Status == "revoked" {
		t.Fatalf("busy revocation changed identity: status=%s err=%v", current.Status, err)
	}
	unblock()
	select {
	case err := <-signed:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("signing did not finish")
	}
	// Reusing the exact revocation request must succeed after the conflict. A
	// cached successful CSR response must still be refused after that acceptance.
	servedHostLifecycleTransition(t, h, token, identityID, "revoked", "ordered-revocation", http.StatusOK)
	if _, err := h.client.SignJobCSR(ctx, req); status.Code(err) != codes.PermissionDenied {
		t.Fatalf("cached CSR after revocation: %v", err)
	}
	servedHostLifecycleTransition(t, h, token, identityID, "retired", "ordered-retirement", http.StatusOK)
	if _, err := h.client.SignJobCSR(ctx, req); status.Code(err) != codes.PermissionDenied {
		t.Fatalf("cached CSR after retirement: %v", err)
	}
}
