// SPDX-License-Identifier: BUSL-1.1
package server

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"trstctl.com/trstctl/internal/agent/transport"
	"trstctl.com/trstctl/internal/attest"
	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/crypto/mtls"
	"trstctl.com/trstctl/internal/crypto/secret"
	"trstctl.com/trstctl/internal/crypto/winaccounts"
	"trstctl.com/trstctl/internal/dynsecret"
	"trstctl.com/trstctl/internal/hostaccounts"
	"trstctl.com/trstctl/internal/store"
)

// TestServedWindowsLocalCheckoutRotatesOnHostA268: a Windows local
// administrator account vaulted as a windows_local target is checked out
// through A261 — reviewed, revealed once — and never opened as a session.
// Checking it in queues the native in-place rotation; while the host is
// offline the generation waits, and when the host returns it redeems the
// revealed password as the predecessor and a distinct successor, and its
// signed proof publishes the new version. A check-out not checked in is
// rotated at its deadline, as the next host generation. The signed native
// report is a fixture; real Windows authentication is the windows-latest job.
func TestServedWindowsLocalCheckoutRotatesOnHostA268(t *testing.T) {
	ctx := t.Context()
	hostID := agentRowID(servedTestTenant, "role-agent")
	cfg := config.DynamicSecretProviderConfig{TenantID: servedTestTenant, ID: "host-sam", Type: "windows", WindowsHostAgentID: hostID,
		AllowedRoles: []string{"hosts/admin"}, RoleBindings: map[string]string{"hosts/admin": "S-1-5-21-1-2-3-1001"}, AllowStaticRotation: true}
	p := newConfiguredDynamicProvider(cfg, map[string]bool{"hosts/admin": true}, time.Hour, integrationCredentialResolver{}, nil)
	h := newRoleHarnessWithDeps(t, []string{mtls.AgentRoleHost}, []string{hostaccounts.InventoryDestination, hostaccounts.RotationDestination},
		withSecretsEnabled(t, nil), func(d *Deps) {
			d.PAM = PAMConfig{Enabled: true, DefaultTTL: time.Minute, MaxTTL: 3 * time.Minute, Attestors: []attest.Attestor{servedPAMAttestor{}}}
			d.DynamicSecretProviders = []dynsecret.Provider{p}
		})
	if _, e := h.client.Heartbeat(ctx, &transport.HeartbeatRequest{AgentID: h.agent, Version: "test-1.0", Status: "active"}); e != nil {
		t.Fatal(e)
	}
	custodian := seedScopedTokenSubject(t, h.store, h.tenant, "a268-co-custodian", "access:read", "access:targets.write", "secrets:read", "secrets:write")
	requester := seedScopedTokenSubject(t, h.store, h.tenant, "a268-co-requester", "access:read", "access:sessions.open")
	reviewers := []string{
		seedScopedTokenSubject(t, h.store, h.tenant, "a268-co-reviewer-1", "access:read", "access:approve"),
		seedScopedTokenSubject(t, h.store, h.tenant, "a268-co-reviewer-2", "access:read", "access:approve"),
	}

	// The enrolled host's inventory names the account the provider binds.
	root := "/api/v1/access/discovery/windows-hosts/" + hostID + "/local-administrators/runs"
	if status, _ := secretsReqKey(t, h.servedHarness, http.MethodPost, root, custodian, "a268-co-inventory", nil); status != http.StatusAccepted {
		t.Fatal("inventory queue", status)
	}
	claims, e := h.client.ClaimJobs(ctx, &transport.ClaimJobsRequest{Kinds: []string{hostaccounts.InventoryDestination}, Limit: 1, LeaseSeconds: 120})
	if e != nil || len(claims.Jobs) != 1 {
		t.Fatal("inventory claim", e)
	}
	read, e := hostaccounts.DecodeInventoryIntent(claims.Jobs[0].Payload)
	if e != nil {
		t.Fatal(e)
	}
	native := winaccounts.RotationBinding{Machine: winaccounts.Machine{Name: "OWNED-HOST", SID: "S-1-5-21-1-2-3", Role: 3},
		Account: winaccounts.Account{Name: "Owned Admin", SID: cfg.RoleBindings["hosts/admin"], Enabled: true, PasswordRequired: true}}
	inventory, e := json.Marshal(hostaccounts.InventoryReport{RunID: read.RunID, BindingDigest: read.BindingDigest, ObservedAt: time.Now().UTC(),
		Status: "complete", Inventory: &winaccounts.Inventory{Machine: native.Machine, Accounts: []winaccounts.Account{native.Account}}})
	if e != nil {
		t.Fatal(e)
	}
	if accepted, e := h.client.ReportJobResult(ctx, h.report(t, claims.Jobs[0].JobID, claims.Jobs[0].Attempt, transport.JobOutcomeExecuted,
		string(inventory), crypto.SHA256Hex(inventory))); e != nil || !accepted.Accepted {
		t.Fatal("inventory report", e)
	}
	seeded := `{"host":"OWNED-HOST","username":"Owned Admin","password":"owned-fixture-password"}`
	if status, _ := secretsReqKey(t, h.servedHarness, http.MethodPost, "/api/v1/secrets/store", custodian, "a268-co-seed",
		map[string]any{"name": "hosts/admin", "value": seeded}); status != http.StatusCreated && status != http.StatusOK {
		t.Fatal("seed the account secret", status)
	}

	// A windows_local target vaults only an account its native provider binds.
	register := func(key string, target map[string]any) (int, []byte) {
		t.Helper()
		return secretsReqKey(t, h.servedHarness, http.MethodPost, "/api/v1/access/targets", custodian, key, target)
	}
	if status, body := register("a268-co-unbound", map[string]any{"id": "other-admin", "target_type": "windows_local", "provider_id": "host-sam",
		"account_secret": "hosts/other"}); status == http.StatusCreated {
		t.Fatalf("a windows_local target naming an unbound role was registered: %s", body)
	}
	if status, body := register("a268-co-gateway", map[string]any{"id": "gateway-admin", "target_type": "windows_local", "provider_id": "host-sam",
		"account_secret": "hosts/admin", "gateway_address": "127.0.0.1:1"}); status == http.StatusCreated {
		t.Fatalf("a windows_local target with gateway fields was registered: %s", body)
	}
	status, body := register("a268-co-register", map[string]any{"id": "owned-host-admin", "target_type": "windows_local", "provider_id": "host-sam",
		"account_secret": "hosts/admin"})
	if status != http.StatusCreated || !strings.Contains(string(body), `"allowed_roles":["hosts/admin"]`) {
		t.Fatalf("register the windows_local target = %d %s", status, body)
	}

	// It has no sessions.
	status, body = secretsReqKey(t, h.servedHarness, http.MethodPost, "/api/v1/access/session-requests", requester, "a268-co-session",
		map[string]any{"request_id": uuid.NewString(), "target_type": "windows_local", "target_id": "owned-host-admin", "role": "hosts/admin",
			"reason": "direct session", "method": "stub_pam", "payload_base64": "Z2VudWluZQ==", "ttl_seconds": 120})
	if status != http.StatusUnprocessableEntity || !strings.Contains(string(body), "no sessions") {
		t.Fatalf("a windows_local session request = %d %s", status, body)
	}

	type review struct {
		RequestID         string `json:"request_id"`
		ApprovalRequestID string `json:"approval_request_id"`
		IntentDigest      string `json:"intent_digest"`
		RequiredApprovals int    `json:"required_approvals"`
	}
	type checkout struct {
		Status            string `json:"status"`
		SecretVersion     int    `json:"secret_version"`
		RotationCommandID string `json:"rotation_command_id"`
	}
	checkOut := func(key string, ttl int) (review, string, checkout) {
		t.Helper()
		status, raw := secretsReqKey(t, h.servedHarness, http.MethodPost, "/api/v1/access/checkouts", requester, key,
			map[string]any{"request_id": uuid.NewString(), "target_type": "windows_local", "target_id": "owned-host-admin",
				"reason": "INC-5120 recover the host's local console", "ttl_seconds": ttl})
		var r review
		if status != http.StatusAccepted || json.Unmarshal(raw, &r) != nil || r.RequiredApprovals < 1 || r.RequiredApprovals > len(reviewers) {
			t.Fatalf("request a windows_local check-out = %d %s", status, raw)
		}
		for i, reviewer := range reviewers[:r.RequiredApprovals] {
			if status, body := secretsReqKey(t, h.servedHarness, http.MethodPost, "/api/v1/approval-requests/"+r.ApprovalRequestID+"/approvals",
				reviewer, key+"-approve-"+strconv.Itoa(i), map[string]any{"intent_digest": r.IntentDigest}); status != http.StatusOK {
				t.Fatalf("review %d = %d %s", i+1, status, body)
			}
		}
		status, raw = secretsReqKey(t, h.servedHarness, http.MethodPost, "/api/v1/access/checkouts/"+r.RequestID+"/reveal", requester, key+"-reveal",
			map[string]any{"approval_request_id": r.ApprovalRequestID, "intent_digest": r.IntentDigest})
		var got struct {
			Checkout   checkout `json:"checkout"`
			Credential string   `json:"credential"`
		}
		if status != http.StatusOK || json.Unmarshal(raw, &got) != nil || got.Checkout.Status != "revealed" {
			t.Fatalf("reveal = %d %s", status, raw)
		}
		return r, got.Credential, got.Checkout
	}
	drain := func() {
		t.Helper()
		c, cancel := context.WithTimeout(ctx, 15*time.Second)
		defer cancel()
		if e := h.srv.Drain(c); e != nil {
			t.Fatal(e)
		}
	}
	// hostReturns claims the waiting native generation, checks its exact
	// predecessor, and reports the fixture's signed success.
	hostReturns := func(commandID string, predecessor []byte) []byte {
		t.Helper()
		claims, e := h.client.ClaimJobs(ctx, &transport.ClaimJobsRequest{Kinds: []string{hostaccounts.RotationDestination}, Limit: 1, LeaseSeconds: 120})
		if e != nil || len(claims.Jobs) != 1 {
			t.Fatal("the returning host found no waiting rotation", e)
		}
		job := claims.Jobs[0]
		intent, e := hostaccounts.DecodeRotationIntent(job.Payload)
		if e != nil || intent.RotationID != commandID || intent.Native != native {
			t.Fatal("the host rotation is not the check-out's exact generation", e)
		}
		creds, e := h.client.RedeemJobCredential(ctx, &transport.RedeemJobCredentialRequest{JobID: job.JobID, Attempt: job.Attempt})
		if e != nil || len(creds.Items) != 2 {
			t.Fatal("generation broker", e)
		}
		if !bytes.Equal(creds.Items[0].Value, predecessor) || bytes.Equal(creds.Items[0].Value, creds.Items[1].Value) || len(creds.Items[1].Value) < 24 {
			t.Fatal("the host was not told to retire the revealed password for a distinct successor")
		}
		successor := append([]byte(nil), creds.Items[1].Value...)
		for _, item := range creds.Items {
			secret.Wipe(item.Value)
		}
		at := time.Now().UTC()
		proof := winaccounts.RotationProof{Binding: native, GenerationID: commandID, ObservedAt: at, NewAuthenticated: true, OldRefused: true}
		raw, e := json.Marshal(hostaccounts.RotationReport{RotationID: commandID, BindingDigest: intent.BindingDigest, ObservedAt: at, Status: "succeeded", Proof: &proof})
		if e != nil {
			t.Fatal(e)
		}
		if accepted, e := h.client.ReportJobResult(ctx, h.report(t, job.JobID, job.Attempt, transport.JobOutcomeExecuted, string(raw), crypto.SHA256Hex(raw))); e != nil || !accepted.Accepted {
			t.Fatal("signed native result", e)
		}
		drain()
		done, e := h.store.GetSecretStaticRotationCommand(ctx, h.tenant, commandID)
		if e != nil || done.Phase != store.SecretStaticRotationCompleted {
			t.Fatal("the host's proof did not finish the rotation", done.Phase, e)
		}
		return successor
	}

	// Checked out, revealed once, checked in: the rotation waits for the
	// offline host, then retires the revealed password when it returns.
	r, credential, c := checkOut("a268-co-first", 120)
	if credential != seeded || c.SecretVersion != 1 {
		t.Fatalf("the reveal showed version %d, not the vaulted account's current credential", c.SecretVersion)
	}
	if status, body := secretsReqKey(t, h.servedHarness, http.MethodPost, "/api/v1/access/checkouts/"+r.RequestID+"/reveal", requester, "a268-co-again",
		map[string]any{"approval_request_id": r.ApprovalRequestID, "intent_digest": r.IntentDigest}); status != http.StatusConflict {
		t.Fatalf("a second reveal = %d %s", status, body)
	}
	status, body = secretsReqKey(t, h.servedHarness, http.MethodPost, "/api/v1/access/checkouts/"+r.RequestID+"/checkin", requester, "a268-co-checkin", nil)
	if status != http.StatusOK || json.Unmarshal(body, &c) != nil || c.Status != "checked_in" || c.RotationCommandID == "" {
		t.Fatalf("check in = %d %s", status, body)
	}
	drain()
	waiting, e := h.store.GetSecretStaticRotationCommand(ctx, h.tenant, c.RotationCommandID)
	if e != nil || waiting.Phase != store.SecretStaticRotationPrepared {
		t.Fatal("the check-in's rotation is not waiting for the host", waiting.Phase, e)
	}
	if current, e := h.store.GetSecret(ctx, h.tenant, "hosts/admin"); e != nil || current.Version != 1 {
		t.Fatal("the vault moved before the host proved the rotation", e)
	}
	firstCommand := c.RotationCommandID
	first := hostReturns(firstCommand, []byte("owned-fixture-password"))
	defer secret.Wipe(first)
	rotated, e := h.store.GetSecret(ctx, h.tenant, "hosts/admin")
	if e != nil || rotated.Version != 2 {
		t.Fatal("check-in did not publish the host's new password", e)
	}

	// Not checked in: the deadline rotates it, as the next host generation.
	_, credential, c = checkOut("a268-co-second", 60)
	if c.SecretVersion != 2 || !strings.Contains(credential, `"username":"Owned Admin"`) || strings.Contains(credential, "owned-fixture-password") {
		t.Fatalf("the second reveal showed version %d", c.SecretVersion)
	}
	h.srv.pam.expireCheckouts(context.Background(), time.Now().Add(2*time.Minute))
	expired, e := h.store.ListPAMCheckouts(ctx, h.tenant, 10)
	if e != nil || len(expired) != 2 || expired[0].Status != "expired" || expired[0].RotationCommandID == "" {
		t.Fatal("the deadline did not end the check-out with a rotation", e)
	}
	drain()
	next, e := h.store.GetWindowsLocalRotation(ctx, h.tenant, expired[0].RotationCommandID)
	if e != nil || next.Intent.PredecessorGenerationID != firstCommand {
		t.Fatal("the deadline's rotation is not the next host generation", e)
	}
	second := hostReturns(expired[0].RotationCommandID, first)
	defer secret.Wipe(second)
	if bytes.Equal(first, second) {
		t.Fatal("consecutive generations reused a password")
	}
}
