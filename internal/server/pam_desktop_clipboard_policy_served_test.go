// SPDX-License-Identifier: BUSL-1.1
package server

import (
	"encoding/json"
	"encoding/pem"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/agent/accessgateway"
	"trstctl.com/trstctl/internal/agent/transport"
	"trstctl.com/trstctl/internal/attest"
	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/crypto/jose"
	"trstctl.com/trstctl/internal/crypto/mtls"
	"trstctl.com/trstctl/internal/crypto/secret"
	"trstctl.com/trstctl/internal/objectstore/s3test"
)

// TestServedDesktopClipboardPolicyReachesTheGatewayA269: a desktop session
// requested through a template whose clipboard policy is "both" is reviewed
// with that policy in its evidence, and the gateway's session intent carries
// it; a session without a template carries deny. The policy is read from the
// approval the session consumed, which the session now keeps.
func TestServedDesktopClipboardPolicyReachesTheGatewayA269(t *testing.T) {
	ctx := t.Context()
	key, err := crypto.GenerateLockedKey(crypto.ECDSAP256)
	if err != nil {
		t.Fatal(err)
	}
	defer key.Destroy()
	der, err := key.PKCS8()
	if err != nil {
		t.Fatal(err)
	}
	defer secret.Wipe(der)
	keyFile := filepath.Join(t.TempDir(), "admin.pem")
	if err = os.WriteFile(keyFile, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg := config.DynamicSecretProviderConfig{TenantID: servedTestTenant, ID: "pam-desktop", Type: "unix", Addr: "127.0.0.1:2222", AdminUser: "root",
		PrivateKeyRef: "file:" + keyFile, HostKeyFingerprint: "SHA256:" + strings.Repeat("A", 43), AllowedRoles: []string{"desktop/account"},
		RoleBindings: map[string]string{"desktop/account": "desktop-proof"}, AllowStaticRotation: true, MaxTTL: "1h"}
	raw, err := json.Marshal(map[string]any{"desktop": map[string]any{"address": "127.0.0.1:3389", "certificate_sha256": strings.Repeat("ab", 32), "width": 800, "height": 600, "tls_only": true}})
	if err != nil {
		t.Fatal(err)
	}
	if err = json.Unmarshal(raw, &cfg); err != nil {
		t.Fatal(err)
	}
	registry, err := dynamicSecretProvidersFromConfig(ctx, []config.DynamicSecretProviderConfig{cfg}, nil, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	audit, err := jose.GenerateRSASigningKey("a269-audit")
	if err != nil {
		t.Fatal(err)
	}
	objects := s3test.NewServer(t)
	h := newRoleHarnessWithDeps(t, []string{mtls.AgentRoleGateway}, []string{accessgateway.KindSessionDesktop}, func(d *Deps) {
		d.ArchiveObjectStore = objects.Open(t)
		d.AuditSigningKey = audit
		d.EnableSecretsAPI = true
		d.TenantDynamicSecretProviders = registry
		d.PAM = PAMConfig{Enabled: true, DefaultTTL: time.Minute, MaxTTL: 3 * time.Minute, Attestors: []attest.Attestor{servedPAMAttestor{}}}
	})
	if _, e := h.client.Heartbeat(ctx, &transport.HeartbeatRequest{AgentID: h.agent, Version: "a269", Status: "active",
		Executors: &transport.ExecutorReport{Version: "a269", Kinds: []transport.ExecutorKind{{Kind: accessgateway.KindSessionDesktop}}}}); e != nil {
		t.Fatal(e)
	}
	registrar := seedScopedTokenSubject(t, h.store, h.tenant, "a269-registrar", "access:read", "access:targets.write", "access:write", "secrets:read", "secrets:write")
	requester := seedScopedTokenSubject(t, h.store, h.tenant, "a269-requester", "access:read", "access:write")
	reviewerOne := seedScopedTokenSubject(t, h.store, h.tenant, "a269-reviewer-one", "access:approve")
	reviewerTwo := seedScopedTokenSubject(t, h.store, h.tenant, "a269-reviewer-two", "access:approve")
	if status, _ := secretsReqKey(t, h.servedHarness, http.MethodPost, "/api/v1/secrets/store", registrar, "a269-seed",
		map[string]any{"name": "desktop/account", "value": `{"Host":"127.0.0.1:2222","Username":"desktop-proof","password":"x"}`}); status != http.StatusCreated && status != http.StatusOK {
		t.Fatalf("seed the desktop secret: %d", status)
	}
	if status, body := secretsReqKey(t, h.servedHarness, http.MethodPost, "/api/v1/access/targets", registrar, "a269-register",
		map[string]any{"id": "desktop-lab", "target_type": "rdp", "provider_id": "pam-desktop", "allowed_roles": []string{"desktop/account"},
			"account_secret": "desktop/account", "gateway_agent_id": agentRowID(servedTestTenant, "role-agent"), "gateway_address": "127.0.0.1:1"}); status != http.StatusCreated {
		t.Fatalf("register the desktop target: %d %s", status, body)
	}
	status, body := secretsReqKey(t, h.servedHarness, http.MethodPost, "/api/v1/access/templates", registrar, "a269-template",
		map[string]any{"name": "desktop-clipboard", "reason": "desktop support", "required_approvals": 2, "max_ttl_seconds": 180, "desktop_clipboard": "both"})
	var template struct {
		ID               string `json:"id"`
		Revision         int    `json:"revision"`
		DesktopClipboard string `json:"desktop_clipboard"`
	}
	if status != http.StatusCreated || json.Unmarshal(body, &template) != nil || template.DesktopClipboard != "both" {
		t.Fatalf("create the clipboard template: %d %s", status, body)
	}
	if status, body := secretsReqKey(t, h.servedHarness, http.MethodPost, "/api/v1/access/templates", registrar, "a269-bad",
		map[string]any{"name": "desktop-bad", "reason": "x", "required_approvals": 2, "max_ttl_seconds": 180, "desktop_clipboard": "drives"}); status == http.StatusCreated {
		t.Fatalf("an unknown clipboard policy was saved: %s", body)
	}
	intentOf := func(key string, request map[string]any) string {
		t.Helper()
		request["reason"], request["method"] = "a269", "stub_pam"
		request["payload_base64"] = "Z2VudWluZQ=="
		session := servedPAMReviewedOpen(t, h.servedHarness, requester, reviewerOne, reviewerTwo, key, request)
		// The session keeps the approval it consumed.
		if rec, e := h.store.GetPAMSession(ctx, h.tenant, session.ID); e != nil || rec.ApprovalRequestID == "" {
			t.Fatalf("the session lost its approval: %v", e)
		}
		claims, e := h.client.ClaimJobs(ctx, &transport.ClaimJobsRequest{Kinds: []string{accessgateway.KindSessionDesktop}, Limit: 1, LeaseSeconds: 60})
		if e != nil || len(claims.Jobs) != 1 {
			t.Fatal("claim the desktop session job", e)
		}
		var intent accessgateway.SessionIntent
		if e = json.Unmarshal(claims.Jobs[0].Payload, &intent); e != nil || intent.SessionID != session.ID || intent.Desktop == nil {
			t.Fatalf("desktop intent: %v %+v", e, intent)
		}
		return intent.Desktop.Clipboard
	}
	if got := intentOf("a269-templated", map[string]any{"target_type": "rdp", "target_id": "desktop-lab", "role": "desktop/account",
		"ttl_seconds": 120, "template_id": template.ID}); got != "both" {
		t.Fatalf("a session through the clipboard template carries clipboard %q", got)
	}
	if got := intentOf("a269-plain", map[string]any{"target_type": "rdp", "target_id": "desktop-lab", "role": "desktop/account", "ttl_seconds": 120}); got != "deny" {
		t.Fatalf("a session without a template carries clipboard %q", got)
	}
}
