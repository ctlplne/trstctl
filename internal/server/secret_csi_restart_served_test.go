// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"bytes"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/container-storage-interface/spec/lib/go/csi"

	"trstctl.com/trstctl/internal/agent/csisecrets"
	apiauth "trstctl.com/trstctl/internal/auth"
	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/crypto"
)

// A238-L9 Done-when (served): a restarted node plugin ends the session its
// volume used before the restart. The plugin keeps the session's ID, never its
// token, in the volume's value-free state; after a restart its next login for
// the volume names that session in replaces, and the control plane ends it
// once the pod's token proves the same principal, recording the principal as
// the one that ended it. A login naming another principal's session leaves it
// alone.
func TestServedCSIPluginRestartEndsItsEarlierSessionA238L9(t *testing.T) {
	signer, err := crypto.GenerateLockedKey(crypto.ECDSAP256)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(signer.Destroy)
	jwk, err := crypto.PublicJWK(signer.Public(), "pod-key")
	if err != nil {
		t.Fatal(err)
	}
	jwks, err := json.Marshal(crypto.JWKS{Keys: []crypto.JWK{jwk}})
	if err != nil {
		t.Fatal(err)
	}
	methods, err := machineAuthMethodsFromConfig([]config.MachineAuthMethod{{
		// The generic JWT method, as A238-L7's test uses, with tokens of
		// their own (jti a238l9-*) on the shared served tenant.
		Name: "jwt", TenantID: servedTestTenant, Issuer: "https://pods.example.test", Audience: "trstctl",
		JWKSJSON: string(jwks), Scopes: []string{"secrets:read"},
	}})
	if err != nil {
		t.Fatal(err)
	}
	h := newServedHarness(t, config.Protocols{}, withSecretsEnabled(t, nil), func(d *Deps) {
		d.MachineAuthMethods = withMachineCredentialReplayGuard(methods, d.Store)
	})
	registerServedTenant(t, h, "A238-L9 plugin restart tenant")
	admin := seedScopedTokenSubject(t, h.store, h.tenant, "a238l9-admin", "secrets:read", "secrets:write")
	if status, raw := secretsReqKey(t, h, http.MethodPost, "/api/v1/secrets/store", admin, "a238l9-seed",
		map[string]any{"name": "a238l9/prod/db-password", "value": "pw-a238l9"}); status != http.StatusCreated {
		t.Fatalf("seed: HTTP %d %s", status, raw)
	}
	const api = "system:serviceaccount:payments:api"
	podJWT := func(subject, jti string) string {
		t.Helper()
		jwt, err := crypto.SignJWT(signer, "pod-key", map[string]any{
			"iss": "https://pods.example.test", "aud": "trstctl", "sub": subject,
			"exp": time.Now().Add(10 * time.Minute).Unix(), "iat": time.Now().Unix(), "jti": jti,
		})
		if err != nil {
			t.Fatal(err)
		}
		return jwt
	}
	type sessionView struct {
		ID        string `json:"id"`
		Principal string `json:"principal"`
		Status    string `json:"status"`
		RevokedBy string `json:"revoked_by"`
	}
	sessions := func() map[string]sessionView {
		t.Helper()
		status, raw := secretsReqKey(t, h, http.MethodGet, "/api/v1/secrets/sessions?limit=200", admin, "", nil)
		var out struct {
			Items []sessionView `json:"items"`
		}
		if status != http.StatusOK || json.Unmarshal(raw, &out) != nil {
			t.Fatalf("list sessions: HTTP %d %s", status, raw)
		}
		views := map[string]sessionView{}
		for _, s := range out.Items {
			views[s.ID] = s
		}
		return views
	}
	newSession := func(before map[string]sessionView) string {
		t.Helper()
		for id, s := range sessions() {
			if _, seen := before[id]; !seen && s.Status == "active" && s.Principal == api {
				return id
			}
		}
		t.Fatal("the volume's login left no new active session")
		return ""
	}

	stateDir := t.TempDir()
	mounter := &a238l7Mounter{mounted: map[string]bool{}}
	start := func() (*csisecrets.Driver, *bytes.Buffer) {
		t.Helper()
		var logs bytes.Buffer
		d, err := csisecrets.NewDriver(csisecrets.Config{Server: h.ts.URL, Tenant: h.tenant, LoginMethod: "jwt", StateDir: stateDir},
			h.ts.Client(), mounter, slog.New(slog.NewTextHandler(&logs, nil)), "node-a238l9", "test")
		if err != nil {
			t.Fatal(err)
		}
		return d, &logs
	}
	target := filepath.Join(t.TempDir(), "pods", "uid-a238l9", "volumes", "kubernetes.io~csi", "secrets", "mount")
	publish := func(d *csisecrets.Driver, logs *bytes.Buffer, jti string) {
		t.Helper()
		tokens, _ := json.Marshal(map[string]any{"trstctl": map[string]string{"token": podJWT(api, jti)}})
		if _, err := d.NodePublishVolume(t.Context(), &csi.NodePublishVolumeRequest{
			VolumeId: "csi-a238l9", TargetPath: target,
			VolumeContext: map[string]string{
				"csi.storage.k8s.io/ephemeral": "true", "csi.storage.k8s.io/pod.name": "api-0",
				"csi.storage.k8s.io/pod.namespace": "payments", "csi.storage.k8s.io/serviceAccount.name": "api",
				"secrets": "password=a238l9/prod/db-password",
			},
			Secrets:          map[string]string{"csi.storage.k8s.io/serviceAccount.tokens": string(tokens)},
			VolumeCapability: &csi.VolumeCapability{AccessType: &csi.VolumeCapability_Mount{Mount: &csi.VolumeCapability_MountVolume{}}},
		}); err != nil {
			t.Fatalf("publish the volume: %v\n%s", err, logs.String())
		}
	}
	state := func() string {
		t.Helper()
		entries, err := os.ReadDir(stateDir)
		if err != nil || len(entries) != 1 {
			t.Fatalf("the plugin's state: %v %v", entries, err)
		}
		raw, err := os.ReadFile(filepath.Join(stateDir, entries[0].Name())) // #nosec G304 -- the test's own temp file (CWE-22)
		if err != nil {
			t.Fatal(err)
		}
		return string(raw)
	}

	before := sessions()
	first, firstLogs := start()
	publish(first, firstLogs, "a238l9-pod-1")
	if raw, err := os.ReadFile(filepath.Join(target, "password")); err != nil || string(raw) != "pw-a238l9" { // #nosec G304 -- the test's own temp file (CWE-22)
		t.Fatalf("the volume's file %q, %v", raw, err)
	}
	earlier := newSession(before)
	if got := state(); !strings.Contains(got, `"session_id":"`+earlier+`"`) || strings.Contains(got, apiauth.TokenPrefix) {
		t.Fatalf("the volume's state %s: want the session's ID and no token", got)
	}

	// The plugin restarts; the kubelet republishes with its current token.
	before = sessions()
	restarted, restartedLogs := start()
	publish(restarted, restartedLogs, "a238l9-pod-2")
	now := sessions()
	if got := now[earlier]; got.Status != "revoked" || got.RevokedBy != api {
		t.Fatalf("the session from before the restart reads %+v, want revoked by %s\n%s", got, api, restartedLogs.String())
	}
	current := newSession(before)
	if !strings.Contains(state(), `"session_id":"`+current+`"`) || !strings.Contains(restartedLogs.String(), "ended the volume's session from before the plugin restarted") {
		t.Fatalf("after the restart: state %s\n%s", state(), restartedLogs.String())
	}

	// Another principal's login can't end the volume's session.
	body, _ := json.Marshal(map[string]any{"method": "jwt", "credential": podJWT("system:serviceaccount:payments:worker", "a238l9-worker"), "replaces": current})
	req, _ := http.NewRequest(http.MethodPost, h.ts.URL+"/api/v1/secrets/login", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Tenant-ID", h.tenant)
	req.Header.Set("Idempotency-Key", "a238l9-worker-login")
	resp, err := h.ts.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	var answer struct {
		SessionID string `json:"session_id"`
		Token     string `json:"token"`
		Replaced  bool   `json:"replaced"`
	}
	if resp.StatusCode != http.StatusOK || json.Unmarshal(raw, &answer) != nil || answer.SessionID == "" || answer.Replaced {
		t.Fatalf("another principal's login naming the volume's session: HTTP %d %s", resp.StatusCode, raw)
	}
	// Served tests share a tenant: that session ends itself before the test does.
	if status, raw := secretsReqKey(t, h, http.MethodPost, "/api/v1/secrets/sessions/self/revoke", answer.Token, "a238l9-worker-end", nil); status != http.StatusOK {
		t.Fatalf("end the worker's session: HTTP %d %s", status, raw)
	}
	if got := sessions()[current]; got.Status != "active" {
		t.Fatalf("another principal's login ended the volume's session: %+v", got)
	}

	// The volume goes: the plugin ends the session it holds (A238-L7).
	if _, err := restarted.NodeUnpublishVolume(t.Context(), &csi.NodeUnpublishVolumeRequest{VolumeId: "csi-a238l9", TargetPath: target}); err != nil {
		t.Fatal(err)
	}
	if got := sessions()[current]; got.Status != "revoked" {
		t.Fatalf("after the unpublish the volume's session reads %+v", got)
	}
	t.Logf("A238L9_RESTART_ENDS_EARLIER_SESSION_OK earlier=%s current=%s", earlier, current)
}
