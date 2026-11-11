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
	"sync"
	"testing"
	"time"

	"github.com/container-storage-interface/spec/lib/go/csi"

	"trstctl.com/trstctl/internal/agent/csisecrets"
	"trstctl.com/trstctl/internal/cli"
	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/crypto"
)

// a238l7Mounter stands in for the node's memory-filesystem mounts.
type a238l7Mounter struct {
	mu      sync.Mutex
	mounted map[string]bool
}

func (m *a238l7Mounter) MountTmpfs(target string, _ int) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.mounted[target] = true
	return nil
}

func (m *a238l7Mounter) IsMountPoint(target string) (bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.mounted[target], nil
}

func (m *a238l7Mounter) Unmount(target string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.mounted, target)
	return nil
}

// TestServedMachineSessionEndsItselfA238L7 is A238-L7 over the served API, the
// CLI and the CSI node plugin:
//   - a read-only machine session (secrets:read only) ends itself; its token
//     then reads nothing, a retry is refused, and the ledger shows it revoked
//     by itself, while another session of the same method still reads;
//   - an operator's API token is not a machine session: 404, and it still works;
//   - `trstctl secrets sessions end` ends the session the CLI's token is;
//   - the node plugin, logged in with a pod's token, ends the volume's session
//     when the volume is unpublished.
func TestServedMachineSessionEndsItselfA238L7(t *testing.T) {
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
		// The generic JWT method, so its single-use records on the shared
		// served tenant stay apart from other tests' "oidc" logins.
		Name: "jwt", TenantID: servedTestTenant, Issuer: "https://pods.example.test", Audience: "trstctl",
		JWKSJSON: string(jwks), Scopes: []string{"secrets:read"},
	}})
	if err != nil {
		t.Fatal(err)
	}
	h := newServedHarness(t, config.Protocols{}, withSecretsEnabled(t, nil), func(d *Deps) {
		d.MachineAuthMethods = withMachineCredentialReplayGuard(methods, d.Store)
	})
	registerServedTenant(t, h, "A238-L7 machine session self-end tenant")
	admin := seedScopedTokenSubject(t, h.store, h.tenant, "a238l7-admin", "secrets:read", "secrets:write")
	operator := seedScopedTokenSubject(t, h.store, h.tenant, "a238l7-operator", "secrets:read")
	call := func(tok, method, path, key string, body any, want int) []byte {
		t.Helper()
		status, raw := secretsReqKey(t, h, method, path, tok, key, body)
		if status != want {
			t.Fatalf("%s %s: HTTP %d %s, want %d", method, path, status, raw, want)
		}
		return raw
	}
	call(admin, http.MethodPost, "/api/v1/secrets/store", "a238l7-seed", map[string]any{"name": "a238l7/prod/db-password", "value": "pw-a238l7"}, http.StatusCreated)
	const readURL = "/api/v1/secrets/store/a238l7/prod/db-password"
	podJWT := func(jti string) string {
		t.Helper()
		jwt, err := crypto.SignJWT(signer, "pod-key", map[string]any{
			"iss": "https://pods.example.test", "aud": "trstctl", "sub": "system:serviceaccount:payments:api",
			"exp": time.Now().Add(10 * time.Minute).Unix(), "iat": time.Now().Unix(), "jti": jti,
		})
		if err != nil {
			t.Fatal(err)
		}
		return jwt
	}
	type loginAnswer struct {
		SessionID string `json:"session_id"`
		Principal string `json:"principal"`
		Token     string `json:"token"`
	}
	login := func(jti string) loginAnswer {
		t.Helper()
		body, _ := json.Marshal(map[string]any{"method": "jwt", "credential": podJWT(jti)})
		req, _ := http.NewRequest(http.MethodPost, h.ts.URL+"/api/v1/secrets/login", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("X-Tenant-ID", h.tenant)
		req.Header.Set("Idempotency-Key", "a238l7-login-"+jti)
		resp, err := h.ts.Client().Do(req)
		if err != nil {
			t.Fatal(err)
		}
		raw, _ := io.ReadAll(resp.Body)
		_ = resp.Body.Close()
		var out loginAnswer
		if resp.StatusCode != http.StatusOK || json.Unmarshal(raw, &out) != nil || out.Token == "" || out.SessionID == "" {
			t.Fatalf("machine login: HTTP %d %s", resp.StatusCode, raw)
		}
		return out
	}
	type sessionView struct {
		ID        string `json:"id"`
		Status    string `json:"status"`
		RevokedBy string `json:"revoked_by"`
	}
	sessions := func() map[string]sessionView {
		t.Helper()
		var out struct {
			Items []sessionView `json:"items"`
		}
		if err := json.Unmarshal(call(admin, http.MethodGet, "/api/v1/secrets/sessions?limit=200", "", nil, http.StatusOK), &out); err != nil {
			t.Fatal(err)
		}
		views := map[string]sessionView{}
		for _, s := range out.Items {
			views[s.ID] = s
		}
		return views
	}

	// A read-only session ends itself; another session is left as it was.
	first, second := login("a238l7-first"), login("a238l7-second")
	call(first.Token, http.MethodGet, readURL, "", nil, http.StatusOK)
	var ended sessionView
	if err := json.Unmarshal(call(first.Token, http.MethodPost, "/api/v1/secrets/sessions/self/revoke", "a238l7-end-first", nil, http.StatusOK), &ended); err != nil {
		t.Fatal(err)
	}
	if ended.ID != first.SessionID || ended.Status != "revoked" || ended.RevokedBy != first.Principal {
		t.Fatalf("the ended session reads %+v, want %s revoked by %s", ended, first.SessionID, first.Principal)
	}
	call(first.Token, http.MethodGet, readURL, "", nil, http.StatusUnauthorized)
	call(first.Token, http.MethodPost, "/api/v1/secrets/sessions/self/revoke", "a238l7-end-first", nil, http.StatusUnauthorized)
	call(second.Token, http.MethodGet, readURL, "", nil, http.StatusOK)
	if got := sessions(); got[first.SessionID].Status != "revoked" || got[second.SessionID].Status != "active" {
		t.Fatalf("the ledger after one session ended itself: first %+v, second %+v", got[first.SessionID], got[second.SessionID])
	}

	// An operator's token is not a machine session.
	call(operator, http.MethodPost, "/api/v1/secrets/sessions/self/revoke", "a238l7-end-operator", nil, http.StatusNotFound)
	call(operator, http.MethodGet, readURL, "", nil, http.StatusOK)

	// The CLI ends the session its token is.
	var stdout, stderr bytes.Buffer
	if code := cli.Run(t.Context(), []string{"--server", h.ts.URL, "--token", second.Token, "--tenant", h.tenant,
		"secrets", "sessions", "end"}, cli.Env{HTTPClient: h.ts.Client()}, nil, &stdout, &stderr); code != 0 || !strings.Contains(stdout.String(), "revoked") {
		t.Fatalf("trstctl secrets sessions end: exit %d %s%s", code, stdout.String(), stderr.String())
	}
	call(second.Token, http.MethodGet, readURL, "", nil, http.StatusUnauthorized)

	// The node plugin ends the volume's session when the volume goes.
	before := sessions()
	mounter := &a238l7Mounter{mounted: map[string]bool{}}
	var logs bytes.Buffer
	driver, err := csisecrets.NewDriver(csisecrets.Config{Server: h.ts.URL, Tenant: h.tenant, LoginMethod: "jwt", StateDir: t.TempDir()},
		h.ts.Client(), mounter, slog.New(slog.NewTextHandler(&logs, nil)), "node-a238l7", "test")
	if err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(t.TempDir(), "pods", "uid-a238l7", "volumes", "kubernetes.io~csi", "secrets", "mount")
	tokens, _ := json.Marshal(map[string]any{"trstctl": map[string]string{"token": podJWT("a238l7-pod")}})
	if _, err := driver.NodePublishVolume(t.Context(), &csi.NodePublishVolumeRequest{
		VolumeId: "csi-a238l7", TargetPath: target,
		VolumeContext: map[string]string{
			"csi.storage.k8s.io/ephemeral": "true", "csi.storage.k8s.io/pod.name": "api-0",
			"csi.storage.k8s.io/pod.namespace": "payments", "csi.storage.k8s.io/serviceAccount.name": "api",
			"secrets": "password=a238l7/prod/db-password",
		},
		Secrets:          map[string]string{"csi.storage.k8s.io/serviceAccount.tokens": string(tokens)},
		VolumeCapability: &csi.VolumeCapability{AccessType: &csi.VolumeCapability_Mount{Mount: &csi.VolumeCapability_MountVolume{}}},
	}); err != nil {
		t.Fatalf("publish the volume: %v\n%s", err, logs.String())
	}
	if raw, err := os.ReadFile(filepath.Join(target, "password")); err != nil || string(raw) != "pw-a238l7" { // #nosec G304 -- the test's own temp file (CWE-22)
		t.Fatalf("the volume's file %q, %v", raw, err)
	}
	var volumeSession string
	for id, s := range sessions() {
		if _, seen := before[id]; !seen && s.Status == "active" {
			volumeSession = id
		}
	}
	if volumeSession == "" {
		t.Fatal("the volume's login left no active session in the ledger")
	}
	if _, err := driver.NodeUnpublishVolume(t.Context(), &csi.NodeUnpublishVolumeRequest{VolumeId: "csi-a238l7", TargetPath: target}); err != nil {
		t.Fatal(err)
	}
	if got := sessions()[volumeSession]; got.Status != "revoked" {
		t.Fatalf("after the unpublish the volume's session reads %+v\n%s", got, logs.String())
	}
	if !strings.Contains(logs.String(), "ended the volume's session") {
		t.Fatalf("the plugin did not say it ended the session:\n%s", logs.String())
	}
	t.Logf("A238L7_SELF_END_OK session=%s volume_session=%s", first.SessionID, volumeSession)
}
