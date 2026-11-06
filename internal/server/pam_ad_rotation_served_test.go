// SPDX-License-Identifier: BUSL-1.1
package server

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"github.com/google/uuid"
	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/crypto/secret"
	"trstctl.com/trstctl/internal/crypto/secretfile"
	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/store"
)

func TestServedADAccountRotationA263(t *testing.T) {
	if os.Getenv("TRSTCTL_AD_SERVED_LAB") != "1" {
		t.Skip("owned Samba and Linux PostgreSQL lab not requested")
	}
	ctx := t.Context()
	st := nativeDesktopOwnedStore(t)
	admin, err := os.ReadFile("/run/ad-admin-password")
	if err != nil {
		t.Fatal(err)
	}
	defer secret.Wipe(admin)
	adminPath := filepath.Join(t.TempDir(), "admin")
	if err = secretfile.Create(adminPath, admin); err != nil {
		t.Fatal(err)
	}
	const account = "CN=a263-served,OU=TrstctlA263,DC=a263,DC=test"
	cfg := config.DynamicSecretProviderConfig{TenantID: servedTestTenant, ID: "ad-vault", Type: "ldap", Addr: "ad263:636", TLSServerName: "ad263", TLSCARef: "file:/run/ad-ca.pem", BindDN: "CN=Administrator,CN=Users,DC=a263,DC=test", PasswordRef: "file:" + adminPath, UsersDN: "OU=TrstctlA263,DC=a263,DC=test", AllowedRoles: []string{"directory/served"}, RoleBindings: map[string]string{"directory/served": account}, AllowStaticRotation: true, MaxTTL: "1h"}
	if err := json.Unmarshal([]byte(`{"directory_mode":"active_directory"}`), &cfg); err != nil {
		t.Fatal(err)
	}
	if err := config.ValidateSecretIntegrations(config.SecretIntegrationsConfig{DynamicProviders: []config.DynamicSecretProviderConfig{cfg}}, true); err != nil {
		t.Fatal(err)
	}
	providers, err := dynamicSecretProvidersFromConfig(ctx, []config.DynamicSecretProviderConfig{cfg}, nil, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	h := newServedHarnessWithOwnedStore(t, config.Protocols{}, []events.OpenOption{events.WithRequiredPrivacyEventPolicies()}, st, withSecretsEnabled(t, nil), func(d *Deps) { d.TenantDynamicSecretProviders = providers })
	registerServedTenant(t, h, "A263 AD rotation")
	token := seedScopedToken(t, st, h.tenant, "secrets:read", "secrets:write")
	initial, err := json.Marshal(struct {
		Username string           `json:"username"`
		BindDN   string           `json:"bind_dn"`
		Password secret.JSONBytes `json:"password"`
	}{Username: "a263-served", BindDN: account, Password: []byte("unused-owned-bootstrap")})
	if err != nil {
		t.Fatal(err)
	}
	defer secret.Wipe(initial)
	if status, _ := secretsReqKey(t, h, http.MethodPost, "/api/v1/secrets/store", token, "ad-import", map[string]any{"name": "directory/served", "value": secret.JSONBytes(initial)}); status != http.StatusCreated && status != http.StatusOK {
		t.Fatalf("vault import status=%d", status)
	}
	request := map[string]any{"provider": "ad-vault", "key": "directory/served", "old_ref": account}
	if status, body := secretsReqKey(t, h, http.MethodPost, "/api/v1/secrets/rotations", token, "ad-unacknowledged", request); status != http.StatusBadRequest || !bytes.Contains(body, []byte("rotates in a single phase")) {
		t.Fatalf("AD rotation must require explicit interruption acknowledgement: status=%d", status)
	}
	request["acknowledge_single_phase"] = true
	rotate := func(key string) staticRotationCommandView {
		t.Helper()
		status, body := secretsReqKey(t, h, http.MethodPost, "/api/v1/secrets/rotations", token, key, request)
		var queued struct {
			ID string `json:"command_id"`
		}
		if status != http.StatusOK || json.Unmarshal(body, &queued) != nil || queued.ID == "" {
			t.Fatalf("queue AD rotation status=%d", status)
		}
		// Replayed admission must return the same durable operation.
		status, body = secretsReqKey(t, h, http.MethodPost, "/api/v1/secrets/rotations", token, key, request)
		var replay struct {
			ID string `json:"command_id"`
		}
		if status != http.StatusOK || json.Unmarshal(body, &replay) != nil || replay.ID != queued.ID {
			t.Fatal("AD rotation idempotency changed its operation")
		}
		var result staticRotationCommandView
		desktopAwait(t, "AD rotation outbox completion", func() bool {
			h.srv.dispatchOnce(ctx)
			code, raw := secretsReqKey(t, h, http.MethodGet, "/api/v1/secrets/rotations/"+queued.ID, token, "", nil)
			if code != http.StatusOK || json.Unmarshal(raw, &result) != nil {
				t.Fatal("rotation read failed")
			}
			if result.Terminal && result.Phase != store.SecretStaticRotationCompleted {
				t.Fatalf("AD rotation failed: phase=%s verify=%s failure=%s", result.Phase, result.VerifyMode, result.Error)
			}
			return result.Phase == store.SecretStaticRotationCompleted
		})
		if result.RotationPhase != "single_phase" || result.VerifyMode != "authenticated" || result.NewRef != account {
			t.Fatalf("AD completion lacks native proof: phase=%s mode=%s", result.RotationPhase, result.VerifyMode)
		}
		return result
	}
	read := func() []byte {
		t.Helper()
		status, body := secretsReqKey(t, h, http.MethodGet, "/api/v1/secrets/store/directory/served", token, "", nil)
		var view struct {
			Value secret.JSONBytes `json:"value"`
		}
		if status != http.StatusOK || json.Unmarshal(body, &view) != nil || len(view.Value) == 0 {
			t.Fatal("rotated vault read failed")
		}
		return view.Value
	}
	first := rotate("ad-rotation-1")
	firstRaw := read()
	defer secret.Wipe(firstRaw)
	second := rotate("ad-rotation-2")
	secondRaw := read()
	defer secret.Wipe(secondRaw)
	if first.ID == second.ID {
		t.Fatal("two distinct rotations collapsed")
	}
	password := func(raw []byte) []byte {
		t.Helper()
		var c struct {
			Password secret.JSONBytes `json:"password"`
		}
		if json.Unmarshal(raw, &c) != nil || len(c.Password) == 0 {
			t.Fatal("vault lacks a password")
		}
		return c.Password
	}
	old, current := password(firstRaw), password(secondRaw)
	defer secret.Wipe(old)
	defer secret.Wipe(current)
	if out, e := servedADStockRead(ctx, current, account); e != nil || !bytes.Contains(bytes.ToLower(out), []byte("a263-served")) {
		t.Fatal("stock AD read refused current password")
	}
	if out, e := servedADStockRead(ctx, old, account); e == nil || !bytes.Contains(out, []byte("Invalid credentials (49)")) {
		t.Fatal("stock AD read accepted the predecessor")
	}
	other := uuid.NewString()
	registerServedTenantID(t, h, other, "AD isolation")
	otherToken := seedScopedToken(t, st, other, "secrets:read")
	if status, _ := secretsReqKey(t, h, http.MethodGet, "/api/v1/secrets/rotations/"+first.ID, otherToken, "", nil); status != http.StatusNotFound {
		t.Fatalf("cross-tenant rotation read status=%d", status)
	}
	if err = h.log.Replay(ctx, 0, func(event events.Event) error {
		if event.TenantID == h.tenant && (bytes.Contains(event.Data, old) || bytes.Contains(event.Data, current) || bytes.Contains(event.Data, admin)) {
			t.Fatal("directory credential escaped into an event")
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}
func servedADStockRead(ctx context.Context, password []byte, dn string) ([]byte, error) {
	bounded, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	input, output, err := os.Pipe()
	if err != nil {
		return nil, err
	}
	defer func() { _ = input.Close() }()
	if _, err = output.Write(password); err != nil {
		_ = output.Close()
		return nil, err
	}
	_ = output.Close()
	cmd := exec.CommandContext(bounded, "/usr/bin/ldapsearch", "-x", "-H", "ldaps://ad263:636", "-D", dn, "-y", "/proc/self/fd/3", "-LLL", "-b", dn, "-s", "base", "sAMAccountName") // #nosec G204 -- fixed stock client, exact owned directory DN and inherited password pipe; no shell (CWE-78)
	cmd.ExtraFiles = []*os.File{input}
	cmd.Env = []string{"PATH=/usr/bin:/bin", "HOME=/nonexistent", "LDAPTLS_CACERT=/run/ad-ca.pem"}
	return cmd.CombinedOutput()
}
