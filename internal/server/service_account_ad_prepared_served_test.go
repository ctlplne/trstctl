// SPDX-License-Identifier: BUSL-1.1
package server

import (
	"bytes"
	"encoding/json"
	"github.com/jackc/pgx/v5"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/crypto/secret"
	"trstctl.com/trstctl/internal/crypto/secretfile"
	"trstctl.com/trstctl/internal/dynsecret"
	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/orchestrator"
	"trstctl.com/trstctl/internal/projections"
	"trstctl.com/trstctl/internal/store"
)

func TestServedADPreparedResponseLossA267(t *testing.T) {
	if os.Getenv("TRSTCTL_AD_SERVED_LAB") != "1" {
		t.Skip("owned native Samba and PostgreSQL lab not requested")
	}
	ctx := t.Context()
	st := nativeDesktopOwnedStore(t)
	admin, err := os.ReadFile("/run/ad-admin-password")
	if err != nil {
		t.Fatal(err)
	}
	defer secret.Wipe(admin)
	path := filepath.Join(t.TempDir(), "admin")
	if err := secretfile.Create(path, admin); err != nil {
		t.Fatal(err)
	}
	const account = "CN=a267-prepared,OU=TrstctlA263,DC=a263,DC=test"
	cfg := config.DynamicSecretProviderConfig{TenantID: servedTestTenant, ID: "a267-prepared-directory", Type: "ldap", DirectoryMode: "active_directory", Addr: "ad263:636", TLSServerName: "ad263", TLSCARef: "file:/run/ad-ca.pem", BindDN: "CN=Administrator,CN=Users,DC=a263,DC=test", PasswordRef: "file:" + path, UsersDN: "OU=TrstctlA263,DC=a263,DC=test", AllowedRoles: []string{"directory/prepared"}, RoleBindings: map[string]string{"directory/prepared": account}, AllowStaticRotation: true, MaxTTL: "1h"}
	providers, err := dynamicSecretProvidersFromConfig(ctx, []config.DynamicSecretProviderConfig{cfg}, nil, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	fault := &adRollbackFaultProvider{Provider: providers[servedTestTenant][0]}
	providers[servedTestTenant][0] = fault
	h := newServedHarnessWithOwnedStore(t, config.Protocols{}, []events.OpenOption{events.WithRequiredPrivacyEventPolicies()}, st, withSecretsEnabled(t, nil), func(d *Deps) { d.TenantDynamicSecretProviders = providers })
	registerServedTenant(t, h, "A267 prepared response loss")
	token := seedScopedToken(t, st, h.tenant, "secrets:read", "secrets:write")
	bootstrap, err := json.Marshal(map[string]any{"username": "a267-prepared", "bind_dn": account, "password": secret.JSONBytes([]byte("unused-owned-bootstrap"))})
	if err != nil {
		t.Fatal(err)
	}
	defer secret.Wipe(bootstrap)
	if status, _ := secretsReqKey(t, h, http.MethodPost, "/api/v1/secrets/store", token, "a267-prepared-bootstrap", map[string]any{"name": "directory/prepared", "value": secret.JSONBytes(bootstrap)}); status != 200 && status != 201 {
		t.Fatal("bootstrap unavailable")
	}
	rotate := func(key string) store.SecretStaticRotationCommand {
		t.Helper()
		status, body := secretsReqKey(t, h, http.MethodPost, "/api/v1/secrets/rotations", token, key, map[string]any{"provider": cfg.ID, "key": "directory/prepared", "old_ref": account, "acknowledge_single_phase": true})
		var queued struct {
			ID string `json:"command_id"`
		}
		if status != 200 || json.Unmarshal(body, &queued) != nil {
			t.Fatalf("enqueue unavailable: %d %s", status, body)
		}
		deadline := time.Now().Add(20 * time.Second)
		for time.Now().Before(deadline) {
			cmd, e := st.GetSecretStaticRotationCommand(ctx, h.tenant, queued.ID)
			if e != nil {
				t.Fatal(e)
			}
			if cmd.Terminal() {
				return cmd
			}
			if e := st.WithTenant(ctx, h.tenant, func(tx pgx.Tx) error {
				_, err := tx.Exec(ctx, `UPDATE outbox SET next_attempt_at=now() WHERE tenant_id=$1 AND id=$2 AND status='pending'`, h.tenant, cmd.OutboxID)
				return err
			}); e != nil {
				t.Fatal(e)
			}
			_, _ = h.srv.outbox.DispatchOneScoped(ctx, h.srv.obHandler, orchestrator.DestinationScope{IncludeDestinations: []string{store.SecretStaticRotationDestination}})
		}
		t.Fatal("native response-loss command did not terminate")
		return store.SecretStaticRotationCommand{}
	}
	read := func() []byte {
		t.Helper()
		status, body := secretsReq(t, h, http.MethodGet, "/api/v1/secrets/store/directory/prepared", token, nil)
		var value struct {
			Value secret.JSONBytes `json:"value"`
		}
		if status != 200 || json.Unmarshal(body, &value) != nil {
			t.Fatal("vault read unavailable")
		}
		return value.Value
	}
	if first := rotate("a267-prepared-first"); first.Phase != store.SecretStaticRotationCompleted {
		t.Fatalf("initial rotation failed: phase=%s error=%s", first.Phase, first.Error)
	}
	old := read()
	defer secret.Wipe(old)
	fault.applyMu.Lock()
	fault.applied = map[string]int{}
	fault.applyMu.Unlock()
	fault.loseApplyResponse.Store(true)
	failed := rotate("a267-response-lost")
	if failed.Phase != store.SecretStaticRotationRolledBack {
		t.Fatalf("ambiguous native apply did not recover its predecessor: phase=%s error=%s", failed.Phase, failed.Error)
	}
	current := read()
	defer secret.Wipe(current)
	if !bytes.Equal(current, old) {
		t.Fatal("response-loss recovery changed the predecessor value")
	}
	var credential struct {
		Password secret.JSONBytes `json:"password"`
	}
	if json.Unmarshal(current, &credential) != nil {
		t.Fatal("restored credential unavailable")
	}
	defer secret.Wipe(credential.Password)
	if out, e := servedADStockRead(ctx, credential.Password, account); e != nil || !bytes.Contains(bytes.ToLower(out), []byte("a267-prepared")) {
		t.Fatal("ambiguous apply restored only the vault")
	}
	fault.applyMu.Lock()
	identities := len(fault.applied)
	fault.applyMu.Unlock()
	if identities != 1 {
		t.Fatalf("native retry minted %d distinct credential values; want the same sealed preparation", identities)
	}
	if len(failed.ProviderBinding) != 64 || len(failed.SealedPreparation) == 0 || len(failed.SealedOld) == 0 {
		t.Fatal("ambiguous apply lost its frozen authority or sealed recovery material")
	}
	projector := projections.New(st)
	if err := projector.ProjectCatchUp(ctx, h.log); err != nil {
		t.Fatal(err)
	}
	if _, err := projector.Snapshot(ctx); err != nil {
		t.Fatal(err)
	}
	if err := projector.Rebuild(ctx, h.log); err != nil {
		t.Fatal(err)
	}
	replayed, err := st.GetSecretStaticRotationCommand(ctx, h.tenant, failed.ID)
	if err != nil || replayed.Phase != failed.Phase || replayed.ProviderBinding != failed.ProviderBinding || !bytes.Equal(replayed.SealedPreparation, failed.SealedPreparation) || !bytes.Equal(replayed.SealedOld, failed.SealedOld) {
		t.Fatal("prepared native rotation changed across snapshot/rebuild")
	}

	// Native adapter contract: even a well-formed preparation may not substitute
	// another GUID or another configured provider before resetting a password.
	preparer := fault.Provider.(dynsecret.PreparedStaticRotationProvider)
	probe := dynsecret.GenerateRequest{Role: "directory/prepared", LeaseID: "owned-native-binding-probe", Static: true, Predecessor: account}
	prepared, err := preparer.PrepareStaticCredential(ctx, probe)
	if err != nil {
		t.Fatal(err)
	}
	defer secret.Wipe(prepared)
	var binding struct {
		GUID string `json:"native_guid"`
	}
	if json.Unmarshal(prepared, &binding) != nil || len(binding.GUID) != 32 {
		t.Fatal("native GUID missing from preparation")
	}
	altered := bytes.Replace(prepared, []byte(binding.GUID), []byte("00000000000000000000000000000000"), 1)
	defer secret.Wipe(altered)
	if credential, e := preparer.GenerateStaticPrepared(ctx, probe, altered); e == nil || !strings.Contains(e.Error(), "preparation differs") {
		secret.Wipe(credential.Secret)
		t.Fatal("different native account GUID was allowed")
	}
	changedCfg := cfg
	changedCfg.Addr = "127.0.0.1:1"
	changed, err := dynamicSecretProvidersFromConfig(ctx, []config.DynamicSecretProviderConfig{changedCfg}, nil, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if credential, e := changed[servedTestTenant][0].(dynsecret.PreparedStaticRotationProvider).GenerateStaticPrepared(ctx, probe, prepared); e == nil || !strings.Contains(e.Error(), "preparation differs") {
		secret.Wipe(credential.Secret)
		t.Fatal("changed provider configuration accepted the old preparation")
	}
	if out, e := servedADStockRead(ctx, credential.Password, account); e != nil || !bytes.Contains(bytes.ToLower(out), []byte("a267-prepared")) {
		t.Fatal("refused GUID/config probes changed the actual account")
	}

}
