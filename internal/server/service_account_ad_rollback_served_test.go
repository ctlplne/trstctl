// SPDX-License-Identifier: BUSL-1.1
package server

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"github.com/jackc/pgx/v5"
	"net/http"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"
	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/crypto/secret"
	"trstctl.com/trstctl/internal/crypto/secretfile"
	"trstctl.com/trstctl/internal/dynsecret"
	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/orchestrator"
	"trstctl.com/trstctl/internal/projections"
	"trstctl.com/trstctl/internal/store"
)

type adRollbackFaultProvider struct {
	dynsecret.Provider
	fail              atomic.Bool
	restoreFail       atomic.Bool
	rejected          atomic.Pointer[secret.Buffer]
	restoreCalls      atomic.Int32
	afterRestore      func() error
	loseApplyResponse atomic.Bool
	applyMu           sync.Mutex
	applied           map[string]int
}

func (p *adRollbackFaultProvider) recordNativeApply(credential dynsecret.Credential, err error) (dynsecret.Credential, error) {
	if err != nil {
		return credential, err
	}
	p.applyMu.Lock()
	if p.applied == nil {
		p.applied = map[string]int{}
	}
	p.applied[crypto.SHA256Hex(credential.Secret)]++
	p.applyMu.Unlock()
	if p.loseApplyResponse.Load() {
		secret.Wipe(credential.Secret)
		return dynsecret.Credential{}, errors.New("owned response loss after native directory apply")
	}
	return credential, nil
}
func (p *adRollbackFaultProvider) Generate(ctx context.Context, req dynsecret.GenerateRequest) (dynsecret.Credential, error) {
	return p.recordNativeApply(p.Provider.Generate(ctx, req))
}
func (p *adRollbackFaultProvider) StaticRotationBinding(role string) string {
	if provider, ok := p.Provider.(interface{ StaticRotationBinding(string) string }); ok {
		return provider.StaticRotationBinding(role)
	}
	return ""
}
func (p *adRollbackFaultProvider) PrepareStaticCredential(ctx context.Context, req dynsecret.GenerateRequest) ([]byte, error) {
	if provider, ok := p.Provider.(interface {
		PrepareStaticCredential(context.Context, dynsecret.GenerateRequest) ([]byte, error)
	}); ok {
		return provider.PrepareStaticCredential(ctx, req)
	}
	return nil, errors.New("native directory has no durable static preparation")
}
func (p *adRollbackFaultProvider) GenerateStaticPrepared(ctx context.Context, req dynsecret.GenerateRequest, prepared []byte) (dynsecret.Credential, error) {
	if provider, ok := p.Provider.(interface {
		GenerateStaticPrepared(context.Context, dynsecret.GenerateRequest, []byte) (dynsecret.Credential, error)
	}); ok {
		return p.recordNativeApply(provider.GenerateStaticPrepared(ctx, req, prepared))
	}
	return dynsecret.Credential{}, errors.New("native directory has no prepared static apply")
}
func (p *adRollbackFaultProvider) RestorePreparedStaticCredential(ctx context.Context, req dynsecret.GenerateRequest, prepared, old []byte) error {
	if p.restoreFail.Load() {
		return errors.New("owned native restore failure")
	}
	provider, ok := p.Provider.(dynsecret.PreparedStaticRotationProvider)
	if !ok {
		return errors.New("native directory has no prepared native recovery")
	}
	p.restoreCalls.Add(1)
	if err := provider.RestorePreparedStaticCredential(ctx, req, prepared, old); err != nil {
		return err
	}
	if p.afterRestore != nil {
		return p.afterRestore()
	}
	return nil
}

func (p *adRollbackFaultProvider) AllowsStaticRotation(role string) bool {
	return p.Provider.(dynsecret.StaticRotationProvider).AllowsStaticRotation(role)
}
func (p *adRollbackFaultProvider) RotationPhase(role string) string {
	return p.Provider.(dynsecret.RotationPhaser).RotationPhase(role)
}
func (p *adRollbackFaultProvider) VerifyStaticCredential(ctx context.Context, ref string, value []byte) (string, error) {
	if p.fail.Load() {
		if p.rejected.Load() == nil {
			held, err := secret.NewFrom(value)
			if err != nil {
				return "authenticated", err
			}
			if !p.rejected.CompareAndSwap(nil, held) {
				held.Destroy()
			}
		}
		return "authenticated", errors.New("owned dependent verification fault after native directory update")
	}
	return p.Provider.(dynsecret.StaticRotationProvider).VerifyStaticCredential(ctx, ref, value)
}
func (p *adRollbackFaultProvider) RestoreStaticCredential(ctx context.Context, role, ref string, value []byte) error {
	if p.restoreFail.Load() {
		return errors.New("owned native restore failure")
	}
	if provider, ok := p.Provider.(interface {
		RestoreStaticCredential(context.Context, string, string, []byte) error
	}); ok {
		p.restoreCalls.Add(1)
		if err := provider.RestoreStaticCredential(ctx, role, ref, value); err != nil {
			return err
		}
		if p.afterRestore != nil {
			return p.afterRestore()
		}
		return nil
	}
	return errors.New("native directory has no verified restore")
}

// Samba proves the directory half; Windows dependent execution is a separate
// native runner obligation. A vault-only rollback must never count as recovery.
func TestServedADStaticRotationRollbackA267(t *testing.T) {
	if os.Getenv("TRSTCTL_AD_SERVED_LAB") != "1" {
		t.Skip("owned Samba/real PostgreSQL lab not requested")
	}
	ctx := t.Context()
	st := nativeDesktopOwnedStore(t)
	admin, err := os.ReadFile("/run/ad-admin-password")
	if err != nil {
		t.Fatal(err)
	}
	defer secret.Wipe(admin)
	path := filepath.Join(t.TempDir(), "admin")
	if err = secretfile.Create(path, admin); err != nil {
		t.Fatal(err)
	}
	const account = "CN=a267-served,OU=TrstctlA263,DC=a263,DC=test"
	cfg := config.DynamicSecretProviderConfig{TenantID: servedTestTenant, ID: "a267-directory", Type: "ldap", DirectoryMode: "active_directory", Addr: "ad263:636", TLSServerName: "ad263", TLSCARef: "file:/run/ad-ca.pem", BindDN: "CN=Administrator,CN=Users,DC=a263,DC=test", PasswordRef: "file:" + path, UsersDN: "OU=TrstctlA263,DC=a263,DC=test", AllowedRoles: []string{"directory/dependents"}, RoleBindings: map[string]string{"directory/dependents": account}, AllowStaticRotation: true, MaxTTL: "1h"}
	providers, err := dynamicSecretProvidersFromConfig(ctx, []config.DynamicSecretProviderConfig{cfg}, nil, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	fault := &adRollbackFaultProvider{Provider: providers[servedTestTenant][0]}
	defer func() {
		if held := fault.rejected.Load(); held != nil {
			held.Destroy()
		}
	}()
	providers[servedTestTenant][0] = fault
	h := newServedHarnessWithOwnedStore(t, config.Protocols{}, []events.OpenOption{events.WithRequiredPrivacyEventPolicies()}, st, withSecretsEnabled(t, nil), func(d *Deps) { d.TenantDynamicSecretProviders = providers })
	registerServedTenant(t, h, "A267 native rollback")
	token := seedScopedToken(t, st, h.tenant, "secrets:read", "secrets:write")
	raw, err := json.Marshal(struct {
		Username string           `json:"username"`
		BindDN   string           `json:"bind_dn"`
		Password secret.JSONBytes `json:"password"`
	}{"a267-served", account, []byte("unused-owned-bootstrap")}) // #nosec G117 -- byte-backed owned bootstrap sent to the existing sealed-vault API; not logged (CWE-200)
	if err != nil {
		t.Fatal(err)
	}
	defer secret.Wipe(raw)
	if status, _ := secretsReqKey(t, h, http.MethodPost, "/api/v1/secrets/store", token, "a267-bootstrap", map[string]any{"name": "directory/dependents", "value": secret.JSONBytes(raw)}); status != 201 && status != 200 {
		t.Fatal("bootstrap unavailable")
	}
	var recoveryFault atomic.Bool
	recoveryFaultReleased := false
	rotate := func(key string) store.SecretStaticRotationCommand {
		t.Helper()
		status, body := secretsReqKey(t, h, http.MethodPost, "/api/v1/secrets/rotations", token, key, map[string]any{"provider": cfg.ID, "key": "directory/dependents", "old_ref": account, "acknowledge_single_phase": true})
		var queued struct {
			ID string `json:"command_id"`
		}
		if status != 200 || json.Unmarshal(body, &queued) != nil || queued.ID == "" {
			t.Fatalf("rotation enqueue failed: %d %s", status, body)
		}
		var cmd store.SecretStaticRotationCommand
		deadline := time.Now().Add(15 * time.Second)
		for time.Now().Before(deadline) {
			var e error
			cmd, e = st.GetSecretStaticRotationCommand(ctx, h.tenant, queued.ID)
			if e != nil {
				t.Fatal(e)
			}
			if cmd.Terminal() {
				return cmd
			}
			if e = st.WithTenant(ctx, h.tenant, func(tx pgx.Tx) error {
				_, e := tx.Exec(ctx, `UPDATE outbox SET next_attempt_at=now() WHERE tenant_id=$1 AND id=$2 AND status='pending'`, h.tenant, cmd.OutboxID)
				return e
			}); e != nil {
				t.Fatal(e)
			}
			_, _ = h.srv.outbox.DispatchOneScoped(ctx, h.srv.obHandler, orchestrator.DestinationScope{IncludeDestinations: []string{store.SecretStaticRotationDestination}})
			if recoveryFault.Swap(false) {
				paused, e := st.GetSecretStaticRotationCommand(ctx, h.tenant, queued.ID)
				if e != nil || paused.Terminal() {
					t.Fatal("failed recovery publication prematurely ended the command")
				}
				currentValue, e := st.GetSecret(ctx, h.tenant, "directory/dependents")
				if e != nil || currentValue.Version != paused.ResultVersion {
					t.Fatal("failed SQL projection changed the published version before catch-up")
				}
				if _, e := st.SystemPool().Exec(ctx, `DROP TRIGGER a267_restore_fault ON secret_store; DROP FUNCTION a267_restore_fault()`); e != nil {
					t.Fatal(e)
				}
				// The next worker attempt must recover the retained event itself.
				recoveryFaultReleased = true
			}

		}
		t.Fatalf("native directory rotation did not finish: phase=%s error=%s", cmd.Phase, cmd.Error)
		return cmd
	}
	read := func() []byte {
		t.Helper()
		status, body := secretsReq(t, h, http.MethodGet, "/api/v1/secrets/store/directory/dependents", token, nil)
		var value struct {
			Value secret.JSONBytes `json:"value"`
		}
		if status != 200 || json.Unmarshal(body, &value) != nil {
			t.Fatal("vault read failed")
		}
		return value.Value
	}
	first := rotate("a267-first")
	if first.Phase != store.SecretStaticRotationCompleted {
		t.Fatalf("initial native rotation failed: %+v", first)
	}
	predecessor := read()
	defer secret.Wipe(predecessor)
	fault.afterRestore = func() error {
		if recoveryFaultReleased {
			return nil
		}
		_, err := st.SystemPool().Exec(ctx, `CREATE FUNCTION a267_restore_fault() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'owned native recovery publication fault'; END $$; CREATE TRIGGER a267_restore_fault BEFORE UPDATE ON secret_store FOR EACH ROW WHEN (NEW.name='directory/dependents' AND NEW.tenant_id=OLD.tenant_id) EXECUTE FUNCTION a267_restore_fault()`)
		if err != nil {
			return err
		}
		recoveryFault.Store(true)
		return nil
	}
	fault.fail.Store(true)
	rolled := rotate("a267-failing-dependent")
	if !recoveryFaultReleased || fault.restoreCalls.Load() != 1 {
		t.Fatal("native recovery was not retained across publication rollback or repeated the native inverse")
	}
	if rolled.Phase != store.SecretStaticRotationRolledBack {
		t.Fatalf("recoverable native update was not rolled back: phase=%s error=%s", rolled.Phase, rolled.Error)
	}
	restored := read()
	defer secret.Wipe(restored)
	if !bytes.Equal(predecessor, restored) {
		t.Fatal("vault did not retain the exact predecessor")
	}
	var old struct {
		Password secret.JSONBytes `json:"password"`
	}
	if json.Unmarshal(restored, &old) != nil {
		t.Fatal("old credential unavailable")
	}
	defer secret.Wipe(old.Password)
	if output, e := servedADStockRead(ctx, old.Password, account); e != nil || !bytes.Contains(bytes.ToLower(output), []byte("a267-served")) {
		t.Fatal("reported rollback restored the vault but not the native AD password")
	}
	held := fault.rejected.Load()
	if held == nil {
		t.Fatal("missing rejected successor evidence")
	}
	var rejected struct {
		Password secret.JSONBytes `json:"password"`
	}
	if json.Unmarshal(held.Bytes(), &rejected) != nil {
		t.Fatal("rejected successor cannot be read")
	}
	defer secret.Wipe(rejected.Password)
	if output, e := servedADStockRead(ctx, rejected.Password, account); e == nil || !bytes.Contains(output, []byte("Invalid credentials (49)")) {
		t.Fatal("native rollback still accepts its rejected successor")
	}
	// Old native password history refusal must not cause an unbounded login loop.
	held.Destroy()
	fault.rejected.Store(nil)
	fault.restoreFail.Store(true)
	failed := rotate("a267-failed-native-restore")
	if failed.Phase != store.SecretStaticRotationRollbackFailed || failed.RestoredVersion != 0 {
		t.Fatal("native restore failure was claimed as recovered")
	}
	stillPublished := read()
	defer secret.Wipe(stillPublished)
	if bytes.Equal(stillPublished, predecessor) {
		t.Fatal("failed native inverse incorrectly published the predecessor")
	}
	var live struct {
		Password secret.JSONBytes `json:"password"`
	}
	if json.Unmarshal(stillPublished, &live) != nil {
		t.Fatal("live successor cannot be read")
	}
	defer secret.Wipe(live.Password)
	if output, e := servedADStockRead(ctx, live.Password, account); e != nil || !bytes.Contains(bytes.ToLower(output), []byte("a267-served")) {
		t.Fatal("native restore failure's reported successor does not match AD")
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
	replayed, err := st.GetSecretStaticRotationCommand(ctx, h.tenant, rolled.ID)
	if err != nil || replayed.Phase != rolled.Phase || replayed.RestoredVersion != rolled.RestoredVersion || replayed.ProviderBinding != rolled.ProviderBinding || !bytes.Equal(replayed.SealedPreparation, rolled.SealedPreparation) {
		t.Fatal("native rollback lost its durable result")
	}
	if err := h.log.Replay(ctx, 0, func(event events.Event) error {
		if event.TenantID == h.tenant && (bytes.Contains(event.Data, old.Password) || bytes.Contains(event.Data, admin)) {
			t.Fatal("native rollback leaked credential material")
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}
