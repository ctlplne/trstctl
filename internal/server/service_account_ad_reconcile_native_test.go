// SPDX-License-Identifier: BUSL-1.1
package server

import (
	"encoding/json"
	"os"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/crypto/secret"
	"trstctl.com/trstctl/internal/dynsecret"
	"trstctl.com/trstctl/internal/servicedependents"
)

func TestNativeADDesignatedReconciliationAuthorityA267(t *testing.T) {
	if os.Getenv("TRSTCTL_AD_RECONCILE_LAB") != "1" {
		t.Skip("owned Samba reconciliation lab not requested")
	}
	if runtime.GOOS != "linux" {
		t.Fatal("native reconciliation requires the retained Linux stock-client lab")
	}
	raw, err := os.ReadFile("/run/ad-reconcile-public.json")
	if err != nil {
		t.Fatal("owned public reconciliation identity manifest unavailable")
	}
	var owned []struct {
		Name string `json:"name"`
		DN   string `json:"dn"`
		SID  string `json:"sid"`
		GUID string `json:"guid"`
	}
	if json.Unmarshal(raw, &owned) != nil || len(owned) != 3 {
		t.Fatal("owned public reconciliation manifest invalid")
	}
	// Manifest order is target, foreign target, designated writer. Both test
	// targets belong to the isolated fixture; only the first has a reset grant.
	cfg := config.DynamicSecretProviderConfig{TenantID: servedTestTenant, ID: "ad-reconcile-native", Type: "ldap", DirectoryMode: "active_directory", Addr: "ad263:636", TLSServerName: "ad263", TLSCARef: "file:/run/ad-ca.pem", BindDN: "CN=Administrator,CN=Users,DC=a263,DC=test", PasswordRef: "file:/run/ad-admin-password", UsersDN: "OU=TrstctlA263,DC=a263,DC=test", AllowedRoles: []string{"app/reconcile"}, RoleBindings: map[string]string{"app/reconcile": owned[0].DN}, AllowStaticRotation: true, MaxTTL: "1h"} // #nosec G101 -- protected owned lab credential-file reference, never credential bytes (CWE-798)
	makeProvider := func(c config.DynamicSecretProviderConfig) dynsecret.Provider {
		return newConfiguredDynamicProvider(c, map[string]bool{"app/reconcile": true}, time.Hour, integrationCredentialResolver{}, nil)
	}
	request := func(dn string) dynsecret.GenerateRequest {
		return dynsecret.GenerateRequest{Role: "app/reconcile", Static: true, LeaseID: uuid.NewString(), Predecessor: dn}
	}
	identity := func(index int) servicedependents.AccountBinding {
		v := owned[index]
		return servicedependents.AccountBinding{ProviderID: cfg.ID, DN: v.DN, SID: v.SID, GUID: v.GUID, Name: v.Name}
	}
	ordinary := makeProvider(cfg)
	old, err := ordinary.Generate(t.Context(), request(owned[0].DN))
	if err != nil {
		t.Fatal(err)
	}
	defer secret.Wipe(old.Secret)
	// An independent administrator changes the native password without updating
	// the retained old bytes. No target-password guess is needed to detect/repair.
	drift, err := ordinary.Generate(t.Context(), request(owned[0].DN))
	if err != nil {
		t.Fatal(err)
	}
	defer secret.Wipe(drift.Secret)
	if !nativeDependentStockBind(t, t.Context(), identity(0), drift.Secret) {
		t.Fatal("independent drift was not native")
	}
	cfg.ADReconcile = &config.ADReconcileConfig{BindDN: owned[2].DN, PasswordRef: "file:/run/ad-reconcile-password", SID: owned[2].SID, GUID: owned[2].GUID, AllowedRoles: []string{"app/reconcile"}} // #nosec G101 -- protected owned lab credential-file reference, never credential bytes (CWE-798)
	// The ordinary writer cannot be opened in this test selection. Native success
	// must therefore use the separate protected reference and its exact ACL.
	cfg.PasswordRef = "file:/run/ordinary-writer-intentionally-unavailable"
	selectProvider := func(c config.DynamicSecretProviderConfig) dynsecret.PreparedStaticRotationProvider {
		p, principal, e := makeProvider(c).(dynsecret.StaticReconciliationProvider).StaticReconciliation("app/reconcile")
		if e != nil || principal.DN != owned[2].DN {
			t.Fatal("designated native selection failed", e)
		}
		return p.(dynsecret.PreparedStaticRotationProvider)
	}
	for _, badGUID := range []string{strings.Repeat("0", 32), owned[0].GUID} {
		bad := cfg
		grant := *cfg.ADReconcile
		grant.GUID = badGUID
		bad.ADReconcile = &grant
		candidate := selectProvider(bad)
		if value, e := candidate.PrepareStaticCredential(t.Context(), request(owned[0].DN)); e == nil {
			secret.Wipe(value)
			t.Fatal("wrong designated native GUID accepted")
		}
		if !nativeDependentStockBind(t, t.Context(), identity(0), drift.Secret) {
			t.Fatal("refused principal changed the target")
		}
	}
	selected := selectProvider(cfg)
	req := request(owned[0].DN)
	prepared, err := selected.PrepareStaticCredential(t.Context(), req)
	if err != nil {
		t.Fatal(err)
	}
	defer secret.Wipe(prepared)
	next, err := selected.GenerateStaticPrepared(t.Context(), req, prepared)
	if err != nil {
		t.Fatal(err)
	}
	defer secret.Wipe(next.Secret)
	if !nativeDependentStockBind(t, t.Context(), identity(0), next.Secret) {
		t.Fatal("designated reset was not accepted by stock LDAP")
	}
	if nativeDependentStockBind(t, t.Context(), identity(0), drift.Secret) {
		t.Fatal("retired drift password still accepted")
	}
	if !nativeDependentStockBind(t, t.Context(), identity(0), next.Secret) {
		t.Fatal("known generation did not clear the single owned refusal")
	}
	// A dependent failure would restore the retained stored value, not invent the
	// unknown drift password. Exercise the exact native inverse with that value.
	if err = selected.RestorePreparedStaticCredential(t.Context(), req, prepared, old.Secret); err != nil {
		t.Fatal(err)
	}
	if !nativeDependentStockBind(t, t.Context(), identity(0), old.Secret) {
		t.Fatal("designated inverse did not restore retained stored generation")
	}
	if nativeDependentStockBind(t, t.Context(), identity(0), next.Secret) {
		t.Fatal("inverse left rejected successor accepted")
	}
	if !nativeDependentStockBind(t, t.Context(), identity(0), old.Secret) {
		t.Fatal("known inverse did not clear the single owned refusal")
	}
	// The same principal and role are explicitly configured for a second owned
	// account with NO native reset ACE. There is no administrator fallback.
	foreign := cfg
	foreign.RoleBindings = map[string]string{"app/reconcile": owned[1].DN}
	setup := foreign
	setup.ADReconcile = nil
	setup.PasswordRef = "file:/run/ad-admin-password"
	foreignOld, e := makeProvider(setup).Generate(t.Context(), request(owned[1].DN))
	if e != nil {
		t.Fatal(e)
	}
	defer secret.Wipe(foreignOld.Secret)
	denied := selectProvider(foreign)
	foreignReq := request(owned[1].DN)
	foreignPrep, e := denied.PrepareStaticCredential(t.Context(), foreignReq)
	if e != nil {
		t.Fatal(e)
	}
	defer secret.Wipe(foreignPrep)
	unexpected, e := denied.GenerateStaticPrepared(t.Context(), foreignReq, foreignPrep)
	secret.Wipe(unexpected.Secret)
	if e == nil || !strings.Contains(e.Error(), "LDAP operation was refused (result 50)") {
		t.Fatal("ungranted target lacked an explicit native permission refusal", e)
	}
	if !nativeDependentStockBind(t, t.Context(), identity(1), foreignOld.Secret) {
		t.Fatal("permission refusal changed the foreign target")
	}
	t.Log("A267_NATIVE_RECONCILE_AUTHORITY_OK: distinct pinned writer, exact object reset ACL, independent drift, stock forward/inverse acceptance and refusal, foreign target denial without fallback; coordinated approval/audit not asserted")
}
