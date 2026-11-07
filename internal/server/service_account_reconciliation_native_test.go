// SPDX-License-Identifier: BUSL-1.1
package server

import (
	"encoding/json"
	"github.com/google/uuid"
	"os"
	"runtime"
	"testing"
	"time"
	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/crypto/secret"
	"trstctl.com/trstctl/internal/dynsecret"
	"trstctl.com/trstctl/internal/servicedependents"
)

// The directory, queue, vault and audit are real. Signed host reports remain
// explicit boundary fixtures; the Windows native receiver is qualified separately.
func nativeReconcileDirectoryFixture(t *testing.T) *dependentNativeDirectoryFixture {
	t.Helper()
	raw, err := os.ReadFile("/run/ad-reconcile-public.json")
	if err != nil {
		t.Fatal("owned public reconciliation identities unavailable")
	}
	var owned []struct {
		Name string `json:"name"`
		DN   string `json:"dn"`
		SID  string `json:"sid"`
		GUID string `json:"guid"`
	}
	if json.Unmarshal(raw, &owned) != nil || len(owned) != 3 {
		t.Fatal("invalid owned public reconciliation identity manifest")
	}
	cfg := config.DynamicSecretProviderConfig{TenantID: servedTestTenant, ID: "ad-native-approved-reconcile", Type: "ldap", DirectoryMode: "active_directory", Addr: "ad263:636", TLSServerName: "ad263", TLSCARef: "file:/run/ad-ca.pem", BindDN: "CN=Administrator,CN=Users,DC=a263,DC=test", PasswordRef: "file:/run/ad-admin-password", UsersDN: "OU=TrstctlA263,DC=a263,DC=test", AllowedRoles: []string{"app/dependent"}, RoleBindings: map[string]string{"app/dependent": owned[0].DN}, AllowStaticRotation: true, MaxTTL: "1h"} // #nosec G101 -- protected owned lab credential-file reference only (CWE-798)
	makeProvider := func(c config.DynamicSecretProviderConfig) dynsecret.Provider {
		return newConfiguredDynamicProvider(c, map[string]bool{"app/dependent": true}, time.Hour, integrationCredentialResolver{}, nil)
	}
	ordinary := makeProvider(cfg)
	accounts, err := ordinary.(pamAccountDiscoverer).DynamicSecretDiscoverAccounts(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	var identity servicedependents.AccountBinding
	for _, account := range accounts {
		if dynsecret.SameADNativeDN(account.Details["dn"], owned[0].DN) {
			if identity.DN != "" {
				t.Fatal("owned native target ambiguous")
			}
			identity = servicedependents.AccountBinding{ProviderID: cfg.ID, Name: account.Name, DN: account.Details["dn"], SID: account.Details["native_sid"], GUID: account.Details["native_guid"]}
		}
	}
	if identity.DN == "" || identity.SID != owned[0].SID || identity.GUID != owned[0].GUID {
		t.Fatal("owned native target differs from fixture pins")
	}
	generate := func() *secret.Buffer {
		t.Helper()
		credential, e := ordinary.Generate(t.Context(), dynsecret.GenerateRequest{Role: "app/dependent", Static: true, LeaseID: uuid.NewString(), Predecessor: identity.DN})
		if e != nil {
			t.Fatal(e)
		}
		held, e := secret.NewFrom(credential.Secret)
		secret.Wipe(credential.Secret)
		if e != nil {
			t.Fatal(e)
		}
		t.Cleanup(held.Destroy)
		return held
	}
	old := generate()
	drift := generate()
	if !nativeDependentStockBind(t, t.Context(), identity, drift.Bytes()) {
		t.Fatal("independently changed native drift generation not accepted")
	}
	cfg.ADReconcile = &config.ADReconcileConfig{BindDN: owned[2].DN, PasswordRef: "file:/run/ad-reconcile-password", SID: owned[2].SID, GUID: owned[2].GUID, AllowedRoles: []string{"app/dependent"}} // #nosec G101 -- separate protected owned lab reference only (CWE-798)
	cfg.PasswordRef = "file:/run/ordinary-writer-intentionally-unavailable"
	return &dependentNativeDirectoryFixture{provider: makeProvider(cfg), store: nativeDesktopOwnedStore(t), identity: identity, initial: old, drift: drift}
}

func TestServedNativeADReconciliationCoordinatorA267(t *testing.T) {
	if os.Getenv("TRSTCTL_AD_RECONCILE_LAB") != "1" {
		t.Skip("owned Samba approved reconciliation lab not requested")
	}
	if runtime.GOOS != "linux" {
		t.Fatal("native approved reconciliation requires the retained Linux lab")
	}
	for _, failure := range []bool{false, true} {
		name := "forward"
		if failure {
			name = "dependent failure"
		}
		t.Run(name, func(t *testing.T) {
			servedDependentRotationCaseWithMode(t, nativeReconcileDirectoryFixture(t), failure, true)
		})
	}
	if !t.Failed() {
		t.Log("A267_NATIVE_RECONCILE_COORDINATOR_OK: real Samba drift and designated reset, independent approved public manifest, durable audit and vault barriers, forward/inverse stock LDAP; signed host boundary fixtures")
	}
}

func TestServedNativePagedADReconciliationCoordinatorA267(t *testing.T) {
	if os.Getenv("TRSTCTL_AD_RECONCILE_LAB") != "1" {
		t.Skip("owned Samba paged reconciliation lab not requested")
	}
	if runtime.GOOS != "linux" {
		t.Fatal("native paged reconciliation requires the retained Linux lab")
	}
	for _, failure := range []bool{false, true} {
		name := "forward"
		if failure {
			name = "inverse"
		}
		t.Run(name, func(t *testing.T) {
			servedDependentRotationScenario(t, nativeReconcileDirectoryFixture(t), failure, dependentRotationOptions{Reconcile: true, ManifestExecution: true})
		})
	}
	if !t.Failed() {
		t.Log("A267_NATIVE_PAGED_RECONCILE_OK: one sealed account, real Samba designated reset and stored inverse, stock LDAP; signed host boundary fixtures, not Windows runtime")
	}
}
