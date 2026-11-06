// SPDX-License-Identifier: BUSL-1.1
package server

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"os"
	"os/exec"
	"testing"
	"time"

	"github.com/google/uuid"
	"trstctl.com/trstctl/internal/attest"
	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/projections"
)

func nativeADDiscoveryPublicSnapshot(t *testing.T, ctx context.Context) string {
	t.Helper()
	command := exec.CommandContext(ctx, "/usr/bin/ldapsearch", "-x", "-H", "ldaps://ad263:636", "-D", "CN=Administrator,CN=Users,DC=a263,DC=test", "-y", "/run/ad-admin-password", "-LLL", "-o", "ldif-wrap=no", "-b", "OU=TrstctlA263,DC=a263,DC=test", "(|(sAMAccountName=a267-discovery-spn)(sAMAccountName=a267-discovery-bound))", "sAMAccountName", "objectGUID", "objectSid", "servicePrincipalName", "userAccountControl", "pwdLastSet", "uSNChanged", "memberOf") // #nosec G204 -- fixed stock read-only LDAP client, owned account filter and protected credential reference; no shell or credential argv (CWE-78)
	command.Env = []string{"PATH=/usr/bin:/bin", "HOME=/nonexistent", "LDAPTLS_CACERT=/run/ad-ca.pem"}
	raw, err := command.Output()
	if err != nil {
		t.Fatal("stock native metadata read failed")
	}
	if !bytes.Contains(raw, []byte("a267-discovery-spn")) || !bytes.Contains(raw, []byte("a267-discovery-bound")) {
		t.Fatal("owned discovery accounts are not seeded")
	}
	return crypto.SHA256Hex(raw)
}
func TestServedADServiceAccountDiscoveryA267(t *testing.T) {
	if os.Getenv("TRSTCTL_AD_SERVED_LAB") != "1" {
		t.Skip("owned Samba and Linux PostgreSQL lab not requested")
	}
	ctx := t.Context()
	st := nativeDesktopOwnedStore(t)
	before := nativeADDiscoveryPublicSnapshot(t, ctx)
	cfg := config.DynamicSecretProviderConfig{TenantID: servedTestTenant, ID: "ad-service-discovery", Type: "ldap", DirectoryMode: "active_directory", Addr: "ad263:636", TLSServerName: "ad263", TLSCARef: "file:/run/ad-ca.pem", BindDN: "CN=Administrator,CN=Users,DC=a263,DC=test", PasswordRef: "file:/run/ad-admin-password", UsersDN: "OU=TrstctlA263,DC=a263,DC=test", AllowedRoles: []string{"directory/discovery"}, RoleBindings: map[string]string{"directory/discovery": "CN=a267-discovery-bound,OU=TrstctlA263,DC=a263,DC=test"}, AllowStaticRotation: true, MaxTTL: "1h"} // #nosec G101 -- configuration carries only a protected credential-file reference, never a credential value (CWE-798)
	providers, err := dynamicSecretProvidersFromConfig(ctx, []config.DynamicSecretProviderConfig{cfg}, nil, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	h := newRoleHarnessNamedWithOwnedStore(t, "ad-discovery-agent", nil, nil, []events.OpenOption{events.WithRequiredPrivacyEventPolicies()}, st, func(d *Deps) {
		d.TenantDynamicSecretProviders = providers
		d.PAM = PAMConfig{Enabled: true, DefaultTTL: time.Minute, MaxTTL: 3 * time.Minute, Attestors: []attest.Attestor{servedPAMAttestor{}}}
	})
	operator := seedScopedTokenSubject(t, st, h.tenant, "ad-service-discovery", "access:read", "access:targets.write")
	root := "/api/v1/access/discovery/sources/ad-service-discovery"
	if status, _ := secretsReqKey(t, h.servedHarness, http.MethodPut, root, operator, "service-discovery-source", map[string]any{"interval_seconds": 0}); status != http.StatusOK {
		t.Fatalf("save discovery source status=%d", status)
	}
	var runID string
	for i := 0; i < 2; i++ {
		status, raw := secretsReqKey(t, h.servedHarness, http.MethodPost, root+"/runs", operator, "service-discovery-run-"+string(rune('a'+i)), nil)
		var run apiRunDiscoveryFixture
		if status != http.StatusAccepted || json.Unmarshal(raw, &run) != nil || run.Status != "queued" {
			t.Fatalf("native discovery run status=%d body=%s", status, raw)
		}
		completed := awaitQueuedDiscoveryProofA267(t, h.servedHarness, operator, run.ID)
		if completed.Status != "completed" {
			t.Fatalf("native worker scan failed: %+v", completed)
		}
		if i == 0 {
			runID = run.ID
		}
	}
	list := func(token string) map[string]apiDiscoveredServiceFixture {
		t.Helper()
		status, raw := secretsReq(t, h.servedHarness, http.MethodGet, "/api/v1/access/discovery/accounts?provider_id=ad-service-discovery", token, nil)
		var page struct {
			Items []apiDiscoveredServiceFixture `json:"items"`
		}
		if status != http.StatusOK || json.Unmarshal(raw, &page) != nil {
			t.Fatalf("list service discoveries status=%d", status)
		}
		found := map[string]apiDiscoveredServiceFixture{}
		for _, account := range page.Items {
			found[account.Name] = account
		}
		return found
	}
	check := func() {
		t.Helper()
		found := list(operator)
		for _, name := range []string{"a267-discovery-spn", "a267-discovery-bound"} {
			account, ok := found[name]
			if !ok || account.Kind != "directory_service_account" || account.Details["service_account"] != "true" || account.Details["native_sid"] == "" || len(account.Details["native_guid"]) != 32 {
				t.Fatal("non-admin AD service account/native identity omitted")
			}
			if len(account.Privileges) != 0 {
				t.Fatal("service-account selection invented administrator rights")
			}
		}
		if !bytes.Contains([]byte(found["a267-discovery-spn"].Details["service_principal_names"]), []byte("HTTP/a267-discovery.test")) {
			t.Fatal("native service principal provenance missing")
		}
	}
	check()
	other := uuid.NewString()
	registerServedTenantID(t, h.servedHarness, other, "AD discovery isolation")
	otherToken := seedScopedToken(t, st, other, "access:read")
	if len(list(otherToken)) != 0 {
		t.Fatal("cross-tenant service discovery leaked")
	}
	if status, _ := secretsReq(t, h.servedHarness, http.MethodGet, "/api/v1/access/discovery/runs/"+runID, otherToken, nil); status != http.StatusNotFound {
		t.Fatal("cross-tenant discovery run leaked")
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
	check()
	if after := nativeADDiscoveryPublicSnapshot(t, ctx); after != before {
		t.Fatal("read-only discovery changed native account state")
	}
	t.Log("A267_AD_DISCOVERY_OK: stock metadata unchanged, SPN/configured non-admin accounts, SID/GUID, no invented rights, tenant isolation and projection rebuild")
}

type apiRunDiscoveryFixture struct{ ID, Status string }
type apiDiscoveredServiceFixture struct {
	Kind       string
	Name       string
	Privileges []string
	Details    map[string]string
}
