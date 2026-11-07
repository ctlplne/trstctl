// SPDX-License-Identifier: BUSL-1.1
package server

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/dynsecret"
)

func TestADReconcileProviderIsFrozenScopedAndCannotFallBackA267(t *testing.T) {
	root := t.TempDir()
	cfg := config.DynamicSecretProviderConfig{TenantID: servedTestTenant, ID: "ad-reconcile-scope", Type: "ldap", DirectoryMode: "active_directory", Addr: "directory.example:636", BindDN: "CN=rotation,OU=operators,DC=example,DC=test", PasswordRef: "file:" + filepath.Join(root, "ordinary-missing"), UsersDN: "OU=services,DC=example,DC=test", AllowedRoles: []string{"directory/service", "directory/other"}, RoleBindings: map[string]string{"directory/service": "CN=service,OU=services,DC=example,DC=test", "directory/other": "CN=other,OU=services,DC=example,DC=test"}, AllowStaticRotation: true, MaxTTL: "1h", ADReconcile: &config.ADReconcileConfig{BindDN: "CN=reconcile,OU=operators,DC=example,DC=test", PasswordRef: "file:" + filepath.Join(root, "designated-missing"), SID: "S-1-5-21-1-2-3-1002", GUID: strings.Repeat("a", 32), AllowedRoles: []string{"directory/service"}}}
	original := newConfiguredDynamicProvider(cfg, map[string]bool{"directory/service": true, "directory/other": true}, time.Hour, integrationCredentialResolver{}, nil)
	selector, ok := original.(dynsecret.StaticReconciliationProvider)
	if !ok {
		t.Fatal("explicit AD provider has no designated reconciliation capability")
	}
	// Configuration attachment owns a copy, so caller mutation cannot widen the
	// selected principal or its scope after it has been validated.
	cfg.ADReconcile.GUID = strings.Repeat("b", 32)
	cfg.ADReconcile.AllowedRoles[0] = "directory/other"
	selected, principal, err := selector.StaticReconciliation("directory/service")
	if err != nil {
		t.Fatal(err)
	}
	if selected == original || selected.Name() != original.Name() || principal.DN != "CN=reconcile,OU=operators,DC=example,DC=test" || principal.SID != "S-1-5-21-1-2-3-1002" || principal.GUID != strings.Repeat("a", 32) {
		t.Fatal("selected authority differs from the frozen designated principal")
	}
	if _, err := selected.Generate(context.Background(), dynsecret.GenerateRequest{Role: "directory/service", Static: true}); err == nil {
		t.Fatal("designated authority accepted an unprepared native effect")
	}
	normalBinding := original.(dynsecret.PreparedStaticRotationProvider).StaticRotationBinding("directory/service")
	selectedPrepared, ok := selected.(dynsecret.PreparedStaticRotationProvider)
	if !ok || selectedPrepared.StaticRotationBinding("directory/service") == "" || selectedPrepared.StaticRotationBinding("directory/service") == normalBinding {
		t.Fatal("ordinary and reconcile preparations share an authority binding")
	}
	if selected.(dynsecret.StaticRotationProvider).AllowsStaticRotation("directory/other") || selectedPrepared.StaticRotationBinding("directory/other") != "" {
		t.Fatal("derived reconciliation widened its single reviewed role")
	}
	if _, _, err := selector.StaticReconciliation("directory/other"); err == nil {
		t.Fatal("ungranted reconcile role accepted")
	}
	if _, _, err := selector.StaticReconciliation("unknown"); err == nil {
		t.Fatal("unknown reconcile role accepted")
	}
	// Both references are absent. The exact designated path error proves that
	// the derived opener did not retain the ordinary provider's captured closure.
	_, err = selectedPrepared.PrepareStaticCredential(context.Background(), dynsecret.GenerateRequest{Role: "directory/service", Static: true, LeaseID: "57500000-0000-4000-8000-000000000001", Predecessor: cfg.RoleBindings["directory/service"]})
	var pathErr *os.PathError
	if !errors.As(err, &pathErr) || pathErr.Path != filepath.Join(root, "designated-missing") {
		t.Fatalf("designated failure did not remain on its own credential reference: %T", err)
	}
	frozen := selectedPrepared.StaticRotationBinding("directory/service")
	selected.(*configuredADRotationProvider).rotationBindDN = "CN=other-rotation,OU=operators,DC=example,DC=test"
	if selectedPrepared.StaticRotationBinding("directory/service") == frozen {
		t.Fatal("preparation did not bind the ordinary writer identity exclusion")
	}
	if original.(dynsecret.PreparedStaticRotationProvider).StaticRotationBinding("directory/service") != normalBinding {
		t.Fatal("selection changed the registered ordinary provider")
	}
}
