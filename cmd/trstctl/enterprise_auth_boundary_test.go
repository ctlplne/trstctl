// SPDX-License-Identifier: BUSL-1.1

package main

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/license"
	"trstctl.com/trstctl/internal/server"
)

// Run in both normal and core-only builds: an enabled tenant authentication
// method must never silently fall back to an unlicensed implementation.
func TestTenantEnterpriseAuthRefusesUnlicensedStartup(t *testing.T) {
	const want = "SAML, LDAP and SCIM login require an Enterprise licence."
	for _, method := range []string{"saml", "ldap", "scim", "all"} {
		for _, absent := range []bool{false, true} {
			name := method + "/community"
			if absent {
				name = method + "/no-manager"
			}
			t.Run(name, func(t *testing.T) {
				dir := t.TempDir()
				cfg := &config.Config{}
				cfg.Auth.SAML.Enabled = method == "saml" || method == "all"
				cfg.Auth.SAML.SessionSecretFile = filepath.Join(dir, "saml-session")
				cfg.Auth.SAML.IDPMetadataFile = filepath.Join(dir, "absent-metadata")
				cfg.Auth.LDAP.Enabled = method == "ldap" || method == "all"
				cfg.Auth.LDAP.SessionSecretFile = filepath.Join(dir, "ldap-session")
				cfg.Auth.LDAP.BindPasswordFile = filepath.Join(dir, "absent-bind-password")
				cfg.Auth.SCIM.Enabled = method == "scim" || method == "all"
				lic := license.Community()
				if absent {
					lic = nil
				}
				err := attachEE(context.Background(), cfg, nil, lic, &server.Deps{})
				if err == nil || err.Error() != want {
					t.Fatalf("unlicensed %s startup = %v, want %q before credential loading", method, err, want)
				}
				entries, err := os.ReadDir(dir)
				if err != nil || len(entries) != 0 {
					t.Fatalf("refused startup created authentication material: entries=%v err=%v", entries, err)
				}
			})
		}
	}
}

func TestTenantOIDCDoesNotRequireEnterpriseAttach(t *testing.T) {
	cfg := &config.Config{}
	cfg.Auth.OIDC.Enabled = true
	// OIDC validation and construction belong to core, after this seam. An
	// Enterprise check must not intercept even an incomplete OIDC configuration.
	if err := attachEE(context.Background(), cfg, nil, license.Community(), &server.Deps{}); err != nil {
		t.Fatalf("core OIDC was intercepted by the Enterprise seam: %v", err)
	}
}
