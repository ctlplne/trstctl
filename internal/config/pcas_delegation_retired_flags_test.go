// SPDX-License-Identifier: BUSL-1.1

package config_test

import (
	"strings"
	"testing"

	"trstctl.com/trstctl/internal/config"
)

func TestPCASDelegationLegacyControlPlaneSettingsFailWithSignerMigrationHint(t *testing.T) {
	for _, name := range []string{
		"TRSTCTL_PCAS_DELEGATION_ENABLED",
		"TRSTCTL_PCAS_DELEGATION_REFRESH_INTERVAL",
		"TRSTCTL_PCAS_DELEGATION_SIGNER_STORE_DIR",
	} {
		_, err := config.Load(func(key string) string {
			if key == name {
				return "true"
			}
			return ""
		})
		if err == nil || !strings.Contains(err.Error(), "signer --keystore") {
			t.Errorf("legacy %s = %v; want actionable migration error", name, err)
		}
	}
	if _, err := config.Parse([]byte(`{"pcas":{"delegation":{"enabled":true}}}`)); err == nil || !strings.Contains(err.Error(), "signer --keystore") {
		t.Errorf("legacy config file = %v; want actionable migration error", err)
	}
}
