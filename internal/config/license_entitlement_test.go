// SPDX-License-Identifier: BUSL-1.1

package config

import (
	"strings"
	"testing"
)

func TestAUD56LicenseDeploymentBindingConfiguration(t *testing.T) {
	base := map[string]string{
		"TRSTCTL_LICENSE_FILE":          "/etc/trstctl/license.json",
		"TRSTCTL_LICENSE_DEPLOYMENT_ID": "acme-stage",
		"TRSTCTL_LICENSE_ENVIRONMENT":   "non_production",
	}
	cfg, err := Load(func(key string) string { return base[key] })
	if err != nil {
		t.Fatal(err)
	}
	if cfg.License.DeploymentID != "acme-stage" || cfg.License.Environment != "non_production" {
		t.Fatalf("license deployment binding = %+v", cfg.License)
	}

	for name, override := range map[string]map[string]string{
		"id without environment": {
			"TRSTCTL_LICENSE_FILE":          "/etc/trstctl/license.json",
			"TRSTCTL_LICENSE_DEPLOYMENT_ID": "acme-stage",
		},
		"environment without id": {
			"TRSTCTL_LICENSE_FILE":        "/etc/trstctl/license.json",
			"TRSTCTL_LICENSE_ENVIRONMENT": "non_production",
		},
		"unknown environment": {
			"TRSTCTL_LICENSE_FILE":          "/etc/trstctl/license.json",
			"TRSTCTL_LICENSE_DEPLOYMENT_ID": "acme-stage",
			"TRSTCTL_LICENSE_ENVIRONMENT":   "staging",
		},
	} {
		t.Run(name, func(t *testing.T) {
			_, err := Load(func(key string) string { return override[key] })
			if err == nil || !strings.Contains(err.Error(), "license") {
				t.Fatalf("Load() error = %v, want a named license deployment error", err)
			}
		})
	}
}
