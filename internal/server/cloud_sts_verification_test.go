// SPDX-License-Identifier: BUSL-1.1
package server

import (
	"errors"
	"testing"
	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/egress"
)

func TestCloudSTSDefaultOriginHonorsAirGapA264(t *testing.T) {
	guard, err := egress.NewGuard(egress.Config{Enabled: true})
	if err != nil {
		t.Fatal(err)
	}
	provider := &configuredDynamicProvider{cfg: config.DynamicSecretProviderConfig{Type: "aws-sts", Region: "us-east-1"}, guard: guard}
	if _, err := provider.VerifyLeaseCredential(t.Context(), []byte(`{}`)); !errors.Is(err, egress.ErrBlocked) || guard.Trips() != 1 {
		t.Fatalf("default STS origin bypassed air-gap policy: %v", err)
	}
	allowed, err := egress.NewGuard(egress.Config{Enabled: true, AllowHosts: []string{"sts.us-east-1.amazonaws.com"}})
	if err != nil {
		t.Fatal(err)
	}
	provider.guard = allowed
	provider.allowedRoles = map[string]bool{"reader": true}
	provider.cfg.RoleBindings = map[string]string{"reader": "arn:aws:iam::111122223333:role/reader"}
	if _, err := provider.VerifyLeaseCredential(t.Context(), []byte(`{}`)); err == nil || errors.Is(err, egress.ErrBlocked) || allowed.Trips() != 0 {
		t.Fatalf("configured default STS origin was not admitted before credential validation: %v", err)
	}

}
