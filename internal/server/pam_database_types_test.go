// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"testing"

	"trstctl.com/trstctl/internal/agent/accessgateway"
	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/projections"
)

// TestPAMDatabaseTargetTypesAgreeAcrossLayers: every database target type
// the configuration admits is one the broker builds, the projections record
// and the gateway redeems a credential for; and PostgreSQL stays out of
// database_targets (it has postgres_targets).
func TestPAMDatabaseTargetTypesAgreeAcrossLayers(t *testing.T) {
	for _, targetType := range config.PAMDatabaseTargetTypes {
		if targetType == pamTargetPostgres {
			t.Fatal("pam.database_targets admits postgres; PostgreSQL targets are postgres_targets")
		}
		if !isPAMDatabaseType(targetType) {
			t.Errorf("configuration admits %q, which the broker does not build", targetType)
		}
	}
	for targetType := range pamDatabaseProviderTypes {
		if !projections.PAMDatabaseTargetType(targetType) {
			t.Errorf("the projections refuse the database type %q", targetType)
		}
		if !accessgateway.RedeemsCredential(targetType) {
			t.Errorf("the gateway redeems no credential for %q", targetType)
		}
		if pamDatabaseKinds[targetType] == "" {
			t.Errorf("%q has no operator-facing name", targetType)
		}
	}
	if projections.PAMDatabaseTargetType(pamTargetSSH) || accessgateway.RedeemsCredential(pamTargetSSH) {
		t.Fatal("SSH is treated as a database type")
	}
}
