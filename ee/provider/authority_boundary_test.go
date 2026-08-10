// SPDX-License-Identifier: LicenseRef-trstctl-EE

package provider

import (
	"reflect"
	"testing"

	"trstctl.com/trstctl/ee/billing"
	"trstctl.com/trstctl/ee/whitelabel"
)

// A PostgreSQL authority writer is an AN-2 bypass even if no current caller
// uses it: the next feature can discover and call the method. Keep the durable
// stores read-only so event projection is the only compilable write path.
func TestPostgresProviderAuthorityStoresExposeNoDirectMutators(t *testing.T) {
	t.Parallel()
	for _, target := range []struct {
		name    string
		typ     reflect.Type
		methods []string
	}{
		{"provider registry", reflect.TypeOf((*PGStore)(nil)), []string{
			"CreateTenant", "UpdateTenantStatus", "CreateBreakGlassGrant",
			"UpdateBreakGlassGrant", "IncrementBreakGlassUse",
		}},
		{"delegation view", reflect.TypeOf((*PGDelegationSource)(nil)), []string{
			"Grant", "Revoke", "RevokeAllForCustomer",
		}},
		{"quota view", reflect.TypeOf((*billing.PGStore)(nil)), []string{"SetQuota"}},
		{"brand view", reflect.TypeOf((*whitelabel.PGStore)(nil)), []string{
			"SetTenantBrand", "SetProviderBrand",
		}},
	} {
		for _, method := range target.methods {
			if _, ok := target.typ.MethodByName(method); ok {
				t.Errorf("%s exposes direct mutator %s; provider authority must enter through MutationSink", target.name, method)
			}
		}
	}
}
