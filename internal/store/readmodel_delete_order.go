// SPDX-License-Identifier: MPL-2.0

package store

import (
	"fmt"
	"strings"
)

// RMODEL-001 — the rebuild's tenant erase covers EVERY event-sourced read model.
//
// DeleteTenantReadModelTx replays a tenant.offboarded event during an atomic
// read-model rebuild (RESIL-003). It used to carry its own hand-typed table list,
// which drifted seven tables behind ReadModelTables: agents,
// kubernetes_controller_posture, tenant_members, ca_authorities,
// incident_executions, machine_sessions and machine_auth_method_overrides. The
// replay re-derived those rows from the log and then never deleted them, so a
// rebuilt read model resurrected an offboarded tenant's data — tenant_members holds
// member subject identities and email addresses, so the residue is personal data.
//
// The live erase was never affected: Store.OffboardTenant iterates
// TenantScopedTables, which already covers all seven and fails closed on residue.
// This is the DR/rebuild boundary only.
//
// The fix is structural rather than seven more hand-typed names: the SET is DERIVED
// from ReadModelTables here, so adding an event-sourced read model cannot leave this
// path behind, and the ORDER is borrowed from TenantScopedTables so there is no
// second ordering to maintain either.

// readModelDeleteOrder returns every table in ReadModelTables, arranged so a
// per-table DELETE never trips a foreign key: children before the parents they
// reference, and the tenant's own `tenants` row last.
//
// The order is taken from TenantScopedTables — the authoritative FK-safe erase order
// the live OffboardTenant path uses, which the offboarding catalog test keeps in sync
// with the live schema. Restricting a valid topological order to a subset of its
// nodes yields a valid topological order for that subset, so filtering it down to the
// read-model tables preserves FK safety.
//
// It fails closed (AN-1): a read-model table absent from TenantScopedTables has no
// known FK-safe position, so the caller gets an error — rolling the rebuild
// transaction back — instead of a silently partial tenant erase.
func readModelDeleteOrder() ([]string, error) {
	inReadModel := make(map[string]bool, len(ReadModelTables))
	for _, table := range ReadModelTables {
		inReadModel[table] = true
	}

	ordered := make([]string, 0, len(inReadModel))
	placed := make(map[string]bool, len(inReadModel))
	for _, table := range TenantScopedTables {
		if !inReadModel[table] || placed[table] {
			continue
		}
		placed[table] = true
		ordered = append(ordered, table)
	}

	if len(ordered) != len(inReadModel) {
		missing := make([]string, 0, len(inReadModel)-len(ordered))
		for _, table := range ReadModelTables {
			if !placed[table] {
				missing = append(missing, table)
			}
		}
		return nil, fmt.Errorf(
			"store: read-model table(s) %s are absent from TenantScopedTables, so no FK-safe rebuild-erase order exists for them (RMODEL-001)",
			strings.Join(missing, ", "))
	}
	return ordered, nil
}
