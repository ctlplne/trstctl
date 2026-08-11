// SPDX-License-Identifier: MPL-2.0

package store

import "testing"

// RMODEL-001 guard: the rebuild's replay of tenant.offboarded
// (DeleteTenantReadModelTx) must erase EVERY event-sourced read model, in an order
// no foreign key can block. These are pure list assertions over the manifests, so
// the drift they catch — a read model added to ReadModelTables but not to the
// rebuild's erase — is caught without a database.

// TestReadModelDeleteOrderCoversEveryReadModelTable is the completeness gate: the
// rebuild delete order is the whole of ReadModelTables and nothing else, each table
// exactly once. A new read model is covered automatically; a read model that
// TenantScopedTables cannot place is a hard error rather than a silent omission.
func TestReadModelDeleteOrderCoversEveryReadModelTable(t *testing.T) {
	ordered, err := readModelDeleteOrder()
	if err != nil {
		t.Fatalf("readModelDeleteOrder: %v", err)
	}

	count := make(map[string]int, len(ordered))
	for _, table := range ordered {
		count[table]++
	}
	for table, n := range count {
		if n != 1 {
			t.Errorf("%s appears %d times in the rebuild delete order; each table must be deleted exactly once", table, n)
		}
	}

	inReadModel := make(map[string]bool, len(ReadModelTables))
	for _, table := range ReadModelTables {
		inReadModel[table] = true
	}
	for _, table := range ReadModelTables {
		if count[table] == 0 {
			t.Errorf("%s is in ReadModelTables but not in the rebuild delete order; a rebuilt read model would resurrect an offboarded tenant's rows in it (RMODEL-001)", table)
		}
	}
	for _, table := range ordered {
		if !inReadModel[table] {
			t.Errorf("%s is in the rebuild delete order but not in ReadModelTables; the rebuild must not delete from tables it does not own", table)
		}
	}

	if len(count) != len(inReadModel) {
		t.Fatalf("rebuild delete order covers %d distinct tables, ReadModelTables has %d distinct tables", len(count), len(inReadModel))
	}
}

// TestReadModelDeleteOrderIsForeignKeySafe pins the ordering the per-table DELETEs
// depend on: every child before the parent it references, and the tenant's own row
// last. The pairs are the RESTRICT / NO ACTION foreign keys between read-model
// tables declared in internal/store/migrations:
//
//	identities -> owners, issuers                        0004_core_data_model.sql
//	certificates -> owners                               0006_certificates.sql
//	ca_ceremony_approvals -> ca_key_ceremonies           0008_ca_hierarchy.sql
//	discovery_runs -> discovery_schedules                0037_discovery_control_plane.sql
//	secret_sync_workload_identity_sources ->
//	    workload_attester_trust_sources                  0088_secret_sync_workload_identity_sources.sql
func TestReadModelDeleteOrderIsForeignKeySafe(t *testing.T) {
	ordered, err := readModelDeleteOrder()
	if err != nil {
		t.Fatalf("readModelDeleteOrder: %v", err)
	}

	position := make(map[string]int, len(ordered))
	for i, table := range ordered {
		position[table] = i
	}

	edges := [][2]string{
		{"identities", "owners"},
		{"identities", "issuers"},
		{"certificates", "owners"},
		{"ca_ceremony_approvals", "ca_key_ceremonies"},
		{"discovery_runs", "discovery_schedules"},
		{"secret_sync_workload_identity_sources", "workload_attester_trust_sources"},
		{"operation_approval_decisions", "operation_approval_requests"},
	}
	for _, edge := range edges {
		child, parent := edge[0], edge[1]
		c, ok := position[child]
		if !ok {
			t.Errorf("%s is missing from the rebuild delete order", child)
			continue
		}
		p, ok := position[parent]
		if !ok {
			t.Errorf("%s is missing from the rebuild delete order", parent)
			continue
		}
		if c >= p {
			t.Errorf("%s (position %d) must be deleted before %s (position %d) or the foreign key blocks the tenant erase", child, c, parent, p)
		}
	}

	if len(ordered) == 0 || ordered[len(ordered)-1] != "tenants" {
		t.Fatalf("the tenants row must be deleted last; rebuild delete order = %v", ordered)
	}
}

// TestReadModelDeleteOrderCoversPreviouslyOmittedTables names the seven tables the
// hand-typed list had drifted past, so the specific regression — an offboarded
// tenant's tenant_members (member subject identities and email addresses), agents,
// CA authorities, incident executions and machine sessions coming back after a
// read-model rebuild — cannot return unnoticed even if the derivation above is ever
// rewritten.
func TestReadModelDeleteOrderCoversPreviouslyOmittedTables(t *testing.T) {
	ordered, err := readModelDeleteOrder()
	if err != nil {
		t.Fatalf("readModelDeleteOrder: %v", err)
	}

	covered := make(map[string]bool, len(ordered))
	for _, table := range ordered {
		covered[table] = true
	}
	for _, table := range []string{
		"agents",
		"kubernetes_controller_posture",
		"tenant_members",
		"ca_authorities",
		"incident_executions",
		"machine_sessions",
		"machine_auth_method_overrides",
	} {
		if !covered[table] {
			t.Errorf("%s is not erased by the rebuild's tenant.offboarded replay; an offboarded tenant's rows in it survive a rebuild (RMODEL-001 regression)", table)
		}
	}
}
