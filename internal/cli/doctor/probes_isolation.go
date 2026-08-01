// SPDX-License-Identifier: MPL-2.0

package doctor

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"trstctl.com/trstctl/internal/store"
)

const groupIsolation = "tenant-isolation (AN-1)"

// ProbeTenantPrefix is the reserved synthetic prefix of every probe-tenant id.
// It is deliberately unmistakable in an audit log; a real tenant id never
// starts with this, and doctor treats ANY row under it — before or after a run
// — as a leak and a FAIL.
const ProbeTenantPrefix = "00000000-d0c7"

func newProbeTenantID() string {
	// Valid v4-shaped UUID under the reserved prefix: the random tail keeps
	// concurrent doctor runs from colliding.
	tail := uuid.NewString()
	return ProbeTenantPrefix + "-4" + tail[15:]
}

func runIsolationProbes(ctx context.Context, s *store.Store, writeProbe bool) []Probe {
	var out []Probe

	// ISO-1 / ISO-2 reuse the exact shared inventories the CI guards
	// (TestEveryTenantTableForcesRLS, TestNoTenantPolicyIsUsingOnly) assert
	// over, so this probe and the test suite cannot drift.
	states, err := s.TenantTableRLSStates(ctx)
	switch {
	case err != nil:
		out = append(out, Probe{ID: "ISO-1", Group: groupIsolation, Status: StatusFail,
			Detail: "could not inventory tenant tables from pg_catalog: " + err.Error()})
	default:
		var bad []string
		for _, st := range states {
			if !st.Enabled || !st.Forced {
				bad = append(bad, st.Table)
			}
		}
		p := Probe{ID: "ISO-1", Group: groupIsolation,
			Limits:   "proves the catalog posture of every tenant table now, not the absence of RLS-bypassing SQL elsewhere",
			Evidence: map[string]any{"tables_checked": len(states), "source": "pg_class"}}
		switch {
		case len(states) < 20:
			p.Status = StatusFail
			p.Detail = fmt.Sprintf("only %d tenant tables discovered; the catalog derivation is not meaningful against this schema", len(states))
		case len(bad) > 0:
			p.Status = StatusFail
			p.Detail = fmt.Sprintf("%d/%d tenant tables do not both ENABLE and FORCE row level security: %s", len(bad), len(states), strings.Join(bad, ", "))
		default:
			p.Status = StatusPass
			p.Detail = fmt.Sprintf("%d/%d tenant tables ENABLE + FORCE row level security", len(states), len(states))
		}
		out = append(out, p)
	}

	usingOnly, err := s.USINGOnlyTenantPolicies(ctx)
	if err != nil {
		out = append(out, Probe{ID: "ISO-2", Group: groupIsolation, Status: StatusFail,
			Detail: "could not inventory tenant policies from pg_policies: " + err.Error()})
	} else if len(usingOnly) > 0 {
		out = append(out, Probe{ID: "ISO-2", Group: groupIsolation, Status: StatusFail,
			Detail: fmt.Sprintf("%d tenant policies are USING-only (no WITH CHECK): %s", len(usingOnly), strings.Join(usingOnly, ", "))})
	} else {
		out = append(out, Probe{ID: "ISO-2", Group: groupIsolation, Status: StatusPass,
			Detail:   "no USING-only policy on any tenant table (every policy carries WITH CHECK)",
			Limits:   "proves write-check symmetry of the declared policies, not their semantic correctness",
			Evidence: map[string]any{"source": "pg_policies"}})
	}

	// Leak sweep runs in every mode: residue under the reserved prefix from a
	// prior run is a FAIL even before any new probe writes.
	if residue, err := s.DoctorProbeResidue(ctx, ProbeTenantPrefix); err != nil {
		out = append(out, Probe{ID: "ISO-LEAK", Group: groupIsolation, Status: StatusFail,
			Detail: "probe-residue sweep failed: " + err.Error()})
	} else if residue > 0 {
		out = append(out, Probe{ID: "ISO-LEAK", Group: groupIsolation, Status: StatusFail,
			Detail: fmt.Sprintf("%d leaked probe row(s) under the reserved prefix %s* — a prior doctor run did not clean up", residue, ProbeTenantPrefix)})
	} else {
		out = append(out, Probe{ID: "ISO-LEAK", Group: groupIsolation, Status: StatusPass,
			Detail: "no residue under the reserved probe-tenant prefix"})
	}

	if !writeProbe {
		skip := "write probe not permitted (run with --write-probe for the full proof)"
		for _, id := range []string{"ISO-3", "ISO-4", "ISO-5"} {
			out = append(out, Probe{ID: id, Group: groupIsolation, Status: StatusSkip, Detail: skip})
		}
	} else {
		out = append(out, runWriteProbes(ctx, s)...)
	}

	out = append(out, probeTenantContext(ctx, s))

	out = append(out, Probe{ID: "ISO-7", Group: groupIsolation, Status: StatusSkip,
		Detail: "the RLS-bypass call-site inventory is pinned by a compile-time CI guard (TestSystemPoolProductionUseInventory) and is not derivable from a running deployment"})
	return out
}

// runWriteProbes performs the cross-tenant write attempts against two
// ephemeral probe tenants. Rows are deleted afterwards and the deletion is
// verified; failure to clean up is itself a FAIL (emitted as ISO-CLEAN).
func runWriteProbes(ctx context.Context, s *store.Store) (out []Probe) {
	tenantA, tenantB := newProbeTenantID(), newProbeTenantID()
	agentID := uuid.NewString()

	// Deferred, verified cleanup: delete under each probe tenant's own RLS
	// context, then sweep the reserved prefix system-side.
	cleanup := func() Probe {
		for _, tid := range []string{tenantA, tenantB} {
			_ = s.WithTenant(ctx, tid, func(tx pgx.Tx) error {
				if _, err := tx.Exec(ctx, `DELETE FROM ca_authorities WHERE tenant_id = $1`, tid); err != nil {
					return err
				}
				_, err := tx.Exec(ctx, `DELETE FROM agents WHERE tenant_id = $1`, tid)
				return err
			})
		}
		residue, err := s.DoctorProbeResidue(ctx, ProbeTenantPrefix)
		if err != nil {
			return Probe{ID: "ISO-CLEAN", Group: groupIsolation, Status: StatusFail,
				Detail: "cleanup verification failed: " + err.Error()}
		}
		if residue > 0 {
			return Probe{ID: "ISO-CLEAN", Group: groupIsolation, Status: StatusFail,
				Detail: fmt.Sprintf("%d probe row(s) survived cleanup under prefix %s*", residue, ProbeTenantPrefix)}
		}
		return Probe{ID: "ISO-CLEAN", Group: groupIsolation, Status: StatusPass,
			Detail: "probe tenants fully cleaned up (verified zero residue)"}
	}
	defer func() { out = append(out, cleanup()) }()

	// Seed one marker row as tenant A.
	if err := s.UpsertAgent(ctx, store.Agent{ID: agentID, TenantID: tenantA, Name: "doctor-probe", Status: "active"}); err != nil {
		out = append(out, Probe{ID: "ISO-3", Group: groupIsolation, Status: StatusFail,
			Detail: "could not seed the probe marker row as tenant A: " + err.Error()})
		return out
	}

	// ISO-3: tenant B must not read A's row, and must see zero rows.
	if _, err := s.GetAgent(ctx, tenantB, agentID); !errors.Is(err, pgx.ErrNoRows) {
		out = append(out, Probe{ID: "ISO-3", Group: groupIsolation, Status: StatusFail,
			Detail: fmt.Sprintf("cross-tenant read of A's row as B returned %v, want no rows", err)})
	} else {
		out = append(out, Probe{ID: "ISO-3", Group: groupIsolation, Status: StatusPass,
			Detail: "cross-tenant read returned 0 rows (expected 0)",
			Limits: "proves the policy held for this table and this path, not that no bug exists anywhere"})
	}

	// ISO-4: an upsert-hijack of A's primary key as B must be refused and A's
	// row must survive intact.
	err := s.UpsertAgent(ctx, store.Agent{ID: agentID, TenantID: tenantB, Name: "doctor-hijack", Status: "active"})
	if err == nil {
		out = append(out, Probe{ID: "ISO-4", Group: groupIsolation, Status: StatusFail,
			Detail: "a cross-tenant id-collision upsert was ACCEPTED; RLS must reject it fail-closed"})
	} else if a, gerr := s.GetAgent(ctx, tenantA, agentID); gerr != nil || a.Name != "doctor-probe" {
		out = append(out, Probe{ID: "ISO-4", Group: groupIsolation, Status: StatusFail,
			Detail: fmt.Sprintf("the rejected hijack still disturbed tenant A's row (name=%q err=%v)", a.Name, gerr)})
	} else {
		out = append(out, Probe{ID: "ISO-4", Group: groupIsolation, Status: StatusPass,
			Detail: "cross-tenant upsert-hijack refused fail-closed; tenant A's row intact",
			Limits: "proves FORCE-d RLS write symmetry on this table, not every write path"})
	}

	// ISO-5: a cross-tenant foreign-key parent must be rejected by the
	// composite (tenant_id, id) self-reference.
	parent, err := s.InsertCAAuthority(ctx, store.CAAuthority{
		TenantID: tenantA, CommonName: "doctor-probe-root", Kind: "root",
		CertificatePEM: "DOCTOR-PROBE", Serial: "DOCTOR-PROBE-ROOT", MaxPathLen: -1,
	})
	if err != nil {
		out = append(out, Probe{ID: "ISO-5", Group: groupIsolation, Status: StatusFail,
			Detail: "could not seed the probe CA parent as tenant A: " + err.Error()})
		return out
	}
	if _, err := s.InsertCAAuthority(ctx, store.CAAuthority{
		TenantID: tenantB, ParentID: &parent.ID, CommonName: "doctor-probe-sub", Kind: "intermediate",
		CertificatePEM: "DOCTOR-PROBE", Serial: "DOCTOR-PROBE-SUB", MaxPathLen: -1,
	}); err == nil {
		out = append(out, Probe{ID: "ISO-5", Group: groupIsolation, Status: StatusFail,
			Detail: "a cross-tenant parent_id was ACCEPTED; the composite tenant-scoped FK must reject it"})
	} else {
		out = append(out, Probe{ID: "ISO-5", Group: groupIsolation, Status: StatusPass,
			Detail: "cross-tenant foreign-key parent rejected",
			Limits: "proves the composite-FK fence on ca_authorities, the pattern's reference table"})
	}
	return out
}

// probeTenantContext is ISO-6: the application path runs as a non-owner role
// with a transaction-local tenant GUC — inside WithTenant the role is the app
// role and the GUC carries the tenant; outside, the GUC is empty.
func probeTenantContext(ctx context.Context, s *store.Store) Probe {
	probeTenant := newProbeTenantID()
	var role, guc string
	if err := s.WithTenant(ctx, probeTenant, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT current_user, current_setting('trstctl.tenant_id', true)`).Scan(&role, &guc)
	}); err != nil {
		return Probe{ID: "ISO-6", Group: groupIsolation, Status: StatusFail,
			Detail: "could not inspect the tenant execution context: " + err.Error()}
	}
	var outside string
	//trstctl:system-query — cross-tenant by design: reads only current_setting() to prove the tenant GUC is transaction-local (empty outside WithTenant); touches no tenant rows and no tenant_id predicate applies to a GUC read.
	if err := s.SystemPool().QueryRow(ctx, `SELECT coalesce(current_setting('trstctl.tenant_id', true), '')`).Scan(&outside); err != nil {
		return Probe{ID: "ISO-6", Group: groupIsolation, Status: StatusFail,
			Detail: "could not read the GUC outside a tenant transaction: " + err.Error()}
	}
	switch {
	case role == "trstctl_app" && guc == probeTenant && outside == "":
		return Probe{ID: "ISO-6", Group: groupIsolation, Status: StatusPass,
			Detail:   "tenant work runs as trstctl_app with a transaction-local trstctl.tenant_id GUC (unset outside the transaction)",
			Evidence: map[string]any{"role": role},
			Limits:   "proves the connection discipline of this client path; server handlers are asserted by the same WithTenant implementation"}
	default:
		return Probe{ID: "ISO-6", Group: groupIsolation, Status: StatusFail,
			Detail: fmt.Sprintf("tenant context wrong: role=%q guc=%q outside=%q (want trstctl_app / the probe tenant / empty)", role, guc, outside)}
	}
}
