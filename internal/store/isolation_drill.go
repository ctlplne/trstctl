// SPDX-License-Identifier: MPL-2.0

package store

import (
	"context"
	"errors"
	"fmt"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// On-demand tenant-isolation drill (epic L3).
//
// The provider console needs to prove, at any moment, that the deployment's
// tenant isolation actually holds — not that it held when the doctor last ran,
// but right now, on demand, with a fresh recorded outcome. This is the same
// cross-tenant read/write proof the doctor's ISO probes run, made callable at
// runtime so a provider operator can trigger it and get an attestation.
//
// It is NON-INVASIVE: it uses two ephemeral probe tenants under the reserved
// probe prefix, never a real customer's tenancy, and it verifies its own
// cleanup. A drill that left probe rows behind would be a worse outcome than
// one that never ran, so residual rows are themselves a FAIL.

// isolationProbePrefix is the reserved synthetic prefix of every drill probe
// tenant. It is deliberately identical to the doctor's ProbeTenantPrefix
// (internal/cli/doctor) so DoctorProbeResidue and the doctor's own leak sweep
// both recognise — and refuse to ignore — any residue a drill leaves behind.
// Keep the two values in lockstep.
const isolationProbePrefix = "00000000-d0c7"

func newIsolationProbeTenantID() string {
	tail := uuid.NewString()
	return isolationProbePrefix + "-4" + tail[15:]
}

// IsolationDrillCheck is one assertion in a drill and whether it held.
type IsolationDrillCheck struct {
	Name   string `json:"name"`
	Passed bool   `json:"passed"`
	Detail string `json:"detail"`
}

// IsolationDrillReport is the outcome of one isolation drill. Passed is true
// only if every check — including cleanup — passed.
type IsolationDrillReport struct {
	Passed bool                  `json:"passed"`
	Checks []IsolationDrillCheck `json:"checks"`
}

// RunIsolationDrill runs one on-demand tenant-isolation drill and returns a
// structured report. The error return is reserved for the drill being unable to
// run at all (e.g. it could not seed its own marker); a deployment whose
// isolation is BROKEN returns a report with Passed=false and a non-nil error is
// not raised for that — the failed drill is a result, not an outage.
func (s *Store) RunIsolationDrill(ctx context.Context) (report IsolationDrillReport, err error) {
	tenantA, tenantB := newIsolationProbeTenantID(), newIsolationProbeTenantID()
	agentID := uuid.NewString()

	// Verified cleanup runs no matter how the drill exits, and its own result is
	// a check: probe rows that survive are a failure of the drill.
	defer func() {
		for _, tid := range []string{tenantA, tenantB} {
			_ = s.WithTenant(ctx, tid, func(tx pgx.Tx) error {
				_, derr := tx.Exec(ctx, `DELETE FROM agents WHERE tenant_id = $1`, tid)
				return derr
			})
		}
		residue, rerr := s.DoctorProbeResidue(ctx, isolationProbePrefix)
		switch {
		case rerr != nil:
			report.Checks = append(report.Checks, IsolationDrillCheck{
				Name: "cleanup", Passed: false, Detail: "cleanup verification failed: " + rerr.Error()})
		case residue > 0:
			report.Checks = append(report.Checks, IsolationDrillCheck{
				Name: "cleanup", Passed: false,
				Detail: fmt.Sprintf("%d probe row(s) survived cleanup under prefix %s*", residue, isolationProbePrefix)})
		default:
			report.Checks = append(report.Checks, IsolationDrillCheck{
				Name: "cleanup", Passed: true, Detail: "probe tenants fully cleaned up (verified zero residue)"})
		}
		report.Passed = true
		for _, c := range report.Checks {
			if !c.Passed {
				report.Passed = false
				break
			}
		}
	}()

	// Seed one marker row as tenant A. If even this fails the drill cannot make
	// its assertions, so it is the one condition surfaced as an error.
	if seedErr := s.UpsertAgent(ctx, Agent{ID: agentID, TenantID: tenantA, Name: "isolation-drill", Status: "active"}); seedErr != nil {
		return report, fmt.Errorf("store: isolation drill could not seed its probe marker: %w", seedErr)
	}

	// Check 1 — cross-tenant read denial: tenant B must see zero rows even
	// though A has one, so a neighbour cannot read this tenancy's data.
	if _, gerr := s.GetAgent(ctx, tenantB, agentID); errors.Is(gerr, pgx.ErrNoRows) {
		report.Checks = append(report.Checks, IsolationDrillCheck{
			Name: "cross_tenant_read_denied", Passed: true,
			Detail: "a neighbouring tenant read 0 rows of the marker (expected 0)"})
	} else {
		report.Checks = append(report.Checks, IsolationDrillCheck{
			Name: "cross_tenant_read_denied", Passed: false,
			Detail: fmt.Sprintf("a neighbouring tenant's read returned %v, want no rows", gerr)})
	}

	// Check 2 — cross-tenant write symmetry: an upsert-hijack of A's primary key
	// as tenant B must be refused fail-closed, and A's row must survive intact.
	// Without FORCE-d RLS the table owner would bypass the policy and this write
	// would land.
	hijackErr := s.UpsertAgent(ctx, Agent{ID: agentID, TenantID: tenantB, Name: "isolation-drill-hijack", Status: "active"})
	if hijackErr == nil {
		report.Checks = append(report.Checks, IsolationDrillCheck{
			Name: "cross_tenant_write_refused", Passed: false,
			Detail: "a cross-tenant id-collision upsert was ACCEPTED; RLS must reject it fail-closed"})
	} else if a, aerr := s.GetAgent(ctx, tenantA, agentID); aerr != nil || a.Name != "isolation-drill" {
		report.Checks = append(report.Checks, IsolationDrillCheck{
			Name: "cross_tenant_write_refused", Passed: false,
			Detail: fmt.Sprintf("the refused hijack still disturbed the marker (name=%q err=%v)", a.Name, aerr)})
	} else {
		report.Checks = append(report.Checks, IsolationDrillCheck{
			Name: "cross_tenant_write_refused", Passed: true,
			Detail: "cross-tenant upsert-hijack refused fail-closed; the marker row is intact"})
	}

	return report, nil
}
