// SPDX-License-Identifier: MPL-2.0

package server

import (
	"context"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"trstctl.com/trstctl/internal/ownership"
	"trstctl.com/trstctl/internal/projections"
	"trstctl.com/trstctl/internal/store"
)

const (
	// cmdbSchedulerInterval bounds how quickly a due schedule is noticed. Each
	// schedule's own interval decides when it is due; this is detection latency
	// only, matching the discovery scheduler.
	cmdbSchedulerInterval = time.Minute
	// cmdbPageLimit bounds one relay job and one page event. A large CMDB is a
	// chain of these bounded units, never one unbounded fetch/reconcile (AN-7).
	cmdbPageLimit = 500
)

// CMDBReconcileResult is what one sync did, and what it refused to do.
type CMDBReconcileResult struct {
	Read         int
	Applied      int
	Unchanged    int
	Conflicts    int
	Unattributed []string
	Observations []projections.CMDBCIObservation
}

// cmdbEndpoint is a compatibility helper for the architecture tests. The relay
// executor uses the same ownership builder with a durable cursor; no network
// client or credential exists in this control-plane package.
func cmdbEndpoint(instanceURL, query string) (string, error) {
	return ownership.CMDBPageEndpoint(instanceURL, query, cmdbPageLimit, "")
}

// reconcileCMDBRecords is the control-plane decision core for a typed relay
// observation. The brain never fetches the CMDB and never resolves its token.
func (s *Server) reconcileCMDBRecords(ctx context.Context, tenantID, resultKey string, observedAt time.Time, records []ownership.Record, unattributed []string) (CMDBReconcileResult, error) {
	out := CMDBReconcileResult{Read: len(records), Unattributed: unattributed}

	names := make([]string, 0, len(records))
	for _, record := range records {
		names = append(names, record.OwnerName)
	}
	owners, err := s.store.ListOwnersByNames(ctx, tenantID, names)
	if err != nil {
		return out, err
	}
	byName := make(map[string]store.Owner, len(owners))
	ambiguous := make(map[string]bool)
	for _, o := range owners {
		key := strings.ToLower(strings.TrimSpace(o.Name))
		if _, duplicate := byName[key]; duplicate {
			delete(byName, key)
			ambiguous[key] = true
			continue
		}
		if !ambiguous[key] {
			byName[key] = o
		}
	}
	if observedAt.IsZero() {
		return out, fmt.Errorf("server: CMDB relay report has no observation time")
	}
	for _, rec := range records {
		existing, ok := byName[strings.ToLower(strings.TrimSpace(rec.OwnerName))]
		if !ok {
			// A CMDB naming an owner this estate has never heard of is NOT an
			// invitation to create one. A CI's assignment group is not evidence
			// that a trstctl owner should exist, and auto-creating would build a
			// parallel estate out of the CMDB's typos. It is reported instead.
			out.Unattributed = append(out.Unattributed, rec.OwnerName)
			out.Observations = append(out.Observations, projections.CMDBCIObservation{SourceRef: rec.SourceRef})
			continue
		}
		out.Observations = append(out.Observations, projections.CMDBCIObservation{
			SourceRef: rec.SourceRef, OwnerID: existing.ID,
			ApplicationID: rec.ApplicationID, Service: rec.Service,
			BusinessUnit: rec.BusinessUnit, Environment: rec.Environment,
		})
		plan := ownership.Reconcile(rec, ownership.Existing{
			OwnerID:       existing.ID,
			ApplicationID: existing.ApplicationID,
			Service:       existing.Service,
			BusinessUnit:  existing.BusinessUnit,
			Environment:   existing.Environment,
			Attested:      existing.OwnershipAttested(),
		}, ownership.SourceCMDB, observedAt)
		out.Unchanged += plan.Unchanged
		out.Applied += len(plan.Apply)
		out.Conflicts += len(plan.Conflicts)
		// AN-2: the change goes through the log, not into the read model. The
		// whole value of this feature is answering "where did this ownership
		// come from, and what did we overrule to get it" — an answer that lives
		// only in a mutable row cannot survive a rebuild.
		event := projections.OwnershipReconciledFrom(
			existing.ID, string(ownership.SourceCMDB), rec.SourceRef, observedAt, plan)
		if err := s.orch.ReconcileOwnershipFromRelay(ctx, tenantID, resultKey, event); err != nil {
			return out, err
		}
		// A page may carry several CIs for one owner. Keep the in-memory row in
		// step with each projected event so the stable sys_id order decides the
		// final value, and a crash retry replays the same per-CI event sequence.
		for _, applied := range plan.Apply {
			switch applied.Field {
			case "application_id":
				existing.ApplicationID = applied.Value
			case "service":
				existing.Service = applied.Value
			case "business_unit":
				existing.BusinessUnit = applied.Value
			case "environment":
				existing.Environment = applied.Value
			}
		}
		byName[strings.ToLower(strings.TrimSpace(rec.OwnerName))] = existing
	}
	return out, nil
}

// RunCMDBScheduler is the leader-only ticker. A failed sync stamps the schedule
// with its error and retries next interval, so a CMDB that is down does not
// hot-loop and does not silently look idle.
func (s *Server) RunCMDBScheduler(ctx context.Context) {
	if s.store == nil {
		return
	}
	sweep := func() {
		tenants, err := s.store.TenantsWithEnabledCMDBSchedules(ctx)
		if err != nil {
			s.logger.Warn("cmdb scheduler: list tenants failed", slog.String("error", err.Error()))
			return
		}
		for _, tenantID := range tenants {
			sched, due, err := s.store.CMDBScheduleDue(ctx, tenantID, time.Now())
			if err != nil || !due {
				continue
			}
			// The only production execution path is a tenant-scoped durable
			// network-relay job. The report path performs the decision.
			s.dispatchCMDBSyncJob(ctx, tenantID, sched)
		}
	}
	sweep()
	t := time.NewTicker(cmdbSchedulerInterval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			sweep()
		}
	}
}
