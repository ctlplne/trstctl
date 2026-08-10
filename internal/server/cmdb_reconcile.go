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
	// cmdbPageLimit bounds one sweep's read. A CMDB with a hundred thousand CIs
	// must not turn one tick into an unbounded fetch-and-reconcile (AN-7).
	cmdbPageLimit = 500
)

// CMDBReconcileResult is what one sync did, and what it refused to do.
type CMDBReconcileResult struct {
	Read         int
	Applied      int
	Unchanged    int
	Conflicts    int
	Unattributed []string
}

// cmdbEndpoint is a pure builder kept beside the scheduler's fixed bound. Both
// the relay executor and architecture tests use ownership.CMDBEndpoint; no
// network client or credential exists in this control-plane package.
func cmdbEndpoint(instanceURL, query string) (string, error) {
	return ownership.CMDBEndpoint(instanceURL, query, cmdbPageLimit)
}

// reconcileCMDBRecords is the control-plane decision core for a typed relay
// observation. The brain never fetches the CMDB and never resolves its token.
func (s *Server) reconcileCMDBRecords(ctx context.Context, tenantID, resultKey string, observedAt time.Time, records []ownership.Record, unattributed []string) (CMDBReconcileResult, error) {
	out := CMDBReconcileResult{Read: len(records), Unattributed: unattributed}

	owners, err := s.store.ListOwnersPage(ctx, tenantID, store.ZeroUUID, cmdbPageLimit)
	if err != nil {
		return out, err
	}
	byName := make(map[string]store.Owner, len(owners))
	for _, o := range owners {
		byName[strings.ToLower(strings.TrimSpace(o.Name))] = o
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
			continue
		}
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
