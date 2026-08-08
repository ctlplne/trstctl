// SPDX-License-Identifier: MPL-2.0

package server

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"trstctl.com/trstctl/internal/crypto/secret"
	"trstctl.com/trstctl/internal/ownership"
	"trstctl.com/trstctl/internal/projections"
	"trstctl.com/trstctl/internal/secrettext"
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

// RunCMDBReconcileOnce reads a tenant's CMDB and reconciles ownership.
//
// It only ever GETs. There is no write path here and the ticket writer's table
// allow-list does not contain cmdb_ci, so "no CMDB write unless explicitly
// configured" holds because no such code exists — not because a flag is off.
//
// Conflicts are recorded, never resolved by overwriting: ownership.Reconcile
// decides, and its rule is that a source fills in what nobody recorded and
// never overwrites what a human attested.
func (s *Server) RunCMDBReconcileOnce(ctx context.Context, tenantID string, sched store.CMDBReconcileSchedule) (CMDBReconcileResult, error) {
	body, err := s.fetchCMDBPage(ctx, sched)
	if err != nil {
		return CMDBReconcileResult{}, err
	}
	defer func() { _ = body.Close() }()
	records, unattributed, err := ownership.ParseCMDB(body)
	if err != nil {
		return CMDBReconcileResult{}, err
	}
	return s.reconcileCMDBRecords(ctx, tenantID, records, unattributed)
}

// reconcileCMDBRecords is the reconcile core, shared by BOTH vantages: the
// control plane's own fetch above, and a relay's reported observation (I2).
// One implementation, because the rule that matters — a source fills in what
// nobody recorded and never overwrites what a human attested — must not have
// a second copy that drifts on the vantage exercised less.
func (s *Server) reconcileCMDBRecords(ctx context.Context, tenantID string, records []ownership.Record, unattributed []string) (CMDBReconcileResult, error) {
	out := CMDBReconcileResult{Read: len(records), Unattributed: unattributed}

	owners, err := s.store.ListOwnersPage(ctx, tenantID, store.ZeroUUID, cmdbPageLimit)
	if err != nil {
		return out, err
	}
	byName := make(map[string]store.Owner, len(owners))
	for _, o := range owners {
		byName[strings.ToLower(strings.TrimSpace(o.Name))] = o
	}
	now := time.Now().UTC()
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
		}, ownership.SourceCMDB, now)
		out.Unchanged += plan.Unchanged
		out.Applied += len(plan.Apply)
		out.Conflicts += len(plan.Conflicts)
		// AN-2: the change goes through the log, not into the read model. The
		// whole value of this feature is answering "where did this ownership
		// come from, and what did we overrule to get it" — an answer that lives
		// only in a mutable row cannot survive a rebuild.
		if err := s.orch.ReconcileOwnership(ctx, tenantID, projections.OwnershipReconciledFrom(
			existing.ID, string(ownership.SourceCMDB), rec.SourceRef, now, plan)); err != nil {
			return out, err
		}
	}
	return out, nil
}

// fetchCMDBPage performs the read. GET only, through the same egress guard the
// ticket path uses, against an instance the operator's binding allow-list has
// approved.
func (s *Server) fetchCMDBPage(ctx context.Context, sched store.CMDBReconcileSchedule) (io.ReadCloser, error) {
	endpoint, err := cmdbEndpoint(sched.InstanceURL, sched.CIQuery)
	if err != nil {
		return nil, err
	}
	// The private-egress grant is the OPERATOR's, resolved now rather than
	// copied when the schedule was saved: narrowing the grant must take effect
	// on the next sync, not the next time somebody re-saves the schedule.
	var cidrs []string
	if sched.AllowPrivateEndpoint {
		for _, b := range s.serviceNowBindings {
			if strings.TrimRight(b.InstanceURL, "/") == strings.TrimRight(sched.InstanceURL, "/") &&
				b.AllowPrivateEndpoint {
				cidrs = b.PrivateEgressCIDRs
				break
			}
		}
		if len(cidrs) == 0 {
			return nil, fmt.Errorf("server: CMDB schedule requests a private endpoint but no operator " +
				"binding grants private egress to that instance; the schedule outlived its grant")
		}
	}
	client, err := cloudHTTPClient(endpoint, sched.AllowPrivateEndpoint, cidrs)
	if err != nil {
		return nil, fmt.Errorf("server: CMDB endpoint rejected: %w", err)
	}
	token, err := resolveDiscoveryCredentialRef(ctx, sched.TokenRef)
	if err != nil {
		return nil, fmt.Errorf("server: resolve ServiceNow token ref: %w", err)
	}
	tokenBytes := []byte(token)
	defer secret.Wipe(tokenBytes)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return nil, fmt.Errorf("server: build CMDB request: %w", err)
	}
	req.Header.Set("Authorization", secrettext.Prefixed("Bearer ", tokenBytes))
	req.Header.Set("Accept", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("server: read CMDB: %w", err)
	}
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		limited, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		_ = resp.Body.Close()
		return nil, fmt.Errorf("server: CMDB read failed with status %d: %s",
			resp.StatusCode, strings.TrimSpace(string(limited)))
	}
	return resp.Body, nil
}

// cmdbEndpoint delegates to the shared builder beside ParseCMDB, so the
// control plane and the relay (I2) cannot drift on which table may be read.
func cmdbEndpoint(instanceURL, query string) (string, error) {
	return ownership.CMDBEndpoint(instanceURL, query, cmdbPageLimit)
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
			if sched.Execution == "relay" {
				// I2: the read happens from a network relay inside the segment.
				// The scheduler's job shrinks to dispatching; the report path
				// runs the reconcile and stamps the real outcome.
				s.dispatchCMDBSyncJob(ctx, tenantID, sched)
				continue
			}
			res, runErr := s.RunCMDBReconcileOnce(ctx, tenantID, sched)
			msg := ""
			if runErr != nil {
				msg = runErr.Error()
				s.logger.Warn("cmdb reconcile failed",
					slog.String("tenant_id", tenantID), slog.String("error", msg))
			} else {
				s.logger.Info("cmdb reconcile complete",
					slog.String("tenant_id", tenantID),
					slog.Int("read", res.Read), slog.Int("applied", res.Applied),
					slog.Int("conflicts", res.Conflicts),
					slog.Int("unattributed", len(res.Unattributed)))
			}
			if err := s.store.MarkCMDBScheduleRun(ctx, tenantID, time.Now().UTC(), msg); err != nil {
				s.logger.Warn("cmdb scheduler: stamp run failed",
					slog.String("tenant_id", tenantID), slog.String("error", err.Error()))
			}
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
