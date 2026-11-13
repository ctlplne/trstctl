// SPDX-License-Identifier: LicenseRef-trstctl-EE

package billing

import (
	"context"
	"errors"
	"log/slog"
	"sync/atomic"
	"time"

	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/projections"
	corestore "trstctl.com/trstctl/internal/store"
	"trstctl.com/trstctl/internal/usage"
)

// The billing-sync sweep (MSP-2): on the leader, for every configured
// billing target and every customer mapped to a company there, each closed
// period of the target's cadence is signed and queued for delivery once, or
// held with its reason (and one alert) when it cannot be signed. Delivery,
// its record and its retries belong to the core outbox; the sweep never
// sends anything itself.

// BillingSyncQueuer is the core command side the sweep drives.
type BillingSyncQueuer interface {
	QueueBillingSyncPush(ctx context.Context, tenantID string, push projections.BillingSyncPushEvent) (bool, error)
	HoldBillingSyncPush(ctx context.Context, tenantID string, push projections.BillingSyncPushEvent) (bool, error)
}

// syncMeters are the figures a period push carries: the customer's current
// certificates, agents and stored secrets.
var syncMeters = map[string]bool{usage.MeterCertificatesCurrent: true, usage.MeterAgents: true, usage.MeterSecretsStored: true}

const (
	// syncCatchUpPeriods bounds how far back a sweep looks.
	syncCatchUpPeriods = 3
	// syncGrace lets metering cover a period's last minutes before the
	// sweep judges it, so a period is not held for a coverage gap that
	// closes a minute later.
	syncGrace = 2 * time.Hour
	// syncMaxPerSweep bounds one sweep's work (backpressure).
	syncMaxPerSweep = 500
)

// SyncSweeper is the leader worker.
type SyncSweeper struct {
	Store    *corestore.Store
	Evidence EvidenceDeps
	Targets  []config.ProviderBillingTarget
	Interval time.Duration
	Log      *slog.Logger
	Now      func() time.Time

	queuer atomic.Pointer[billingSyncQueuerBox]
}

type billingSyncQueuerBox struct{ q BillingSyncQueuer }

// Bind attaches the core command side once the orchestrator is assembled;
// until then a sweep does nothing.
func (s *SyncSweeper) Bind(q BillingSyncQueuer) {
	if s != nil && q != nil {
		s.queuer.Store(&billingSyncQueuerBox{q: q})
	}
}

// Name identifies the worker.
func (s *SyncSweeper) Name() string { return "provider.billing_sync.sweep" }

// Run sweeps every Interval until ctx ends.
func (s *SyncSweeper) Run(ctx context.Context) error {
	interval := s.Interval
	if interval <= 0 {
		interval = 10 * time.Minute
	}
	for {
		if _, err := s.Sweep(ctx); err != nil && ctx.Err() == nil && s.Log != nil {
			s.Log.Warn("billing sync sweep failed", slog.String("error", err.Error()))
		}
		select {
		case <-ctx.Done():
			return nil
		case <-time.After(interval):
		}
	}
}

// SweepResult counts one sweep's outcomes.
type SweepResult struct {
	Queued, Held, Skipped int
}

// Sweep runs one pass and reports what it queued and held.
func (s *SyncSweeper) Sweep(ctx context.Context) (SweepResult, error) {
	var out SweepResult
	box := s.queuer.Load()
	if box == nil || s.Store == nil {
		return out, nil
	}
	if s.Evidence.Reader == nil {
		return out, errors.New("billing: billing sync needs the metering store")
	}
	now := time.Now().UTC()
	if s.Now != nil {
		now = s.Now().UTC()
	}
	work := 0
	var firstErr error
	for _, target := range s.Targets {
		if !target.PushesUsage() {
			continue
		}
		mappings, err := s.Store.BillingCompanyMappings(ctx, target.ID)
		if err != nil {
			return out, err
		}
		for _, period := range ClosedSyncPeriods(target.EffectiveCadence(), now.Add(-syncGrace), syncCatchUpPeriods) {
			for _, m := range mappings {
				if work >= syncMaxPerSweep || ctx.Err() != nil {
					return out, firstErr
				}
				existing, found, err := s.Store.BillingSyncPushFor(ctx, m.TenantID, target.ID, period.Start)
				if err != nil {
					firstErr = errors.Join(firstErr, err)
					continue
				}
				if found && existing.Status != corestore.BillingSyncHeld {
					out.Skipped++
					continue
				}
				work++
				queued, err := s.syncOne(ctx, box.q, target.ID, m, period, now)
				if err != nil {
					firstErr = errors.Join(firstErr, err)
					continue
				}
				if queued {
					out.Queued++
				} else {
					out.Held++
				}
			}
		}
	}
	return out, firstErr
}

// syncOne signs one customer's period and queues it, or holds it with the
// reason the evidence refuses to be signed.
func (s *SyncSweeper) syncOne(ctx context.Context, q BillingSyncQueuer, targetID string, m corestore.BillingCompanyMapping, period SyncPeriod, now time.Time) (bool, error) {
	coverage, err := s.Evidence.Reader.CoverageFor(ctx, m.TenantID)
	if err != nil {
		return false, err
	}
	records, err := s.Evidence.Reader.Query(ctx, period.Start, period.End, m.TenantID)
	if err != nil {
		return false, err
	}
	doc, err := BuildSignedEvidence(ctx, EvidencePeriod{CustomerID: m.TenantID, Start: period.Start, End: period.End},
		coverage, records, s.Evidence.Reconciler, s.Evidence.Signer, now)
	if err != nil {
		return false, err
	}
	push := projections.BillingSyncPushEvent{
		TargetID: targetID, PeriodStart: period.Start, PeriodEnd: period.End,
		ExternalCompanyID: m.ExternalCompanyID, EvidenceDigest: doc.Digest,
	}
	if !doc.Signable || doc.Signature == nil || doc.Signature.JWS == "" {
		push.Reason = doc.Reason
		if push.Reason == "" {
			push.Reason = "the period's evidence carries no signature"
		}
		_, err := q.HoldBillingSyncPush(ctx, m.TenantID, push)
		return false, err
	}
	push.EvidenceJWS = doc.Signature.JWS
	for _, line := range doc.Lines {
		if syncMeters[line.Meter] {
			push.Lines = append(push.Lines, projections.BillingUsageLine{Meter: line.Meter, Kind: line.Kind, Value: line.Value})
		}
	}
	_, err = q.QueueBillingSyncPush(ctx, m.TenantID, push)
	return err == nil, err
}

// SyncPeriod is one whole UTC calendar period.
type SyncPeriod struct{ Start, End time.Time }

// ClosedSyncPeriods are the latest n whole periods of a cadence that ended at
// or before asOf, oldest first.
func ClosedSyncPeriods(cadence string, asOf time.Time, n int) []SyncPeriod {
	asOf = asOf.UTC()
	var end time.Time
	step := func(t time.Time) time.Time { return t.AddDate(0, -1, 0) }
	if cadence == "daily" {
		end = time.Date(asOf.Year(), asOf.Month(), asOf.Day(), 0, 0, 0, 0, time.UTC)
		step = func(t time.Time) time.Time { return t.AddDate(0, 0, -1) }
	} else {
		end = time.Date(asOf.Year(), asOf.Month(), 1, 0, 0, 0, 0, time.UTC)
	}
	out := make([]SyncPeriod, n)
	for i := n - 1; i >= 0; i-- {
		start := step(end)
		out[i] = SyncPeriod{Start: start, End: end}
		end = start
	}
	return out
}
