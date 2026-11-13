// SPDX-License-Identifier: LicenseRef-trstctl-EE

// Package misuse is basic misuse detection for Enterprise governance (M2). It
// reads the usage trstctl records from its own activity (M1) and flags two
// deviations: an API token requesting a dynamic-secret lease from a client
// network it has not used on three different days while it has a network it
// has, and an hour in which a token's secret reads reach at least 64 and four
// times its largest earlier hour in the last 14 days. Each deviation becomes a
// finding (one per token, rule and day, so repeats fold into it) and, within a
// per-tenant hourly budget, one alert through the notification outbox. A
// leader worker detects on a bounded schedule; the findings read model is a
// projection of misuse.finding.detected, so it rebuilds from the event log and
// a rebuild never alerts again.
package misuse

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/eventspec"
	"trstctl.com/trstctl/internal/notify"
	"trstctl.com/trstctl/internal/projections"
	"trstctl.com/trstctl/internal/store"
)

// EventFindingDetected records one misuse finding.
const EventFindingDetected = "misuse.finding.detected"

// Rules.
const (
	RuleNewSourceLease  = "new_source_lease"
	RuleSecretReadBurst = "secret_read_burst" // #nosec G101 -- identifier/constant matching the secret-name heuristic; no credential value present (CWE-798)
)

const (
	normalDays       = 3
	burstFloor       = 64
	burstFactor      = 4
	burstLookback    = 14 * 24 * time.Hour
	detectWindow     = 2 * time.Hour
	candidateLimit   = 100
	defaultInterval  = time.Minute
	defaultHourlyCap = 20
	// alertReconcileWindow bounds the M2-L4 reconciliation to findings
	// detected this recently: long enough to cover a projection delayed by a
	// database outage, well inside the day a delivered alert row is kept
	// (internal/outboxgc), so an alert that was written is always seen and
	// never written again.
	alertReconcileWindow = 6 * time.Hour
)

var findingNamespace = uuid.MustParse("3b8f6d2e-91c4-4f7a-a5d0-2c6e8b1f9a47")

// FindingDetected is the payload of misuse.finding.detected. Alerted says
// whether the finding raised an alert; false means the tenant's hourly alert
// budget was spent, and the finding stands without one.
type FindingDetected struct {
	Rule          string    `json:"rule"`
	CredentialID  string    `json:"credential_id"`
	Principal     string    `json:"principal"`
	Source        string    `json:"source"`
	WindowStart   time.Time `json:"window_start"`
	ObservedCount int       `json:"observed_count"`
	Baseline      int       `json:"baseline,omitempty"`
	NormalSources []string  `json:"normal_sources,omitempty"`
	Alerted       bool      `json:"alerted"`
}

// Projection is the misuse findings read model, rebuilt from the event log.
type Projection struct{ store *store.Store }

// NewProjection returns the findings projection.
func NewProjection(st *store.Store) *Projection { return &Projection{store: st} }

// Name implements projections.EventProjection.
func (p *Projection) Name() string { return "misuse_findings" }

// Reset clears the read model before a full replay.
func (p *Projection) Reset(ctx context.Context) error {
	tx, err := p.store.SystemPool().Begin(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if err := p.ResetTx(ctx, tx); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

// ResetTx clears the read model inside a rebuild transaction.
func (p *Projection) ResetTx(ctx context.Context, tx pgx.Tx) error {
	//trstctl:system-query — cross-tenant full rebuild uses a system transaction to clear only the derived misuse findings and policies; tenant-bound immutable events restore them under RLS.
	if _, err := tx.Exec(ctx, `DELETE FROM misuse_findings`); err != nil {
		return err
	}
	//trstctl:system-query — the same rebuild clears the derived misuse policies (M2-L2).
	if _, err := tx.Exec(ctx, `DELETE FROM misuse_policies`); err != nil {
		return err
	}
	//trstctl:system-query — and the derived misuse incidents (M2-L3).
	_, err := tx.Exec(ctx, `DELETE FROM misuse_incidents`)
	return err
}

// Apply projects one event in its own tenant transaction.
func (p *Projection) Apply(ctx context.Context, ev eventspec.Event) error {
	if ev.Type != EventFindingDetected && ev.Type != EventPolicySet && ev.Type != EventIncidentOpened && ev.Type != EventIncidentClosed {
		return nil
	}
	return p.store.WithTenant(ctx, ev.TenantID, func(tx pgx.Tx) error { return p.ApplyTx(ctx, tx, ev) })
}

// ApplyTx projects one event inside the caller's transaction. Applying the
// same event twice changes nothing.
func (p *Projection) ApplyTx(ctx context.Context, tx pgx.Tx, ev eventspec.Event) error {
	if ev.Type == EventPolicySet {
		return p.applyPolicySetTx(ctx, tx, ev)
	}
	if ev.Type == EventIncidentOpened || ev.Type == EventIncidentClosed {
		return p.applyIncidentTx(ctx, tx, ev)
	}
	if ev.Type != EventFindingDetected {
		return nil
	}
	var f FindingDetected
	if err := json.Unmarshal(ev.Data, &f); err != nil {
		return fmt.Errorf("misuse: decode %s: %w", ev.Type, err)
	}
	if (f.Rule != RuleNewSourceLease && f.Rule != RuleSecretReadBurst) || f.CredentialID == "" || f.ObservedCount < 1 || ev.Sequence == 0 {
		return fmt.Errorf("misuse: %s payload is incomplete", ev.Type)
	}
	if err := p.store.SetTenantGUCTx(ctx, tx, ev.TenantID); err != nil {
		return err
	}
	_, err := tx.Exec(ctx, `
		INSERT INTO misuse_findings (tenant_id, finding_id, rule, credential_id, principal, source, window_start,
		                             observed_count, baseline, alerted, detected_at, event_sequence)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)
		ON CONFLICT (tenant_id, finding_id) DO NOTHING`,
		ev.TenantID, ev.ID, f.Rule, f.CredentialID, f.Principal, f.Source, f.WindowStart.UTC(),
		f.ObservedCount, f.Baseline, f.Alerted, ev.Time.UTC(), int64(ev.Sequence)) // #nosec G115 -- event sequences fit int64 (CWE-190)
	return err
}

var _ projections.TransactionalEventProjection = (*Projection)(nil)

// Detector is the leader's misuse detection worker.
type Detector struct {
	store     *store.Store
	log       *events.Log
	proj      *Projection
	now       func() time.Time
	interval  time.Duration
	hourlyCap int
	logger    *slog.Logger
}

// Options configure a Detector; zero values use the defaults.
type Options struct {
	Store     *store.Store
	Log       *events.Log
	Logger    *slog.Logger
	Now       func() time.Time
	Interval  time.Duration
	HourlyCap int
}

// NewDetector returns the detection worker and the projection it writes
// through.
func NewDetector(opts Options) (*Detector, *Projection) {
	proj := NewProjection(opts.Store)
	d := &Detector{store: opts.Store, log: opts.Log, proj: proj, now: opts.Now, interval: opts.Interval,
		hourlyCap: opts.HourlyCap, logger: opts.Logger}
	if d.now == nil {
		d.now = time.Now
	}
	if d.interval <= 0 {
		d.interval = defaultInterval
	}
	if d.hourlyCap <= 0 {
		d.hourlyCap = defaultHourlyCap
	}
	return d, proj
}

// Name implements server.BackgroundWorker.
func (d *Detector) Name() string { return "misuse_detector" }

// Run detects on every interval until ctx ends.
func (d *Detector) Run(ctx context.Context) error {
	ticker := time.NewTicker(d.interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
			if err := d.DetectOnce(ctx); err != nil && d.logger != nil {
				d.logger.Warn("misuse detection could not check every tenant", slog.String("error", err.Error()))
			}
		}
	}
}

type candidate struct {
	finding FindingDetected
	id      string
}

// DetectOnce checks the last two hours of usage of every tenant once.
func (d *Detector) DetectOnce(ctx context.Context) error {
	if d.store == nil || d.log == nil {
		return errors.New("misuse: detector needs the store and the event log")
	}
	now := d.now().UTC()
	since := now.Add(-detectWindow).Truncate(time.Hour)
	tenants, err := d.store.TenantsWithUsageWindowsSince(ctx, since)
	if err != nil {
		return err
	}
	var firstErr error
	for _, tenantID := range tenants {
		if err := d.detectTenant(ctx, tenantID, since, now); err != nil && firstErr == nil {
			firstErr = fmt.Errorf("tenant %s: %w", tenantID, err)
		}
		if err := d.reconcileAlerts(ctx, tenantID, now); err != nil && firstErr == nil {
			firstErr = fmt.Errorf("tenant %s: %w", tenantID, err)
		}
	}
	return firstErr
}

// reconcileAlerts writes the alert of an alerting finding that has none
// (M2-L4). record appends the finding's event and then, in one tenant
// transaction, projects it and enqueues its alert; when that transaction
// fails after the append, the event tail projects the finding later but
// nothing enqueued its alert. The alert is rebuilt from the finding's own
// event and keyed as record keys it, so it is written once.
func (d *Detector) reconcileAlerts(ctx context.Context, tenantID string, now time.Time) error {
	type missing struct {
		id       string
		sequence int64
	}
	var findings []missing
	err := d.store.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `
			SELECT f.finding_id, f.event_sequence FROM misuse_findings f
			 WHERE f.tenant_id = $1 AND f.alerted AND f.detected_at >= $2
			   AND NOT EXISTS (SELECT 1 FROM outbox o
			                    WHERE o.tenant_id = f.tenant_id AND o.destination = $3
			                      AND o.idempotency_key = 'misuse:' || f.finding_id)
			 ORDER BY f.event_sequence
			 LIMIT $4`, tenantID, now.Add(-alertReconcileWindow), notify.DestinationRisk, candidateLimit)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var m missing
			if err := rows.Scan(&m.id, &m.sequence); err != nil {
				return err
			}
			findings = append(findings, m)
		}
		return rows.Err()
	})
	if err != nil {
		return err
	}
	if len(findings) == 0 {
		return nil
	}
	policy, err := readPolicy(ctx, d.store, tenantID, DefaultPolicy(d.hourlyCap))
	if err != nil {
		return err
	}
	for _, m := range findings {
		ev, ok, err := d.log.EventAtSequence(ctx, uint64(m.sequence)) // #nosec G115 -- a projected event sequence is positive (CWE-190)
		if err != nil {
			return err
		}
		if !ok || ev.Type != EventFindingDetected || ev.ID != m.id || ev.TenantID != tenantID {
			continue
		}
		var f FindingDetected
		if err := json.Unmarshal(ev.Data, &f); err != nil {
			return fmt.Errorf("misuse: decode finding %s: %w", m.id, err)
		}
		if err := d.store.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
			return enqueueAlert(ctx, tx, tenantID, m.id, f, policy.Policy)
		}); err != nil {
			return err
		}
	}
	return nil
}

func (d *Detector) detectTenant(ctx context.Context, tenantID string, since, now time.Time) error {
	// M2-L2: the tenant's own thresholds, or the defaults.
	policy, err := readPolicy(ctx, d.store, tenantID, DefaultPolicy(d.hourlyCap))
	if err != nil {
		return err
	}
	leases, err := d.store.NewSourceUses(ctx, tenantID, projections.CredentialActionLeaseRequest, since, policy.NormalDays, candidateLimit)
	if err != nil {
		return err
	}
	bursts, err := d.store.UsageBursts(ctx, tenantID, projections.CredentialActionSecretRead, since, policy.BurstFloor, policy.BurstFactor,
		time.Duration(policy.BurstLookbackDays)*24*time.Hour, candidateLimit)
	if err != nil {
		return err
	}
	var found []candidate
	for _, u := range leases {
		found = append(found, newCandidate(tenantID, FindingDetected{
			Rule: RuleNewSourceLease, CredentialID: u.CredentialID, Principal: u.Principal, Source: u.Source,
			WindowStart: u.WindowStart, ObservedCount: u.Count, NormalSources: u.NormalSources,
		}))
	}
	for _, b := range bursts {
		found = append(found, newCandidate(tenantID, FindingDetected{
			Rule: RuleSecretReadBurst, CredentialID: b.CredentialID, Principal: b.Principal, Source: b.Source,
			WindowStart: b.WindowStart, ObservedCount: b.Count, Baseline: b.Baseline,
		}))
	}
	if len(found) == 0 {
		return nil
	}
	budget, err := d.alertBudget(ctx, tenantID, now, policy.HourlyAlertCap)
	if err != nil {
		return err
	}
	for _, c := range found {
		if _, exists, err := d.log.EventByID(ctx, c.id); err != nil {
			return err
		} else if exists {
			continue // the same credential, rule and day: it folds into the finding
		}
		c.finding.Alerted = budget > 0
		if c.finding.Alerted {
			budget--
		}
		if err := d.record(ctx, tenantID, c, policy.Policy); err != nil {
			return err
		}
	}
	return nil
}

// newCandidate names a finding by tenant, rule, credential and the UTC day of
// its window, so a deviation that repeats that day folds into one finding.
func newCandidate(tenantID string, f FindingDetected) candidate {
	day := f.WindowStart.UTC().Format("2006-01-02")
	id := uuid.NewSHA1(findingNamespace, []byte(tenantID+"\x00"+f.Rule+"\x00"+f.CredentialID+"\x00"+day)).String()
	return candidate{finding: f, id: id}
}

func (d *Detector) alertBudget(ctx context.Context, tenantID string, now time.Time, hourlyCap int) (int, error) {
	var raised int
	err := d.store.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT count(*) FROM misuse_findings WHERE tenant_id = $1 AND alerted AND detected_at > $2`,
			tenantID, now.Add(-time.Hour)).Scan(&raised)
	})
	return hourlyCap - raised, err
}

// record appends the finding, projects it and, when it alerts, enqueues the
// alert in the same tenant transaction (AN-2, AN-6).
func (d *Detector) record(ctx context.Context, tenantID string, c candidate, policy Policy) error {
	payload, err := json.Marshal(c.finding)
	if err != nil {
		return err
	}
	return d.store.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		ev, err := d.log.Append(ctx, events.Event{ID: c.id, Type: EventFindingDetected, TenantID: tenantID, Data: payload})
		if err != nil {
			return err
		}
		if err := d.proj.ApplyTx(ctx, tx, ev); err != nil {
			return err
		}
		// M2-L3: the finding opens its token's incident when none is open.
		if err := d.openIncidentTx(ctx, tx, tenantID, c); err != nil {
			return err
		}
		if !c.finding.Alerted {
			return nil
		}
		return enqueueAlert(ctx, tx, tenantID, c.id, c.finding, policy)
	})
}

// enqueueAlert writes one finding's alert to the outbox, keyed by the finding
// so it is written at most once (AN-6).
func enqueueAlert(ctx context.Context, tx pgx.Tx, tenantID, id string, f FindingDetected, policy Policy) error {
	alert, err := json.Marshal(map[string]any{
		"kind": "credential.misuse", "tenant_id": tenantID, "operation_id": "misuse:" + id,
		"subject": alertSubject(f), "detail": alertDetail(f, policy), "severity": "high",
	})
	if err != nil {
		return err
	}
	_, err = tx.Exec(ctx, `INSERT INTO outbox (tenant_id, destination, payload, idempotency_key)
		VALUES ($1, $2, $3, $4) ON CONFLICT DO NOTHING`, tenantID, notify.DestinationRisk, alert, "misuse:"+id)
	return err
}

func alertSubject(f FindingDetected) string {
	return "API token " + f.CredentialID + " (" + f.Principal + ")"
}

func alertDetail(f FindingDetected, policy Policy) string {
	switch f.Rule {
	case RuleNewSourceLease:
		return fmt.Sprintf("requested a dynamic-secret lease from %s, a network it has not used on %d different days (its normal networks: %v), in the hour from %s",
			f.Source, policy.NormalDays, f.NormalSources, f.WindowStart.UTC().Format(time.RFC3339))
	default:
		return fmt.Sprintf("read secrets %d times from %s in the hour from %s; its largest earlier hour in %d days was %d",
			f.ObservedCount, f.Source, f.WindowStart.UTC().Format(time.RFC3339), policy.BurstLookbackDays, f.Baseline)
	}
}
