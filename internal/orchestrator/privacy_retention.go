package orchestrator

import (
	"context"
	"fmt"
	"time"

	"trstctl.com/trstctl/internal/privacy"
	"trstctl.com/trstctl/internal/store"
)

// PrivacyRetentionSummary reports one worker pass.
type PrivacyRetentionSummary struct {
	TenantsProcessed int
	RunsRecorded     int
	RowsAnonymized   int
	Counts           map[string]int
}

// PrivacyRetentionWorker runs the non-audit PII retention policy across tenants.
type PrivacyRetentionWorker struct {
	orch   *Orchestrator
	store  *store.Store
	policy privacy.RetentionPolicy
	source privacy.RetentionPolicySource
	now    func() time.Time
}

// NewPrivacyRetentionWorker returns a worker for the configured policy.
func NewPrivacyRetentionWorker(orch *Orchestrator, st *store.Store, policy privacy.RetentionPolicy, sources ...privacy.RetentionPolicySource) *PrivacyRetentionWorker {
	var source privacy.RetentionPolicySource
	if len(sources) > 0 {
		source = sources[0]
	}
	return &PrivacyRetentionWorker{orch: orch, store: st, policy: policy.WithDefaults(), source: source, now: time.Now}
}

// RunOnce performs one pass across all tenants. Tenant enumeration is a system
// operation; each retention command re-enters the tenant-scoped event/projection
// path before changing read-model rows.
func (w *PrivacyRetentionWorker) RunOnce(ctx context.Context) (PrivacyRetentionSummary, error) {
	sum := PrivacyRetentionSummary{Counts: map[string]int{}}
	if w == nil || w.orch == nil || w.store == nil {
		return sum, nil
	}
	tenants, err := w.store.ListTenants(ctx)
	if err != nil {
		return sum, fmt.Errorf("privacy retention: list tenants: %w", err)
	}
	now := w.now().UTC()
	for _, tenant := range tenants {
		policy, err := privacy.ResolveRetentionPolicy(ctx, w.source, tenant.TenantID, w.policy)
		if err != nil {
			return sum, fmt.Errorf("privacy retention: tenant %s policy: %w", tenant.TenantID, err)
		}
		run, err := w.orch.EnforcePrivacyRetention(ctx, tenant.TenantID, policy, now)
		if err != nil {
			return sum, fmt.Errorf("privacy retention: tenant %s: %w", tenant.TenantID, err)
		}
		sum.TenantsProcessed++
		sum.RunsRecorded++
		for k, v := range run.Counts {
			sum.Counts[k] += v
			sum.RowsAnonymized += v
		}
	}
	return sum, nil
}
