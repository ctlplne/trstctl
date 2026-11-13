// SPDX-License-Identifier: LicenseRef-trstctl-EE

package billing_test

import (
	"context"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"trstctl.com/trstctl/ee/billing"
	"trstctl.com/trstctl/internal/config"
)

type rmmQueuer struct {
	mu     sync.Mutex
	queued []string
}

func (q *rmmQueuer) QueueRMMInventory(_ context.Context, tenantID, targetID string, bucket time.Time) (bool, error) {
	q.mu.Lock()
	defer q.mu.Unlock()
	q.queued = append(q.queued, tenantID[:8]+"/"+targetID+"/"+bucket.Format("15:04"))
	return true, nil
}

// MSP-9: the RMM sweep queues one inventory per mapped customer of every RMM
// target for the current interval (nothing before Bind, nothing for a
// billing target), and the billing sweep pushes no usage to an RMM target.
func TestRMMSweepQueuesOneInventoryPerMappedCustomerMSP9(t *testing.T) {
	ctx := context.Background()
	_, cs := newBillingStoreOn(t, "billing_rmm_sweep_msp9")
	const customerA, customerB = "1a2b3c4d-0000-4000-8000-00000000009a", "1a2b3c4d-0000-4000-8000-00000000009b"
	if _, err := cs.SystemPool().Exec(ctx, `INSERT INTO provider_billing_companies (tenant_id, target_id, external_company_id, mapped_by, mapped_at)
		VALUES ($1, 'ninja', '11', 'op', now()), ($2, 'ninja', '22', 'op', now()), ($1, 'psa', 'COMPANY-A', 'op', now())`, customerA, customerB); err != nil {
		t.Fatal(err)
	}
	targets := []config.ProviderBillingTarget{{ID: "ninja", Type: "ninjaone"}, {ID: "psa", Type: "json"}}
	if got := billing.RMMTargets(config.ProviderBillingSync{Targets: targets}); len(got) != 1 || got[0].ID != "ninja" {
		t.Fatalf("RMM targets = %+v", got)
	}
	now := time.Date(2026, time.November, 13, 9, 37, 0, 0, time.UTC)
	sweeper := &billing.RMMSweeper{Store: cs, Targets: targets, Now: func() time.Time { return now }}
	if n, err := sweeper.Sweep(ctx); n != 0 || err != nil {
		t.Fatalf("an unbound sweep = %d %v", n, err)
	}
	q := &rmmQueuer{}
	sweeper.Bind(q)
	n, err := sweeper.Sweep(ctx)
	sort.Strings(q.queued)
	if err != nil || n != 2 || strings.Join(q.queued, ",") != "1a2b3c4d/ninja/09:30,1a2b3c4d/ninja/09:30" {
		t.Fatalf("sweep = %d %v, queued %v", n, err, q.queued)
	}

	// The billing sweep pushes no usage to the RMM target.
	usage := &syncQueuer{}
	billingSweeper := &billing.SyncSweeper{Store: cs, Evidence: billing.EvidenceDeps{Reader: syncReader{durable: map[string]bool{customerA: true}, asOf: now}},
		Targets: []config.ProviderBillingTarget{{ID: "ninja", Type: "ninjaone"}}, Now: func() time.Time { return now }}
	billingSweeper.Bind(usage)
	if res, err := billingSweeper.Sweep(ctx); err != nil || res != (billing.SweepResult{}) || len(usage.queued)+len(usage.held) != 0 {
		t.Fatalf("the billing sweep on an RMM target = %+v %v", res, err)
	}
}
