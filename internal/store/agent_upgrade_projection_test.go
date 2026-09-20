// SPDX-License-Identifier: BUSL-1.1

package store_test

import (
	"context"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
)

// DP2-048: a campaign-opened event that lost the one-active-campaign rule can
// already be durable in an older log. Projecting it must absorb the loser rather
// than fail forever and wedge the event tail; the winner stays the active campaign.
func TestAgentUpgradeCampaignOpenedProjectionAbsorbsASecondActiveCampaign(t *testing.T) {
	st := newStore(t)
	seedTwoTenants(t, st)
	ctx := context.Background()
	now := time.Now().UTC()
	const winner, loser = "0dc00000-0000-4000-8000-000000000001", "0dc00000-0000-4000-8000-000000000002"
	for _, id := range []string{winner, loser, loser} {
		if err := st.WithTenant(ctx, tenantA, func(tx pgx.Tx) error {
			return st.ApplyAgentUpgradeCampaignOpenedTx(ctx, tx, tenantA, id, "2.0.0", "ops", []byte(`{}`), now)
		}); err != nil {
			t.Fatalf("project campaign %s: %v", id, err)
		}
	}
	active, found, err := st.ActiveAgentUpgradeCampaign(ctx, tenantA)
	if err != nil || !found || active.ID != winner {
		t.Fatalf("active campaign = %+v found=%v err=%v, want the winner %s", active, found, err, winner)
	}
	var rows int
	if err := st.SystemPool().QueryRow(ctx, `SELECT count(*) FROM agent_upgrade_campaigns WHERE tenant_id = $1::uuid`, tenantA).Scan(&rows); err != nil {
		t.Fatal(err)
	}
	if rows != 1 {
		t.Fatalf("campaign rows = %d, want the winner only", rows)
	}
}
