// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/projections"
	"trstctl.com/trstctl/internal/store"
)

// G2-L3: the lease access worker records an observation when it changes, plus
// a daily heartbeat, instead of on every six-hourly read. A read that finds the
// access as recorded appends nothing: it stamps the recorded observation, so
// the lease is not due again for six hours, and the graph shows when it was
// last read beside when it was recorded. A day after the recorded one, an
// unchanged read is recorded again as the heartbeat; a read that finds the
// access changed is recorded at once, and an unknown read that stays unknown is
// not recorded again either. A rebuild keeps every recorded observation.
func TestServedLeaseAccessRecordsOnlyChangesAndAHeartbeatG2L3(t *testing.T) {
	aws := newG2AWSStandIn(t)
	h := newOperatingServedHarness(t, config.Protocols{}, func(d *Deps) {
		d.EnableSecretsAPI = true
		resolver := integrationCredentialResolver{store: d.Store, kek: d.KEK, crypto: d.TenantCrypto}
		sts := config.DynamicSecretProviderConfig{
			TenantID: servedTestTenant, ID: "aws-deploy", Type: "aws-sts", Endpoint: aws.URL, IAMEndpoint: aws.URL,
			AllowInsecureLoopback: true, Region: "us-west-2", AccessKeyID: "AKIAG2ADMIN",
			SecretAccessRef: writeServedCredentialFile(t, "g2l3-aws-secret", "g2-admin-secret"),
			AllowedRoles:    []string{"deployer"}, RoleBindings: map[string]string{"deployer": g2RoleARN}, MaxTTL: "1h",
		}
		d.TenantDynamicSecretProviders = DynamicSecretProviderRegistry{servedTestTenant: {
			newConfiguredDynamicProvider(sts, map[string]bool{"deployer": true}, time.Hour, resolver, nil),
		}}
		d.DynamicSecretAccessInterval = time.Hour // the test drives each read itself
	})
	startServedExternalCADispatcher(t, h)
	ctx := t.Context()
	issuer := seedScopedTokenSubject(t, h.store, h.tenant, "g2l3-issuer", "secrets:read", "secrets:write")
	reader := seedScopedTokenSubject(t, h.store, h.tenant, "g2l3-graph-reader", "graph:read", "access:read")
	lease, _ := issueG2Lease(t, h, issuer, "g2l3-sts-1", "aws-deploy", "deployer")

	recorded := func() int {
		t.Helper()
		n := 0
		if err := h.log.Replay(context.Background(), 0, func(e events.Event) error {
			if e.Type != projections.EventDynamicSecretLeaseAccessObserved || e.TenantID != h.tenant {
				return nil
			}
			var pl projections.DynamicSecretLeaseAccessObserved
			if json.Unmarshal(e.Data, &pl) == nil && pl.LeaseID == lease {
				n++
			}
			return nil
		}); err != nil {
			t.Fatalf("replay events: %v", err)
		}
		return n
	}
	resolve := func() {
		t.Helper()
		if err := h.srv.ResolveDynamicSecretAccessOnce(ctx); err != nil {
			t.Fatalf("lease access pass: %v", err)
		}
	}
	// age moves the recorded observation, and its last unchanged read, back in
	// time, as the hours between passes would.
	age := func(recordedBy, recheckedBy time.Duration) {
		t.Helper()
		if _, err := h.store.SystemPool().Exec(ctx,
			`UPDATE dynamic_secret_lease_access
			    SET checked_at = checked_at - make_interval(secs => $3), rechecked_at = rechecked_at - make_interval(secs => $4)
			  WHERE tenant_id = $1 AND lease_id = $2`, h.tenant, lease, recordedBy.Seconds(), recheckedBy.Seconds()); err != nil {
			t.Fatal(err)
		}
	}
	attrs := func() map[string]string {
		t.Helper()
		n, ok := readG2Graph(t, h, reader).node("lease:" + lease)
		if !ok {
			t.Fatal("the lease is not in the graph")
		}
		return n.Attrs
	}
	due := func() int {
		t.Helper()
		leases, err := h.store.DynamicSecretLeasesNeedingAccess(ctx, h.tenant, time.Now(), dynamicSecretAccessRefresh, dynamicSecretAccessRetry, 50)
		if err != nil {
			t.Fatal(err)
		}
		n := 0
		for _, l := range leases {
			if l.ID == lease {
				n++
			}
		}
		return n
	}

	resolve()
	if got := recorded(); got != 1 {
		t.Fatalf("the first read recorded %d observations, want 1", got)
	}
	reads := aws.iamReads()

	// Six hours on, the lease is read again and found as recorded: nothing is
	// recorded, the read is stamped, and the lease is not due again.
	age(7*time.Hour, 0)
	resolve()
	if aws.iamReads() == reads {
		t.Fatal("a stale lease was not read again")
	}
	if got := recorded(); got != 1 {
		t.Fatalf("an unchanged read recorded another observation: %d recorded", got)
	}
	if n := due(); n != 0 {
		t.Fatal("a lease read a moment ago is due again")
	}
	a := attrs()
	checkedAt, err1 := time.Parse(time.RFC3339, a["access_checked_at"])
	recordedAt, err2 := time.Parse(time.RFC3339, a["access_recorded_at"])
	if err1 != nil || err2 != nil || a["access_status"] != store.DynamicSecretAccessResolved || !recordedAt.Before(checkedAt.Add(-6*time.Hour)) {
		t.Fatalf("the graph's lease after an unchanged read = %v, want it read now and recorded seven hours ago", a)
	}

	// A day after the recorded observation, an unchanged read is the
	// heartbeat and is recorded.
	age(18*time.Hour, 7*time.Hour)
	resolve()
	if got := recorded(); got != 2 {
		t.Fatalf("the day's heartbeat recorded %d observations in all, want 2", got)
	}

	// A read that finds the access changed is recorded at once; an unknown
	// read that stays unknown is not recorded again.
	aws.denyIAM.Store(true)
	age(7*time.Hour, 0)
	resolve()
	if got := recorded(); got != 3 || attrs()["access_status"] != store.DynamicSecretAccessUnknown {
		t.Fatalf("a changed read: %d recorded, graph %v", recorded(), attrs())
	}
	age(6*time.Minute, 0)
	resolve()
	if got := recorded(); got != 3 {
		t.Fatalf("an unknown read that stayed unknown recorded another observation: %d recorded", got)
	}

	// A rebuild keeps the recorded observation; the unrecorded read stamp is
	// the worker's own and starts over.
	if err := h.srv.proj.Rebuild(ctx, h.log); err != nil {
		t.Fatalf("rebuild: %v", err)
	}
	if a := attrs(); a["access_status"] != store.DynamicSecretAccessUnknown || a["access_reason"] != "access_denied" || a["access_checked_at"] != a["access_recorded_at"] {
		t.Fatalf("after a rebuild the lease = %v", a)
	}
}
