// SPDX-License-Identifier: LicenseRef-trstctl-EE

package misuse_test

import (
	"context"
	"reflect"
	"strings"
	"testing"
	"time"

	"trstctl.com/trstctl/ee/governance/misuse"
	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/projections"
)

// M2-L2: detection follows the tenant's own thresholds. A floor of 100 reads
// keeps an hour of 64 from being a burst; lowering it to 32 records the burst,
// and a cap of one alert an hour keeps it from alerting after the lease
// finding did; the lease finding's alert names the tenant's own day count.
// The policy is recorded as an event by its setter, rebuilds from the log,
// refuses a threshold out of range, and a tenant that set none reads the
// defaults.
func TestMisuseDetectionFollowsTheTenantsPolicyM2L2(t *testing.T) {
	ctx := events.ContextWithActor(context.Background(), events.Actor{Subject: "sec-admin"})
	st := newMisuseTestStore(t)
	log, err := events.Open(ctx, config.NATS{Mode: config.NATSEmbedded, StoreDir: t.TempDir(), SyncAlways: true})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = log.Close() })
	f := &usageFixture{t: t, ctx: ctx, st: st, log: log, proj: projections.New(st)}
	reg, err := log.Append(ctx, events.Event{Type: projections.EventTenantRegistered, TenantID: misuseTenant, Data: []byte(`{"name":"misuse tenant"}`)})
	if err != nil {
		t.Fatal(err)
	}
	if err := f.proj.Apply(ctx, reg); err != nil {
		t.Fatal(err)
	}
	policies := misuse.PolicyStore{Store: st, Log: log, Defaults: misuse.DefaultPolicy(0)}
	if view, err := policies.Get(ctx, misuseTenant); err != nil || view.Custom || view.Policy != misuse.DefaultPolicy(0) {
		t.Fatalf("a tenant with no policy = %+v, %v; want the defaults", view, err)
	}
	if _, err := policies.Set(ctx, misuseTenant, misuse.Policy{NormalDays: 3, BurstFloor: 64, BurstFactor: 1, BurstLookbackDays: 14, HourlyAlertCap: 5}); err == nil {
		t.Fatal("a burst factor of 1 was accepted")
	}
	strict := misuse.Policy{NormalDays: 3, BurstFloor: 100, BurstFactor: 4, BurstLookbackDays: 30, HourlyAlertCap: 1}
	view, err := policies.Set(ctx, misuseTenant, strict)
	if err != nil || !view.Custom || view.Policy != strict || view.SetBy != "sec-admin" || view.UpdatedAt == nil {
		t.Fatalf("set policy = %+v, %v", view, err)
	}

	now := time.Now().UTC()
	hour := now.Truncate(time.Hour)
	day := func(n int) time.Time { return hour.AddDate(0, 0, -n) }
	for n := 5; n >= 3; n-- {
		f.use("deployer", "127.0.0.0/24", projections.CredentialActionAPICall, day(n), 1)
	}
	for n := 6; n >= 2; n-- {
		f.use("reader", "127.0.0.0/24", projections.CredentialActionSecretRead, day(n), 2)
	}
	f.use("deployer", "10.20.30.0/24", projections.CredentialActionLeaseRequest, hour, 1)
	f.use("reader", "127.0.0.0/24", projections.CredentialActionSecretRead, hour, 64)
	detector, findingsProj := misuse.NewDetector(misuse.Options{Store: st, Log: log, Now: func() time.Time { return now }})
	if err := detector.DetectOnce(ctx); err != nil {
		t.Fatal(err)
	}
	if got, want := f.findings(), []string{"new_source_lease|deployer|10.20.30.0/24|1|0|true"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("with a floor of 100: findings = %v, want %v", got, want)
	}
	if alerts := strings.Join(f.alerts(), "\n"); !strings.Contains(alerts, "has not used on 3 different days") {
		t.Fatalf("the lease alert does not name the policy's days: %s", alerts)
	}

	lower := strict
	lower.BurstFloor = 32
	if _, err := policies.Set(ctx, misuseTenant, lower); err != nil {
		t.Fatal(err)
	}
	if err := detector.DetectOnce(ctx); err != nil {
		t.Fatal(err)
	}
	want := []string{"new_source_lease|deployer|10.20.30.0/24|1|0|true", "secret_read_burst|reader|127.0.0.0/24|64|2|false"}
	if got := f.findings(); !reflect.DeepEqual(got, want) || len(f.alerts()) != 1 {
		t.Fatalf("with a floor of 32 and one alert an hour: findings = %v, %d alerts; want %v and 1", got, len(f.alerts()), want)
	}

	// The policy is event-sourced: a rebuild from the log restores it.
	if err := findingsProj.Reset(ctx); err != nil {
		t.Fatal(err)
	}
	if view, err := policies.Get(ctx, misuseTenant); err != nil || view.Custom {
		t.Fatalf("after reset = %+v, %v; want the defaults", view, err)
	}
	if err := log.Replay(ctx, 1, func(ev events.Event) error { return findingsProj.Apply(ctx, ev) }); err != nil {
		t.Fatal(err)
	}
	if view, err := policies.Get(ctx, misuseTenant); err != nil || view.Policy != lower || view.SetBy != "sec-admin" {
		t.Fatalf("after rebuild = %+v, %v; want %+v", view, err, lower)
	}
	t.Logf("M2L2_POLICY_OK findings=%d", len(f.findings()))
}
