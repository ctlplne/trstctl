// SPDX-License-Identifier: LicenseRef-trstctl-EE

package misuse_test

import (
	"context"
	"encoding/json"
	"fmt"
	"reflect"
	"strings"
	"testing"
	"time"

	_ "trstctl.com/trstctl/ee" // registers the licensed event privacy catalog
	"trstctl.com/trstctl/ee/governance/misuse"
	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/notify"
	"trstctl.com/trstctl/internal/projections"
	"trstctl.com/trstctl/internal/store"
)

const misuseTenant = "22222222-2222-2222-2222-222222222222"

type usageFixture struct {
	t    *testing.T
	ctx  context.Context
	st   *store.Store
	log  *events.Log
	proj *projections.Projector
}

// use records one credential.used note exactly as the API's recorder emits
// it, and projects it.
func (f *usageFixture) use(token, source, action string, window time.Time, count int) {
	f.t.Helper()
	payload, err := json.Marshal(projections.CredentialUsed{
		Kind: store.CredentialUsageAPIToken, CredentialID: token, Principal: "svc-" + token,
		SourceKind: store.CredentialUsageSourceNetwork, Source: source, Action: action,
		WindowStart: window.Truncate(time.Hour), UsedAt: window, Count: count,
	})
	if err != nil {
		f.t.Fatal(err)
	}
	ev, err := f.log.Append(f.ctx, events.Event{Type: projections.EventCredentialUsed, TenantID: misuseTenant, Data: payload})
	if err != nil {
		f.t.Fatal(err)
	}
	if err := f.proj.Apply(f.ctx, ev); err != nil {
		f.t.Fatal(err)
	}
}

func (f *usageFixture) findings() []string {
	f.t.Helper()
	var out []string
	rows, err := f.st.SystemPool().Query(f.ctx, `SELECT rule || '|' || credential_id || '|' || source || '|' || observed_count || '|' || baseline || '|' || alerted
		FROM misuse_findings WHERE tenant_id = $1 ORDER BY 1`, misuseTenant)
	if err != nil {
		f.t.Fatal(err)
	}
	defer rows.Close()
	for rows.Next() {
		var row string
		if err := rows.Scan(&row); err != nil {
			f.t.Fatal(err)
		}
		out = append(out, row)
	}
	return out
}

func (f *usageFixture) alerts() []string {
	f.t.Helper()
	var out []string
	rows, err := f.st.SystemPool().Query(f.ctx, `SELECT convert_from(payload, 'UTF8') FROM outbox WHERE tenant_id = $1 AND destination = $2 ORDER BY id`,
		misuseTenant, notify.DestinationRisk)
	if err != nil {
		f.t.Fatal(err)
	}
	defer rows.Close()
	for rows.Next() {
		var row string
		if err := rows.Scan(&row); err != nil {
			f.t.Fatal(err)
		}
		out = append(out, row)
	}
	return out
}

// M2: a lease requested from a new client network raises one alert with
// evidence, and so does a burst of secret reads; repeats fold into the
// finding, an alert storm is capped, and the findings rebuild from the log.
func TestMisuseDetectionAlertsOnceWithEvidenceM2(t *testing.T) {
	ctx := context.Background()
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
	now := time.Now().UTC()
	hour := now.Truncate(time.Hour)
	day := func(n int) time.Time { return hour.AddDate(0, 0, -n) }

	// The deployer token has used one network on three days.
	for n := 5; n >= 3; n-- {
		f.use("deployer", "127.0.0.0/24", projections.CredentialActionAPICall, day(n), 1)
	}
	// The reader token reads two secrets an hour on earlier days.
	for n := 6; n >= 2; n-- {
		f.use("reader", "127.0.0.0/24", projections.CredentialActionSecretRead, day(n), 2)
	}
	detector, findingsProj := misuse.NewDetector(misuse.Options{Store: st, Log: log, Now: func() time.Time { return now }})
	if err := detector.DetectOnce(ctx); err != nil {
		t.Fatal(err)
	}
	if got := f.findings(); len(got) != 0 {
		t.Fatalf("normal use raised findings: %v", got)
	}

	// A lease request from a new network, and a burst of reads this hour.
	f.use("deployer", "10.20.30.0/24", projections.CredentialActionLeaseRequest, hour, 1)
	for count := 1; count <= 64; count *= 2 {
		f.use("reader", "127.0.0.0/24", projections.CredentialActionSecretRead, hour, count)
	}
	if err := detector.DetectOnce(ctx); err != nil {
		t.Fatal(err)
	}
	want := []string{
		"new_source_lease|deployer|10.20.30.0/24|1|0|true",
		"secret_read_burst|reader|127.0.0.0/24|64|2|true",
	}
	if got := f.findings(); !reflect.DeepEqual(got, want) {
		t.Fatalf("findings = %v, want %v", got, want)
	}
	alerts := f.alerts()
	if len(alerts) != 2 {
		t.Fatalf("alerts = %v", alerts)
	}
	joined := strings.Join(alerts, "\n")
	for _, evidence := range []string{"10.20.30.0/24", "127.0.0.0/24", "read secrets 64 times", "largest earlier hour in 14 days was 2", "svc-deployer", `"severity":"high"`} {
		if !strings.Contains(joined, evidence) {
			t.Fatalf("alerts lack %q: %s", evidence, joined)
		}
	}

	// The same deviations again, and another new network the same day: they
	// fold into the findings, with no second alert.
	f.use("deployer", "10.20.31.0/24", projections.CredentialActionLeaseRequest, hour, 1)
	f.use("reader", "127.0.0.0/24", projections.CredentialActionSecretRead, hour, 128)
	if err := detector.DetectOnce(ctx); err != nil {
		t.Fatal(err)
	}
	if got := f.findings(); !reflect.DeepEqual(got, want) || len(f.alerts()) != 2 {
		t.Fatalf("a repeat raised more: findings %v, %d alerts", got, len(f.alerts()))
	}

	// A storm: 40 tokens burst in the same hour. Every finding is recorded;
	// alerts stop at the tenant's hourly budget (20, two already raised).
	for i := 0; i < 40; i++ {
		f.use(fmt.Sprintf("storm-%02d", i), "127.0.0.0/24", projections.CredentialActionSecretRead, hour, 64)
	}
	if err := detector.DetectOnce(ctx); err != nil {
		t.Fatal(err)
	}
	all := f.findings()
	alerted := 0
	for _, row := range all {
		if strings.HasSuffix(row, "|true") {
			alerted++
		}
	}
	if len(all) != 42 || alerted != 20 || len(f.alerts()) != 20 {
		t.Fatalf("storm: %d findings, %d alerted, %d alert rows; want 42, 20, 20", len(all), alerted, len(f.alerts()))
	}

	// The findings read model rebuilds from the event log, and a rebuild
	// never alerts again.
	before := f.findings()
	if err := findingsProj.Reset(ctx); err != nil {
		t.Fatal(err)
	}
	if got := f.findings(); len(got) != 0 {
		t.Fatalf("reset left %d findings", len(got))
	}
	if err := log.Replay(ctx, 1, func(ev events.Event) error { return findingsProj.Apply(ctx, ev) }); err != nil {
		t.Fatal(err)
	}
	if after := f.findings(); !reflect.DeepEqual(before, after) || len(f.alerts()) != 20 {
		t.Fatalf("rebuild changed the findings or alerted again:\nbefore %v\nafter  %v (%d alerts)", before, after, len(f.alerts()))
	}
	t.Logf("M2_OK findings=%d alerted=%d", len(before), alerted)
}
