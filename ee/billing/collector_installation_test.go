// SPDX-License-Identifier: LicenseRef-trstctl-EE

package billing_test

import (
	"context"
	"testing"
	"time"

	"trstctl.com/trstctl/ee/billing"
	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/crypto/jose"
	"trstctl.com/trstctl/internal/usage"
)

func TestDurableInstallationCollectsResourceGaugesWithoutUsageHooks(t *testing.T) {
	pg, cs := newBillingStoreOn(t, "billing_installed_collector")
	_, _, orch := billingHistory(t, cs)
	for range 2 {
		if _, err := orch.RecordCertificate(t.Context(), quotaTenant, billingMintedCertificate(t, "imported", "")); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := orch.RecordCertificate(t.Context(), otherTenant, billingMintedCertificate(t, "imported", "")); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	inst := billing.InstallDurable(ctx, nil, billing.StoreTenantCounter(cs), cs)
	t.Cleanup(func() { cancel(); <-inst.Stopped })
	t.Cleanup(func() { usage.SetRecorder(nil); usage.SetQuotaChecker(nil) })
	deadline := time.Now().Add(5 * time.Second)
	var last map[string]map[string]int64
	for time.Now().Before(deadline) {
		last = map[string]map[string]int64{}
		complete := true
		for tenant, want := range map[string]int64{quotaTenant: 2, otherTenant: 1} {
			rows, err := pg.Query(ctx, time.Now().Add(-time.Hour), time.Now().Add(time.Hour), tenant)
			if err != nil {
				t.Fatal(err)
			}
			values := map[string]int64{}
			for _, row := range rows {
				if row.TenantID != tenant {
					t.Fatalf("resource snapshot crossed customer boundary: %+v", row)
				}
				if row.Kind == billing.KindGauge {
					values[row.Meter] = row.Value
				}
			}
			last[tenant] = values
			certs, hasCerts := values[usage.MeterCertificatesStored]
			agents, hasAgents := values[usage.MeterAgents]
			secrets, hasSecrets := values[usage.MeterSecretsStored]
			complete = complete && hasCerts && certs == want && hasAgents && agents == 0 && hasSecrets && secrets == 0
		}
		if complete {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("durable installation never collected real customer resources without usage hooks: %v", last)
}

func TestCollectorCoversAQuietHourOnlyAfterObservationStarts(t *testing.T) {
	pg, cs := newBillingStoreOn(t, "billing_quiet_collector")
	_, _, _ = billingHistory(t, cs)
	start := time.Date(2026, 7, 15, 12, 0, 0, 0, time.UTC)
	now := start
	collector := billing.NewCollector(pg,
		func(context.Context) ([]string, error) { return []string{quotaTenant}, nil },
		billing.StoreTenantCounter(cs), nil).WithClock(func() time.Time { return now })
	for i := 0; i <= 4; i++ {
		now = start.Add(time.Duration(i) * 15 * time.Minute)
		if err := collector.Snapshot(t.Context()); err != nil {
			t.Fatal(err)
		}
	}
	coverage, err := pg.CoverageFor(t.Context(), quotaTenant)
	if err != nil {
		t.Fatal(err)
	}
	period := billing.EvidencePeriod{CustomerID: quotaTenant, Start: start, End: now}
	if verdict := billing.MaySign(period, coverage, now); !verdict.Signable {
		t.Fatalf("quiet hour observed by the collector remains unsignable: %+v; coverage=%+v", verdict, coverage)
	}
	rows, err := pg.Query(t.Context(), period.Start, period.End, quotaTenant)
	if err != nil || len(rows) != 4 {
		t.Fatalf("quiet customer's four resource gauges: rows=%+v error=%v", rows, err)
	}
	key, err := jose.GenerateRSASigningKey("quiet-resource-proof")
	if err != nil {
		t.Fatal(err)
	}
	doc, err := billing.BuildSignedEvidence(t.Context(), period, coverage, rows, pg, &billing.AuditKeySigner{Key: key}, now)
	if err != nil || !doc.Signable || doc.Signature == nil {
		t.Fatalf("quiet resource evidence was not signed: document=%+v error=%v", doc, err)
	}
	payload, err := key.JWKS().VerifyArtifact(doc.Signature.JWS, jose.ArtifactBillingInvoice)
	if err != nil || crypto.SHA256Hex(payload) != doc.Digest {
		t.Fatalf("quiet resource signature does not verify the document digest: %v", err)
	}
	period.Start, period.End = start.Add(-time.Hour), start
	if billing.MaySign(period, coverage, now).Signable {
		t.Fatal("collector invented observation before it started")
	}
	neighbor, err := pg.CoverageFor(t.Context(), otherTenant)
	if err != nil {
		t.Fatal(err)
	}
	period.CustomerID, period.Start, period.End = otherTenant, start, now
	if billing.MaySign(period, neighbor, now).Signable {
		t.Fatal("collector invented observation for an unobserved neighbor")
	}
}
