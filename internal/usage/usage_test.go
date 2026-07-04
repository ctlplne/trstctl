// SPDX-License-Identifier: MPL-2.0

package usage

import (
	"context"
	"errors"
	"strings"
	"testing"
)

type recordCall struct {
	tenant string
	meter  string
	delta  int64
}

type fakeRecorder struct {
	calls []recordCall
}

func (f *fakeRecorder) Record(tenantID, meter string, delta int64) {
	f.calls = append(f.calls, recordCall{tenant: tenantID, meter: meter, delta: delta})
}

type fakeQuotaChecker struct {
	err error
	got recordCall
}

func (f *fakeQuotaChecker) AllowCreate(_ context.Context, tenantID, resource string) error {
	f.got = recordCall{tenant: tenantID, meter: resource}
	return f.err
}

func TestUsageDefaultsAreInert(t *testing.T) {
	SetRecorder(nil)
	SetQuotaChecker(nil)

	Record("tenant-a", MeterCertificatesIssued, 1)
	if err := AllowCreate(context.Background(), "tenant-a", MeterAgents); err != nil {
		t.Fatalf("default quota checker denied create: %v", err)
	}
}

func TestUsageSetterHooksFire(t *testing.T) {
	SetRecorder(nil)
	SetQuotaChecker(nil)
	t.Cleanup(func() {
		SetRecorder(nil)
		SetQuotaChecker(nil)
	})

	rec := &fakeRecorder{}
	SetRecorder(rec)
	Record("", MeterCertificatesIssued, 1)
	Record("tenant-a", MeterCertificatesIssued, 0)
	Record("tenant-a", MeterCertificatesIssued, 2)
	if len(rec.calls) != 1 {
		t.Fatalf("recorder calls = %d, want 1: %+v", len(rec.calls), rec.calls)
	}
	if got := rec.calls[0]; got.tenant != "tenant-a" || got.meter != MeterCertificatesIssued || got.delta != 2 {
		t.Fatalf("recorder call = %+v", got)
	}

	quotaErr := errors.New("quota exhausted")
	q := &fakeQuotaChecker{err: quotaErr}
	SetQuotaChecker(q)
	if err := AllowCreate(context.Background(), "tenant-b", MeterAgents); !errors.Is(err, quotaErr) {
		t.Fatalf("quota error = %v, want %v", err, quotaErr)
	}
	if q.got.tenant != "tenant-b" || q.got.meter != MeterAgents {
		t.Fatalf("quota checker saw %+v", q.got)
	}
}

func TestUsageResetRestoresUnlicensedNoop(t *testing.T) {
	rec := &fakeRecorder{}
	SetRecorder(rec)
	SetRecorder(nil)
	Record("tenant-a", MeterCertificatesIssued, 1)
	if len(rec.calls) != 0 {
		t.Fatalf("uninstalled recorder still saw calls: %+v", rec.calls)
	}

	q := &fakeQuotaChecker{err: errors.New("should not be called")}
	SetQuotaChecker(q)
	SetQuotaChecker(nil)
	if err := AllowCreate(context.Background(), "tenant-a", MeterAgents); err != nil {
		t.Fatalf("uninstalled quota checker denied create: %v", err)
	}
	if q.got.tenant != "" || q.got.meter != "" {
		t.Fatalf("uninstalled quota checker was called: %+v", q.got)
	}
}

func TestMeterDefinitionsClassifyCertificateCountersAsTelemetry(t *testing.T) {
	meters := MeterDefinitions()
	if len(meters) == 0 {
		t.Fatal("meter definitions are empty")
	}
	var sawPrimary bool
	for _, meter := range meters {
		if strings.HasPrefix(meter.Name, "certificates_") {
			if meter.Classification != MeterOperationalTelemetry || meter.PrimaryBillable {
				t.Fatalf("certificate meter must stay operational telemetry, got %+v", meter)
			}
		}
		if meter.Name == BillingUnitManagedTenantBand && meter.PrimaryBillable {
			sawPrimary = true
		}
	}
	if !sawPrimary {
		t.Fatalf("managed tenant band must be the Provider/Managed primary billable unit: %+v", meters)
	}
}
