package usage

import (
	"context"
	"errors"
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
