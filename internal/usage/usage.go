// Package usage is the core metering and quota seam for Provider-tier attach.
//
// Community builds install no recorder and an allow-all quota checker. Licensed
// Provider code can swap those implementations at the single edition seam
// without core importing ee/.
package usage

import (
	"context"
	"sync"
)

const (
	MeterCertificatesIssued = "certificates_issued"
	MeterCertificatesStored = "certificates_stored"
	MeterSecretsStored      = "secrets_stored"
	MeterAgents             = "agents"
	MeterTenants            = "tenants"
)

type Recorder interface {
	Record(tenantID, meter string, delta int64)
}

type QuotaChecker interface {
	AllowCreate(ctx context.Context, tenantID, resource string) error
}

type nopRecorder struct{}

func (nopRecorder) Record(string, string, int64) {}

type allowAllQuota struct{}

func (allowAllQuota) AllowCreate(context.Context, string, string) error { return nil }

var (
	mu     sync.RWMutex
	rec    Recorder     = nopRecorder{}
	quota  QuotaChecker = allowAllQuota{}
	active bool
)

func SetRecorder(r Recorder) {
	mu.Lock()
	defer mu.Unlock()
	if r == nil {
		rec = nopRecorder{}
		active = false
		return
	}
	rec = r
	active = true
}

func SetQuotaChecker(q QuotaChecker) {
	mu.Lock()
	defer mu.Unlock()
	if q == nil {
		quota = allowAllQuota{}
		return
	}
	quota = q
}

func Record(tenantID, meter string, delta int64) {
	if tenantID == "" || meter == "" || delta <= 0 {
		return
	}
	mu.RLock()
	r, on := rec, active
	mu.RUnlock()
	if !on {
		return
	}
	r.Record(tenantID, meter, delta)
}

func AllowCreate(ctx context.Context, tenantID, resource string) error {
	mu.RLock()
	q := quota
	mu.RUnlock()
	return q.AllowCreate(ctx, tenantID, resource)
}
