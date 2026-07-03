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
	MeterCertificatesIssued      = "certificates_issued"
	MeterCertificatesStored      = "certificates_stored"
	MeterSecretsStored           = "secrets_stored"
	MeterAgents                  = "agents"
	MeterTenants                 = "tenants"
	MeterManagedTenantBand       = "managed_tenant_band"
	BillingUnitControlPlane      = "control_plane_deployment"
	BillingUnitManagedTenantBand = "managed_tenant_band"
	MeterOperationalTelemetry    = "operational_telemetry"
	MeterCapacitySignal          = "capacity_signal"
	MeterPrimaryBillableUnit     = "primary_billable_unit"
)

// MeterDefinition classifies a usage counter for public packaging and Provider
// export. Counters can exist for operations without becoming pricing axes.
type MeterDefinition struct {
	Name            string `json:"name"`
	Classification  string `json:"classification"`
	PrimaryBillable bool   `json:"primary_billable"`
	Notes           string `json:"notes,omitempty"`
}

// MeterDefinitions returns the public usage-meter contract. Certificate counters
// are intentionally telemetry only; RED-006 pins the billable unit to the control
// plane / managed tenant band instead of issued or stored certificates.
func MeterDefinitions() []MeterDefinition {
	return []MeterDefinition{
		{
			Name:           MeterCertificatesIssued,
			Classification: MeterOperationalTelemetry,
			Notes:          "issuance volume, capacity planning, and abuse detection; never the primary billable unit",
		},
		{
			Name:           MeterCertificatesStored,
			Classification: MeterOperationalTelemetry,
			Notes:          "inventory size, storage planning, and renewal posture; never the primary billable unit",
		},
		{
			Name:           MeterSecretsStored,
			Classification: MeterOperationalTelemetry,
			Notes:          "storage and risk posture only",
		},
		{
			Name:           MeterAgents,
			Classification: MeterCapacitySignal,
			Notes:          "fleet sizing and support planning",
		},
		{
			Name:            MeterManagedTenantBand,
			Classification:  MeterPrimaryBillableUnit,
			PrimaryBillable: true,
			Notes:           "Provider and Managed packaging unit; implemented as tenant-band licensing",
		},
		{
			Name:            MeterTenants,
			Classification:  MeterPrimaryBillableUnit,
			PrimaryBillable: true,
			Notes:           "self-hosted license capacity band",
		},
	}
}

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
