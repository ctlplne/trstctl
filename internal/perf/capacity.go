package perf

import "math"

const (
	CapacityMeasurementArtifact = "scripts/perf/artifacts/capacity-measurement-baseline.json"

	capacityUnitPostgresCertificate = "postgres_certificate_row"
	capacityUnitPostgresCredential  = "postgres_credential_row"
	capacityUnitJetStreamEvent      = "jetstream_event"
)

// CapacityMeasurementReport is the committed capacity denominator. It is kept in
// code so docs, the API contract, and the calibration artifact stay tied together.
type CapacityMeasurementReport struct {
	SchemaVersion        int                          `json:"schema_version"`
	Profile              string                       `json:"profile"`
	GeneratedAt          string                       `json:"generated_at"`
	MeasurementArtifact  string                       `json:"measurement_artifact"`
	MeasurementMethod    string                       `json:"measurement_method"`
	SourceArtifacts      []string                     `json:"source_artifacts"`
	SampleSize           int                          `json:"sample_size"`
	StorageMeasurements  []CapacityStorageMeasurement `json:"storage_measurements"`
	ResourceMeasurement  CapacityResourceMeasurement  `json:"resource_measurement"`
	CostModel            CapacityCostModel            `json:"cost_model"`
	DerivedCapacityTiers []CapacityTier               `json:"derived_capacity_tiers"`
	Summary              CapacityMeasurementSummary   `json:"summary"`
}

type CapacityStorageMeasurement struct {
	ID                    string  `json:"id"`
	Unit                  string  `json:"unit"`
	Surface               string  `json:"surface"`
	MeasurementSource     string  `json:"measurement_source"`
	Samples               int     `json:"samples"`
	PostgresRelationBytes int64   `json:"postgres_relation_bytes,omitempty"`
	JetStreamStoreBytes   int64   `json:"jetstream_store_bytes,omitempty"`
	SerializedBytes       int64   `json:"serialized_bytes,omitempty"`
	BytesPerUnit          int64   `json:"bytes_per_unit"`
	HeadroomMultiplier    float64 `json:"headroom_multiplier"`
}

type CapacityResourceMeasurement struct {
	LiveStackProfile                    string  `json:"live_stack_profile"`
	CPUCount                            int     `json:"cpu_count"`
	PeakMemorySysBytes                  uint64  `json:"peak_memory_sys_bytes"`
	PeakHeapInuseBytes                  uint64  `json:"peak_heap_inuse_bytes"`
	PeakOpenFDs                         int     `json:"peak_open_fds"`
	PostgresCalibrationConnections      int     `json:"postgres_calibration_connections"`
	SignerRPCPeakMemorySysBytes         uint64  `json:"signer_rpc_peak_memory_sys_bytes"`
	SignerRPCPeakHeapInuseBytes         uint64  `json:"signer_rpc_peak_heap_inuse_bytes"`
	SignerRPCPeakThroughputPerSecond    float64 `json:"signer_rpc_peak_throughput_per_second"`
	ProjectionReplayThroughputPerSecond float64 `json:"projection_replay_throughput_per_second"`
}

type CapacityCostModel struct {
	Currency                      string  `json:"currency"`
	RetentionDays                 int     `json:"retention_days"`
	HeadroomMultiplier            float64 `json:"headroom_multiplier"`
	PostgresGiBMonthUSD           float64 `json:"postgres_gib_month_usd"`
	JetStreamGiBMonthUSD          float64 `json:"jetstream_gib_month_usd"`
	ControlPlaneVCPUMonthUSD      float64 `json:"control_plane_vcpu_month_usd"`
	ControlPlaneMemoryGiBMonthUSD float64 `json:"control_plane_memory_gib_month_usd"`
	SignerVCPUMonthUSD            float64 `json:"signer_vcpu_month_usd"`
	SignerMemoryGiBMonthUSD       float64 `json:"signer_memory_gib_month_usd"`
}

type CapacityMeasurementSummary struct {
	OK                                bool     `json:"ok"`
	PostgresBytesPerManagedCredential int64    `json:"postgres_bytes_per_managed_credential"`
	JetStreamBytesPerEvent            int64    `json:"jetstream_bytes_per_event"`
	Notes                             []string `json:"notes"`
}

type capacityTierBlueprint struct {
	ID                    string
	Name                  string
	Tenants               int
	ManagedCredentials    int
	EventsPerDay          int
	BasePostgresGiB       float64
	BaseJetStreamGiB      float64
	ControlPlaneCPU       string
	ControlPlaneVCPU      float64
	ControlPlaneMemoryGiB int
	SignerCPU             string
	SignerVCPU            float64
	SignerMemoryGiB       int
	BaseMonthlyCostUSD    int
	Notes                 string
}

var capacityTierBlueprints = []capacityTierBlueprint{
	{
		ID: "CAP-SMALL", Name: "single-node regulated evaluation", Tenants: 5, ManagedCredentials: 25000, EventsPerDay: 250000,
		BasePostgresGiB: 8, BaseJetStreamGiB: 8, ControlPlaneCPU: "2 vCPU", ControlPlaneVCPU: 2, ControlPlaneMemoryGiB: 4,
		SignerCPU: "1 vCPU", SignerVCPU: 1, SignerMemoryGiB: 1, BaseMonthlyCostUSD: 180,
		Notes: "Bundled PostgreSQL/NATS for evaluation; move to external datastores before production multi-tenant use.",
	},
	{
		ID: "CAP-MEDIUM", Name: "external datastore production", Tenants: 50, ManagedCredentials: 250000, EventsPerDay: 2500000,
		BasePostgresGiB: 72, BaseJetStreamGiB: 80, ControlPlaneCPU: "6 vCPU", ControlPlaneVCPU: 6, ControlPlaneMemoryGiB: 12,
		SignerCPU: "2 vCPU", SignerVCPU: 2, SignerMemoryGiB: 2, BaseMonthlyCostUSD: 1250,
		Notes: "External PostgreSQL and JetStream, two control-plane replicas, isolated signer process.",
	},
	{
		ID: "CAP-LARGE", Name: "multi-replica enterprise", Tenants: 250, ManagedCredentials: 1000000, EventsPerDay: 10000000,
		BasePostgresGiB: 280, BaseJetStreamGiB: 320, ControlPlaneCPU: "16 vCPU", ControlPlaneVCPU: 16, ControlPlaneMemoryGiB: 32,
		SignerCPU: "6 vCPU", SignerVCPU: 6, SignerMemoryGiB: 8, BaseMonthlyCostUSD: 3800,
		Notes: "External HA PostgreSQL, external JetStream cluster, isolated signer capacity scaled separately.",
	},
}

func DefaultCapacityCostModel() CapacityCostModel {
	return CapacityCostModel{
		Currency:                      "USD",
		RetentionDays:                 30,
		HeadroomMultiplier:            1.35,
		PostgresGiBMonthUSD:           0.16,
		JetStreamGiBMonthUSD:          0.10,
		ControlPlaneVCPUMonthUSD:      55,
		ControlPlaneMemoryGiBMonthUSD: 8,
		SignerVCPUMonthUSD:            75,
		SignerMemoryGiBMonthUSD:       10,
	}
}

func DeriveCapacityTiers(report CapacityMeasurementReport) []CapacityTier {
	cost := report.CostModel
	if cost.RetentionDays == 0 || cost.HeadroomMultiplier == 0 {
		cost = DefaultCapacityCostModel()
	}
	postgresBytesPerCredential := int64(0)
	jetStreamBytesPerEvent := int64(0)
	for _, m := range report.StorageMeasurements {
		switch m.ID {
		case capacityUnitPostgresCertificate, capacityUnitPostgresCredential:
			postgresBytesPerCredential += m.BytesPerUnit
		case capacityUnitJetStreamEvent:
			jetStreamBytesPerEvent = m.BytesPerUnit
		}
	}
	if postgresBytesPerCredential == 0 {
		postgresBytesPerCredential = report.Summary.PostgresBytesPerManagedCredential
	}
	if jetStreamBytesPerEvent == 0 {
		jetStreamBytesPerEvent = report.Summary.JetStreamBytesPerEvent
	}

	out := make([]CapacityTier, 0, len(capacityTierBlueprints))
	for _, bp := range capacityTierBlueprints {
		postgresGiB := roundGiB(bp.BasePostgresGiB + bytesToGiB(float64(bp.ManagedCredentials)*float64(postgresBytesPerCredential)*cost.HeadroomMultiplier))
		jetStreamGiB := roundGiB(bp.BaseJetStreamGiB + bytesToGiB(float64(bp.EventsPerDay)*float64(cost.RetentionDays)*float64(jetStreamBytesPerEvent)*cost.HeadroomMultiplier))
		monthly := roundUpInt(bp.BaseMonthlyCostUSD+
			int(math.Ceil(postgresGiB*cost.PostgresGiBMonthUSD))+
			int(math.Ceil(jetStreamGiB*cost.JetStreamGiBMonthUSD))+
			int(math.Ceil(bp.ControlPlaneVCPU*cost.ControlPlaneVCPUMonthUSD))+
			int(math.Ceil(float64(bp.ControlPlaneMemoryGiB)*cost.ControlPlaneMemoryGiBMonthUSD))+
			int(math.Ceil(bp.SignerVCPU*cost.SignerVCPUMonthUSD))+
			int(math.Ceil(float64(bp.SignerMemoryGiB)*cost.SignerMemoryGiBMonthUSD)), 10)
		out = append(out, CapacityTier{
			ID: bp.ID, Name: bp.Name, Tenants: bp.Tenants, ManagedCredentials: bp.ManagedCredentials, EventsPerDay: bp.EventsPerDay,
			PostgresGiB30Day: postgresGiB, JetStreamGiB30Day: jetStreamGiB, ControlPlaneCPU: bp.ControlPlaneCPU,
			ControlPlaneMemoryGiB: bp.ControlPlaneMemoryGiB, SignerCPU: bp.SignerCPU, SignerMemoryGiB: bp.SignerMemoryGiB,
			EstimatedMonthlyCostUSD: monthly, EstimatedCostPerCredential: roundCostPerCredential(float64(monthly) / float64(bp.ManagedCredentials)),
			Notes: bp.Notes,
		})
	}
	return out
}

func bytesToGiB(v float64) float64 {
	return v / (1024 * 1024 * 1024)
}

func roundGiB(v float64) float64 {
	if v < 10 {
		return math.Ceil(v*10) / 10
	}
	return math.Ceil(v)
}

func roundUpInt(v, unit int) int {
	if unit <= 1 {
		return v
	}
	return int(math.Ceil(float64(v)/float64(unit))) * unit
}

func roundCostPerCredential(v float64) float64 {
	return math.Round(v*10000) / 10000
}
