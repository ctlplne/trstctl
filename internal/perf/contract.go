package perf

// HotPathSLO is one row in the committed performance contract. It is intentionally
// code-owned so docs, the local perf gate, and CI all consume the same denominator.
type HotPathSLO struct {
	ID                     string  `json:"id"`
	HotPath                string  `json:"hot_path"`
	Surface                string  `json:"surface"`
	Owner                  string  `json:"owner"`
	Benchmark              string  `json:"benchmark"`
	P50MS                  float64 `json:"p50_ms"`
	P95MS                  float64 `json:"p95_ms"`
	P99MS                  float64 `json:"p99_ms"`
	MinThroughputPerSecond float64 `json:"min_throughput_per_second"`
	ErrorBudgetPercent     float64 `json:"error_budget_percent"`
	MaxQueueSaturation     float64 `json:"max_queue_saturation"`
	MaxProjectionLagEvents int     `json:"max_projection_lag_events"`
	CapacityRef            string  `json:"capacity_ref"`
}

// CapacityTier is one buyer-facing right-sizing row. Storage and cost values are
// derived from the committed capacity measurement artifact rather than prose
// constants or a vendor-specific cloud SKU; operators can replace unit costs
// without changing the product SLOs.
type CapacityTier struct {
	ID                         string  `json:"id"`
	Name                       string  `json:"name"`
	Tenants                    int     `json:"tenants"`
	ManagedCredentials         int     `json:"managed_credentials"`
	EventsPerDay               int     `json:"events_per_day"`
	PostgresGiB30Day           float64 `json:"postgres_gib_30_day"`
	JetStreamGiB30Day          float64 `json:"jetstream_gib_30_day"`
	ControlPlaneCPU            string  `json:"control_plane_cpu"`
	ControlPlaneMemoryGiB      int     `json:"control_plane_memory_gib"`
	SignerCPU                  string  `json:"signer_cpu"`
	SignerMemoryGiB            int     `json:"signer_memory_gib"`
	EstimatedMonthlyCostUSD    int     `json:"estimated_monthly_cost_usd"`
	EstimatedCostPerCredential float64 `json:"estimated_cost_per_credential_usd"`
	Notes                      string  `json:"notes"`
}

// ScaleOrchestrationPlan turns the measured SLO and capacity denominators into a
// served execution plan for high-volume estates. It carries only product posture
// and tuning guidance, never tenant inventory rows or credential material.
type ScaleOrchestrationPlan struct {
	Capability              string                 `json:"capability"`
	Served                  bool                   `json:"served"`
	GeneratedAt             string                 `json:"generated_at"`
	TargetCredentialBands   []ScaleBand            `json:"target_credential_bands"`
	SelectedCapacityTier    CapacityTier           `json:"selected_capacity_tier"`
	HotPathSLOs             []HotPathSLO           `json:"hot_path_slos"`
	ExecutionLanes          []ExecutionLane        `json:"execution_lanes"`
	ShardPlan               []ShardPlan            `json:"shard_plan"`
	BackpressurePolicy      []BackpressureRule     `json:"backpressure_policy"`
	ReleaseGates            []ScaleReleaseGate     `json:"release_gates"`
	OperatorActions         []string               `json:"operator_actions"`
	Residuals               []string               `json:"residuals"`
	EvidenceRefs            []string               `json:"evidence_refs"`
	MeasurementArtifacts    []string               `json:"measurement_artifacts"`
	EstimatedDailyEventLoad int                    `json:"estimated_daily_event_load"`
	EstimatedMonthlyCostUSD int                    `json:"estimated_monthly_cost_usd"`
	UnitEconomics           ScaleUnitEconomics     `json:"unit_economics"`
	TenantIsolation         ScaleTenantIsolation   `json:"tenant_isolation"`
	Datastore               ScaleDatastorePosture  `json:"datastore"`
	Signer                  ScaleSignerPosture     `json:"signer"`
	ProjectionReplay        ScaleProjectionPosture `json:"projection_replay"`
}

type ScaleBand struct {
	ID                string `json:"id"`
	ManagedCredential string `json:"managed_credential"`
	CapacityTier      string `json:"capacity_tier"`
	Topology          string `json:"topology"`
}

type ExecutionLane struct {
	ID                    string   `json:"id"`
	Subsystem             string   `json:"subsystem"`
	WorkerPool            string   `json:"worker_pool"`
	Queue                 string   `json:"queue"`
	BulkheadEnv           []string `json:"bulkhead_env"`
	FailureMode           string   `json:"failure_mode"`
	ExternalSideEffect    string   `json:"external_side_effect"`
	ReplaySource          string   `json:"replay_source"`
	ScaleTrigger          string   `json:"scale_trigger"`
	HotPathSLO            string   `json:"hot_path_slo"`
	OperatorControl       string   `json:"operator_control"`
	BackpressureSignal    string   `json:"backpressure_signal"`
	Measurement           string   `json:"measurement"`
	ArchitectureInvariant string   `json:"architecture_invariant"`
}

type ShardPlan struct {
	ID                 string `json:"id"`
	AppliesTo          string `json:"applies_to"`
	PartitionKey       string `json:"partition_key"`
	TargetShardSize    int    `json:"target_shard_size"`
	MaxShardCount      int    `json:"max_shard_count"`
	PublicationSurface string `json:"publication_surface"`
}

type BackpressureRule struct {
	ID         string `json:"id"`
	AppliesTo  string `json:"applies_to"`
	Limit      string `json:"limit"`
	RejectMode string `json:"reject_mode"`
	Signal     string `json:"signal"`
}

type ScaleReleaseGate struct {
	ID       string `json:"id"`
	Command  string `json:"command"`
	Artifact string `json:"artifact"`
	Required bool   `json:"required"`
}

type ScaleUnitEconomics struct {
	EstimatedCostPerCredentialUSD float64 `json:"estimated_cost_per_credential_usd"`
	PostgresGiB30Day              float64 `json:"postgres_gib_30_day"`
	JetStreamGiB30Day             float64 `json:"jetstream_gib_30_day"`
	EventsPerDay                  int     `json:"events_per_day"`
}

type ScaleTenantIsolation struct {
	StorageEnforcement string   `json:"storage_enforcement"`
	QueryRule          string   `json:"query_rule"`
	EvidenceRefs       []string `json:"evidence_refs"`
}

type ScaleDatastorePosture struct {
	Postgres  string `json:"postgres"`
	JetStream string `json:"jetstream"`
	RLS       string `json:"rls"`
	Outbox    string `json:"outbox"`
}

type ScaleSignerPosture struct {
	ProcessModel string `json:"process_model"`
	Transport    string `json:"transport"`
	Scaling      string `json:"scaling"`
}

type ScaleProjectionPosture struct {
	ReplayFloorEventsPerSecond int    `json:"replay_floor_events_per_second"`
	MaxLagEvents               int    `json:"max_lag_events"`
	RebuildSource              string `json:"rebuild_source"`
}

// ActiveActiveIssuancePlan describes the served HA issuance contract. It is
// deliberately a fenced active/active ingress model: many regions may accept
// issuance traffic, while idempotency, PostgreSQL transactions, the event log, and
// signer isolation keep each mutation single-writer and replayable.
type ActiveActiveIssuancePlan struct {
	Capability             string                 `json:"capability"`
	Served                 bool                   `json:"served"`
	GeneratedAt            string                 `json:"generated_at"`
	Topology               string                 `json:"topology"`
	WriteModel             string                 `json:"write_model"`
	Regions                []IssuanceRegion       `json:"regions"`
	TenantWriteFences      []TenantWriteFence     `json:"tenant_write_fences"`
	IssuanceLanes          []RegionalIssuanceLane `json:"issuance_lanes"`
	FailoverRunbook        []RegionalFailoverStep `json:"failover_runbook"`
	ReleaseGates           []ScaleReleaseGate     `json:"release_gates"`
	RPOSeconds             int                    `json:"rpo_seconds"`
	RTOSeconds             int                    `json:"rto_seconds"`
	OperatorActions        []string               `json:"operator_actions"`
	Residuals              []string               `json:"residuals"`
	EvidenceRefs           []string               `json:"evidence_refs"`
	ArchitectureInvariants []string               `json:"architecture_invariants"`
}

type IssuanceRegion struct {
	ID            string `json:"id"`
	Region        string `json:"region"`
	Role          string `json:"role"`
	WritableScope string `json:"writable_scope"`
	Datastore     string `json:"datastore"`
	EventStream   string `json:"event_stream"`
	Signer        string `json:"signer"`
	HealthSignal  string `json:"health_signal"`
}

type TenantWriteFence struct {
	ID              string `json:"id"`
	Scope           string `json:"scope"`
	Mechanism       string `json:"mechanism"`
	ConflictOutcome string `json:"conflict_outcome"`
	Evidence        string `json:"evidence"`
}

type RegionalIssuanceLane struct {
	ID                 string `json:"id"`
	Region             string `json:"region"`
	AcceptedTraffic    string `json:"accepted_traffic"`
	MutationFence      string `json:"mutation_fence"`
	EventAppend        string `json:"event_append"`
	OutboxMode         string `json:"outbox_mode"`
	SignerMode         string `json:"signer_mode"`
	BackpressureSignal string `json:"backpressure_signal"`
	Recovery           string `json:"recovery"`
}

type RegionalFailoverStep struct {
	ID      string `json:"id"`
	Trigger string `json:"trigger"`
	Action  string `json:"action"`
	Gate    string `json:"gate"`
}

const (
	MeasurementArtifact     = "scripts/perf/artifacts/smoke-baseline.json"
	LiveMeasurementArtifact = "scripts/perf/artifacts/live-load-baseline.json"
	SpineBurstArtifact      = "scripts/perf/artifacts/spine-burst-cap-small.json"
)

var hotPathSLOs = []HotPathSLO{
	{
		ID: "PERF-SLO-001", HotPath: "api.issuance", Surface: "POST /api/v1/identities + served signer issuance",
		Owner: "CORRECT/API", Benchmark: "BenchmarkIssuance", P50MS: 50, P95MS: 150, P99MS: 300,
		MinThroughputPerSecond: 25, ErrorBudgetPercent: 0.10, MaxQueueSaturation: 0.80, MaxProjectionLagEvents: 25,
		CapacityRef: "CAP-SMALL",
	},
	{
		ID: "PERF-SLO-002", HotPath: "api.inventory", Surface: "GET /api/v1/certificates + inventory pagination",
		Owner: "API/STORE", Benchmark: "BenchmarkInventory", P50MS: 25, P95MS: 75, P99MS: 150,
		MinThroughputPerSecond: 100, ErrorBudgetPercent: 0.10, MaxQueueSaturation: 0.80, MaxProjectionLagEvents: 25,
		CapacityRef: "CAP-SMALL",
	},
	{
		ID: "PERF-SLO-003", HotPath: "api.graph_risk", Surface: "GET /api/v1/graph/* + /api/v1/risk/*",
		Owner: "GRAPH/RISK", Benchmark: "BenchmarkGraphRiskQuery", P50MS: 75, P95MS: 250, P99MS: 500,
		MinThroughputPerSecond: 20, ErrorBudgetPercent: 0.10, MaxQueueSaturation: 0.80, MaxProjectionLagEvents: 25,
		CapacityRef: "CAP-MEDIUM",
	},
	{
		ID: "PERF-SLO-004", HotPath: "api.secrets", Surface: "GET/PUT /api/v1/secrets/*",
		Owner: "SECRETS/CRYPTO", Benchmark: "BenchmarkSecrets", P50MS: 50, P95MS: 150, P99MS: 300,
		MinThroughputPerSecond: 50, ErrorBudgetPercent: 0.10, MaxQueueSaturation: 0.80, MaxProjectionLagEvents: 25,
		CapacityRef: "CAP-SMALL",
	},
	{
		ID: "PERF-SLO-005", HotPath: "protocol.enrollment", Surface: "ACME/EST/SCEP/CMP/SPIFFE/SSH enrollment parsers",
		Owner: "PROTOCOLS", Benchmark: "BenchmarkProtocolEnrollment", P50MS: 50, P95MS: 150, P99MS: 300,
		MinThroughputPerSecond: 40, ErrorBudgetPercent: 0.10, MaxQueueSaturation: 0.80, MaxProjectionLagEvents: 25,
		CapacityRef: "CAP-MEDIUM",
	},
	{
		ID: "PERF-SLO-006", HotPath: "revocation.ocsp_crl", Surface: "POST /ocsp/{tenant} + GET /crl/{tenant}",
		Owner: "REVOCATION", Benchmark: "BenchmarkOCSPCRL", P50MS: 25, P95MS: 75, P99MS: 150,
		MinThroughputPerSecond: 100, ErrorBudgetPercent: 0.10, MaxQueueSaturation: 0.80, MaxProjectionLagEvents: 25,
		CapacityRef: "CAP-SMALL",
	},
	{
		ID: "PERF-SLO-007", HotPath: "signer.rpc", Surface: "trustctl-signer gRPC Sign/GenerateKey request path",
		Owner: "SIGNING", Benchmark: "BenchmarkSignerRPC", P50MS: 25, P95MS: 75, P99MS: 150,
		MinThroughputPerSecond: 100, ErrorBudgetPercent: 0.10, MaxQueueSaturation: 0.70, MaxProjectionLagEvents: 0,
		CapacityRef: "CAP-SMALL",
	},
	{
		ID: "PERF-SLO-008", HotPath: "spine.projection_replay", Surface: "event replay + projection decode/apply loop",
		Owner: "SPINE/PROJECTIONS", Benchmark: "BenchmarkProjectionReplay", P50MS: 100, P95MS: 300, P99MS: 750,
		MinThroughputPerSecond: 500, ErrorBudgetPercent: 0.10, MaxQueueSaturation: 0.80, MaxProjectionLagEvents: 50,
		CapacityRef: "CAP-LARGE",
	},
}

var capacityTiers = []CapacityTier{
	{
		ID: "CAP-SMALL", Name: "single-node regulated evaluation", Tenants: 5, ManagedCredentials: 25000, EventsPerDay: 250000,
		PostgresGiB30Day: 8.1, JetStreamGiB30Day: 18, ControlPlaneCPU: "2 vCPU", ControlPlaneMemoryGiB: 4,
		SignerCPU: "1 vCPU", SignerMemoryGiB: 1, EstimatedMonthlyCostUSD: 420, EstimatedCostPerCredential: 0.0168,
		Notes: "Bundled PostgreSQL/NATS for evaluation; move to external datastores before production multi-tenant use.",
	},
	{
		ID: "CAP-MEDIUM", Name: "external datastore production", Tenants: 50, ManagedCredentials: 250000, EventsPerDay: 2500000,
		PostgresGiB30Day: 73, JetStreamGiB30Day: 173, ControlPlaneCPU: "6 vCPU", ControlPlaneMemoryGiB: 12,
		SignerCPU: "2 vCPU", SignerMemoryGiB: 2, EstimatedMonthlyCostUSD: 1880, EstimatedCostPerCredential: 0.0075,
		Notes: "External PostgreSQL and JetStream, two control-plane replicas, isolated signer process.",
	},
	{
		ID: "CAP-LARGE", Name: "multi-replica enterprise", Tenants: 250, ManagedCredentials: 1000000, EventsPerDay: 10000000,
		PostgresGiB30Day: 282, JetStreamGiB30Day: 690, ControlPlaneCPU: "16 vCPU", ControlPlaneMemoryGiB: 32,
		SignerCPU: "6 vCPU", SignerMemoryGiB: 8, EstimatedMonthlyCostUSD: 5590, EstimatedCostPerCredential: 0.0056,
		Notes: "External HA PostgreSQL, external JetStream cluster, isolated signer capacity scaled separately.",
	},
}

var scaleBands = []ScaleBand{
	{ID: "SCALE-100K", ManagedCredential: "100,000 managed credentials", CapacityTier: "CAP-MEDIUM", Topology: "external PostgreSQL and JetStream with at least two control-plane replicas and isolated signer capacity"},
	{ID: "SCALE-250K", ManagedCredential: "250,000 managed credentials", CapacityTier: "CAP-MEDIUM", Topology: "external datastore production tier; split connector and read-query lanes before adding tenants"},
	{ID: "SCALE-1M", ManagedCredential: "1,000,000 managed credentials", CapacityTier: "CAP-LARGE", Topology: "multi-replica enterprise tier with signer scaled separately from control-plane API workers"},
}

var scaleExecutionLanes = []ExecutionLane{
	{
		ID: "scale-issue", Subsystem: "issuance", WorkerPool: "lifecycle issue/deploy workers", Queue: "bounded lifecycle queue",
		BulkheadEnv: []string{"TRSTCTL_BULKHEAD_LIFECYCLE_WORKERS", "TRSTCTL_BULKHEAD_LIFECYCLE_QUEUE"},
		FailureMode: "full queue rejects before signer work starts", ExternalSideEffect: "connector delivery intent is written through the outbox",
		ReplaySource: "events log", ScaleTrigger: "issuance p95, signer saturation, or queue saturation exceeds SLO",
		HotPathSLO: "PERF-SLO-001", OperatorControl: "increase lifecycle workers or split connector targets before raising signer concurrency",
		BackpressureSignal: "queue saturation and HTTP 429/structured problem response", Measurement: "perf live api.issuance",
		ArchitectureInvariant: "AN-2/AN-5/AN-6/AN-7",
	},
	{
		ID: "scale-inventory", Subsystem: "inventory/read API", WorkerPool: "read/query workers", Queue: "bounded read query queue",
		BulkheadEnv: []string{"TRSTCTL_BULKHEAD_QUERY_WORKERS", "TRSTCTL_BULKHEAD_QUERY_QUEUE"},
		FailureMode: "large scans reject fast instead of starving mutation paths", ExternalSideEffect: "none",
		ReplaySource: "projection tables rebuilt from events", ScaleTrigger: "inventory p95 or projection lag exceeds SLO",
		HotPathSLO: "PERF-SLO-002", OperatorControl: "raise read replicas or page size discipline before widening result sets",
		BackpressureSignal: "read queue saturation and projection lag", Measurement: "perf live api.inventory",
		ArchitectureInvariant: "AN-1/AN-2/AN-7",
	},
	{
		ID: "scale-risk-graph", Subsystem: "graph/risk", WorkerPool: "heavy read-query workers", Queue: "bounded graph/risk queue",
		BulkheadEnv: []string{"TRSTCTL_BULKHEAD_QUERY_WORKERS", "TRSTCTL_BULKHEAD_QUERY_QUEUE"},
		FailureMode: "expensive graph/risk jobs cannot starve certificate or agent APIs", ExternalSideEffect: "none",
		ReplaySource: "credential graph projection", ScaleTrigger: "graph/risk p99 exceeds SLO or hot partition appears",
		HotPathSLO: "PERF-SLO-003", OperatorControl: "increase read capacity, shard graph export jobs, and precompute heavy tenant views",
		BackpressureSignal: "queue saturation and graph query latency", Measurement: "perf live api.graph_risk",
		ArchitectureInvariant: "AN-1/AN-2/AN-7",
	},
	{
		ID: "scale-revocation", Subsystem: "revocation distribution", WorkerPool: "revocation publication workers", Queue: "bounded revocation queue",
		BulkheadEnv: []string{"TRSTCTL_BULKHEAD_REVOCATION_WORKERS", "TRSTCTL_BULKHEAD_REVOCATION_QUEUE"},
		FailureMode: "revocation publication is isolated from issuance and read APIs", ExternalSideEffect: "CRL/OCSP publication artifacts are event-projected",
		ReplaySource: "certificate.revoked and ca.crl.published events", ScaleTrigger: "OCSP/CRL p95, shard count, or delta cadence exceeds SLO",
		HotPathSLO: "PERF-SLO-006", OperatorControl: "serve partitioned CRLs and tune CDN/ingress outside the control plane",
		BackpressureSignal: "revocation queue saturation and stale next_update", Measurement: "perf live revocation.ocsp_crl",
		ArchitectureInvariant: "AN-2/AN-7",
	},
	{
		ID: "scale-signer", Subsystem: "signer", WorkerPool: "isolated signer process pool", Queue: "signer RPC backlog",
		BulkheadEnv: []string{"TRSTCTL_SIGNER_WORKERS", "TRSTCTL_SIGNER_QUEUE"},
		FailureMode: "signer saturation does not import SQL or HTTP into the signer process", ExternalSideEffect: "signature only; orchestrator records state outside signer",
		ReplaySource: "orchestrator idempotency and events", ScaleTrigger: "signer p95 or CPU headroom becomes limiting resource",
		HotPathSLO: "PERF-SLO-007", OperatorControl: "scale signer replicas or HSM partitions separately from control-plane API workers",
		BackpressureSignal: "signer queue saturation and gRPC timeout rate", Measurement: "perf live signer.rpc",
		ArchitectureInvariant: "AN-3/AN-4/AN-7/AN-8",
	},
	{
		ID: "scale-projections", Subsystem: "event replay/projections", WorkerPool: "projection workers", Queue: "JetStream consumer backlog",
		BulkheadEnv: []string{"TRSTCTL_PROJECTION_WORKERS", "TRSTCTL_PROJECTION_QUEUE"},
		FailureMode: "read models fall behind visibly instead of mutating read tables directly", ExternalSideEffect: "none",
		ReplaySource: "append-only event log", ScaleTrigger: "projection lag or rebuild window exceeds recovery objective",
		HotPathSLO: "PERF-SLO-008", OperatorControl: "increase projection workers, split consumers, or reduce hot tenant batch size",
		BackpressureSignal: "consumer lag and replay throughput", Measurement: "perf live spine.projection_replay",
		ArchitectureInvariant: "AN-2/AN-7",
	},
}

var scaleShardPlan = []ShardPlan{
	{ID: "inventory-pages", AppliesTo: "certificate and NHI inventory", PartitionKey: "tenant_id plus cursor/id order", TargetShardSize: 1000, MaxShardCount: 0, PublicationSurface: "/api/v1/certificates and /api/v1/nhi/inventory"},
	{ID: "crl-shards", AppliesTo: "revoked serial distribution", PartitionKey: "tenant_id plus serial hash", TargetShardSize: 100000, MaxShardCount: 1024, PublicationSurface: "/crl/{tenant}/manifest.json, /shards/{index}, and /delta/{base}"},
	{ID: "projection-batches", AppliesTo: "event replay and read-model rebuild", PartitionKey: "tenant_id plus event sequence", TargetShardSize: 50000, MaxShardCount: 0, PublicationSurface: "projection workers and recovery runbooks"},
}

var scaleBackpressure = []BackpressureRule{
	{ID: "queue-saturation", AppliesTo: "all bounded worker queues", Limit: "80% queue saturation, 70% for signer", RejectMode: "structured 429/problem response before accepting new work", Signal: "queue_saturation in perf and metrics"},
	{ID: "projection-lag", AppliesTo: "read-model rebuild and replay", Limit: "25 events for normal hot paths, 50 events for projection replay", RejectMode: "surface stale read posture and hold bulk fanout", Signal: "projection_lag_events"},
	{ID: "outbox-delivery", AppliesTo: "connectors, upstream CAs, notifications, webhooks", Limit: "destination circuit opens after repeated delivery failures", RejectMode: "record dead-letter/circuit state and keep mutation committed", Signal: "outbox circuit status"},
}

var scaleReleaseGates = []ScaleReleaseGate{
	{ID: "perf-smoke", Command: "scripts/perf/run-local.sh --profile smoke", Artifact: MeasurementArtifact, Required: true},
	{ID: "perf-live", Command: "scripts/perf/run-local.sh --profile live", Artifact: LiveMeasurementArtifact, Required: true},
	{ID: "perf-capacity", Command: "scripts/perf/run-capacity-calibration.sh --out scripts/perf/artifacts/capacity-measurement-baseline.json", Artifact: CapacityMeasurementArtifact, Required: true},
	{ID: "spine-burst", Command: "scripts/perf/run-spine-burst.sh --profile cap-small --out scripts/perf/artifacts/spine-burst-cap-small.json && scripts/perf/soak.sh --in scripts/perf/artifacts/spine-burst-cap-small.json", Artifact: SpineBurstArtifact, Required: true},
	{ID: "soak", Command: "scripts/perf/soak.sh --in <series.json> --out <report.json>", Artifact: "soak-trend.json", Required: true},
	{ID: "architecture-lint", Command: "make lint test", Artifact: "local gate transcript", Required: true},
}

var activeActiveRegions = []IssuanceRegion{
	{
		ID: "region-a", Region: "primary-us-east", Role: "active issuance ingress and eligible worker leader",
		WritableScope: "all tenant issuance requests whose idempotency and event append transactions commit in the shared writer plane",
		Datastore:     "external PostgreSQL with RLS, advisory locks, idempotency records, and transactional outbox",
		EventStream:   "replicated external NATS JetStream event log",
		Signer:        "local sidecar signer over UDS or isolated signer over pinned mTLS",
		HealthSignal:  "readyz, signer rpc latency, queue saturation, projection lag, and event append error rate",
	},
	{
		ID: "region-b", Region: "secondary-us-west", Role: "active issuance ingress and leader-election follower/standby leader",
		WritableScope: "same tenant-safe shared writer plane; duplicate retries return the original idempotent result",
		Datastore:     "external PostgreSQL with the same tenant RLS and idempotency table",
		EventStream:   "replicated external NATS JetStream event log with the same append contract",
		Signer:        "same CA key material via shared signer store or isolated signer pool",
		HealthSignal:  "readyz, signer rpc latency, queue saturation, projection lag, and event append error rate",
	},
	{
		ID: "region-c", Region: "eu-central", Role: "active read/API ingress, issuance enabled after datastore/signer health gate",
		WritableScope: "enabled only when latency and signer health stay inside operator SLO",
		Datastore:     "external PostgreSQL writer endpoint or promoted regional endpoint",
		EventStream:   "external JetStream cluster with observed replica health",
		Signer:        "isolated signer pool preferred for cross-region latency boundaries",
		HealthSignal:  "federation cursor, projection lag, signer rpc latency, and regional synthetic issue smoke",
	},
}

var activeActiveFences = []TenantWriteFence{
	{ID: "idempotency", Scope: "every issuance mutation", Mechanism: "Idempotency-Key recorded before execution", ConflictOutcome: "retry returns original result instead of minting a second certificate", Evidence: "AN-5 and idempotency tests"},
	{ID: "event-log", Scope: "issued certificate state", Mechanism: "append event first, then project read models", ConflictOutcome: "read state is rebuilt from one ordered event stream", Evidence: "AN-2 and projection replay tests"},
	{ID: "outbox", Scope: "connector/upstream side effects", Mechanism: "write external-call intent in the same transaction as state", ConflictOutcome: "regional retry delivers at-least-once without losing the committed state", Evidence: "AN-6 and outbox worker tests"},
	{ID: "leader-workers", Scope: "continuous schedulers", Mechanism: "PostgreSQL advisory leader lock", ConflictOutcome: "only one region/replica runs renewal, CRL, projection tail, GC, and outbox dispatcher loops", Evidence: "internal/server/run.go leaderRuntimeWork"},
	{ID: "signer-boundary", Scope: "private key operations", Mechanism: "separate signer process reached over UDS or pinned mTLS", ConflictOutcome: "API region compromise does not embed private-key operations in the control-plane process", Evidence: "AN-4 signer isolation tests"},
}

var regionalIssuanceLanes = []RegionalIssuanceLane{
	{
		ID: "issue-region-a", Region: "primary-us-east", AcceptedTraffic: "interactive API, agent renewal, ACME/SCEP/EST enrollment",
		MutationFence: "idempotency record plus tenant-scoped PostgreSQL transaction", EventAppend: "certificate.issued appended before projection",
		OutboxMode: "connector delivery and notifications queued in transactional outbox", SignerMode: "region-local signer sidecar or isolated signer pool",
		BackpressureSignal: "lifecycle queue saturation, signer queue saturation, and HTTP 429/problem response",
		Recovery:           "duplicate request in another region returns the idempotent result after shared store convergence",
	},
	{
		ID: "issue-region-b", Region: "secondary-us-west", AcceptedTraffic: "same issuance APIs through regional ingress",
		MutationFence: "same shared idempotency and event append contract", EventAppend: "same replicated JetStream subject and event schema",
		OutboxMode: "outbox worker runs only on the elected leader; regional API only commits intent", SignerMode: "same CA key via shared store or isolated signer pool",
		BackpressureSignal: "regional readyz degradation before accepting issuance beyond queue limits",
		Recovery:           "leader failover resumes workers; event replay rebuilds read state",
	},
}

var activeActiveFailover = []RegionalFailoverStep{
	{ID: "detect", Trigger: "region API, PostgreSQL writer endpoint, JetStream replica, or signer health outside SLO", Action: "stop routing new issuance to the impaired ingress", Gate: "readyz and synthetic issue smoke fail closed"},
	{ID: "fence", Trigger: "suspected split-brain or stale writer endpoint", Action: "hold issuance traffic until idempotency/event append health is green in one writer plane", Gate: "no new certificate.issued event accepted from stale plane"},
	{ID: "promote", Trigger: "leader lock released or writer endpoint promoted", Action: "regional follower acquires leader lock and resumes outbox, CRL, lifecycle, and projection workers", Gate: "leader election healthy and projection lag within target"},
	{ID: "verify", Trigger: "traffic moved", Action: "run synthetic issue/renew/revoke smoke and compare event/audit evidence", Gate: "same serial/idempotency result visible from every active region"},
}

var activeActiveReleaseGates = []ScaleReleaseGate{
	{ID: "regional-smoke", Command: "trstctl-cli scale ha-issuance && synthetic issue from each ingress", Artifact: "regional-issuance-smoke.json", Required: true},
	{ID: "failover-drill", Command: "operator runbook: withdraw region, promote writer endpoint, replay projections", Artifact: "ha-failover-drill.json", Required: true},
	{ID: "idempotency-replay", Command: "go test ./internal/api ./internal/server -run Idempotency", Artifact: "idempotency transcript", Required: true},
	{ID: "architecture-lint", Command: "make lint test", Artifact: "local gate transcript", Required: true},
}

func HotPaths() []HotPathSLO {
	out := make([]HotPathSLO, len(hotPathSLOs))
	copy(out, hotPathSLOs)
	return out
}

func CapacityTiers() []CapacityTier {
	out := make([]CapacityTier, len(capacityTiers))
	copy(out, capacityTiers)
	return out
}

func ScaleOrchestration(generatedAt string) ScaleOrchestrationPlan {
	if generatedAt == "" {
		generatedAt = "1970-01-01T00:00:00Z"
	}
	large := capacityTierByID("CAP-LARGE")
	return ScaleOrchestrationPlan{
		Capability:              "CAP-SCALE-01",
		Served:                  true,
		GeneratedAt:             generatedAt,
		TargetCredentialBands:   append([]ScaleBand(nil), scaleBands...),
		SelectedCapacityTier:    large,
		HotPathSLOs:             HotPaths(),
		ExecutionLanes:          copyExecutionLanes(scaleExecutionLanes),
		ShardPlan:               append([]ShardPlan(nil), scaleShardPlan...),
		BackpressurePolicy:      append([]BackpressureRule(nil), scaleBackpressure...),
		ReleaseGates:            append([]ScaleReleaseGate(nil), scaleReleaseGates...),
		EstimatedDailyEventLoad: large.EventsPerDay,
		EstimatedMonthlyCostUSD: large.EstimatedMonthlyCostUSD,
		MeasurementArtifacts:    []string{MeasurementArtifact, LiveMeasurementArtifact, CapacityMeasurementArtifact, SpineBurstArtifact},
		UnitEconomics: ScaleUnitEconomics{
			EstimatedCostPerCredentialUSD: large.EstimatedCostPerCredential,
			PostgresGiB30Day:              large.PostgresGiB30Day,
			JetStreamGiB30Day:             large.JetStreamGiB30Day,
			EventsPerDay:                  large.EventsPerDay,
		},
		TenantIsolation: ScaleTenantIsolation{
			StorageEnforcement: "every table carries tenant_id and PostgreSQL RLS enforces isolation below the API",
			QueryRule:          "repository queries must filter on tenant_id and the architecture linter fails unsafe paths",
			EvidenceRefs:       []string{"CLAUDE.md: AN-1", "tools/trstctllint", "internal/store/migrations"},
		},
		Datastore: ScaleDatastorePosture{
			Postgres:  "external HA PostgreSQL for CAP-MEDIUM and CAP-LARGE; no SQLite path",
			JetStream: "NATS JetStream is the source-of-truth event log with external cluster for production",
			RLS:       "tenant_id is enforced at storage layer",
			Outbox:    "external calls run through transactional outbox workers",
		},
		Signer: ScaleSignerPosture{
			ProcessModel: "separate signer process, never in-process with the control plane",
			Transport:    "gRPC over UDS for single-node or mTLS across nodes",
			Scaling:      "scale signer CPU/HSM partitions separately from control-plane API replicas",
		},
		ProjectionReplay: ScaleProjectionPosture{
			ReplayFloorEventsPerSecond: 500,
			MaxLagEvents:               50,
			RebuildSource:              "append-only events log",
		},
		OperatorActions: []string{
			"run perf-live and soak gates against the chosen datastore, signer placement, and connector mix before production launch",
			"move tenants above 250k credentials to CAP-LARGE topology before increasing issuer fanout",
			"watch projection lag, signer saturation, outbox circuit state, and revocation next_update freshness during bulk rotation",
			"use sharded/delta CRLs and external ingress/CDN distribution for high-churn revocation lanes",
		},
		Residuals: []string{
			"customer infrastructure pricing and exact datastore SKU are operator-specific",
			"external relying-party adoption of CRL shard and delta URLs depends on customer CDP/AIA rollout",
			"remote GitHub-hosted matrix behavior is not proven by this local served endpoint",
		},
		EvidenceRefs: []string{
			"internal/perf/contract.go",
			"internal/perf/live.go",
			"docs/performance.md",
			"docs/performance-capacity.md",
			"scripts/perf/artifacts/capacity-measurement-baseline.json",
			"scripts/perf/artifacts/live-load-baseline.json",
			"scripts/perf/artifacts/spine-burst-cap-small.json",
		},
	}
}

func ActiveActiveIssuance(generatedAt string) ActiveActiveIssuancePlan {
	if generatedAt == "" {
		generatedAt = "1970-01-01T00:00:00Z"
	}
	return ActiveActiveIssuancePlan{
		Capability:  "CAP-SCALE-02",
		Served:      true,
		GeneratedAt: generatedAt,
		Topology:    "multi-region active ingress on a shared external PostgreSQL writer plane and replicated JetStream event log",
		WriteModel:  "active-active regional API acceptance with single-writer mutation fencing per idempotency key and event append; not split-brain independent CAs",
		Regions:     append([]IssuanceRegion(nil), activeActiveRegions...),
		TenantWriteFences: append(
			[]TenantWriteFence(nil),
			activeActiveFences...,
		),
		IssuanceLanes:   append([]RegionalIssuanceLane(nil), regionalIssuanceLanes...),
		FailoverRunbook: append([]RegionalFailoverStep(nil), activeActiveFailover...),
		ReleaseGates:    append([]ScaleReleaseGate(nil), activeActiveReleaseGates...),
		RPOSeconds:      5,
		RTOSeconds:      30,
		OperatorActions: []string{
			"route issuance only to regions whose readyz, signer latency, queue saturation, and event append health are green",
			"keep one shared writer plane or a fenced promoted writer endpoint for tenant mutations",
			"run regional synthetic issue/renew/revoke smoke before and after failover drills",
			"treat any idempotency, event append, or signer fence degradation as a fail-closed issuance condition",
		},
		Residuals: []string{
			"customer DNS, ingress, datastore promotion, and signer/HSM latency determine the real RTO",
			"independent split-brain writers for the same tenant are intentionally not supported",
			"external CA connectors may impose provider-side regional limits outside trstctl's worker bulkheads",
		},
		EvidenceRefs: []string{
			"internal/server/run.go",
			"internal/store/leader.go",
			"internal/idem",
			"internal/events",
			"internal/orchestrator",
			"docs/disaster-recovery.md",
		},
		ArchitectureInvariants: []string{"AN-1", "AN-2", "AN-4", "AN-5", "AN-6", "AN-7", "AN-8"},
	}
}

func capacityTierByID(id string) CapacityTier {
	for _, tier := range capacityTiers {
		if tier.ID == id {
			return tier
		}
	}
	return CapacityTier{}
}

func copyExecutionLanes(in []ExecutionLane) []ExecutionLane {
	out := make([]ExecutionLane, len(in))
	copy(out, in)
	for i := range out {
		out[i].BulkheadEnv = append([]string(nil), out[i].BulkheadEnv...)
	}
	return out
}
