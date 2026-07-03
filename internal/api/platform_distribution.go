package api

import (
	"net/http"

	cfg "trstctl.com/trstctl/internal/config"
)

const platformDistributionCapability = "CAP-MODEL-01"

type platformDistributionStatus struct {
	Served                 bool                  `json:"served"`
	Capability             string                `json:"capability"`
	ControlPlaneLineage    string                `json:"control_plane_lineage"`
	DefaultEvaluationMode  string                `json:"default_evaluation_mode"`
	ProductionMode         string                `json:"production_mode"`
	OfflineLicenseVerifier bool                  `json:"offline_license_verifier"`
	CoreAuditAndExport     bool                  `json:"core_audit_and_export"`
	RunModes               []platformRunMode     `json:"run_modes"`
	SupportedHostArchives  []platformHostArchive `json:"supported_host_archives"`
	ReleaseGates           []string              `json:"release_gates"`
	EvidenceRefs           []string              `json:"evidence_refs"`
	BuyerEvidenceReceipts  []string              `json:"buyer_evidence_receipts"`
}

type platformRunMode struct {
	ID                 string   `json:"id"`
	Label              string   `json:"label"`
	Packaging          string   `json:"packaging"`
	PostgresMode       string   `json:"postgres_mode"`
	NATSMode           string   `json:"nats_mode"`
	SignerProcessModel string   `json:"signer_process_model"`
	TenantIsolation    string   `json:"tenant_isolation"`
	IntendedUse        string   `json:"intended_use"`
	EvidenceRefs       []string `json:"evidence_refs"`
}

type platformHostArchive struct {
	OSArch          string `json:"os_arch"`
	PostgresVersion string `json:"postgres_version"`
	RuntimePin      string `json:"runtime_pin"`
	RuntimeCheck    string `json:"runtime_check"`
	EvaluationOnly  bool   `json:"evaluation_only"`
}

func (a *API) getPlatformDistribution(w http.ResponseWriter, _ *http.Request) {
	a.writeJSON(w, http.StatusOK, buildPlatformDistributionStatus())
}

func buildPlatformDistributionStatus() platformDistributionStatus {
	return platformDistributionStatus{
		Served:                 true,
		Capability:             platformDistributionCapability,
		ControlPlaneLineage:    "one repo and one binary lineage; Enterprise/Provider code attaches only through the tagged ee seam, while core never imports ee",
		DefaultEvaluationMode:  "host archive can supervise bundled PostgreSQL plus embedded file-backed NATS JetStream for single-node evaluation on pinned archives",
		ProductionMode:         "self-hosted production uses external PostgreSQL and external replicated NATS JetStream; the signer remains a separate process",
		OfflineLicenseVerifier: true,
		CoreAuditAndExport:     true,
		RunModes: []platformRunMode{
			{
				ID:                 "host-archive-eval",
				Label:              "Host archive / single-node eval",
				Packaging:          "one trstctl binary plus a supervised signer child process",
				PostgresMode:       cfg.PostgresBundled,
				NATSMode:           cfg.NATSEmbedded,
				SignerProcessModel: "separate supervised child process over peer-authenticated UDS",
				TenantIsolation:    "PostgreSQL RLS and tenant_id stay enabled even when PostgreSQL is bundled",
				IntendedUse:        "local evaluation and demos on supported host archives",
				EvidenceRefs: []string{
					"internal/server/startBundledPostgres",
					"internal/server/bundled_pg_verify.go",
					"internal/config/config.go",
					"docs/getting-started.md",
				},
			},
			{
				ID:                 "docker-compose-eval",
				Label:              "Docker Compose eval",
				Packaging:          "control plane, PostgreSQL, NATS JetStream, and signer containers wired like production dependencies",
				PostgresMode:       cfg.PostgresExternal,
				NATSMode:           cfg.NATSExternal,
				SignerProcessModel: "separate service/container with explicit authorizer posture",
				TenantIsolation:    "the same external PostgreSQL RLS path as production",
				IntendedUse:        "local self-hosted proof with explicit datastores and loopback-friendly defaults",
				EvidenceRefs: []string{
					"deploy/docker/docker-compose.yml",
					"deploy/docker/README.md",
					"docs/getting-started.md",
				},
			},
			{
				ID:                 "kubernetes-helm",
				Label:              "Kubernetes / Helm / Operator",
				Packaging:          "Helm chart and operator-managed deployment with external PostgreSQL and NATS",
				PostgresMode:       cfg.PostgresExternal,
				NATSMode:           cfg.NATSExternal,
				SignerProcessModel: "separate signer sidecar or service with UDS or mTLS transport",
				TenantIsolation:    "tenant tables stay scoped by tenant_id and PostgreSQL RLS",
				IntendedUse:        "self-hosted production or regulated on-prem deployment",
				EvidenceRefs: []string{
					"deploy/helm",
					"deploy/operator",
					"deploy/kubernetes",
					"docs/journeys/run-in-production.md",
				},
			},
			{
				ID:                 "external-production",
				Label:              "External datastore production",
				Packaging:          "trstctl binaries or containers pointed at operator-owned PostgreSQL and NATS endpoints",
				PostgresMode:       cfg.PostgresExternal,
				NATSMode:           cfg.NATSExternal,
				SignerProcessModel: "separate signer process; UDS when colocated or mTLS across nodes",
				TenantIsolation:    "no SQLite path; PostgreSQL remains the datastore in every deployment mode",
				IntendedUse:        "production HA, backup/restore, federation, and DR",
				EvidenceRefs: []string{
					"docs/configuration.md",
					"docs/journeys/run-in-production.md",
					"docs/disaster-recovery.md",
					"internal/server/run.go",
				},
			},
		},
		SupportedHostArchives: []platformHostArchive{
			{
				OSArch:          "linux-amd64",
				PostgresVersion: "16.4.0",
				RuntimePin:      "deploy/supply-chain/embedded-postgres.json",
				RuntimeCheck:    "cached embedded-postgres .txz SHA-256 is verified before startup",
				EvaluationOnly:  true,
			},
			{
				OSArch:          "linux-arm64v8",
				PostgresVersion: "16.4.0",
				RuntimePin:      "deploy/supply-chain/embedded-postgres.json",
				RuntimeCheck:    "cached embedded-postgres .txz SHA-256 is verified before startup",
				EvaluationOnly:  true,
			},
			{
				OSArch:          "darwin-arm64v8",
				PostgresVersion: "16.4.0",
				RuntimePin:      "deploy/supply-chain/embedded-postgres.json",
				RuntimeCheck:    "cached embedded-postgres .txz SHA-256 is verified before startup",
				EvaluationOnly:  true,
			},
		},
		ReleaseGates: []string{
			"make lint test",
			"architecture linter",
			"embedded-postgres scan receipts",
			"OpenAPI/CLI route parity",
			"core-only build links zero ee packages",
		},
		EvidenceRefs: []string{
			"deploy/supply-chain/embedded-postgres.json",
			"internal/server/startBundledPostgres",
			"internal/server/bundled_pg_verify.go",
			"internal/config/config.go",
			"deploy/docker/docker-compose.yml",
			"deploy/helm",
			"deploy/operator",
			"docs/features/platform-and-api.md",
			"docs/configuration.md",
			"docs/getting-started.md",
		},
		BuyerEvidenceReceipts: []string{
			"GET /api/v1/platform/distribution",
			"trstctl-cli platform distribution",
			"deploy/supply-chain/embedded-postgres.json",
			"docs/features/platform-and-api.md#single-binary-distribution-f14",
		},
	}
}
