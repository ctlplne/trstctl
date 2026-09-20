// SPDX-License-Identifier: BUSL-1.1

package api

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	gouuid "github.com/google/uuid"

	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/crypto/secret"
	"trstctl.com/trstctl/internal/secretscan"
	"trstctl.com/trstctl/internal/store"
)

// SecretScanner is the process boundary used by POST /api/v1/secrets/scans.
// Implementations must return metadata only; secret values stay inside the scanner
// process and redacted report file.
type SecretScanner interface {
	Scan(ctx context.Context, path string) (secretscan.Report, error)
}

type SecretScannerWithOptions interface {
	ScanWithOptions(ctx context.Context, path string, opts secretscan.ScanOptions) (secretscan.Report, error)
}

type secretScannerPlanner interface {
	Plan(path string, opts secretscan.ScanOptions) (secretscan.Plan, error)
}

const secretScanReviewDomain = "trstctl.api.f39-secret-scan-review.v1" // #nosec G101 -- public MAC domain label, not a credential

type secretRepoScanProviderResponse struct {
	ID               string   `json:"id"`
	Name             string   `json:"name"`
	RealtimeTriggers []string `json:"realtime_triggers"`
	AuthMode         string   `json:"auth_mode"`
	IngestMode       string   `json:"ingest_mode"`
	RefTypes         []string `json:"ref_types"`
	SecretHandling   string   `json:"secret_handling"`
	OutboxMode       string   `json:"outbox_mode"`
}

type secretRepoScanGateResponse struct {
	ID       string `json:"id"`
	Command  string `json:"command"`
	Artifact string `json:"artifact"`
	Required bool   `json:"required"`
}

type secretRepoScanWebhookRequest struct {
	Repository    string `json:"repository"`
	CloneURL      string `json:"clone_url,omitempty"`
	CheckoutPath  string `json:"checkout_path,omitempty"`
	Ref           string `json:"ref,omitempty"`
	CommitSHA     string `json:"commit_sha,omitempty"`
	Event         string `json:"event,omitempty"`
	CredentialRef string `json:"credential_ref,omitempty"`
}

type secretRepoScanWebhookResponse struct {
	Capability        string `json:"capability"`
	Provider          string `json:"provider"`
	Repository        string `json:"repository"`
	SourceID          string `json:"source_id"`
	RunID             string `json:"run_id"`
	Queued            bool   `json:"queued"`
	Status            string `json:"status"`
	OutboxDestination string `json:"outbox_destination"`
	Scanner           string `json:"scanner"`
	DiscoveryRunPath  string `json:"discovery_run_path"`
}

type secretRepoScanPostureResponse struct {
	Capability           string                           `json:"capability"`
	Served               bool                             `json:"served"`
	GeneratedAt          string                           `json:"generated_at"`
	Providers            []secretRepoScanProviderResponse `json:"providers"`
	WebhookPaths         []string                         `json:"webhook_paths"`
	QueueModel           string                           `json:"queue_model"`
	Scanner              string                           `json:"scanner"`
	MinimumRulesActive   int                              `json:"minimum_rules_active"`
	RedactionModel       string                           `json:"redaction_model"`
	EventFlow            []string                         `json:"event_flow"`
	ReleaseGates         []secretRepoScanGateResponse     `json:"release_gates"`
	OperatorActions      []string                         `json:"operator_actions"`
	Residuals            []string                         `json:"residuals"`
	EvidenceRefs         []string                         `json:"evidence_refs"`
	ArchitectureControls []string                         `json:"architecture_controls"`
}

type thirdPartySecretScanProviderResponse struct {
	ID             string   `json:"id"`
	Name           string   `json:"name"`
	ArtifactKinds  []string `json:"artifact_kinds"`
	IngestMode     string   `json:"ingest_mode"`
	SecretHandling string   `json:"secret_handling"`
	OutboxMode     string   `json:"outbox_mode"`
}

type thirdPartySecretScanIngestRequest struct {
	Source        string `json:"source"`
	ArtifactPath  string `json:"artifact_path"`
	ArtifactKind  string `json:"artifact_kind,omitempty"`
	Event         string `json:"event,omitempty"`
	CredentialRef string `json:"credential_ref,omitempty"`
}

type thirdPartySecretScanReceipt struct {
	Capability        string `json:"capability"`
	Provider          string `json:"provider"`
	Source            string `json:"source"`
	SourceID          string `json:"source_id"`
	RunID             string `json:"run_id"`
	Queued            bool   `json:"queued"`
	Status            string `json:"status"`
	OutboxDestination string `json:"outbox_destination"`
	Scanner           string `json:"scanner"`
	DiscoveryRunPath  string `json:"discovery_run_path"`
}

type thirdPartySecretScanPostureResponse struct {
	Capability           string                                 `json:"capability"`
	Served               bool                                   `json:"served"`
	GeneratedAt          string                                 `json:"generated_at"`
	Providers            []thirdPartySecretScanProviderResponse `json:"providers"`
	IngestPaths          []string                               `json:"ingest_paths"`
	QueueModel           string                                 `json:"queue_model"`
	Scanner              string                                 `json:"scanner"`
	MinimumRulesActive   int                                    `json:"minimum_rules_active"`
	RedactionModel       string                                 `json:"redaction_model"`
	EventFlow            []string                               `json:"event_flow"`
	ReleaseGates         []secretRepoScanGateResponse           `json:"release_gates"`
	OperatorActions      []string                               `json:"operator_actions"`
	Residuals            []string                               `json:"residuals"`
	EvidenceRefs         []string                               `json:"evidence_refs"`
	ArchitectureControls []string                               `json:"architecture_controls"`
}

type secretScanRequest struct {
	Path               string `json:"path"`
	Mode               string `json:"mode,omitempty"`
	CustomRulesPath    string `json:"custom_rules_path,omitempty"`
	PreviewFingerprint string `json:"preview_fingerprint,omitempty"`
}

type secretScanPreviewResponse struct {
	Capability             string   `json:"capability"`
	Operation              string   `json:"operation"`
	Ready                  bool     `json:"ready"`
	EffectFree             bool     `json:"effect_free"`
	TargetPath             string   `json:"target_path"`
	Mode                   string   `json:"mode"`
	CustomRules            bool     `json:"custom_rules"`
	CustomRulesPath        string   `json:"custom_rules_path,omitempty"`
	CustomRulesSHA256      string   `json:"custom_rules_sha256,omitempty"`
	Scanner                string   `json:"scanner"`
	RulesActive            int      `json:"rules_active"`
	Capabilities           []string `json:"capabilities"`
	RequiredPermission     string   `json:"required_permission"`
	RequestFingerprint     string   `json:"request_fingerprint"`
	Blockers               []string `json:"blockers"`
	Prerequisites          []string `json:"prerequisites"`
	PreviewWrites          []string `json:"preview_writes"`
	PreviewExternalEffects []string `json:"preview_external_effects"`
	ExecuteWrites          []string `json:"execute_writes"`
	ExecuteExternalEffects []string `json:"execute_external_effects"`
	RecoverySteps          []string `json:"recovery_steps"`
	VerificationSteps      []string `json:"verification_steps"`
	CLIArgv                []string `json:"cli_argv"`
	DataHandling           string   `json:"secret_data_handling"`
}

type secretScanFindingResponse struct {
	RuleID        string `json:"rule_id"`
	File          string `json:"file"`
	Line          int    `json:"line"`
	CredentialRef string `json:"credential_ref"`
}

type secretScanResponse struct {
	RunID         string                      `json:"run_id"`
	Scanner       string                      `json:"scanner"`
	EngineVersion string                      `json:"engine_version"`
	Mode          string                      `json:"mode"`
	CustomRules   bool                        `json:"custom_rules"`
	Capabilities  []string                    `json:"capabilities"`
	RulesActive   int                         `json:"rules_active"`
	FindingsCount int                         `json:"findings_count"`
	Findings      []secretScanFindingResponse `json:"findings"`
}

func normalizeSecretScanRequest(scanner SecretScanner, req secretScanRequest) (secretscan.Plan, error) {
	path := strings.TrimSpace(req.Path)
	if path == "" {
		return secretscan.Plan{}, errStatus(http.StatusBadRequest, "path is required")
	}
	mode, err := secretscan.NormalizeScanMode(req.Mode)
	if err != nil {
		return secretscan.Plan{}, errStatus(http.StatusBadRequest, err.Error())
	}
	opts := secretscan.ScanOptions{Mode: mode, CustomRulesPath: strings.TrimSpace(req.CustomRulesPath)}
	if planner, ok := scanner.(secretScannerPlanner); ok {
		plan, err := planner.Plan(path, opts)
		if err != nil {
			return secretscan.Plan{}, secretScanRequestError(err)
		}
		return plan, nil
	}
	// Test and embedded scanners may predate the optional planner interface. The
	// execution request is still bound exactly and the scanner remains responsible
	// for enforcing its own target boundary. Production uses GitleaksRunner.Plan.
	return secretscan.Plan{
		TargetPath: path, TargetRoot: path, Mode: mode,
		CustomRulesPath: opts.CustomRulesPath, CustomRules: opts.CustomRulesPath != "",
		RulesActive:  secretscan.GitleaksDefaultRulesActive,
		Capabilities: secretscan.ScanCapabilities(mode, opts.CustomRulesPath != ""),
	}, nil
}

func secretScanRequestError(err error) error {
	switch {
	case errors.Is(err, secretscan.ErrInvalidScanTarget):
		return errStatus(http.StatusBadRequest, err.Error())
	case errors.Is(err, secretscan.ErrInvalidScanMode), errors.Is(err, secretscan.ErrInvalidCustomRules):
		return errStatus(http.StatusBadRequest, err.Error())
	case errors.Is(err, secretscan.ErrGitleaksBinaryNotFound):
		return errStatus(http.StatusServiceUnavailable, "gitleaks binary is not configured")
	default:
		return err
	}
}

func (a *API) secretScanPreviewFingerprint(tenantID, principal string, plan secretscan.Plan) (string, error) {
	if a.commandMAC == nil {
		return "", errors.New("api: server-keyed secret-scan preview evidence is unavailable")
	}
	material, err := json.Marshal(struct {
		Domain            string   `json:"domain"`
		TenantID          string   `json:"tenant_id"`
		Principal         string   `json:"principal"`
		Operation         string   `json:"operation"`
		TargetPath        string   `json:"target_path"`
		Mode              string   `json:"mode"`
		CustomRulesPath   string   `json:"custom_rules_path,omitempty"`
		CustomRulesSHA256 string   `json:"custom_rules_sha256,omitempty"`
		Capabilities      []string `json:"capabilities"`
	}{
		Domain: secretScanReviewDomain, TenantID: tenantID, Principal: principal,
		Operation: "run_secret_scan", TargetPath: plan.TargetPath, Mode: plan.Mode,
		CustomRulesPath: plan.CustomRulesPath, CustomRulesSHA256: plan.CustomRulesSHA256,
		Capabilities: append([]string(nil), plan.Capabilities...),
	})
	if err != nil {
		return "", err
	}
	defer secret.Wipe(material)
	mac, err := a.commandMAC([]byte(secretScanReviewDomain), material)
	if err != nil {
		return "", err
	}
	if len(mac) != 32 {
		secret.Wipe(mac)
		return "", errors.New("api: secret-scan preview MAC has invalid length")
	}
	defer secret.Wipe(mac)
	return "sha256:" + hex.EncodeToString(mac), nil
}

// previewSecretScan validates the exact scanner, confinement boundary, target,
// mode, and custom rule file without starting Git/Gitleaks, writing a report,
// recording idempotency, appending an event, or calling another system.
func (a *API) previewSecretScan(w http.ResponseWriter, r *http.Request) {
	if a.secrets == nil {
		a.writeProblem(w, secretsDisabledProblem())
		return
	}
	if a.secrets.be.SecretScanner == nil {
		a.writeError(w, errStatus(http.StatusServiceUnavailable, "secret scanner is not configured"))
		return
	}
	tenantID, ok := a.tenant(r)
	if !ok {
		a.writeProblem(w, problemUnauthorized())
		return
	}
	principal, err := requestPrincipalSubject(r.Context())
	if err != nil {
		a.writeError(w, err)
		return
	}
	var req secretScanRequest
	if err := decodeJSON(r, &req); err != nil {
		a.writeError(w, errWithStatus(http.StatusBadRequest, err))
		return
	}
	plan, err := normalizeSecretScanRequest(a.secrets.be.SecretScanner, req)
	if err != nil {
		a.writeError(w, err)
		return
	}
	fingerprint, err := a.secretScanPreviewFingerprint(tenantID, principal, plan)
	if err != nil {
		a.writeError(w, err)
		return
	}
	a.writeJSON(w, http.StatusOK, secretScanPreviewResponse{
		Capability: "F39", Operation: "run_secret_scan", Ready: true, EffectFree: true,
		TargetPath: plan.TargetPath, Mode: plan.Mode, CustomRules: plan.CustomRules,
		CustomRulesPath: plan.CustomRulesPath, CustomRulesSHA256: plan.CustomRulesSHA256,
		Scanner:     "gitleaks " + secretscan.GitleaksPinnedVersion,
		RulesActive: plan.RulesActive, Capabilities: append([]string(nil), plan.Capabilities...),
		RequiredPermission: "secrets:write", RequestFingerprint: fingerprint,
		Blockers: []string{},
		Prerequisites: []string{
			"The target and optional custom-rules file must remain inside an operator-configured scan root.",
			"Git-history mode requires a local Git worktree whose repository root is inside that same boundary.",
			"Custom rules may add detectors but cannot allowlist or disable the pinned defaults.",
		},
		PreviewWrites: []string{}, PreviewExternalEffects: []string{},
		ExecuteWrites: []string{
			"create and remove one private redacted scanner report in the process temporary directory",
			"append tenant-scoped discovery run and redacted finding events after the scanner succeeds",
			"store the successful response under the supplied Idempotency-Key for exact replay",
		},
		ExecuteExternalEffects: []string{
			"start the pinned Gitleaks process with redaction enabled",
			"read the reviewed target and optional custom-rules file within the configured scan roots",
		},
		RecoverySteps: []string{
			"If the scanner fails before results are recorded, keep the reviewed plan visible and retry it with the same Idempotency-Key.",
			"If the response is interrupted after completion, retry the identical request with the same Idempotency-Key to recover the original run instead of scanning twice.",
			"If target, mode, or rules change, discard the old review and preview again.",
		},
		VerificationSteps: []string{
			"Open the returned discovery run and confirm its completed state.",
			"Review finding rule, file, line, fingerprint, and credential reference metadata; no matched secret value should be present.",
			"Use the discovery, graph, risk, and incident views to assign and remediate confirmed findings.",
		},
		CLIArgv:      []string{"trstctl", "secrets", "scans", "preview", "-f", "secret-scan.json"},
		DataHandling: "Preview reads only path metadata and validated custom-rule configuration. Execution runs Gitleaks with redaction; matched values are dropped before tenant-scoped discovery events, API responses, logs, or evidence are created.",
	})
}

// scanSecrets invokes the configured Gitleaks binary through the served API and
// records redacted metadata into discovery findings. The scanner output is parsed
// for rule/file/line only; the secret value is neither read nor persisted.
//
//trstctl:mutation
func (a *API) scanSecrets(w http.ResponseWriter, r *http.Request) {
	idempotencyKey := r.Header.Get("Idempotency-Key")
	a.mutate(w, r, idempotencyKey, func(ctx context.Context, tenantID string) (int, any, error) {
		if a.secrets == nil {
			return 0, nil, secretsDisabledProblem()
		}
		if a.secrets.be.SecretScanner == nil {
			return 0, nil, errStatus(http.StatusServiceUnavailable, "secret scanner is not configured")
		}
		var req secretScanRequest
		if err := decodeJSON(r, &req); err != nil {
			return 0, nil, errWithStatus(http.StatusBadRequest, err)
		}
		plan, err := normalizeSecretScanRequest(a.secrets.be.SecretScanner, req)
		if err != nil {
			return 0, nil, err
		}
		if fingerprint := strings.TrimSpace(req.PreviewFingerprint); fingerprint != "" {
			principal, principalErr := requestPrincipalSubject(ctx)
			if principalErr != nil {
				return 0, nil, principalErr
			}
			want, fingerprintErr := a.secretScanPreviewFingerprint(tenantID, principal, plan)
			if fingerprintErr != nil {
				return 0, nil, fingerprintErr
			}
			if !crypto.ConstantTimeEqual([]byte(fingerprint), []byte(want)) {
				return 0, nil, errStatus(http.StatusConflict, "reviewed secret-scan plan is stale; preview the current request again")
			}
		}
		opts := secretscan.ScanOptions{Mode: plan.Mode, CustomRulesPath: plan.CustomRulesPath}

		start := time.Now()
		report, err := runSecretScanner(ctx, a.secrets.be.SecretScanner, plan.TargetPath, opts)
		a.observeFeature("secrets", "scan", start, err)
		if err != nil {
			switch {
			case errors.Is(err, secretscan.ErrInvalidScanTarget), errors.Is(err, secretscan.ErrInvalidScanMode), errors.Is(err, secretscan.ErrInvalidCustomRules), errors.Is(err, secretscan.ErrGitleaksBinaryNotFound):
				return 0, nil, secretScanRequestError(err)
			default:
				return 0, nil, errStatus(http.StatusBadGateway, err.Error())
			}
		}
		if report.RulesActive < secretscan.GitleaksMinRulesActive {
			return 0, nil, errStatus(http.StatusServiceUnavailable, "gitleaks rule set is below the required 140-rule floor")
		}

		rows, findings, err := discoveryFindingsFromSecretScan(report)
		if err != nil {
			return 0, nil, err
		}
		run, _, _, err := a.orch.RecordSecretScan(ctx, tenantID, report.Scanner, plan.TargetPath, report.RulesActive, rows)
		if err != nil {
			return 0, nil, err
		}
		if report.Mode == "" {
			report.Mode = plan.Mode
		}
		if len(report.Capabilities) == 0 {
			report.Capabilities = secretscan.ScanCapabilities(report.Mode, report.CustomRules || plan.CustomRules)
		}
		return http.StatusCreated, secretScanResponse{
			RunID:         run.ID,
			Scanner:       report.Scanner,
			EngineVersion: report.EngineVersion,
			Mode:          report.Mode,
			CustomRules:   report.CustomRules || plan.CustomRules,
			Capabilities:  report.Capabilities,
			RulesActive:   report.RulesActive,
			FindingsCount: len(findings),
			Findings:      findings,
		}, nil
	})
}

func runSecretScanner(ctx context.Context, scanner SecretScanner, path string, opts secretscan.ScanOptions) (secretscan.Report, error) {
	if withOptions, ok := scanner.(SecretScannerWithOptions); ok {
		return withOptions.ScanWithOptions(ctx, path, opts)
	}
	if opts.Mode != "" && opts.Mode != secretscan.ScanModeWorkspace {
		return secretscan.Report{}, fmt.Errorf("%w: scanner does not support %s", secretscan.ErrInvalidScanMode, opts.Mode)
	}
	if strings.TrimSpace(opts.CustomRulesPath) != "" {
		return secretscan.Report{}, fmt.Errorf("%w: scanner does not support custom rules", secretscan.ErrInvalidCustomRules)
	}
	return scanner.Scan(ctx, path)
}

func discoveryFindingsFromSecretScan(report secretscan.Report) ([]store.DiscoveryFinding, []secretScanFindingResponse, error) {
	rows := make([]store.DiscoveryFinding, 0, len(report.Findings))
	out := make([]secretScanFindingResponse, 0, len(report.Findings))
	for _, f := range report.Findings {
		if strings.TrimSpace(f.RuleID) == "" || strings.TrimSpace(f.File) == "" {
			continue
		}
		ref := f.CredentialRef
		if ref == "" {
			ref = f.RuleID + "@" + f.File
		}
		meta, err := json.Marshal(map[string]any{
			"scanner":        report.Scanner,
			"engine_version": report.EngineVersion,
			"rule_id":        f.RuleID,
			"file":           f.File,
			"line":           f.Line,
			"rules_active":   report.RulesActive,
		})
		if err != nil {
			return nil, nil, err
		}
		rows = append(rows, store.DiscoveryFinding{
			Kind:        "leaked_secret",
			Ref:         ref,
			Provenance:  report.Scanner + ":" + f.File,
			Fingerprint: firstNonEmptyString(f.Fingerprint, ref),
			RiskScore:   95,
			Metadata:    json.RawMessage(meta),
		})
		out = append(out, secretScanFindingResponse{RuleID: f.RuleID, File: f.File, Line: f.Line, CredentialRef: ref})
	}
	return rows, out, nil
}

func (a *API) secretRepoScanPosture(w http.ResponseWriter, _ *http.Request) {
	a.writeJSON(w, http.StatusOK, buildSecretRepoScanPosture(time.Now().UTC().Format(time.RFC3339)))
}

func (a *API) thirdPartySecretScanPosture(w http.ResponseWriter, _ *http.Request) {
	a.writeJSON(w, http.StatusOK, buildThirdPartySecretScanPosture(time.Now().UTC().Format(time.RFC3339)))
}

// ingestThirdPartySecretScan is the normalized CAP-SCAN-04 ingress for CI/CD logs,
// container-registry exports, Slack exports, and Jira exports. It records only
// metadata and an artifact path; the discovery.run worker performs the scan.
//
//trstctl:mutation
func (a *API) ingestThirdPartySecretScan(w http.ResponseWriter, r *http.Request) {
	idempotencyKey := r.Header.Get("Idempotency-Key")
	provider := secretscan.NormalizeThirdPartyProvider(r.PathValue("provider"))
	a.mutate(w, r, idempotencyKey, func(ctx context.Context, tenantID string) (int, any, error) {
		if a.secrets == nil {
			return 0, nil, secretsDisabledProblem()
		}
		if a.orch == nil {
			return 0, nil, errStatus(http.StatusServiceUnavailable, "third-party secret scan queue is not configured")
		}
		if provider == "" {
			return 0, nil, errStatus(http.StatusBadRequest, "provider must be cicd_log, container_registry, slack, or jira")
		}
		var req thirdPartySecretScanIngestRequest
		if err := decodeJSON(r, &req); err != nil {
			return 0, nil, errWithStatus(http.StatusBadRequest, err)
		}
		cfg, err := thirdPartySecretScanConfig(provider, req)
		if err != nil {
			return 0, nil, err
		}
		body, err := json.Marshal(cfg)
		if err != nil {
			return 0, nil, err
		}
		sourceID := thirdPartySecretScanSourceID(tenantID, cfg)
		src, err := a.orch.UpsertDiscoverySource(ctx, tenantID, store.DiscoverySource{
			ID:     sourceID,
			Kind:   secretscan.ThirdPartySourceKind,
			Name:   thirdPartySecretScanSourceName(cfg),
			Config: body,
		})
		if err != nil {
			return 0, nil, err
		}
		run, err := a.orch.QueueDiscoveryRun(ctx, tenantID, store.DiscoveryRun{
			SourceID: src.ID,
			DryRun:   false,
		})
		if err != nil {
			return 0, nil, err
		}
		return http.StatusAccepted, thirdPartySecretScanReceipt{
			Capability:        "CAP-SCAN-04",
			Provider:          cfg.Provider,
			Source:            cfg.Source,
			SourceID:          src.ID,
			RunID:             run.ID,
			Queued:            true,
			Status:            run.Status,
			OutboxDestination: "discovery.run",
			Scanner:           "gitleaks " + secretscan.GitleaksPinnedVersion,
			DiscoveryRunPath:  "/api/v1/discovery/runs/" + run.ID,
		}, nil
	})
}

// receiveSecretRepoWebhook is the normalized GitHub/GitLab/Bitbucket realtime
// repository secret-scan ingress. It does not clone or call providers inline:
// the mutation records a tenant-scoped discovery source/run and the existing
// discovery.run outbox worker performs checkout + Gitleaks (AN-2/AN-6).
//
//trstctl:mutation
func (a *API) receiveSecretRepoWebhook(w http.ResponseWriter, r *http.Request) {
	idempotencyKey := r.Header.Get("Idempotency-Key")
	provider := normalizeSecretRepoProvider(r.PathValue("provider"))
	a.mutate(w, r, idempotencyKey, func(ctx context.Context, tenantID string) (int, any, error) {
		if a.secrets == nil {
			return 0, nil, secretsDisabledProblem()
		}
		if a.orch == nil {
			return 0, nil, errStatus(http.StatusServiceUnavailable, "secret repository scan queue is not configured")
		}
		if provider == "" {
			return 0, nil, errStatus(http.StatusBadRequest, "provider must be github, gitlab, or bitbucket")
		}
		var req secretRepoScanWebhookRequest
		if err := decodeJSON(r, &req); err != nil {
			return 0, nil, errWithStatus(http.StatusBadRequest, err)
		}
		cfg, err := secretRepoScanConfig(provider, req)
		if err != nil {
			return 0, nil, err
		}
		body, err := json.Marshal(cfg)
		if err != nil {
			return 0, nil, err
		}
		sourceID := secretRepoSourceID(tenantID, cfg)
		src, err := a.orch.UpsertDiscoverySource(ctx, tenantID, store.DiscoverySource{
			ID:     sourceID,
			Kind:   secretscan.RepositorySourceKind,
			Name:   secretRepoSourceName(cfg),
			Config: body,
		})
		if err != nil {
			return 0, nil, err
		}
		run, err := a.orch.QueueDiscoveryRun(ctx, tenantID, store.DiscoveryRun{
			SourceID: src.ID,
			DryRun:   false,
		})
		if err != nil {
			return 0, nil, err
		}
		return http.StatusAccepted, secretRepoScanWebhookResponse{
			Capability:        "CAP-SCAN-01",
			Provider:          cfg.Provider,
			Repository:        cfg.Repository,
			SourceID:          src.ID,
			RunID:             run.ID,
			Queued:            true,
			Status:            run.Status,
			OutboxDestination: "discovery.run",
			Scanner:           "gitleaks " + secretscan.GitleaksPinnedVersion,
			DiscoveryRunPath:  "/api/v1/discovery/runs/" + run.ID,
		}, nil
	})
}

func buildThirdPartySecretScanPosture(generatedAt string) thirdPartySecretScanPostureResponse {
	if generatedAt == "" {
		generatedAt = "1970-01-01T00:00:00Z"
	}
	providers := []thirdPartySecretScanProviderResponse{
		{ // #nosec G101 -- identifier/constant matching the secret-name heuristic; no credential value present (CWE-798)
			ID:             secretscan.ThirdPartyProviderCICDLog,
			Name:           "CI/CD logs",
			ArtifactKinds:  []string{"ci_cd_log", "job_trace", "workflow_log", "build_artifact"},
			IngestMode:     "POST normalized CI/CD log artifact metadata and artifact_path to queue a secret_third_party discovery run",
			SecretHandling: "raw log lines stay in the artifact path; persisted findings contain only rule, file, line, fingerprint, and credential_ref",
			OutboxMode:     "artifact scan is discovery.run outbox work, never inline request handling",
		},
		{
			ID:             secretscan.ThirdPartyProviderContainerRegistry,
			Name:           "Container registry exports",
			ArtifactKinds:  []string{"container_registry_export", "image_config", "layer_tree", "sbom"},
			IngestMode:     "POST registry export metadata and artifact_path to queue Gitleaks over exported image/layer/config material",
			SecretHandling: "registry tokens and matched values stay outside events; only redacted leaked-secret evidence is recorded",
			OutboxMode:     "artifact scan is discovery.run outbox work, never inline request handling",
		},
		{
			ID:             secretscan.ThirdPartyProviderSlack,
			Name:           "Slack exports",
			ArtifactKinds:  []string{"slack_export", "channel_export", "message_export"},
			IngestMode:     "POST Slack export metadata and artifact_path to queue redacted scanning of exported messages/files",
			SecretHandling: "Slack message text remains in the export artifact; trstctl stores metadata-only findings",
			OutboxMode:     "artifact scan is discovery.run outbox work, never inline request handling",
		},
		{ // #nosec G101 -- identifier/constant matching the secret-name heuristic; no credential value present (CWE-798)
			ID:             secretscan.ThirdPartyProviderJira,
			Name:           "Jira exports",
			ArtifactKinds:  []string{"jira_export", "issue_export", "attachment_export"},
			IngestMode:     "POST Jira export metadata and artifact_path to queue redacted scanning of issues and attachments",
			SecretHandling: "Jira issue text and attachments remain in the export artifact; trstctl stores metadata-only findings",
			OutboxMode:     "artifact scan is discovery.run outbox work, never inline request handling",
		},
	}
	return thirdPartySecretScanPostureResponse{
		Capability:         "CAP-SCAN-04",
		Served:             true,
		GeneratedAt:        generatedAt,
		Providers:          providers,
		IngestPaths:        []string{"/api/v1/secrets/scans/third-party/cicd_log/ingest", "/api/v1/secrets/scans/third-party/container_registry/ingest", "/api/v1/secrets/scans/third-party/slack/ingest", "/api/v1/secrets/scans/third-party/jira/ingest"},
		QueueModel:         "authenticated ingest records a tenant-scoped secret_third_party discovery source/run and the discovery.run outbox worker performs artifact scanning",
		Scanner:            "gitleaks " + secretscan.GitleaksPinnedVersion,
		MinimumRulesActive: secretscan.GitleaksMinRulesActive,
		RedactionModel:     "scanner runs with redaction; parser drops secret/match fields and persists only rule, file, line, fingerprint, provider, source, and credential_ref",
		EventFlow: []string{
			"discovery.source.upserted",
			"discovery.run.queued",
			"discovery.run.started",
			"discovery.finding.recorded",
			"discovery.run.completed",
		},
		ReleaseGates: []secretRepoScanGateResponse{
			{ID: "third-party-ingest-contract", Command: "go test ./internal/server -run TestServedThirdPartySecretScanningCAPSCAN04EndToEnd", Artifact: "third-party-secret-scan-contract", Required: true},
			{ID: "redaction-regression", Command: "go test ./internal/secretscan -run TestParseGitleaksDropsSecret", Artifact: "redaction transcript", Required: true},
			{ID: "architecture-lint", Command: "make lint test", Artifact: "local gate transcript", Required: true},
		},
		OperatorActions: []string{
			"export CI/CD job logs, container registry layer/config material, Slack messages, or Jira issues to a tenant-local artifact path",
			"submit only artifact_path and metadata through the authenticated ingest route; do not inline secret-bearing log/chat text",
			"route redacted leaked-secret findings into discovery, graph, risk, and incident workflows",
		},
		Residuals: []string{
			"native Slack/Jira/registry API polling is not yet implemented; operators provide exported artifacts or callbacks",
			"provider signature verification and export-chain integrity checks remain architecture follow-ups",
			"artifact retention, deletion, and access controls are operator-owned outside the trstctl database",
		},
		EvidenceRefs: []string{
			"internal/api/secrets.go",
			"internal/server/discovery.go",
			"internal/secretscan/thirdparty.go",
			"docs/features/secrets.md",
		},
		ArchitectureControls: []string{"AN-1", "AN-2", "AN-5", "AN-6", "AN-7", "AN-8"},
	}
}

func buildSecretRepoScanPosture(generatedAt string) secretRepoScanPostureResponse {
	if generatedAt == "" {
		generatedAt = "1970-01-01T00:00:00Z"
	}
	providers := []secretRepoScanProviderResponse{
		{ // #nosec G101 -- identifier/constant matching the secret-name heuristic; no credential value present (CWE-798)
			ID:               "github",
			Name:             "GitHub",
			RealtimeTriggers: []string{"push", "pull_request", "workflow_run", "repository_dispatch"},
			AuthMode:         "authenticated trstctl SecretsWrite webhook; GitHub App token is referenced by credential_ref for private clone follow-up",
			IngestMode:       "POST normalized GitHub event enqueues a secret_repo discovery run; worker scans checkout_path or public/local clone_url with Gitleaks",
			RefTypes:         []string{"branch", "tag", "pull_request_head", "commit_sha"},
			SecretHandling:   "raw token and finding value stay outside events; only rule/file/line/redacted reference are recorded",
			OutboxMode:       "clone and scan are discovery.run outbox work, never inline request handling",
		},
		{ // #nosec G101 -- identifier/constant matching the secret-name heuristic; no credential value present (CWE-798)
			ID:               "gitlab",
			Name:             "GitLab",
			RealtimeTriggers: []string{"push", "merge_request", "tag_push", "pipeline"},
			AuthMode:         "authenticated trstctl SecretsWrite webhook; GitLab token is referenced by credential_ref for private clone follow-up",
			IngestMode:       "POST normalized GitLab event enqueues a secret_repo discovery run; worker scans checkout_path or public/local clone_url with Gitleaks",
			RefTypes:         []string{"branch", "tag", "merge_request_source", "commit_sha"},
			SecretHandling:   "raw token and finding value stay outside events; only rule/file/line/redacted reference are recorded",
			OutboxMode:       "clone and scan are discovery.run outbox work, never inline request handling",
		},
		{ // #nosec G101 -- identifier/constant matching the secret-name heuristic; no credential value present (CWE-798)
			ID:               "bitbucket",
			Name:             "Bitbucket",
			RealtimeTriggers: []string{"repo:push", "pullrequest:created", "pullrequest:updated", "repo:refs_changed"},
			AuthMode:         "authenticated trstctl SecretsWrite webhook; Bitbucket credential is referenced by credential_ref for private clone follow-up",
			IngestMode:       "POST normalized Bitbucket event enqueues a secret_repo discovery run; worker scans checkout_path or public/local clone_url with Gitleaks",
			RefTypes:         []string{"branch", "tag", "pull_request_source", "commit_sha"},
			SecretHandling:   "raw token and finding value stay outside events; only rule/file/line/redacted reference are recorded",
			OutboxMode:       "clone and scan are discovery.run outbox work, never inline request handling",
		},
	}
	return secretRepoScanPostureResponse{
		Capability:         "CAP-SCAN-01",
		Served:             true,
		GeneratedAt:        generatedAt,
		Providers:          providers,
		WebhookPaths:       []string{"/api/v1/secrets/scans/repositories/github/webhook", "/api/v1/secrets/scans/repositories/gitlab/webhook", "/api/v1/secrets/scans/repositories/bitbucket/webhook"},
		QueueModel:         "authenticated provider webhook records a tenant-scoped secret_repo discovery source/run and the discovery.run outbox worker performs clone/scan side effects",
		Scanner:            "gitleaks " + secretscan.GitleaksPinnedVersion,
		MinimumRulesActive: secretscan.GitleaksMinRulesActive,
		RedactionModel:     "scanner runs with redaction; parser drops secret/match fields and persists only rule, file, line, fingerprint, and credential_ref",
		EventFlow: []string{
			"discovery.source.upserted",
			"discovery.run.queued",
			"discovery.run.started",
			"discovery.finding.recorded",
			"discovery.run.completed",
		},
		ReleaseGates: []secretRepoScanGateResponse{
			{ID: "provider-webhook-contract", Command: "go test ./internal/api -run TestServedRepoSecretScanningCAPSCAN01", Artifact: "repo-secret-scan-contract", Required: true},
			{ID: "redaction-regression", Command: "go test ./internal/secretscan -run TestParseGitleaksDropsSecret", Artifact: "redaction transcript", Required: true},
			{ID: "architecture-lint", Command: "make lint test", Artifact: "local gate transcript", Required: true},
		},
		OperatorActions: []string{
			"install provider webhooks or CI callbacks for GitHub, GitLab, and Bitbucket repository events",
			"store provider credentials as tenant-scoped secret references, not inline webhook config",
			"send checkout_path or public/local clone_url to the normalized webhook; private credential_ref clone resolution is tracked as a shortfall",
			"route redacted leaked-secret findings into discovery, graph, risk, and incident workflows",
		},
		Residuals: []string{
			"provider webhook delivery latency and repository checkout time determine real-time detection delay",
			"native provider signature verification and private clone credential_ref resolution remain architecture follow-ups",
			"self-hosted Git providers may require custom CA/proxy configuration before clone workers can reach them",
			"historical full-repo scanning still depends on operators scheduling a baseline scan for existing repositories",
		},
		EvidenceRefs: []string{
			"internal/api/secrets.go",
			"internal/secretscan/gitleaks.go",
			"internal/orchestrator/discovery.go",
			"docs/features/secrets.md",
		},
		ArchitectureControls: []string{"AN-1", "AN-2", "AN-5", "AN-6", "AN-7", "AN-8"},
	}
}

func normalizeSecretRepoProvider(raw string) string {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case "github", "gitlab", "bitbucket":
		return strings.ToLower(strings.TrimSpace(raw))
	default:
		return ""
	}
}

func secretRepoScanConfig(provider string, req secretRepoScanWebhookRequest) (secretscan.RepositoryScanConfig, error) {
	repo := strings.TrimSpace(req.Repository)
	cloneURL := strings.TrimSpace(req.CloneURL)
	checkoutPath := strings.TrimSpace(req.CheckoutPath)
	if repo == "" {
		repo = repositoryNameFromTarget(cloneURL)
	}
	if repo == "" {
		repo = repositoryNameFromTarget(checkoutPath)
	}
	if repo == "" {
		return secretscan.RepositoryScanConfig{}, errStatus(http.StatusBadRequest, "repository is required")
	}
	if cloneURL == "" && checkoutPath == "" {
		return secretscan.RepositoryScanConfig{}, errStatus(http.StatusBadRequest, "clone_url or checkout_path is required")
	}
	if cloneURL != "" && strings.Contains(cloneURL, "://") {
		if strings.Contains(strings.SplitN(cloneURL, "://", 2)[1], "@") {
			return secretscan.RepositoryScanConfig{}, errStatus(http.StatusBadRequest, "clone_url must not embed credentials; use credential_ref")
		}
	}
	return secretscan.RepositoryScanConfig{
		Provider:      provider,
		Repository:    repo,
		CloneURL:      cloneURL,
		CheckoutPath:  checkoutPath,
		Ref:           strings.TrimSpace(req.Ref),
		CommitSHA:     strings.TrimSpace(req.CommitSHA),
		Event:         strings.TrimSpace(req.Event),
		CredentialRef: strings.TrimSpace(req.CredentialRef),
	}, nil
}

func thirdPartySecretScanConfig(provider string, req thirdPartySecretScanIngestRequest) (secretscan.ThirdPartyScanConfig, error) {
	source := strings.TrimSpace(req.Source)
	artifactPath := strings.TrimSpace(req.ArtifactPath)
	if source == "" {
		source = repositoryNameFromTarget(artifactPath)
	}
	if source == "" {
		return secretscan.ThirdPartyScanConfig{}, errStatus(http.StatusBadRequest, "source is required")
	}
	if artifactPath == "" {
		return secretscan.ThirdPartyScanConfig{}, errStatus(http.StatusBadRequest, "artifact_path is required")
	}
	artifactKind := strings.TrimSpace(req.ArtifactKind)
	if artifactKind == "" {
		artifactKind = secretscan.ThirdPartyArtifactKind(provider)
	}
	return secretscan.ThirdPartyScanConfig{
		Provider:      provider,
		Source:        source,
		ArtifactPath:  artifactPath,
		ArtifactKind:  artifactKind,
		Event:         strings.TrimSpace(req.Event),
		CredentialRef: strings.TrimSpace(req.CredentialRef),
	}, nil
}

func repositoryNameFromTarget(target string) string {
	target = strings.TrimRight(strings.TrimSpace(target), "/")
	if target == "" {
		return ""
	}
	parts := strings.Split(target, "/")
	name := parts[len(parts)-1]
	return strings.TrimSuffix(name, ".git")
}

var secretRepoSourceNamespace = gouuid.MustParse("6eb35ad2-cbda-5a23-ae77-8e6ff69881f0")

var thirdPartySecretScanSourceNamespace = gouuid.MustParse("d673a652-8366-52ab-8a58-b1f0d1d17193")

func secretRepoSourceID(tenantID string, cfg secretscan.RepositoryScanConfig) string {
	key := strings.Join([]string{tenantID, cfg.Provider, cfg.Repository, cfg.Ref}, "\x00")
	return gouuid.NewSHA1(secretRepoSourceNamespace, []byte(key)).String()
}

func thirdPartySecretScanSourceID(tenantID string, cfg secretscan.ThirdPartyScanConfig) string {
	key := strings.Join([]string{tenantID, cfg.Provider, cfg.Source, cfg.Event, cfg.ArtifactPath}, "\x00")
	return gouuid.NewSHA1(thirdPartySecretScanSourceNamespace, []byte(key)).String()
}

func secretRepoSourceName(cfg secretscan.RepositoryScanConfig) string {
	name := "secret-repo:" + cfg.Provider + ":" + cfg.Repository
	if cfg.Ref != "" {
		name += ":" + cfg.Ref
	}
	return name
}

func thirdPartySecretScanSourceName(cfg secretscan.ThirdPartyScanConfig) string {
	name := "secret-third-party:" + cfg.Provider + ":" + cfg.Source
	if cfg.Event != "" {
		name += ":" + cfg.Event
	}
	return name
}

func firstNonEmptyString(vals ...string) string {
	for _, v := range vals {
		if v != "" {
			return v
		}
	}
	return ""
}
