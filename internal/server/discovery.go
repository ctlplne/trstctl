// SPDX-License-Identifier: MPL-2.0

package server

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"

	"trstctl.com/trstctl/internal/agent/drift"
	"trstctl.com/trstctl/internal/crypto/secret"
	"trstctl.com/trstctl/internal/discovery/apikey"
	"trstctl.com/trstctl/internal/discovery/cloudcert"
	"trstctl.com/trstctl/internal/discovery/cloudcert/acmdisc"
	"trstctl.com/trstctl/internal/discovery/cloudcert/gcmdisc"
	"trstctl.com/trstctl/internal/discovery/cloudcert/kvdisc"
	"trstctl.com/trstctl/internal/discovery/cloudsecret"
	awssmdisc "trstctl.com/trstctl/internal/discovery/cloudsecret/awssm"
	azurekvsecretdisc "trstctl.com/trstctl/internal/discovery/cloudsecret/azurekv"
	gcpsmdisc "trstctl.com/trstctl/internal/discovery/cloudsecret/gcpsm"
	vaultkvdisc "trstctl.com/trstctl/internal/discovery/cloudsecret/vaultkv"
	"trstctl.com/trstctl/internal/discovery/compromise"
	"trstctl.com/trstctl/internal/discovery/ctmonitor"
	"trstctl.com/trstctl/internal/discovery/k8stls"
	"trstctl.com/trstctl/internal/discovery/netscan"
	"trstctl.com/trstctl/internal/discovery/nhi"
	"trstctl.com/trstctl/internal/discovery/nhibehavior"
	"trstctl.com/trstctl/internal/discovery/oauthgrant"
	"trstctl.com/trstctl/internal/discovery/serviceaccount"
	"trstctl.com/trstctl/internal/netsec"
	"trstctl.com/trstctl/internal/notify"
	"trstctl.com/trstctl/internal/orchestrator"
	"trstctl.com/trstctl/internal/projections"
	"trstctl.com/trstctl/internal/secretscan"
	"trstctl.com/trstctl/internal/store"
)

type manualDiscoveryConfig struct {
	Findings []manualDiscoveryFinding `json:"findings"`
}

type cloudCertificateDiscoveryConfig struct {
	Providers []cloudCertificateProviderConfig `json:"providers"`
}

type cloudCertificateProviderConfig struct {
	Provider             string   `json:"provider"`
	Region               string   `json:"region"`
	Endpoint             string   `json:"endpoint"`
	AllowPrivateEndpoint bool     `json:"allow_private_endpoint"`
	PrivateEgressCIDRs   []string `json:"private_egress_cidrs"`
	AccessKeyIDRef       string   `json:"access_key_id_ref"`
	SecretAccessKeyRef   string   `json:"secret_access_key_ref"`
	SessionTokenRef      string   `json:"session_token_ref"`
	VaultURL             string   `json:"vault_url"`
	TokenRef             string   `json:"token_ref"`
	Project              string   `json:"project"`
	Location             string   `json:"location"`
}

type cloudSecretDiscoveryConfig struct {
	Providers []cloudSecretProviderConfig `json:"providers"`
}

type cloudSecretProviderConfig struct {
	Provider             string   `json:"provider"`
	Region               string   `json:"region"`
	Endpoint             string   `json:"endpoint"`
	AllowPrivateEndpoint bool     `json:"allow_private_endpoint"`
	PrivateEgressCIDRs   []string `json:"private_egress_cidrs"`
	VaultURL             string   `json:"vault_url"`
	APIVersion           string   `json:"api_version"`
	Mount                string   `json:"mount"`
	PathPrefix           string   `json:"path_prefix"`
	AccessKeyIDRef       string   `json:"access_key_id_ref"`
	SecretAccessKeyRef   string   `json:"secret_access_key_ref"`
	SessionTokenRef      string   `json:"session_token_ref"`
	TokenRef             string   `json:"token_ref"`
	Project              string   `json:"project"`
	TagKey               string   `json:"tag_key"`
	TagValue             string   `json:"tag_value"`
	LabelKey             string   `json:"label_key"`
	LabelValue           string   `json:"label_value"`
	NamePrefix           string   `json:"name_prefix"`
}

type ctLogDiscoveryConfig struct {
	Logs                 []string `json:"logs"`
	Log                  string   `json:"log"`
	WatchedDomains       []string `json:"watched_domains"`
	Domain               string   `json:"domain"`
	MaxBatch             int      `json:"max_batch"`
	AllowPrivateEndpoint bool     `json:"allow_private_endpoint"`
	PrivateEgressCIDRs   []string `json:"private_egress_cidrs"`
}

type driftDiscoveryConfig struct {
	Watched []driftWatchedConfig `json:"watched"`
	Scope   []string             `json:"scope"`
	Policy  map[string]string    `json:"policy"`
}

type driftWatchedConfig struct {
	Path        string `json:"path"`
	Class       string `json:"class"`
	Fingerprint string `json:"fingerprint"`
	Mode        string `json:"mode"`
	Restricted  bool   `json:"restricted"`
}

type manualDiscoveryFinding struct {
	Kind        string          `json:"kind"`
	Ref         string          `json:"ref"`
	Provenance  string          `json:"provenance"`
	Fingerprint string          `json:"fingerprint"`
	RiskScore   int             `json:"risk_score"`
	Metadata    json.RawMessage `json:"metadata"`
}

func (d *issuanceDispatcher) handleDiscoveryRun(ctx context.Context, m orchestrator.Message) error {
	if d.orch == nil || d.store == nil || d.idem == nil {
		return errors.New("server: discovery dispatcher is not configured")
	}
	var p projections.DiscoveryRunQueued
	if err := json.Unmarshal(m.Payload, &p); err != nil {
		return fmt.Errorf("server: decode discovery.run payload: %w", err)
	}
	if p.ID == "" || p.SourceID == "" {
		return nil
	}
	_, err := d.idem.Do(ctx, m.TenantID, "discovery:"+m.IdempotencyKey, func(ctx context.Context) ([]byte, error) {
		run, err := d.store.GetDiscoveryRun(ctx, m.TenantID, p.ID)
		if err != nil {
			return nil, err
		}
		if discoveryRunTerminal(run.Status) {
			return []byte(run.Status), nil
		}
		if run.Status == "queued" {
			if err := d.orch.StartDiscoveryRun(ctx, m.TenantID, p.ID); err != nil {
				return nil, err
			}
		}
		src, err := d.store.GetDiscoverySource(ctx, m.TenantID, p.SourceID)
		if err != nil {
			return nil, err
		}
		rep, status, msg, err := d.executeDiscoveryRun(ctx, m.TenantID, src, p)
		if err != nil {
			return nil, err
		}
		if err := d.orch.CompleteDiscoveryRun(ctx, m.TenantID, store.DiscoveryRun{
			ID: p.ID, Status: status, Targets: rep.Targets, Discovered: rep.Discovered,
			Failed: rep.Failed, Rejected: rep.Rejected, Error: msg,
			TargetResults: discoveryTargetResults(rep.TargetResults),
		}); err != nil {
			return nil, err
		}
		return []byte(status), nil
	})
	return err
}

// discoveryRunRelayOwned closes the old production escape hatch too: rows
// queued before AUD-28 lack the execution field, so source kind is checked as a
// compatibility fallback before the dispatcher performs any receiver I/O.
func (d *issuanceDispatcher) discoveryRunRelayOwned(ctx context.Context, m orchestrator.Message) (bool, error) {
	var p projections.DiscoveryRunQueued
	if err := json.Unmarshal(m.Payload, &p); err != nil {
		return false, fmt.Errorf("server: decode discovery.run payload: %w", err)
	}
	if p.Execution == "relay" {
		return true, nil
	}
	if p.SourceID == "" || d.store == nil {
		return false, nil
	}
	source, err := d.store.GetDiscoverySource(ctx, m.TenantID, p.SourceID)
	if err != nil {
		return false, err
	}
	return source.Kind == "network" || source.Kind == "ssh", nil
}

// discoveryRunExecutor executes one discovery run for a source of a specific
// kind on behalf of the dispatcher.
type discoveryRunExecutor func(d *issuanceDispatcher, ctx context.Context, tenantID string, src store.DiscoverySource, run projections.DiscoveryRunQueued) (netscan.Report, string, string, error)

// discoveryRunExecutors is THE catalog of served discovery-source kinds: the
// set the server can actually execute when a run is queued. Coverage treats
// this registry as authoritative (see internal/cbom/coverage) —
// TestEveryDiscoverySourceDeclaresEnvelope requires every kind here to carry
// an observability envelope, and every envelope (bar the manual fallback) to
// name a kind here, so the two cannot drift. A kind absent from this map
// falls back to recording operator-supplied manual findings.
var discoveryRunExecutors = map[string]discoveryRunExecutor{
	"network":           (*issuanceDispatcher).executeRelayOwnedDiscoveryRun,
	"ssh":               (*issuanceDispatcher).executeRelayOwnedDiscoveryRun,
	"cloud_certificate": (*issuanceDispatcher).executeCloudCertificateDiscoveryRun,
	// secret_store routes through the same served secret-manager
	// connectors as cloud_secret (aws-secrets-manager, gcp-secret-manager,
	// azure-key-vault, hashicorp-vault): the kinds share the providers
	// config shape, so the previously executor-less kind now runs for the
	// served backends, and a provider outside that set fails with the
	// connector's clear "unsupported provider" error instead of the
	// generic no-connector fallback (A0.2b).
	cloudsecret.SourceKind:          (*issuanceDispatcher).executeCloudSecretDiscoveryRun,
	"secret_store":                  (*issuanceDispatcher).executeCloudSecretDiscoveryRun,
	"ct_log":                        (*issuanceDispatcher).executeCTLogDiscoveryRun,
	"drift":                         (*issuanceDispatcher).executeDriftDiscoveryRun,
	nhi.SourceKind:                  (*issuanceDispatcher).executeNHICrossSurfaceDiscoveryRun,
	oauthgrant.SourceKind:           (*issuanceDispatcher).executeOAuthGrantDiscoveryRun,
	serviceaccount.SourceKind:       (*issuanceDispatcher).executeServiceAccountDiscoveryRun,
	nhibehavior.SourceKind:          (*issuanceDispatcher).executeNHIBehaviorDiscoveryRun,
	apikey.SourceKind:               (*issuanceDispatcher).executeAPIKeyOrManualDiscoveryRun,
	compromise.SourceKind:           (*issuanceDispatcher).executeCompromisedCredentialDiscoveryRun,
	k8stls.SourceKind:               (*issuanceDispatcher).executeKubernetesTLSAutoIssuanceRun,
	secretscan.RepositorySourceKind: (*issuanceDispatcher).executeSecretRepositoryDiscoveryRun,
	secretscan.ThirdPartySourceKind: (*issuanceDispatcher).executeThirdPartySecretDiscoveryRun,
}

func (d *issuanceDispatcher) executeRelayOwnedDiscoveryRun(context.Context, string, store.DiscoverySource, projections.DiscoveryRunQueued) (netscan.Report, string, string, error) {
	return netscan.Report{}, "", "", errors.New("server: relay-owned discovery reached the control-plane executor")
}

// servedDiscoverySourceKinds returns the sorted catalog of source kinds the
// server can execute, derived from the executor registry rather than a
// hand-typed list.
func servedDiscoverySourceKinds() []string {
	kinds := make([]string, 0, len(discoveryRunExecutors))
	for k := range discoveryRunExecutors {
		kinds = append(kinds, k)
	}
	sort.Strings(kinds)
	return kinds
}

func (d *issuanceDispatcher) executeDiscoveryRun(ctx context.Context, tenantID string, src store.DiscoverySource, run projections.DiscoveryRunQueued) (netscan.Report, string, string, error) {
	if execute, ok := discoveryRunExecutors[src.Kind]; ok {
		return execute(d, ctx, tenantID, src, run)
	}
	rep, err := d.recordManualDiscoveryFindings(ctx, tenantID, src, run.ID)
	if err != nil {
		return rep, "", "", err
	}
	if rep.Targets > 0 {
		return rep, "succeeded", "", nil
	}
	return netscan.Report{}, "failed", "no server-side connector is configured for discovery source kind " + src.Kind, nil
}

// executeAPIKeyOrManualDiscoveryRun serves the api_key kind: an
// observation-shaped config runs the served observer; an older
// manual-findings api_key source still records its supplied findings. A
// config that is neither gets a kind-specific refusal rather than the generic
// no-connector message, which read as "api_key is not served" when the real
// cause is a config that carries no observations and no findings (A0.2c).
func (d *issuanceDispatcher) executeAPIKeyOrManualDiscoveryRun(ctx context.Context, tenantID string, src store.DiscoverySource, run projections.DiscoveryRunQueued) (netscan.Report, string, string, error) {
	if apikey.UsesObservationConfig(src.Config) {
		return d.executeAPIKeyTokenDiscoveryRun(ctx, tenantID, src, run)
	}
	rep, err := d.recordManualDiscoveryFindings(ctx, tenantID, src, run.ID)
	if err != nil {
		return rep, "", "", err
	}
	if rep.Targets > 0 {
		return rep, "succeeded", "", nil
	}
	return netscan.Report{}, "failed", "api_key discovery requires either an observations config or inline findings", nil
}

func (d *issuanceDispatcher) executeCloudCertificateDiscoveryRun(ctx context.Context, tenantID string, src store.DiscoverySource, run projections.DiscoveryRunQueued) (netscan.Report, string, string, error) {
	providers, err := cloudCertificateProviders(ctx, src.Config)
	if err != nil {
		return netscan.Report{}, "failed", err.Error(), nil
	}
	if len(providers) == 0 {
		return netscan.Report{}, "failed", "cloud_certificate discovery requires at least one provider", nil
	}
	if run.DryRun {
		return netscan.Report{Targets: len(providers)}, "succeeded", "", nil
	}
	sink := cloudDiscoveryRunSink{orch: d.orch, tenantID: tenantID, runID: run.ID, sourceID: src.ID}
	discoverer := cloudcert.NewDiscoverer(sink, cloudcert.WithWorkers(4), cloudcert.WithQueue(64), cloudcert.WithBackoff(10*time.Millisecond))
	defer discoverer.Close()
	rep := discoverer.Discover(ctx, providers)
	out := netscan.Report{Targets: rep.Providers, Discovered: rep.Discovered, Failed: rep.Failed}
	status := "succeeded"
	msg := ""
	if rep.Failed > 0 {
		if rep.Discovered > 0 {
			status = "partial"
			msg = "some cloud certificate providers failed"
		} else {
			status = "failed"
			msg = "all cloud certificate providers failed"
		}
	}
	if rep.Discovered == 0 && rep.Failed == 0 {
		status = "failed"
		msg = "cloud certificate providers returned no certificates"
	}
	return out, status, msg, nil
}

func (d *issuanceDispatcher) executeCloudSecretDiscoveryRun(ctx context.Context, tenantID string, src store.DiscoverySource, run projections.DiscoveryRunQueued) (netscan.Report, string, string, error) {
	providers, err := cloudSecretProviders(ctx, src.Config)
	if err != nil {
		return netscan.Report{}, "failed", err.Error(), nil
	}
	if len(providers) == 0 {
		return netscan.Report{}, "failed", src.Kind + " discovery requires at least one provider", nil
	}
	if run.DryRun {
		return netscan.Report{Targets: len(providers)}, "succeeded", "", nil
	}
	sink := cloudSecretDiscoveryRunSink{orch: d.orch, tenantID: tenantID, runID: run.ID, sourceID: src.ID}
	discoverer := cloudsecret.NewDiscoverer(sink, cloudsecret.WithWorkers(4), cloudsecret.WithQueue(64), cloudsecret.WithBackoff(10*time.Millisecond))
	defer discoverer.Close()
	rep := discoverer.Discover(ctx, providers)
	out := netscan.Report{Targets: rep.Providers, Discovered: rep.Discovered, Failed: rep.Failed}
	status := "succeeded"
	msg := ""
	if rep.Failed > 0 {
		if rep.Discovered > 0 {
			status = "partial"
			msg = "some cloud secret-manager providers failed"
		} else {
			status = "failed"
			msg = "all cloud secret-manager providers failed"
		}
	}
	if rep.Discovered == 0 && rep.Failed == 0 {
		status = "failed"
		msg = "cloud secret-manager providers returned no certificate secrets"
	}
	return out, status, msg, nil
}

func (d *issuanceDispatcher) executeCTLogDiscoveryRun(ctx context.Context, tenantID string, src store.DiscoverySource, run projections.DiscoveryRunQueued) (netscan.Report, string, string, error) {
	if d.outbox == nil {
		return netscan.Report{}, "failed", "ct_log discovery requires the served outbox", nil
	}
	logs, domains, maxBatch, client, err := ctLogDiscoverySettings(src.Config)
	if err != nil {
		return netscan.Report{}, "failed", err.Error(), nil
	}
	if run.DryRun {
		return netscan.Report{Targets: len(logs)}, "succeeded", "", nil
	}
	sched := ctmonitor.NewScheduler(
		ctmonitor.NewStorePersistenceForWatchlist(d.store, domains, logs),
		ctmonitor.NewHTTPFetcherWithClient(client),
		ctmonitor.NewStoreKnownGood(d.store),
		ctmonitor.NewStoreAlerter(d.store, d.outbox),
		ctmonitor.WithMaxBatch(maxBatch),
		ctmonitor.WithMonitorOptions(ctmonitor.WithWorkers(4), ctmonitor.WithQueue(64), ctmonitor.WithBackoff(10*time.Millisecond)),
	)
	result, _ := sched.RunOnceDetailed(ctx, tenantID)
	if err := d.recordCTLogFindings(ctx, tenantID, src.ID, run.ID, result.Findings); err != nil {
		return netscan.Report{}, "", "", err
	}
	targetResults := make([]netscan.TargetResult, 0, len(result.Logs))
	for _, outcome := range result.Logs {
		targetResults = append(targetResults, netscan.TargetResult{
			Kind: "ct_log", Target: outcome.URL, Status: outcome.Status,
			Cursor: outcome.Checkpoint, Error: outcome.Error,
		})
	}
	report := netscan.Report{
		Targets: len(result.Logs), Discovered: len(result.Findings), Failed: result.FailedLogCount(),
		TargetResults: targetResults,
	}
	if result.FailedLogCount() == 0 {
		return report, "succeeded", "", nil
	}
	message := fmt.Sprintf("%d of %d CT logs failed", result.FailedLogCount(), len(result.Logs))
	for _, outcome := range result.Logs {
		if outcome.Status == ctmonitor.LogPollFailed && outcome.Error != "" {
			message += ": " + outcome.Error
			break
		}
	}
	if result.SucceededLogCount() > 0 {
		return report, "partial", message, nil
	}
	return report, "failed", message, nil
}

func discoveryTargetResults(in []netscan.TargetResult) []store.DiscoveryTargetResult {
	if len(in) == 0 {
		return nil
	}
	out := make([]store.DiscoveryTargetResult, 0, len(in))
	for _, result := range in {
		out = append(out, store.DiscoveryTargetResult{
			Kind: result.Kind, Target: result.Target, Status: result.Status,
			Cursor: result.Cursor, Error: result.Error,
		})
	}
	return out
}

func (d *issuanceDispatcher) executeDriftDiscoveryRun(ctx context.Context, tenantID string, src store.DiscoverySource, run projections.DiscoveryRunQueued) (netscan.Report, string, string, error) {
	cfg, watched, policy, err := driftDiscoverySettings(src.Config)
	if err != nil {
		return netscan.Report{}, "failed", err.Error(), nil
	}
	if run.DryRun {
		return netscan.Report{Targets: len(watched)}, "succeeded", "", nil
	}
	audit := &discoveryDriftAuditor{}
	rec := &drift.Reconciler{Policy: policy, Auditor: audit}
	rep, err := rec.Reconcile(ctx, watched, cfg.Scope...)
	if err != nil {
		return netscan.Report{}, "failed", err.Error(), nil
	}
	if err := d.recordDriftFindings(ctx, tenantID, src.ID, run.ID, rep, audit.events); err != nil {
		return netscan.Report{}, "", "", err
	}
	if d.outbox != nil {
		for i, f := range rep.Findings {
			var ev drift.Event
			if i < len(audit.events) {
				ev = audit.events[i]
			}
			if err := d.enqueueDriftAlert(ctx, tenantID, f, ev); err != nil {
				return netscan.Report{}, "", "", err
			}
		}
	}
	return netscan.Report{Targets: len(watched), Discovered: len(rep.Findings)}, "succeeded", "", nil
}

func (d *issuanceDispatcher) executeNHICrossSurfaceDiscoveryRun(ctx context.Context, tenantID string, src store.DiscoverySource, run projections.DiscoveryRunQueued) (netscan.Report, string, string, error) {
	findings, err := nhi.Findings(src.Config)
	if err != nil {
		return netscan.Report{}, "failed", err.Error(), nil
	}
	if run.DryRun {
		return netscan.Report{Targets: len(findings)}, "succeeded", "", nil
	}
	rep := netscan.Report{Targets: len(findings)}
	for _, f := range findings {
		meta, err := json.Marshal(f.Metadata)
		if err != nil {
			return rep, "", "", err
		}
		if _, err := d.orch.RecordDiscoveryFinding(ctx, tenantID, store.DiscoveryFinding{
			RunID: run.ID, SourceID: src.ID, Kind: nhi.FindingKind, Ref: f.Ref,
			Provenance: f.Provenance, Fingerprint: f.Fingerprint,
			RiskScore: f.RiskScore, Metadata: meta,
		}); err != nil {
			return rep, "", "", err
		}
		rep.Discovered++
	}
	return rep, "succeeded", "", nil
}

func (d *issuanceDispatcher) executeOAuthGrantDiscoveryRun(ctx context.Context, tenantID string, src store.DiscoverySource, run projections.DiscoveryRunQueued) (netscan.Report, string, string, error) {
	findings, err := oauthgrant.Findings(src.Config)
	if err != nil {
		return netscan.Report{}, "failed", err.Error(), nil
	}
	abuseFindings, err := oauthgrant.AbuseFindings(src.Config)
	if err != nil {
		return netscan.Report{}, "failed", err.Error(), nil
	}
	if run.DryRun {
		return netscan.Report{Targets: len(findings)}, "succeeded", "", nil
	}
	rep := netscan.Report{Targets: len(findings)}
	for _, f := range findings {
		meta, err := json.Marshal(f.Metadata)
		if err != nil {
			return rep, "", "", err
		}
		if _, err := d.orch.RecordDiscoveryFinding(ctx, tenantID, store.DiscoveryFinding{
			RunID: run.ID, SourceID: src.ID, Kind: oauthgrant.FindingKind, Ref: f.Ref,
			Provenance: f.Provenance, Fingerprint: f.Fingerprint,
			RiskScore: f.RiskScore, Metadata: meta,
		}); err != nil {
			return rep, "", "", err
		}
		rep.Discovered++
	}
	for _, f := range abuseFindings {
		meta, err := json.Marshal(f.Metadata)
		if err != nil {
			return rep, "", "", err
		}
		if _, err := d.orch.RecordDiscoveryFinding(ctx, tenantID, store.DiscoveryFinding{
			RunID: run.ID, SourceID: src.ID, Kind: oauthgrant.AbuseFindingKind, Ref: f.Ref,
			Provenance: f.Provenance, Fingerprint: f.Fingerprint,
			RiskScore: f.RiskScore, Metadata: meta,
		}); err != nil {
			return rep, "", "", err
		}
		rep.Discovered++
	}
	return rep, "succeeded", "", nil
}

func (d *issuanceDispatcher) executeServiceAccountDiscoveryRun(ctx context.Context, tenantID string, src store.DiscoverySource, run projections.DiscoveryRunQueued) (netscan.Report, string, string, error) {
	findings, err := serviceaccount.Findings(src.Config)
	if err != nil {
		return netscan.Report{}, "failed", err.Error(), nil
	}
	if run.DryRun {
		return netscan.Report{Targets: len(findings)}, "succeeded", "", nil
	}
	rep := netscan.Report{Targets: len(findings)}
	for _, f := range findings {
		meta, err := json.Marshal(f.Metadata)
		if err != nil {
			return rep, "", "", err
		}
		if _, err := d.orch.RecordDiscoveryFinding(ctx, tenantID, store.DiscoveryFinding{
			RunID: run.ID, SourceID: src.ID, Kind: serviceaccount.FindingKind, Ref: f.Ref,
			Provenance: f.Provenance, Fingerprint: f.Fingerprint,
			RiskScore: f.RiskScore, Metadata: meta,
		}); err != nil {
			return rep, "", "", err
		}
		rep.Discovered++
	}
	return rep, "succeeded", "", nil
}

func (d *issuanceDispatcher) executeNHIBehaviorDiscoveryRun(ctx context.Context, tenantID string, src store.DiscoverySource, run projections.DiscoveryRunQueued) (netscan.Report, string, string, error) {
	findings, err := nhibehavior.Findings(src.Config)
	if err != nil {
		return netscan.Report{}, "failed", err.Error(), nil
	}
	if run.DryRun {
		return netscan.Report{Targets: len(findings)}, "succeeded", "", nil
	}
	rep := netscan.Report{Targets: len(findings)}
	for _, f := range findings {
		meta, err := json.Marshal(f.Metadata)
		if err != nil {
			return rep, "", "", err
		}
		if _, err := d.orch.RecordDiscoveryFinding(ctx, tenantID, store.DiscoveryFinding{
			RunID: run.ID, SourceID: src.ID, Kind: nhibehavior.FindingKind, Ref: f.Ref,
			Provenance: f.Provenance, Fingerprint: f.Fingerprint,
			RiskScore: f.RiskScore, Metadata: meta,
		}); err != nil {
			return rep, "", "", err
		}
		rep.Discovered++
	}
	return rep, "succeeded", "", nil
}

func (d *issuanceDispatcher) executeCompromisedCredentialDiscoveryRun(ctx context.Context, tenantID string, src store.DiscoverySource, run projections.DiscoveryRunQueued) (netscan.Report, string, string, error) {
	findings, err := compromise.Findings(src.Config)
	if err != nil {
		return netscan.Report{}, "failed", err.Error(), nil
	}
	if run.DryRun {
		return netscan.Report{Targets: len(findings)}, "succeeded", "", nil
	}
	rep := netscan.Report{Targets: len(findings)}
	for _, f := range findings {
		meta, err := json.Marshal(f.Metadata)
		if err != nil {
			return rep, "", "", err
		}
		if _, err := d.orch.RecordDiscoveryFinding(ctx, tenantID, store.DiscoveryFinding{
			RunID: run.ID, SourceID: src.ID, Kind: compromise.FindingKind, Ref: f.Ref,
			Provenance: f.Provenance, Fingerprint: f.Fingerprint,
			RiskScore: f.RiskScore, Metadata: meta,
		}); err != nil {
			return rep, "", "", err
		}
		rep.Discovered++
	}
	return rep, "succeeded", "", nil
}

func (d *issuanceDispatcher) executeAPIKeyTokenDiscoveryRun(ctx context.Context, tenantID string, src store.DiscoverySource, run projections.DiscoveryRunQueued) (netscan.Report, string, string, error) {
	findings, err := apikey.Findings(src.Config)
	if err != nil {
		return netscan.Report{}, "failed", err.Error(), nil
	}
	if run.DryRun {
		return netscan.Report{Targets: len(findings)}, "succeeded", "", nil
	}
	rep := netscan.Report{Targets: len(findings)}
	for _, f := range findings {
		meta, err := json.Marshal(f.Metadata)
		if err != nil {
			return rep, "", "", err
		}
		if _, err := d.orch.RecordDiscoveryFinding(ctx, tenantID, store.DiscoveryFinding{
			RunID: run.ID, SourceID: src.ID, Kind: f.Kind, Ref: f.Ref,
			Provenance: f.Provenance, Fingerprint: f.Fingerprint,
			RiskScore: f.RiskScore, Metadata: meta,
		}); err != nil {
			return rep, "", "", err
		}
		rep.Discovered++
	}
	return rep, "succeeded", "", nil
}

func (d *issuanceDispatcher) executeKubernetesTLSAutoIssuanceRun(ctx context.Context, tenantID string, src store.DiscoverySource, run projections.DiscoveryRunQueued) (netscan.Report, string, string, error) {
	findings, err := k8stls.Findings(src.Config)
	if err != nil {
		return netscan.Report{}, "failed", err.Error(), nil
	}
	if run.DryRun {
		return netscan.Report{Targets: len(findings)}, "succeeded", "", nil
	}
	rep := netscan.Report{Targets: len(findings)}
	lastMintErr := ""
	for _, f := range findings {
		meta, err := json.Marshal(f.Metadata)
		if err != nil {
			return rep, "", "", err
		}
		if _, err := d.orch.RecordDiscoveryFinding(ctx, tenantID, store.DiscoveryFinding{
			RunID: run.ID, SourceID: src.ID, Kind: k8stls.FindingKind, Ref: f.Ref,
			Provenance: f.Provenance, Fingerprint: f.Fingerprint,
			RiskScore: f.RiskScore, Metadata: meta,
		}); err != nil {
			return rep, "", "", err
		}
		issuanceKey := "k8s-auto:" + run.ID + ":" + f.Fingerprint
		existing, err := d.store.ListCertificatesByIssuanceIdempotencyKey(ctx, tenantID, issuanceKey)
		if err != nil {
			return rep, "", "", err
		}
		if len(existing) == 0 {
			cert, err := d.mintServedLeaf(ctx, tenantID, "", f.CommonName, f.DNSNames)
			if err != nil {
				rep.Failed++
				lastMintErr = err.Error()
				continue
			}
			cert.DeploymentLocation = f.DeploymentLocation
			cert.Source = "discovery:" + k8stls.SourceKind
			cert.IssuanceIdempotencyKey = issuanceKey
			if _, err := d.orch.RecordCertificate(ctx, tenantID, cert); err != nil {
				return rep, "", "", err
			}
		}
		rep.Discovered++
	}
	if rep.Failed > 0 {
		if rep.Discovered > 0 {
			return rep, "partial", "some Kubernetes TLS resources could not be auto-issued: " + lastMintErr, nil
		}
		return rep, "failed", "all Kubernetes TLS resources could not be auto-issued: " + lastMintErr, nil
	}
	return rep, "succeeded", "", nil
}

func ctLogDiscoverySettings(raw json.RawMessage) ([]string, []string, int, *http.Client, error) {
	var cfg ctLogDiscoveryConfig
	if err := json.Unmarshal(raw, &cfg); err != nil {
		return nil, nil, 0, nil, fmt.Errorf("decode ct_log discovery config: %w", err)
	}
	logs := append([]string(nil), cfg.Logs...)
	if cfg.Log != "" {
		logs = append(logs, cfg.Log)
	}
	logs = cleanedUnique(logs)
	if len(logs) == 0 {
		return nil, nil, 0, nil, errors.New("ct_log discovery requires at least one log URL")
	}
	domains := append([]string(nil), cfg.WatchedDomains...)
	if cfg.Domain != "" {
		domains = append(domains, cfg.Domain)
	}
	domains = cleanedUnique(domains)
	if len(domains) == 0 {
		return nil, nil, 0, nil, errors.New("ct_log discovery requires at least one watched domain")
	}
	client := netsec.SafeClient(30 * time.Second)
	if cfg.AllowPrivateEndpoint {
		opts, err := privateEgressSafeClientOptions(cfg.PrivateEgressCIDRs)
		if err != nil {
			return nil, nil, 0, nil, err
		}
		for _, logURL := range logs {
			if err := validateHTTPSEgressEndpoint(logURL, true, opts); err != nil {
				return nil, nil, 0, nil, fmt.Errorf("ct_log %q: %w", logURL, err)
			}
		}
		client = netsec.SafeClientWithOptions(30*time.Second, opts)
	} else {
		for _, logURL := range logs {
			if err := netsec.ValidatePublicHTTPSURL(logURL); err != nil {
				return nil, nil, 0, nil, fmt.Errorf("ct_log %q: %w", logURL, err)
			}
		}
	}
	return logs, domains, cfg.MaxBatch, client, nil
}

func driftDiscoverySettings(raw json.RawMessage) (driftDiscoveryConfig, []drift.Watched, drift.ClassPolicy, error) {
	var cfg driftDiscoveryConfig
	if err := json.Unmarshal(raw, &cfg); err != nil {
		return cfg, nil, nil, fmt.Errorf("decode drift discovery config: %w", err)
	}
	if len(cfg.Watched) == 0 {
		return cfg, nil, nil, errors.New("drift discovery requires at least one watched credential")
	}
	watched := make([]drift.Watched, 0, len(cfg.Watched))
	for i, w := range cfg.Watched {
		path := strings.TrimSpace(w.Path)
		class := strings.TrimSpace(w.Class)
		fp := strings.TrimSpace(w.Fingerprint)
		if path == "" || class == "" || fp == "" {
			return cfg, nil, nil, fmt.Errorf("drift watched[%d] requires path, class, and fingerprint", i)
		}
		mode, err := parseOptionalFileMode(w.Mode)
		if err != nil {
			return cfg, nil, nil, fmt.Errorf("drift watched[%d] mode: %w", i, err)
		}
		watched = append(watched, drift.Watched{
			Path: path, Class: class, Fingerprint: fp, Mode: mode, Restricted: w.Restricted,
		})
	}
	policy := drift.ClassPolicy{}
	for class, mode := range cfg.Policy {
		class = strings.TrimSpace(class)
		mode = strings.TrimSpace(mode)
		if class == "" || mode == "" {
			continue
		}
		switch drift.Mode(mode) {
		case drift.AlertOnly, drift.AlertAndBlock:
			policy[class] = drift.Mode(mode)
		case drift.AutoRemediate:
			return cfg, nil, nil, errors.New("served drift discovery does not auto-remediate; use alert_only or alert_and_block")
		default:
			return cfg, nil, nil, fmt.Errorf("unsupported drift policy mode %q", mode)
		}
	}
	return cfg, watched, policy, nil
}

func parseOptionalFileMode(raw string) (os.FileMode, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return 0, nil
	}
	v, err := strconv.ParseUint(raw, 8, 32)
	if err != nil {
		return 0, err
	}
	return os.FileMode(v), nil
}

func cleanedUnique(values []string) []string {
	seen := map[string]bool{}
	out := make([]string, 0, len(values))
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value == "" || seen[value] {
			continue
		}
		seen[value] = true
		out = append(out, value)
	}
	return out
}

func (d *issuanceDispatcher) recordCTLogFindings(ctx context.Context, tenantID, sourceID, runID string, findings []ctmonitor.Finding) error {
	for _, f := range findings {
		meta, err := json.Marshal(map[string]any{
			"log_url":        f.LogURL,
			"index":          f.Index,
			"subject":        f.Subject,
			"issuer":         f.Issuer,
			"serial":         f.Serial,
			"sans":           f.DNSNames,
			"not_after":      f.NotAfter,
			"matched_domain": f.MatchedDomain,
		})
		if err != nil {
			return err
		}
		ref := f.MatchedDomain
		if len(f.DNSNames) > 0 {
			ref = f.DNSNames[0]
		}
		if _, err := d.orch.RecordDiscoveryFinding(ctx, tenantID, store.DiscoveryFinding{
			RunID: runID, SourceID: sourceID, Kind: "ct_unexpected_issuance", Ref: ref,
			Provenance: "ct:" + f.LogURL, Fingerprint: f.Fingerprint,
			RiskScore: discoveryRiskScore(f.NotAfter), Metadata: meta,
		}); err != nil {
			return err
		}
	}
	return nil
}

type discoveryDriftAuditor struct {
	events []drift.Event
}

func (a *discoveryDriftAuditor) Record(e drift.Event) {
	a.events = append(a.events, e)
}

func (d *issuanceDispatcher) recordDriftFindings(ctx context.Context, tenantID, sourceID, runID string, rep drift.Report, events []drift.Event) error {
	for i, f := range rep.Findings {
		var ev drift.Event
		if i < len(events) {
			ev = events[i]
		}
		meta, err := json.Marshal(map[string]any{
			"type":                           string(f.Type),
			"path":                           f.Watched.Path,
			"class":                          f.Watched.Class,
			"found_at":                       f.FoundAt,
			"actual_mode":                    fileModeString(f.ActualMode),
			"detail":                         nonempty(f.Detail, ev.Detail),
			"policy_mode":                    string(ev.Mode),
			"blocked":                        ev.Blocked,
			"remediated":                     ev.Remediated,
			"permission_detection_supported": rep.PermissionDetectionSupported,
		})
		if err != nil {
			return err
		}
		if _, err := d.orch.RecordDiscoveryFinding(ctx, tenantID, store.DiscoveryFinding{
			RunID: runID, SourceID: sourceID, Kind: "credential_drift", Ref: f.Watched.Path,
			Provenance: "drift:" + f.Watched.Path, Fingerprint: f.Watched.Fingerprint,
			RiskScore: driftRiskScore(f.Type), Metadata: meta,
		}); err != nil {
			return err
		}
	}
	return nil
}

func (d *issuanceDispatcher) enqueueDriftAlert(ctx context.Context, tenantID string, f drift.Finding, ev drift.Event) error {
	payload, err := json.Marshal(notify.Alert{
		Kind:     notify.KindCredentialDrift,
		TenantID: tenantID,
		Subject:  f.Watched.Path,
		Detail:   fmt.Sprintf("%s drift for %s: %s", f.Watched.Class, f.Watched.Path, nonempty(f.Detail, ev.Detail)),
	})
	if err != nil {
		return err
	}
	idem := "drift:" + f.Watched.Path + ":" + string(f.Type) + ":" + f.Watched.Fingerprint
	return d.store.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		_, err := d.outbox.EnqueueIfAbsent(ctx, tx, orchestrator.Entry{
			TenantID: tenantID, Destination: notify.DestinationDrift, IdempotencyKey: idem, Payload: payload,
		})
		return err
	})
}

func driftRiskScore(t drift.Type) int {
	switch t {
	case drift.Deleted, drift.Replaced:
		return 80
	case drift.PermissionChanged:
		return 70
	case drift.Relocated:
		return 60
	default:
		return 50
	}
}

func fileModeString(m os.FileMode) string {
	if m == 0 {
		return ""
	}
	return fmt.Sprintf("%04o", m.Perm())
}

func cloudCertificateProviders(ctx context.Context, raw json.RawMessage) ([]cloudcert.Provider, error) {
	var cfg cloudCertificateDiscoveryConfig
	if err := json.Unmarshal(raw, &cfg); err != nil {
		return nil, fmt.Errorf("decode cloud_certificate discovery config: %w", err)
	}
	providers := make([]cloudcert.Provider, 0, len(cfg.Providers))
	for i, p := range cfg.Providers {
		provider, err := cloudCertificateProvider(ctx, p)
		if err != nil {
			return nil, fmt.Errorf("cloud_certificate provider %d: %w", i, err)
		}
		providers = append(providers, provider)
	}
	return providers, nil
}

func cloudSecretProviders(ctx context.Context, raw json.RawMessage) ([]cloudsecret.Provider, error) {
	var cfg cloudSecretDiscoveryConfig
	if err := json.Unmarshal(raw, &cfg); err != nil {
		return nil, fmt.Errorf("decode cloud_secret discovery config: %w", err)
	}
	providers := make([]cloudsecret.Provider, 0, len(cfg.Providers))
	for i, p := range cfg.Providers {
		provider, err := cloudSecretProvider(ctx, p)
		if err != nil {
			return nil, fmt.Errorf("cloud_secret provider %d: %w", i, err)
		}
		providers = append(providers, provider)
	}
	return providers, nil
}

func cloudSecretProvider(ctx context.Context, p cloudSecretProviderConfig) (cloudsecret.Provider, error) {
	switch strings.TrimSpace(p.Provider) {
	case "aws-secrets-manager":
		region := strings.TrimSpace(p.Region)
		if region == "" {
			return nil, errors.New("aws-secrets-manager region is required")
		}
		endpoint := strings.TrimSpace(p.Endpoint)
		if endpoint == "" {
			endpoint = "https://secretsmanager." + region + ".amazonaws.com"
		}
		client, err := cloudHTTPClient(endpoint, p.AllowPrivateEndpoint, p.PrivateEgressCIDRs)
		if err != nil {
			return nil, err
		}
		accessKeyID, err := resolveDiscoveryCredentialRef(ctx, p.AccessKeyIDRef)
		if err != nil {
			return nil, fmt.Errorf("resolve access_key_id_ref: %w", err)
		}
		secretAccessKey, err := resolveDiscoveryCredentialBytesRef(ctx, p.SecretAccessKeyRef)
		if err != nil {
			return nil, fmt.Errorf("resolve secret_access_key_ref: %w", err)
		}
		defer secret.Wipe(secretAccessKey)
		sessionToken, err := resolveOptionalDiscoveryCredentialBytesRef(ctx, p.SessionTokenRef)
		if err != nil {
			return nil, fmt.Errorf("resolve session_token_ref: %w", err)
		}
		defer secret.Wipe(sessionToken)
		return awssmdisc.New(awssmdisc.Config{
			Region: region, Endpoint: endpoint, AccessKeyID: accessKeyID,
			SecretAccessKey: secretAccessKey, SessionToken: sessionToken,
			TagKey: p.TagKey, TagValue: p.TagValue, NamePrefix: p.NamePrefix, HTTPClient: client,
		})
	case "gcp-secret-manager":
		project := strings.TrimSpace(p.Project)
		if project == "" {
			return nil, errors.New("gcp-secret-manager project is required")
		}
		endpoint := strings.TrimSpace(p.Endpoint)
		client := netsec.SafeClient(30 * time.Second)
		if endpoint != "" {
			var err error
			client, err = cloudHTTPClient(endpoint, p.AllowPrivateEndpoint, p.PrivateEgressCIDRs)
			if err != nil {
				return nil, err
			}
		}
		token, err := resolveDiscoveryCredentialRef(ctx, p.TokenRef)
		if err != nil {
			return nil, fmt.Errorf("resolve token_ref: %w", err)
		}
		return gcpsmdisc.New(gcpsmdisc.Config{
			Project: project, Endpoint: endpoint, Token: cloudcert.StaticToken(token),
			LabelKey: p.LabelKey, LabelValue: p.LabelValue, NamePrefix: p.NamePrefix, HTTPClient: client,
		})
	case "azure-key-vault":
		vaultURL := strings.TrimSpace(p.VaultURL)
		if vaultURL == "" {
			return nil, errors.New("azure-key-vault vault_url is required")
		}
		client, err := cloudHTTPClient(vaultURL, p.AllowPrivateEndpoint, p.PrivateEgressCIDRs)
		if err != nil {
			return nil, err
		}
		token, err := resolveDiscoveryCredentialRef(ctx, p.TokenRef)
		if err != nil {
			return nil, fmt.Errorf("resolve token_ref: %w", err)
		}
		return azurekvsecretdisc.New(azurekvsecretdisc.Config{
			VaultURL: vaultURL, APIVersion: p.APIVersion, Token: cloudcert.StaticToken(token),
			TagKey: p.TagKey, TagValue: p.TagValue, NamePrefix: p.NamePrefix, HTTPClient: client,
		})
	case "hashicorp-vault", "vault":
		vaultURL := strings.TrimSpace(p.VaultURL)
		if vaultURL == "" {
			return nil, errors.New("hashicorp-vault vault_url is required")
		}
		client, err := cloudHTTPClient(vaultURL, p.AllowPrivateEndpoint, p.PrivateEgressCIDRs)
		if err != nil {
			return nil, err
		}
		token, err := resolveDiscoveryCredentialRef(ctx, p.TokenRef)
		if err != nil {
			return nil, fmt.Errorf("resolve token_ref: %w", err)
		}
		return vaultkvdisc.New(vaultkvdisc.Config{
			VaultURL: vaultURL, Mount: p.Mount, PathPrefix: p.PathPrefix, Token: cloudcert.StaticToken(token),
			TagKey: p.TagKey, TagValue: p.TagValue, NamePrefix: p.NamePrefix, HTTPClient: client,
		})
	default:
		return nil, fmt.Errorf("unsupported cloud secret-manager provider %q", p.Provider)
	}
}

func cloudCertificateProvider(ctx context.Context, p cloudCertificateProviderConfig) (cloudcert.Provider, error) {
	switch strings.TrimSpace(p.Provider) {
	case "aws-acm":
		region := strings.TrimSpace(p.Region)
		if region == "" {
			return nil, errors.New("aws-acm region is required")
		}
		endpoint := strings.TrimSpace(p.Endpoint)
		if endpoint == "" {
			endpoint = "https://acm." + region + ".amazonaws.com"
		}
		client, err := cloudHTTPClient(endpoint, p.AllowPrivateEndpoint, p.PrivateEgressCIDRs)
		if err != nil {
			return nil, err
		}
		accessKeyID, err := resolveDiscoveryCredentialRef(ctx, p.AccessKeyIDRef)
		if err != nil {
			return nil, fmt.Errorf("resolve access_key_id_ref: %w", err)
		}
		secretAccessKey, err := resolveDiscoveryCredentialRef(ctx, p.SecretAccessKeyRef)
		if err != nil {
			return nil, fmt.Errorf("resolve secret_access_key_ref: %w", err)
		}
		sessionToken, err := resolveOptionalDiscoveryCredentialRef(ctx, p.SessionTokenRef)
		if err != nil {
			return nil, fmt.Errorf("resolve session_token_ref: %w", err)
		}
		return acmdisc.New(acmdisc.Config{
			Region: region, Endpoint: endpoint, AccessKeyID: accessKeyID,
			SecretAccessKey: secretAccessKey, SessionToken: sessionToken, HTTPClient: client,
		})
	case "azure-keyvault":
		vaultURL := strings.TrimSpace(p.VaultURL)
		if vaultURL == "" {
			return nil, errors.New("azure-keyvault vault_url is required")
		}
		client, err := cloudHTTPClient(vaultURL, p.AllowPrivateEndpoint, p.PrivateEgressCIDRs)
		if err != nil {
			return nil, err
		}
		token, err := resolveDiscoveryCredentialRef(ctx, p.TokenRef)
		if err != nil {
			return nil, fmt.Errorf("resolve token_ref: %w", err)
		}
		return kvdisc.New(kvdisc.Config{VaultURL: vaultURL, Token: cloudcert.StaticToken(token), HTTPClient: client})
	case "gcp-certmanager":
		project := strings.TrimSpace(p.Project)
		location := strings.TrimSpace(p.Location)
		if project == "" || location == "" {
			return nil, errors.New("gcp-certmanager project and location are required")
		}
		endpoint := strings.TrimSpace(p.Endpoint)
		client := netsec.SafeClient(30 * time.Second)
		if endpoint != "" {
			var err error
			client, err = cloudHTTPClient(endpoint, p.AllowPrivateEndpoint, p.PrivateEgressCIDRs)
			if err != nil {
				return nil, err
			}
		}
		token, err := resolveDiscoveryCredentialRef(ctx, p.TokenRef)
		if err != nil {
			return nil, fmt.Errorf("resolve token_ref: %w", err)
		}
		return gcmdisc.New(gcmdisc.Config{Project: project, Location: location, Endpoint: endpoint, Token: cloudcert.StaticToken(token), HTTPClient: client})
	default:
		return nil, fmt.Errorf("unsupported cloud certificate provider %q", p.Provider)
	}
}

func cloudHTTPClient(endpoint string, allowPrivate bool, privateCIDRs []string) (*http.Client, error) {
	if strings.TrimSpace(endpoint) == "" {
		return nil, errors.New("cloud provider endpoint is required")
	}
	if allowPrivate {
		opts, err := privateEgressSafeClientOptions(privateCIDRs)
		if err != nil {
			return nil, err
		}
		if err := validateHTTPSEgressEndpoint(endpoint, true, opts); err != nil {
			return nil, err
		}
		return netsec.SafeClientWithOptions(30*time.Second, opts), nil
	}
	if err := validateHTTPSEgressEndpoint(endpoint, false, netsec.SafeClientOptions{}); err != nil {
		return nil, err
	}
	return netsec.SafeClient(30 * time.Second), nil
}

func privateEgressSafeClientOptions(cidrs []string) (netsec.SafeClientOptions, error) {
	opts := netsec.SafeClientOptions{}
	for _, raw := range cidrs {
		raw = strings.TrimSpace(raw)
		if raw == "" {
			continue
		}
		prefix, err := netip.ParsePrefix(raw)
		if err != nil {
			return opts, fmt.Errorf("private_egress_cidrs contains invalid CIDR %q: %w", raw, err)
		}
		opts.AllowPrivateCIDRs = append(opts.AllowPrivateCIDRs, prefix)
	}
	if len(opts.AllowPrivateCIDRs) == 0 {
		return opts, errors.New("private endpoint egress requires private_egress_cidrs")
	}
	return opts, nil
}

func validateHTTPSEgressEndpoint(endpoint string, allowPrivate bool, opts netsec.SafeClientOptions) error {
	if !allowPrivate {
		return netsec.ValidatePublicHTTPSURL(endpoint)
	}
	u, err := url.Parse(strings.TrimSpace(endpoint))
	if err != nil {
		return fmt.Errorf("%w: malformed outbound endpoint", netsec.ErrSSRFBlocked)
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return fmt.Errorf("%w: outbound endpoint must use http or https", netsec.ErrSSRFBlocked)
	}
	if u.Hostname() == "" {
		return fmt.Errorf("%w: outbound endpoint is missing a host", netsec.ErrSSRFBlocked)
	}
	if u.Scheme == "https" {
		return netsec.ValidatePublicHTTPSURLWithOptions(endpoint, opts)
	}
	return nil
}

func resolveOptionalDiscoveryCredentialRef(ctx context.Context, ref string) (string, error) {
	if strings.TrimSpace(ref) == "" {
		return "", nil
	}
	return resolveDiscoveryCredentialRef(ctx, ref)
}

func resolveOptionalDiscoveryCredentialBytesRef(ctx context.Context, ref string) ([]byte, error) {
	if strings.TrimSpace(ref) == "" {
		return nil, nil
	}
	return resolveDiscoveryCredentialBytesRef(ctx, ref)
}

func resolveDiscoveryCredentialBytesRef(ctx context.Context, ref string) ([]byte, error) {
	value, err := resolveDiscoveryCredentialRef(ctx, ref)
	if err != nil {
		return nil, err
	}
	return []byte(value), nil
}

func resolveDiscoveryCredentialRef(ctx context.Context, ref string) (string, error) {
	if err := ctx.Err(); err != nil {
		return "", err
	}
	ref = strings.TrimSpace(ref)
	if ref == "" {
		return "", errors.New("credential reference is required")
	}
	if name, ok := strings.CutPrefix(ref, "env:"); ok {
		name = strings.TrimSpace(name)
		if name == "" {
			return "", errors.New("env credential reference is empty")
		}
		value, ok := os.LookupEnv(name)
		if !ok || value == "" {
			return "", fmt.Errorf("env credential reference %s is not set", name)
		}
		return value, nil
	}
	return "", fmt.Errorf("unsupported credential reference %q; use env:NAME", ref)
}

func (d *issuanceDispatcher) recordManualDiscoveryFindings(ctx context.Context, tenantID string, src store.DiscoverySource, runID string) (netscan.Report, error) {
	var cfg manualDiscoveryConfig
	if err := json.Unmarshal(src.Config, &cfg); err != nil {
		return netscan.Report{}, fmt.Errorf("decode discovery findings config: %w", err)
	}
	rep := netscan.Report{Targets: len(cfg.Findings)}
	for _, f := range cfg.Findings {
		f.Kind = strings.TrimSpace(f.Kind)
		f.Ref = strings.TrimSpace(f.Ref)
		if f.Kind == "" || f.Ref == "" {
			rep.Failed++
			continue
		}
		if f.Provenance == "" {
			f.Provenance = src.Kind + ":" + f.Ref
		}
		if len(f.Metadata) == 0 {
			f.Metadata = json.RawMessage(`{}`)
		}
		if _, err := d.orch.RecordDiscoveryFinding(ctx, tenantID, store.DiscoveryFinding{
			RunID: runID, SourceID: src.ID, Kind: f.Kind, Ref: f.Ref, Provenance: f.Provenance,
			Fingerprint: f.Fingerprint, RiskScore: f.RiskScore, Metadata: f.Metadata,
		}); err != nil {
			return rep, err
		}
		rep.Discovered++
	}
	return rep, nil
}

func (d *issuanceDispatcher) executeSecretRepositoryDiscoveryRun(ctx context.Context, tenantID string, src store.DiscoverySource, run projections.DiscoveryRunQueued) (netscan.Report, string, string, error) {
	if d.secretRepoScanner == nil {
		return netscan.Report{}, "failed", "secret repository scanner is not configured", nil
	}
	var cfg secretscan.RepositoryScanConfig
	if err := json.Unmarshal(src.Config, &cfg); err != nil {
		return netscan.Report{}, "", "", fmt.Errorf("decode secret repository source config: %w", err)
	}
	target, err := secretscan.PrepareRepositoryTarget(ctx, cfg)
	if err != nil {
		if errors.Is(err, secretscan.ErrRepositoryTargetRequired) || errors.Is(err, secretscan.ErrRepositoryUnsafeCloneURL) {
			return netscan.Report{}, "failed", err.Error(), nil
		}
		return netscan.Report{}, "", "", err
	}
	defer target.Cleanup()
	report, err := d.secretRepoScanner.Scan(ctx, target.Path)
	if err != nil {
		return netscan.Report{}, "", "", err
	}
	rep := netscan.Report{Targets: len(report.Findings)}
	for _, f := range report.Findings {
		f.RuleID = strings.TrimSpace(f.RuleID)
		f.File = strings.TrimSpace(f.File)
		if f.RuleID == "" || f.File == "" {
			rep.Failed++
			continue
		}
		ref := f.CredentialRef
		if ref == "" {
			ref = f.RuleID + "@" + f.File
		}
		meta, err := json.Marshal(map[string]any{
			"scanner":        report.Scanner,
			"engine_version": report.EngineVersion,
			"rules_active":   report.RulesActive,
			"provider":       cfg.Provider,
			"repository":     cfg.Repository,
			"ref":            cfg.Ref,
			"commit_sha":     cfg.CommitSHA,
			"event":          cfg.Event,
			"mode":           target.Mode,
			"rule_id":        f.RuleID,
			"file":           f.File,
			"line":           f.Line,
		})
		if err != nil {
			return rep, "", "", err
		}
		if _, err := d.orch.RecordDiscoveryFinding(ctx, tenantID, store.DiscoveryFinding{
			RunID:       run.ID,
			SourceID:    src.ID,
			Kind:        "leaked_secret",
			Ref:         ref,
			Provenance:  secretscan.RepositorySourceKind + ":" + cfg.Provider + ":" + cfg.Repository + ":" + f.File,
			Fingerprint: firstNonEmpty(f.Fingerprint, ref),
			RiskScore:   95,
			Metadata:    json.RawMessage(meta),
		}); err != nil {
			return rep, "", "", err
		}
		rep.Discovered++
	}
	status := "succeeded"
	msg := ""
	if rep.Failed > 0 {
		status = "partial"
		msg = "some secret repository findings were rejected"
	}
	if rep.Discovered == 0 && rep.Failed == 0 {
		msg = "secret repository scan completed with no findings"
	}
	return rep, status, msg, nil
}

func (d *issuanceDispatcher) executeThirdPartySecretDiscoveryRun(ctx context.Context, tenantID string, src store.DiscoverySource, run projections.DiscoveryRunQueued) (netscan.Report, string, string, error) {
	if d.secretRepoScanner == nil {
		return netscan.Report{}, "failed", "third-party secret scanner is not configured", nil
	}
	var cfg secretscan.ThirdPartyScanConfig
	if err := json.Unmarshal(src.Config, &cfg); err != nil {
		return netscan.Report{}, "", "", fmt.Errorf("decode third-party secret source config: %w", err)
	}
	cfg.Provider = secretscan.NormalizeThirdPartyProvider(cfg.Provider)
	if cfg.Provider == "" {
		return netscan.Report{}, "failed", "third-party secret scan provider is unsupported", nil
	}
	target, err := secretscan.PrepareThirdPartyTarget(cfg)
	if err != nil {
		if errors.Is(err, secretscan.ErrThirdPartyTargetRequired) {
			return netscan.Report{}, "failed", err.Error(), nil
		}
		return netscan.Report{}, "", "", err
	}
	defer target.Cleanup()
	report, err := d.secretRepoScanner.Scan(ctx, target.Path)
	if err != nil {
		return netscan.Report{}, "", "", err
	}
	rep := netscan.Report{Targets: len(report.Findings)}
	for _, f := range report.Findings {
		f.RuleID = strings.TrimSpace(f.RuleID)
		f.File = strings.TrimSpace(f.File)
		if f.RuleID == "" || f.File == "" {
			rep.Failed++
			continue
		}
		ref := f.CredentialRef
		if ref == "" {
			ref = f.RuleID + "@" + f.File
		}
		meta, err := json.Marshal(map[string]any{
			"capability":     "CAP-SCAN-04",
			"scanner":        report.Scanner,
			"engine_version": report.EngineVersion,
			"rules_active":   report.RulesActive,
			"provider":       cfg.Provider,
			"source":         cfg.Source,
			"artifact_kind":  cfg.ArtifactKind,
			"event":          cfg.Event,
			"mode":           target.Mode,
			"rule_id":        f.RuleID,
			"file":           f.File,
			"line":           f.Line,
		})
		if err != nil {
			return rep, "", "", err
		}
		if _, err := d.orch.RecordDiscoveryFinding(ctx, tenantID, store.DiscoveryFinding{
			RunID:       run.ID,
			SourceID:    src.ID,
			Kind:        "leaked_secret",
			Ref:         ref,
			Provenance:  secretscan.ThirdPartySourceKind + ":" + cfg.Provider + ":" + cfg.Source + ":" + f.File,
			Fingerprint: firstNonEmpty(f.Fingerprint, ref),
			RiskScore:   95,
			Metadata:    json.RawMessage(meta),
		}); err != nil {
			return rep, "", "", err
		}
		rep.Discovered++
	}
	status := "succeeded"
	msg := ""
	if rep.Failed > 0 {
		status = "partial"
		msg = "some third-party secret findings were rejected"
	}
	if rep.Discovered == 0 && rep.Failed == 0 {
		msg = "third-party secret scan completed with no findings"
	}
	return rep, status, msg, nil
}

func discoveryRunTerminal(status string) bool {
	return status == "succeeded" || status == "partial" || status == "failed"
}

type cloudDiscoveryRunSink struct {
	orch     *orchestrator.Orchestrator
	tenantID string
	runID    string
	sourceID string
}

type cloudSecretDiscoveryRunSink struct {
	orch     *orchestrator.Orchestrator
	tenantID string
	runID    string
	sourceID string
}

func (s cloudDiscoveryRunSink) Record(ctx context.Context, f cloudcert.Found) error {
	meta, err := json.Marshal(map[string]any{
		"provider":        f.Provider,
		"resource_id":     f.ResourceID,
		"location":        f.Location,
		"subject":         f.Cert.Subject,
		"issuer":          f.Cert.Issuer,
		"serial":          f.Cert.SerialNumber,
		"sans":            sansOf(f.Cert),
		"not_before":      f.Cert.NotBefore,
		"not_after":       f.Cert.NotAfter,
		"key_algorithm":   f.Cert.KeyAlgorithm,
		"public_key_bits": f.Cert.PublicKeyBits,
		"is_ca":           f.Cert.IsCA,
	})
	if err != nil {
		return err
	}
	nb, na := f.Cert.NotBefore, f.Cert.NotAfter
	location := f.ResourceID
	if location == "" {
		location = f.Location
	}
	if _, err := s.orch.RecordCertificate(ctx, s.tenantID, store.Certificate{
		Subject: f.Cert.Subject, SANs: sansOf(f.Cert), Issuer: f.Cert.Issuer,
		Serial: f.Cert.SerialNumber, Fingerprint: f.Cert.SHA256Fingerprint,
		KeyAlgorithm: f.Cert.KeyAlgorithm, NotBefore: &nb, NotAfter: &na,
		DeploymentLocation: location, Source: "discovery:cloud:" + f.Provider,
	}); err != nil {
		return err
	}
	_, err = s.orch.RecordDiscoveryFinding(ctx, s.tenantID, store.DiscoveryFinding{
		RunID: s.runID, SourceID: s.sourceID, Kind: "x509_certificate", Ref: location,
		Provenance: "cloud:" + f.Provider + ":" + location, Fingerprint: f.Cert.SHA256Fingerprint,
		RiskScore: discoveryRiskScore(f.Cert.NotAfter), Metadata: meta,
	})
	return err
}

func (s cloudSecretDiscoveryRunSink) Record(ctx context.Context, f cloudsecret.Found) error {
	metaMap := map[string]any{
		"provider":        f.Provider,
		"resource_id":     f.ResourceID,
		"secret_name":     f.SecretName,
		"location":        f.Location,
		"subject":         f.Cert.Subject,
		"issuer":          f.Cert.Issuer,
		"serial":          f.Cert.SerialNumber,
		"sans":            sansOf(f.Cert),
		"not_before":      f.Cert.NotBefore,
		"not_after":       f.Cert.NotAfter,
		"key_algorithm":   f.Cert.KeyAlgorithm,
		"public_key_bits": f.Cert.PublicKeyBits,
		"is_ca":           f.Cert.IsCA,
	}
	for k, v := range f.Metadata {
		metaMap[k] = v
	}
	meta, err := json.Marshal(metaMap)
	if err != nil {
		return err
	}
	nb, na := f.Cert.NotBefore, f.Cert.NotAfter
	location := f.ResourceID
	if location == "" {
		location = f.SecretName
	}
	if _, err := s.orch.RecordCertificate(ctx, s.tenantID, store.Certificate{
		Subject: f.Cert.Subject, SANs: sansOf(f.Cert), Issuer: f.Cert.Issuer,
		Serial: f.Cert.SerialNumber, Fingerprint: f.Cert.SHA256Fingerprint,
		KeyAlgorithm: f.Cert.KeyAlgorithm, NotBefore: &nb, NotAfter: &na,
		DeploymentLocation: location, Source: "discovery:cloud-secret:" + f.Provider,
	}); err != nil {
		return err
	}
	_, err = s.orch.RecordDiscoveryFinding(ctx, s.tenantID, store.DiscoveryFinding{
		RunID: s.runID, SourceID: s.sourceID, Kind: cloudsecret.FindingKindCertificate, Ref: location,
		Provenance: f.Provenance, Fingerprint: f.Cert.SHA256Fingerprint,
		RiskScore: discoveryRiskScore(f.Cert.NotAfter), Metadata: meta,
	})
	return err
}

func discoveryRiskScore(notAfter time.Time) int {
	switch {
	case notAfter.IsZero():
		return 50
	case time.Until(notAfter) < 7*24*time.Hour:
		return 80
	case time.Until(notAfter) < 30*24*time.Hour:
		return 40
	default:
		return 10
	}
}
