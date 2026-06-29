package server

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
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
	gcpsmdisc "trstctl.com/trstctl/internal/discovery/cloudsecret/gcpsm"
	"trstctl.com/trstctl/internal/discovery/compromise"
	"trstctl.com/trstctl/internal/discovery/ctmonitor"
	"trstctl.com/trstctl/internal/discovery/k8stls"
	"trstctl.com/trstctl/internal/discovery/netscan"
	"trstctl.com/trstctl/internal/discovery/nhi"
	"trstctl.com/trstctl/internal/discovery/nhibehavior"
	"trstctl.com/trstctl/internal/discovery/oauthgrant"
	"trstctl.com/trstctl/internal/discovery/serviceaccount"
	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/netsec"
	"trstctl.com/trstctl/internal/notify"
	"trstctl.com/trstctl/internal/orchestrator"
	"trstctl.com/trstctl/internal/projections"
	"trstctl.com/trstctl/internal/secretscan"
	"trstctl.com/trstctl/internal/store"
)

const maxServedDiscoveryTargets = 10000

type networkDiscoveryConfig struct {
	Targets []string `json:"targets"`
	CIDRs   []string `json:"cidrs"`
	CIDR    string   `json:"cidr"`
	Ports   []int    `json:"ports"`
	// AllowRFC1918 explicitly permits private RFC1918 scan targets. The default
	// is false so CIDR scans cannot be turned into metadata/localhost/internal SSRF.
	AllowRFC1918 bool `json:"allow_rfc1918"`
	// AllowLoopback is for explicit localhost diagnostics/tests. It is false by
	// default because loopback scanning is an SSRF boundary.
	AllowLoopback bool `json:"allow_loopback"`
}

type networkDiscoveryPlan struct {
	targets       []string
	allowRFC1918  bool
	allowLoopback bool
}

type manualDiscoveryConfig struct {
	Findings []manualDiscoveryFinding `json:"findings"`
}

type cloudCertificateDiscoveryConfig struct {
	Providers []cloudCertificateProviderConfig `json:"providers"`
}

type cloudCertificateProviderConfig struct {
	Provider             string `json:"provider"`
	Region               string `json:"region"`
	Endpoint             string `json:"endpoint"`
	AllowPrivateEndpoint bool   `json:"allow_private_endpoint"`
	AccessKeyIDRef       string `json:"access_key_id_ref"`
	SecretAccessKeyRef   string `json:"secret_access_key_ref"`
	SessionTokenRef      string `json:"session_token_ref"`
	VaultURL             string `json:"vault_url"`
	TokenRef             string `json:"token_ref"`
	Project              string `json:"project"`
	Location             string `json:"location"`
}

type cloudSecretDiscoveryConfig struct {
	Providers []cloudSecretProviderConfig `json:"providers"`
}

type cloudSecretProviderConfig struct {
	Provider             string `json:"provider"`
	Region               string `json:"region"`
	Endpoint             string `json:"endpoint"`
	AllowPrivateEndpoint bool   `json:"allow_private_endpoint"`
	AccessKeyIDRef       string `json:"access_key_id_ref"`
	SecretAccessKeyRef   string `json:"secret_access_key_ref"`
	SessionTokenRef      string `json:"session_token_ref"`
	TokenRef             string `json:"token_ref"`
	Project              string `json:"project"`
	TagKey               string `json:"tag_key"`
	TagValue             string `json:"tag_value"`
	LabelKey             string `json:"label_key"`
	LabelValue           string `json:"label_value"`
	NamePrefix           string `json:"name_prefix"`
}

type ctLogDiscoveryConfig struct {
	Logs                 []string `json:"logs"`
	Log                  string   `json:"log"`
	WatchedDomains       []string `json:"watched_domains"`
	Domain               string   `json:"domain"`
	MaxBatch             int      `json:"max_batch"`
	AllowPrivateEndpoint bool     `json:"allow_private_endpoint"`
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
		}); err != nil {
			return nil, err
		}
		return []byte(status), nil
	})
	return err
}

func (d *issuanceDispatcher) executeDiscoveryRun(ctx context.Context, tenantID string, src store.DiscoverySource, run projections.DiscoveryRunQueued) (netscan.Report, string, string, error) {
	if src.Kind == "network" {
		return d.executeNetworkDiscoveryRun(ctx, tenantID, src, run)
	}
	if src.Kind == "cloud_certificate" {
		return d.executeCloudCertificateDiscoveryRun(ctx, tenantID, src, run)
	}
	if src.Kind == cloudsecret.SourceKind {
		return d.executeCloudSecretDiscoveryRun(ctx, tenantID, src, run)
	}
	if src.Kind == "ct_log" {
		return d.executeCTLogDiscoveryRun(ctx, tenantID, src, run)
	}
	if src.Kind == "drift" {
		return d.executeDriftDiscoveryRun(ctx, tenantID, src, run)
	}
	if src.Kind == nhi.SourceKind {
		return d.executeNHICrossSurfaceDiscoveryRun(ctx, tenantID, src, run)
	}
	if src.Kind == oauthgrant.SourceKind {
		return d.executeOAuthGrantDiscoveryRun(ctx, tenantID, src, run)
	}
	if src.Kind == serviceaccount.SourceKind {
		return d.executeServiceAccountDiscoveryRun(ctx, tenantID, src, run)
	}
	if src.Kind == nhibehavior.SourceKind {
		return d.executeNHIBehaviorDiscoveryRun(ctx, tenantID, src, run)
	}
	if src.Kind == apikey.SourceKind && apikey.UsesObservationConfig(src.Config) {
		return d.executeAPIKeyTokenDiscoveryRun(ctx, tenantID, src, run)
	}
	if src.Kind == compromise.SourceKind {
		return d.executeCompromisedCredentialDiscoveryRun(ctx, tenantID, src, run)
	}
	if src.Kind == k8stls.SourceKind {
		return d.executeKubernetesTLSAutoIssuanceRun(ctx, tenantID, src, run)
	}
	if src.Kind == secretscan.RepositorySourceKind {
		return d.executeSecretRepositoryDiscoveryRun(ctx, tenantID, src, run)
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

func (d *issuanceDispatcher) executeNetworkDiscoveryRun(ctx context.Context, tenantID string, src store.DiscoverySource, run projections.DiscoveryRunQueued) (netscan.Report, string, string, error) {
	plan, err := networkDiscoveryPlanFromConfig(src.Config)
	if err != nil {
		return netscan.Report{}, "failed", err.Error(), nil
	}
	if run.DryRun {
		return netscan.Report{Targets: len(plan.targets)}, "succeeded", "", nil
	}
	sink := discoveryRunSink{orch: d.orch, tenantID: tenantID, runID: run.ID, sourceID: src.ID}
	scanner := netscan.New(sink,
		netscan.WithWorkers(8),
		netscan.WithQueue(128),
		netscan.WithBackoff(10*time.Millisecond),
		netscan.WithAllowRFC1918Targets(plan.allowRFC1918),
		netscan.WithAllowLoopbackTargets(plan.allowLoopback),
		netscan.WithBlockedTargetHook(d.blockedNetworkTargetHook(tenantID, run.ID, src.ID)),
	)
	defer scanner.Close()
	rep := scanner.Scan(ctx, plan.targets)
	status := "succeeded"
	msg := ""
	if rep.Failed > 0 || rep.Rejected > 0 || rep.Blocked > 0 {
		if rep.Discovered > 0 {
			status = "partial"
			msg = "some discovery probes failed or were blocked"
		} else {
			status = "failed"
			msg = "all discovery probes failed or were blocked"
		}
	}
	return rep, status, msg, nil
}

func (d *issuanceDispatcher) blockedNetworkTargetHook(tenantID, runID, sourceID string) netscan.BlockedTargetHook {
	return func(ctx context.Context, target netscan.BlockedTarget) {
		if d.log == nil {
			return
		}
		payload, err := json.Marshal(struct {
			RunID    string `json:"run_id"`
			SourceID string `json:"source_id"`
			Target   string `json:"target"`
			Reason   string `json:"reason"`
		}{RunID: runID, SourceID: sourceID, Target: target.Address, Reason: target.Reason})
		if err != nil {
			return
		}
		if _, err := d.log.Append(ctx, events.Event{Type: "discovery.network_target_blocked", TenantID: tenantID, Data: payload}); err != nil {
			return
		}
	}
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
		return netscan.Report{}, "failed", "cloud_secret discovery requires at least one provider", nil
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
	for _, domain := range domains {
		if err := d.store.AddWatchedDomain(ctx, tenantID, domain); err != nil {
			return netscan.Report{}, "", "", err
		}
	}
	for _, logURL := range logs {
		if err := d.store.RegisterCTLog(ctx, tenantID, logURL); err != nil {
			return netscan.Report{}, "", "", err
		}
	}
	sched := ctmonitor.NewScheduler(
		ctmonitor.NewStorePersistence(d.store),
		ctmonitor.NewHTTPFetcherWithClient(client),
		ctmonitor.NewStoreKnownGood(d.store),
		ctmonitor.NewStoreAlerter(d.store, d.outbox),
		ctmonitor.WithMaxBatch(maxBatch),
		ctmonitor.WithMonitorOptions(ctmonitor.WithWorkers(4), ctmonitor.WithQueue(64), ctmonitor.WithBackoff(10*time.Millisecond)),
	)
	findings, err := sched.RunOnce(ctx, tenantID)
	if err != nil {
		return netscan.Report{Targets: len(logs), Failed: 1}, "failed", err.Error(), nil
	}
	if err := d.recordCTLogFindings(ctx, tenantID, src.ID, run.ID, findings); err != nil {
		return netscan.Report{}, "", "", err
	}
	return netscan.Report{Targets: len(logs), Discovered: len(findings)}, "succeeded", "", nil
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
		client = http.DefaultClient
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
		client, err := cloudHTTPClient(endpoint, p.AllowPrivateEndpoint)
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
			client, err = cloudHTTPClient(endpoint, p.AllowPrivateEndpoint)
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
		client, err := cloudHTTPClient(endpoint, p.AllowPrivateEndpoint)
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
		client, err := cloudHTTPClient(vaultURL, p.AllowPrivateEndpoint)
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
			client, err = cloudHTTPClient(endpoint, p.AllowPrivateEndpoint)
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

func cloudHTTPClient(endpoint string, allowPrivate bool) (*http.Client, error) {
	if strings.TrimSpace(endpoint) == "" {
		return nil, errors.New("cloud provider endpoint is required")
	}
	if allowPrivate {
		return http.DefaultClient, nil
	}
	if err := netsec.ValidatePublicHTTPSURL(endpoint); err != nil {
		return nil, err
	}
	return netsec.SafeClient(30 * time.Second), nil
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

func networkDiscoveryPlanFromConfig(raw json.RawMessage) (networkDiscoveryPlan, error) {
	var cfg networkDiscoveryConfig
	if err := json.Unmarshal(raw, &cfg); err != nil {
		return networkDiscoveryPlan{}, fmt.Errorf("decode network discovery config: %w", err)
	}
	targets := make([]string, 0, len(cfg.Targets))
	for _, target := range cfg.Targets {
		target = strings.TrimSpace(target)
		if target == "" {
			continue
		}
		if _, _, err := net.SplitHostPort(target); err != nil {
			return networkDiscoveryPlan{}, fmt.Errorf("network discovery target %q must be host:port", target)
		}
		targets = append(targets, target)
	}
	cidrs := append([]string(nil), cfg.CIDRs...)
	if cfg.CIDR != "" {
		cidrs = append(cidrs, cfg.CIDR)
	}
	for _, cidr := range cidrs {
		expanded, err := netscan.ExpandRange(cidr, cfg.Ports)
		if err != nil {
			return networkDiscoveryPlan{}, err
		}
		targets = append(targets, expanded...)
	}
	if len(targets) == 0 {
		return networkDiscoveryPlan{}, errors.New("network discovery source requires targets or cidrs+ports")
	}
	if len(targets) > maxServedDiscoveryTargets {
		return networkDiscoveryPlan{}, fmt.Errorf("network discovery source has %d targets; maximum is %d", len(targets), maxServedDiscoveryTargets)
	}
	return networkDiscoveryPlan{targets: targets, allowRFC1918: cfg.AllowRFC1918, allowLoopback: cfg.AllowLoopback}, nil
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

func discoveryRunTerminal(status string) bool {
	return status == "succeeded" || status == "partial" || status == "failed"
}

type discoveryRunSink struct {
	orch     *orchestrator.Orchestrator
	tenantID string
	runID    string
	sourceID string
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

func (s discoveryRunSink) Record(ctx context.Context, f netscan.Found) error {
	meta, err := json.Marshal(map[string]any{
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
	if _, err := s.orch.RecordCertificate(ctx, s.tenantID, store.Certificate{
		Subject: f.Cert.Subject, SANs: sansOf(f.Cert), Issuer: f.Cert.Issuer,
		Serial: f.Cert.SerialNumber, Fingerprint: f.Cert.SHA256Fingerprint,
		KeyAlgorithm: f.Cert.KeyAlgorithm, NotBefore: &nb, NotAfter: &na,
		DeploymentLocation: f.Address, Source: "discovery:network",
	}); err != nil {
		return err
	}
	_, err = s.orch.RecordDiscoveryFinding(ctx, s.tenantID, store.DiscoveryFinding{
		RunID: s.runID, SourceID: s.sourceID, Kind: "x509_certificate", Ref: f.Address,
		Provenance: "network:" + f.Address, Fingerprint: f.Cert.SHA256Fingerprint,
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
