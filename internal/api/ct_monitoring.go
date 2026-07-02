package api

import (
	"context"
	"encoding/json"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"

	googleuuid "github.com/google/uuid"

	"trstctl.com/trstctl/internal/discovery"
	"trstctl.com/trstctl/internal/store"
)

const defaultCTMonitoringName = "Certificate Transparency monitor"

type ctMonitoringRequest struct {
	SourceID             string   `json:"source_id,omitempty"`
	Name                 string   `json:"name,omitempty"`
	Logs                 []string `json:"logs"`
	WatchedDomains       []string `json:"watched_domains"`
	MaxBatch             int      `json:"max_batch,omitempty"`
	RunNow               bool     `json:"run_now,omitempty"`
	DryRun               bool     `json:"dry_run,omitempty"`
	AllowPrivateEndpoint bool     `json:"allow_private_endpoint,omitempty"`
	PrivateEgressCIDRs   []string `json:"private_egress_cidrs,omitempty"`
}

type ctMonitoringSourceConfig struct {
	Logs                 []string `json:"logs"`
	WatchedDomains       []string `json:"watched_domains"`
	MaxBatch             int      `json:"max_batch,omitempty"`
	AllowPrivateEndpoint bool     `json:"allow_private_endpoint,omitempty"`
	PrivateEgressCIDRs   []string `json:"private_egress_cidrs,omitempty"`
}

type ctMonitoringResponse struct {
	Capability              string                     `json:"capability"`
	WatchlistPath           string                     `json:"watchlist_path"`
	SourcesPath             string                     `json:"sources_path"`
	RunsPath                string                     `json:"runs_path"`
	FindingsPath            string                     `json:"findings_path"`
	NotificationDestination string                     `json:"notification_destination"`
	OutboxBackedAlerts      bool                       `json:"outbox_backed_alerts"`
	WatchedDomains          []string                   `json:"watched_domains"`
	Logs                    []ctMonitoringLogResponse  `json:"logs"`
	Summary                 ctMonitoringSummary        `json:"summary"`
	Source                  *discoverySourceResponse   `json:"source,omitempty"`
	Run                     *discoveryRunResponse      `json:"run,omitempty"`
	Findings                []discoveryFindingResponse `json:"findings"`
}

type ctMonitoringLogResponse struct {
	URL       string `json:"url"`
	NextIndex int64  `json:"next_index"`
}

type ctMonitoringSummary struct {
	SourceCount             int `json:"source_count"`
	WatchedDomainCount      int `json:"watched_domain_count"`
	LogCount                int `json:"log_count"`
	FindingCount            int `json:"finding_count"`
	UnexpectedIssuanceCount int `json:"unexpected_issuance_count"`
	OpenFindingCount        int `json:"open_finding_count"`
	OutboxAlertChannelCount int `json:"outbox_alert_channel_count"`
}

func (a *API) getCTMonitoring(w http.ResponseWriter, r *http.Request) {
	tenantID, ok := a.tenant(r)
	if !ok {
		a.writeProblem(w, problemUnauthorized())
		return
	}
	out, err := a.ctMonitoringStatus(r.Context(), tenantID, nil, nil)
	if err != nil {
		a.writeError(w, err)
		return
	}
	a.writeJSON(w, http.StatusOK, out)
}

//trstctl:mutation
func (a *API) updateCTMonitoring(w http.ResponseWriter, r *http.Request) {
	idempotencyKey := r.Header.Get("Idempotency-Key")
	a.mutate(w, r, idempotencyKey, func(ctx context.Context, tenantID string) (int, any, error) {
		var req ctMonitoringRequest
		if err := decodeJSON(r, &req); err != nil {
			return 0, nil, errWithStatus(http.StatusBadRequest, err)
		}
		cfg, err := ctMonitoringConfigFromRequest(req)
		if err != nil {
			return 0, nil, err
		}
		cfgJSON, err := json.Marshal(cfg)
		if err != nil {
			return 0, nil, err
		}
		if err := a.requireDiscoveryCredentialRefsAllowed(cfgJSON); err != nil {
			return 0, nil, err
		}
		privateEgress, err := discoveryPrivateEgressRequested(cfgJSON)
		if err != nil {
			return 0, nil, err
		}
		if privateEgress {
			if err := a.requirePrivateEgressPermission(ctx, tenantID); err != nil {
				return 0, nil, err
			}
		}

		name := strings.TrimSpace(req.Name)
		if name == "" {
			name = defaultCTMonitoringName
		}
		sourceID, err := a.ctMonitoringSourceID(ctx, tenantID, strings.TrimSpace(req.SourceID), name)
		if err != nil {
			return 0, nil, err
		}
		start := time.Now()
		source, err := a.orch.UpsertDiscoverySource(ctx, tenantID, store.DiscoverySource{
			ID: sourceID, Kind: "ct_log", Name: name, Config: cfgJSON,
		})
		a.observeFeature("discovery", "ct_monitoring_update", start, err)
		if err != nil {
			return 0, nil, err
		}

		var run *store.DiscoveryRun
		if req.RunNow {
			start = time.Now()
			queued, err := a.orch.QueueDiscoveryRun(ctx, tenantID, store.DiscoveryRun{
				SourceID: source.ID, DryRun: req.DryRun,
			})
			a.observeFeature("discovery", "ct_monitoring_run", start, err)
			if err != nil {
				return 0, nil, err
			}
			run = &queued
		}
		out, err := a.ctMonitoringStatus(ctx, tenantID, &source, run)
		if err != nil {
			return 0, nil, err
		}
		return http.StatusOK, out, nil
	})
}

func ctMonitoringConfigFromRequest(req ctMonitoringRequest) (ctMonitoringSourceConfig, error) {
	logs, err := cleanCTLogURLs(req.Logs)
	if err != nil {
		return ctMonitoringSourceConfig{}, err
	}
	if len(logs) == 0 {
		return ctMonitoringSourceConfig{}, errStatus(http.StatusBadRequest, "logs must include at least one CT log URL")
	}
	domains, err := cleanCTWatchedDomains(req.WatchedDomains)
	if err != nil {
		return ctMonitoringSourceConfig{}, err
	}
	if len(domains) == 0 {
		return ctMonitoringSourceConfig{}, errStatus(http.StatusBadRequest, "watched_domains must include at least one domain")
	}
	if req.MaxBatch < 0 {
		return ctMonitoringSourceConfig{}, errStatus(http.StatusBadRequest, "max_batch must be non-negative")
	}
	cfg := ctMonitoringSourceConfig{
		Logs:                 logs,
		WatchedDomains:       domains,
		MaxBatch:             req.MaxBatch,
		AllowPrivateEndpoint: req.AllowPrivateEndpoint,
		PrivateEgressCIDRs:   cleanStringSet(req.PrivateEgressCIDRs),
	}
	return cfg, nil
}

func cleanCTLogURLs(in []string) ([]string, error) {
	out := make([]string, 0, len(in))
	seen := map[string]struct{}{}
	for _, raw := range in {
		raw = strings.TrimSpace(raw)
		if raw == "" {
			continue
		}
		u, err := url.Parse(raw)
		if err != nil || u.Scheme == "" || u.Host == "" {
			return nil, errStatus(http.StatusBadRequest, "logs must contain absolute http(s) URLs")
		}
		if u.Scheme != "https" && u.Scheme != "http" {
			return nil, errStatus(http.StatusBadRequest, "logs must use http or https")
		}
		if u.User != nil {
			return nil, errStatus(http.StatusBadRequest, "logs must not contain credentials")
		}
		u.Fragment = ""
		normalized := u.String()
		if _, ok := seen[normalized]; ok {
			continue
		}
		seen[normalized] = struct{}{}
		out = append(out, normalized)
	}
	sort.Strings(out)
	return out, nil
}

func cleanCTWatchedDomains(in []string) ([]string, error) {
	out := make([]string, 0, len(in))
	seen := map[string]struct{}{}
	for _, raw := range in {
		domain := strings.ToLower(strings.Trim(strings.TrimSpace(raw), "."))
		if domain == "" {
			continue
		}
		if strings.ContainsAny(domain, "/:@ \t\r\n") || strings.HasPrefix(domain, "*.") {
			return nil, errStatus(http.StatusBadRequest, "watched_domains must contain DNS domain names, not URLs or wildcards")
		}
		if !strings.Contains(domain, ".") {
			return nil, errStatus(http.StatusBadRequest, "watched_domains must include a registrable domain")
		}
		if _, ok := seen[domain]; ok {
			continue
		}
		seen[domain] = struct{}{}
		out = append(out, domain)
	}
	sort.Strings(out)
	return out, nil
}

func cleanStringSet(in []string) []string {
	out := make([]string, 0, len(in))
	seen := map[string]struct{}{}
	for _, raw := range in {
		raw = strings.TrimSpace(raw)
		if raw == "" {
			continue
		}
		if _, ok := seen[raw]; ok {
			continue
		}
		seen[raw] = struct{}{}
		out = append(out, raw)
	}
	sort.Strings(out)
	return out
}

func (a *API) ctMonitoringSourceID(ctx context.Context, tenantID, requestedID, name string) (string, error) {
	if requestedID != "" {
		if _, err := googleuuid.Parse(requestedID); err != nil {
			return "", errStatus(http.StatusBadRequest, "source_id must be a UUID")
		}
		src, err := a.store.GetDiscoverySource(ctx, tenantID, requestedID)
		if err != nil {
			return "", err
		}
		if src.Kind != "ct_log" {
			return "", errStatus(http.StatusConflict, "source_id is not a ct_log discovery source")
		}
		return requestedID, nil
	}
	sources, err := a.store.ListDiscoverySourcesPage(ctx, tenantID, store.ZeroUUID, 100)
	if err != nil {
		return "", err
	}
	for _, src := range sources {
		if src.Kind == "ct_log" && src.Name == name {
			return src.ID, nil
		}
	}
	return "", nil
}

func (a *API) ctMonitoringStatus(ctx context.Context, tenantID string, primary *store.DiscoverySource, queued *store.DiscoveryRun) (ctMonitoringResponse, error) {
	out := ctMonitoringResponse{
		Capability:              "F17",
		WatchlistPath:           "/api/v1/discovery/ct-monitoring",
		SourcesPath:             "/api/v1/discovery/sources",
		RunsPath:                "/api/v1/discovery/runs",
		FindingsPath:            "/api/v1/discovery/findings",
		NotificationDestination: "notification.unexpected_issuance",
		OutboxBackedAlerts:      true,
		Summary: ctMonitoringSummary{
			OutboxAlertChannelCount: len(a.notificationChannels),
		},
	}

	sources, err := a.store.ListDiscoverySourcesPage(ctx, tenantID, store.ZeroUUID, 100)
	if err != nil {
		return out, err
	}
	sourceByID := map[string]store.DiscoverySource{}
	for _, src := range sources {
		if src.Kind != "ct_log" {
			continue
		}
		sourceByID[src.ID] = src
		out.Summary.SourceCount++
		if out.Source == nil {
			resp := toDiscoverySourceResponse(src)
			out.Source = &resp
		}
		addCTConfigToStatus(&out, src.Config)
	}
	if primary != nil {
		resp := toDiscoverySourceResponse(*primary)
		out.Source = &resp
		sourceByID[primary.ID] = *primary
		if _, ok := sourceByID[primary.ID]; !ok {
			out.Summary.SourceCount++
		}
		addCTConfigToStatus(&out, primary.Config)
	}
	if queued != nil {
		resp := toDiscoveryRunResponse(*queued)
		out.Run = &resp
	}

	if domains, err := a.store.ListWatchedDomains(ctx, tenantID); err == nil {
		for _, domain := range domains {
			addString(&out.WatchedDomains, domain)
		}
	} else {
		return out, err
	}
	if checkpoints, err := a.store.ListCTLogCheckpoints(ctx, tenantID); err == nil {
		for _, checkpoint := range checkpoints {
			addCTLog(&out.Logs, checkpoint.LogURL, checkpoint.NextIndex)
		}
	} else {
		return out, err
	}

	findings, err := a.store.ListDiscoveryFindingsPage(ctx, tenantID, "", store.ZeroUUID, 100)
	if err != nil {
		return out, err
	}
	for _, f := range findings {
		if _, ok := sourceByID[f.SourceID]; !ok && !strings.Contains(strings.ToLower(f.Provenance), "ct") {
			continue
		}
		resp := toDiscoveryFindingResponse(f)
		out.Findings = append(out.Findings, resp)
		out.Summary.FindingCount++
		if f.Kind == "ct_unexpected_issuance" {
			out.Summary.UnexpectedIssuanceCount++
		}
		if f.TriageStatus == "" || f.TriageStatus == string(discovery.TriageUnmanaged) {
			out.Summary.OpenFindingCount++
		}
	}
	sort.Strings(out.WatchedDomains)
	sort.Slice(out.Logs, func(i, j int) bool { return out.Logs[i].URL < out.Logs[j].URL })
	out.Summary.WatchedDomainCount = len(out.WatchedDomains)
	out.Summary.LogCount = len(out.Logs)
	return out, nil
}

func addCTConfigToStatus(out *ctMonitoringResponse, raw json.RawMessage) {
	var cfg ctMonitoringSourceConfig
	if err := json.Unmarshal(raw, &cfg); err != nil {
		return
	}
	for _, domain := range cfg.WatchedDomains {
		addString(&out.WatchedDomains, domain)
	}
	for _, logURL := range cfg.Logs {
		addCTLog(&out.Logs, logURL, 0)
	}
}

func addString(values *[]string, value string) {
	value = strings.TrimSpace(value)
	if value == "" {
		return
	}
	for _, existing := range *values {
		if existing == value {
			return
		}
	}
	*values = append(*values, value)
}

func addCTLog(logs *[]ctMonitoringLogResponse, logURL string, nextIndex int64) {
	logURL = strings.TrimSpace(logURL)
	if logURL == "" {
		return
	}
	for i := range *logs {
		if (*logs)[i].URL == logURL {
			if nextIndex > (*logs)[i].NextIndex {
				(*logs)[i].NextIndex = nextIndex
			}
			return
		}
	}
	*logs = append(*logs, ctMonitoringLogResponse{URL: logURL, NextIndex: nextIndex})
}
