package server

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"

	"trstctl.com/trstctl/internal/crypto/secret"
	"trstctl.com/trstctl/internal/orchestrator"
	"trstctl.com/trstctl/internal/secrettext"
)

func (d *issuanceDispatcher) handleSplunkResponseIntegration(ctx context.Context, m orchestrator.Message) error {
	var p orchestrator.ResponseIntegrationPayload
	if err := json.Unmarshal(m.Payload, &p); err != nil {
		return fmt.Errorf("server: decode Splunk response integration payload: %w", err)
	}
	if strings.TrimSpace(p.EndpointURL) == "" {
		return fmt.Errorf("server: Splunk endpoint_url is required")
	}
	client, err := cloudHTTPClient(p.EndpointURL, p.AllowPrivateEndpoint, p.PrivateEgressCIDRs)
	if err != nil {
		return fmt.Errorf("server: Splunk endpoint rejected: %w", err)
	}
	token, err := resolveDiscoveryCredentialRef(ctx, p.TokenRef)
	if err != nil {
		return fmt.Errorf("server: resolve Splunk token ref: %w", err)
	}
	tokenBytes := []byte(token)
	defer secret.Wipe(tokenBytes)
	body := map[string]any{
		"source":     "trstctl",
		"sourcetype": "trstctl:response",
		"event":      responseIntegrationEvent(m.TenantID, p),
	}
	payload, err := json.Marshal(body)
	if err != nil {
		return err
	}
	defer secret.Wipe(payload)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, p.EndpointURL, bytes.NewReader(payload))
	if err != nil {
		return fmt.Errorf("server: build Splunk response integration request: %w", err)
	}
	req.Header.Set("Authorization", secrettext.Prefixed("Splunk ", tokenBytes))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Idempotency-Key", m.IdempotencyKey)
	req.Header.Set("X-Trstctl-Idempotency-Key", m.IdempotencyKey)
	if p.CorrelationID != "" {
		req.Header.Set("X-Trstctl-Correlation-ID", p.CorrelationID)
	}
	return doResponseIntegrationRequest(client, req, "Splunk response integration")
}

func (d *issuanceDispatcher) handleJiraResponseIntegration(ctx context.Context, m orchestrator.Message) error {
	var p orchestrator.ResponseIntegrationPayload
	if err := json.Unmarshal(m.Payload, &p); err != nil {
		return fmt.Errorf("server: decode Jira response integration payload: %w", err)
	}
	endpoint, err := jiraIssueEndpoint(p.EndpointURL)
	if err != nil {
		return err
	}
	client, err := cloudHTTPClient(endpoint, p.AllowPrivateEndpoint, p.PrivateEgressCIDRs)
	if err != nil {
		return fmt.Errorf("server: Jira endpoint rejected: %w", err)
	}
	token, err := resolveDiscoveryCredentialRef(ctx, p.TokenRef)
	if err != nil {
		return fmt.Errorf("server: resolve Jira token ref: %w", err)
	}
	tokenBytes := []byte(token)
	defer secret.Wipe(tokenBytes)
	issueType := strings.TrimSpace(p.IssueType)
	if issueType == "" {
		issueType = "Task"
	}
	body := map[string]any{
		"fields": map[string]any{
			"project":   map[string]string{"key": strings.TrimSpace(p.ProjectKey)},
			"issuetype": map[string]string{"name": issueType},
			"summary":   strings.TrimSpace(p.Title),
			"description": map[string]any{
				"type":    "doc",
				"version": 1,
				"content": []map[string]any{{
					"type": "paragraph",
					"content": []map[string]string{{
						"type": "text",
						"text": responseIntegrationDescription(m.TenantID, p),
					}},
				}},
			},
		},
	}
	payload, err := json.Marshal(body)
	if err != nil {
		return err
	}
	defer secret.Wipe(payload)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(payload))
	if err != nil {
		return fmt.Errorf("server: build Jira response integration request: %w", err)
	}
	req.Header.Set("Authorization", secrettext.Prefixed("Bearer ", tokenBytes))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Idempotency-Key", m.IdempotencyKey)
	req.Header.Set("X-Trstctl-Idempotency-Key", m.IdempotencyKey)
	if p.CorrelationID != "" {
		req.Header.Set("X-Trstctl-Correlation-ID", p.CorrelationID)
	}
	return doResponseIntegrationRequest(client, req, "Jira response integration")
}

func responseIntegrationEvent(tenantID string, p orchestrator.ResponseIntegrationPayload) map[string]any {
	return map[string]any{
		"kind":               "trstctl.response.integration",
		"tenant_id":          tenantID,
		"dispatch_id":        p.DispatchID,
		"title":              p.Title,
		"summary":            p.Summary,
		"severity":           p.Severity,
		"correlation_id":     p.CorrelationID,
		"incident_id":        p.IncidentID,
		"remediation_run_id": p.RemediationRunID,
		"evidence_refs":      p.EvidenceRefs,
	}
}

func responseIntegrationDescription(tenantID string, p orchestrator.ResponseIntegrationPayload) string {
	parts := []string{
		strings.TrimSpace(p.Summary),
		"tenant_id=" + tenantID,
		"dispatch_id=" + strings.TrimSpace(p.DispatchID),
	}
	if p.IncidentID != "" {
		parts = append(parts, "incident_id="+p.IncidentID)
	}
	if p.RemediationRunID != "" {
		parts = append(parts, "remediation_run_id="+p.RemediationRunID)
	}
	if p.CorrelationID != "" {
		parts = append(parts, "correlation_id="+p.CorrelationID)
	}
	if len(p.EvidenceRefs) > 0 {
		parts = append(parts, "evidence_refs="+strings.Join(p.EvidenceRefs, ","))
	}
	return strings.Join(parts, "\n")
}

func jiraIssueEndpoint(baseURL string) (string, error) {
	base, err := url.Parse(strings.TrimSpace(baseURL))
	if err != nil {
		return "", fmt.Errorf("server: parse Jira endpoint URL: %w", err)
	}
	if base.Scheme == "" || base.Host == "" {
		return "", fmt.Errorf("server: Jira endpoint URL must be absolute")
	}
	if !strings.HasSuffix(strings.TrimRight(base.Path, "/"), "/rest/api/3/issue") {
		base.Path = strings.TrimRight(base.Path, "/") + "/rest/api/3/issue"
	}
	base.RawQuery = ""
	base.Fragment = ""
	return base.String(), nil
}

func doResponseIntegrationRequest(client *http.Client, req *http.Request, label string) error {
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("server: deliver %s: %w", label, err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		limited, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return fmt.Errorf("server: %s failed with status %d: %s", label, resp.StatusCode, strings.TrimSpace(string(limited)))
	}
	return nil
}
