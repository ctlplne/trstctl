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

func (d *issuanceDispatcher) handleServiceNowTicket(ctx context.Context, m orchestrator.Message) error {
	var p orchestrator.ServiceNowTicketRequest
	if err := json.Unmarshal(m.Payload, &p); err != nil {
		return fmt.Errorf("server: decode ServiceNow ticket payload: %w", err)
	}
	table, ok := orchestrator.NormalizeServiceNowTable(p.Table)
	if !ok {
		return fmt.Errorf("server: unsupported ServiceNow table %q", p.Table)
	}
	endpoint, err := serviceNowTableEndpoint(p.InstanceURL, table)
	if err != nil {
		return err
	}
	client, err := cloudHTTPClient(endpoint, p.AllowPrivateEndpoint)
	if err != nil {
		return fmt.Errorf("server: ServiceNow endpoint rejected: %w", err)
	}
	token, err := resolveDiscoveryCredentialRef(ctx, p.TokenRef)
	if err != nil {
		return fmt.Errorf("server: resolve ServiceNow token ref: %w", err)
	}
	tokenBytes := []byte(token)
	defer secret.Wipe(tokenBytes)

	body := map[string]string{
		"short_description": strings.TrimSpace(p.ShortDescription),
		"description":       strings.TrimSpace(p.Description),
		"category":          strings.TrimSpace(p.Category),
		"urgency":           strings.TrimSpace(p.Urgency),
		"impact":            strings.TrimSpace(p.Impact),
		"correlation_id":    strings.TrimSpace(p.CorrelationID),
		"u_trstctl_ticket":  strings.TrimSpace(p.ID),
		"u_trstctl_tenant":  m.TenantID,
	}
	for key, value := range body {
		if value == "" {
			delete(body, key)
		}
	}
	payload, err := json.Marshal(body)
	if err != nil {
		return err
	}
	defer secret.Wipe(payload)

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(payload))
	if err != nil {
		return fmt.Errorf("server: build ServiceNow request: %w", err)
	}
	req.Header.Set("Authorization", secrettext.Prefixed("Bearer ", tokenBytes))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Idempotency-Key", m.IdempotencyKey)
	req.Header.Set("X-Trstctl-Idempotency-Key", m.IdempotencyKey)
	if p.CorrelationID != "" {
		req.Header.Set("X-Trstctl-Correlation-ID", p.CorrelationID)
	}

	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("server: deliver ServiceNow ticket: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		limited, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return fmt.Errorf("server: ServiceNow ticket request failed with status %d: %s", resp.StatusCode, strings.TrimSpace(string(limited)))
	}
	return nil
}

func serviceNowTableEndpoint(instanceURL, table string) (string, error) {
	base, err := url.Parse(strings.TrimSpace(instanceURL))
	if err != nil {
		return "", fmt.Errorf("server: parse ServiceNow instance URL: %w", err)
	}
	if base.Scheme == "" || base.Host == "" {
		return "", fmt.Errorf("server: ServiceNow instance URL must be absolute")
	}
	base.Path = strings.TrimRight(base.Path, "/") + "/api/now/table/" + table
	base.RawQuery = ""
	base.Fragment = ""
	return base.String(), nil
}
