// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"

	"trstctl.com/trstctl/internal/crypto/secret"
	"trstctl.com/trstctl/internal/orchestrator"
	"trstctl.com/trstctl/internal/secrettext"
)

// serviceNowResolved is ServiceNow's incident state Resolved; Closed is 7.
const serviceNowResolved = "6"

// handleServiceNowClose resolves the ServiceNow incidents that carry a closed
// trstctl incident's correlation (P13). It reads them first and leaves alone
// any already resolved or closed with this closure's notes, so a replayed
// delivery changes nothing in ServiceNow.
func (d *issuanceDispatcher) handleServiceNowClose(ctx context.Context, m orchestrator.Message) error {
	var p orchestrator.ServiceNowCloseRequest
	if err := json.Unmarshal(m.Payload, &p); err != nil {
		return orchestrator.DefiniteNoEffect(fmt.Errorf("server: decode ServiceNow close payload: %w", err))
	}
	if p.IncidentID == "" || p.CorrelationID != orchestrator.IncidentCorrelationID(p.IncidentID) || p.CloseNotes == "" {
		return orchestrator.DefiniteNoEffect(errors.New("server: the ServiceNow close names no incident correlation"))
	}
	table, ok := orchestrator.NormalizeServiceNowTable(p.Table)
	if !ok {
		return orchestrator.DefiniteNoEffect(fmt.Errorf("server: unsupported ServiceNow table %q", p.Table))
	}
	endpoint, err := serviceNowTableEndpoint(p.InstanceURL, table)
	if err != nil {
		return orchestrator.DefiniteNoEffect(err)
	}
	client, err := cloudHTTPClient(endpoint, p.AllowPrivateEndpoint, p.PrivateEgressCIDRs)
	if err != nil {
		return orchestrator.DefiniteNoEffect(fmt.Errorf("server: ServiceNow endpoint rejected: %w", err))
	}
	token, err := resolveDiscoveryCredentialRef(ctx, p.TokenRef)
	if err != nil {
		return orchestrator.DefiniteNoEffect(fmt.Errorf("server: resolve ServiceNow token ref: %w", err))
	}
	tokenBytes := []byte(token)
	defer secret.Wipe(tokenBytes)
	call := func(method, target string, body []byte) ([]byte, error) {
		req, err := http.NewRequestWithContext(ctx, method, target, bytes.NewReader(body))
		if err != nil {
			return nil, err
		}
		req.Header.Set("Authorization", secrettext.Prefixed("Bearer ", tokenBytes))
		req.Header.Set("Accept", "application/json")
		if body != nil {
			req.Header.Set("Content-Type", "application/json")
		}
		req.Header.Set("X-Trstctl-Idempotency-Key", m.IdempotencyKey)
		resp, err := client.Do(req)
		if err != nil {
			return nil, err
		}
		defer func() { _ = resp.Body.Close() }()
		raw, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
		if resp.StatusCode < 200 || resp.StatusCode > 299 {
			return nil, fmt.Errorf("status %d", resp.StatusCode)
		}
		return raw, nil
	}
	q := url.Values{}
	q.Set("sysparm_query", "correlation_id="+p.CorrelationID)
	q.Set("sysparm_fields", "sys_id,state,close_notes")
	q.Set("sysparm_limit", "20")
	raw, err := call(http.MethodGet, endpoint+"?"+q.Encode(), nil)
	if err != nil {
		return fmt.Errorf("server: read the ServiceNow incidents of %s: %w", p.CorrelationID, err)
	}
	var found struct {
		Result []struct {
			SysID      string `json:"sys_id"`
			State      string `json:"state"`
			CloseNotes string `json:"close_notes"`
		} `json:"result"`
	}
	if err := json.Unmarshal(raw, &found); err != nil {
		return fmt.Errorf("server: parse the ServiceNow incidents of %s: %w", p.CorrelationID, err)
	}
	if len(found.Result) == 0 {
		// The response dispatch's ticket may still be on its way; retry.
		return fmt.Errorf("server: no ServiceNow %s carries correlation %s yet", table, p.CorrelationID)
	}
	update, err := json.Marshal(map[string]string{"state": serviceNowResolved, "close_code": "Solved (Permanently)", "close_notes": p.CloseNotes})
	if err != nil {
		return orchestrator.DefiniteNoEffect(err)
	}
	for _, record := range found.Result {
		if (record.State == serviceNowResolved || record.State == "7") && record.CloseNotes == p.CloseNotes {
			continue
		}
		if record.SysID == "" || strings.ContainsAny(record.SysID, "/?#") {
			return fmt.Errorf("server: ServiceNow returned an unusable sys_id")
		}
		if _, err := call(http.MethodPatch, endpoint+"/"+url.PathEscape(record.SysID), update); err != nil {
			return fmt.Errorf("server: resolve ServiceNow %s %s: %w", table, record.SysID, err)
		}
	}
	return nil
}
