// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"unicode"

	"trstctl.com/trstctl/internal/auditsink"
	"trstctl.com/trstctl/internal/crypto/secret"
	"trstctl.com/trstctl/internal/orchestrator"
	"trstctl.com/trstctl/internal/secrettext"
)

func (d *issuanceDispatcher) handleAuditFeedBatch(ctx context.Context, message orchestrator.Message) error {
	if d.orch == nil {
		return fmt.Errorf("server: audit feed orchestrator is unavailable")
	}
	var batch auditsink.FeedBatch
	if err := json.Unmarshal(message.Payload, &batch); err != nil {
		return fmt.Errorf("server: decode audit feed batch: %w", err)
	}
	wantDestination, ok := orchestrator.AuditFeedDestination(batch.Provider)
	if !ok || wantDestination != message.Destination || batch.BatchID == "" ||
		batch.DestinationID == "" || batch.EndpointURL == "" || batch.TokenRef == "" ||
		len(batch.Records) == 0 || batch.StartSequence != batch.Records[0].Sequence ||
		batch.EndSequence != batch.Records[len(batch.Records)-1].Sequence || batch.ChainHead == "" {
		return fmt.Errorf("server: audit feed batch authority is incomplete or mismatched")
	}
	client, err := cloudHTTPClient(batch.EndpointURL, batch.AllowPrivateEndpoint, batch.PrivateEgressCIDRs)
	if err != nil {
		return fmt.Errorf("server: audit feed endpoint rejected: %w", err)
	}
	tokenBytes, err := resolveDiscoveryCredentialBytesRef(ctx, batch.TokenRef)
	if err != nil {
		return fmt.Errorf("server: resolve audit feed credential reference: %w", err)
	}
	defer secret.Wipe(tokenBytes)
	var body bytes.Buffer
	if err := auditsink.WriteCollectorBatch(&body, batch); err != nil {
		return fmt.Errorf("server: encode audit feed batch: %w", err)
	}
	payload := body.Bytes()
	defer secret.Wipe(payload)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, batch.EndpointURL, bytes.NewReader(payload))
	if err != nil {
		return fmt.Errorf("server: build audit feed request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Trstctl-Idempotency-Key", message.IdempotencyKey)
	req.Header.Set("Idempotency-Key", message.IdempotencyKey)
	switch batch.Provider {
	case auditsink.ProviderSplunkHEC:
		req.Header.Set("Authorization", secrettext.Prefixed("Splunk ", tokenBytes))
		req.Header.Set("X-Splunk-Request-Channel", batch.BatchID)
	case auditsink.ProviderSentinel:
		req.Header.Set("Authorization", secrettext.Prefixed("Bearer ", tokenBytes))
		req.Header.Set("x-ms-client-request-id", batch.BatchID)
	}
	response, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("server: audit feed collector request failed: %w", err)
	}
	defer func() { _ = response.Body.Close() }()
	if response.StatusCode < 200 || response.StatusCode > 299 {
		// Do not copy collector response bodies into the durable outbox error:
		// upstreams routinely echo tokens, request fragments, or tenant data.
		return fmt.Errorf("server: audit feed collector returned HTTP status %d", response.StatusCode)
	}
	requestID := boundedCollectorRequestID(
		response.Header.Get("X-Collector-Request-ID"),
		response.Header.Get("X-Splunk-Request-Channel"),
		response.Header.Get("x-ms-request-id"),
	)
	if err := d.orch.RecordAuditFeedDelivered(ctx, message.TenantID, batch, message.IdempotencyKey, requestID); err != nil {
		return fmt.Errorf("server: record audit feed delivery receipt: %w", err)
	}
	return nil
}

func (d *issuanceDispatcher) failAuditFeedBatchTerminal(ctx context.Context, message orchestrator.Message, cause error) error {
	if d.orch == nil {
		return fmt.Errorf("server: audit feed orchestrator is unavailable")
	}
	var batch auditsink.FeedBatch
	if err := json.Unmarshal(message.Payload, &batch); err != nil {
		return fmt.Errorf("server: decode terminal audit feed batch: %w", err)
	}
	return d.orch.RecordAuditFeedFailed(
		ctx, message.TenantID, batch, message.IdempotencyKey, auditFeedFailureCode(cause),
	)
}

func auditFeedFailureCode(err error) string {
	if err == nil {
		return "retry_exhausted"
	}
	text := strings.ToLower(err.Error())
	switch {
	case strings.Contains(text, "credential reference"):
		return "credential_unavailable"
	case strings.Contains(text, "endpoint rejected"):
		return "endpoint_refused"
	case strings.Contains(text, "http status"):
		return "collector_http_error"
	case strings.Contains(text, "deadline") || strings.Contains(text, "timeout"):
		return "collector_timeout"
	default:
		return "collector_transport_error"
	}
}

func boundedCollectorRequestID(values ...string) string {
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value == "" {
			continue
		}
		var out strings.Builder
		for _, r := range value {
			if out.Len() >= 128 {
				break
			}
			if unicode.IsLetter(r) || unicode.IsDigit(r) || strings.ContainsRune("-_.:/", r) {
				out.WriteRune(r)
			}
		}
		return out.String()
	}
	return ""
}
