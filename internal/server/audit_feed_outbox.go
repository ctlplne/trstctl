// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"unicode"

	"trstctl.com/trstctl/internal/audit"
	"trstctl.com/trstctl/internal/auditsink"
	"trstctl.com/trstctl/internal/crypto/secret"
	"trstctl.com/trstctl/internal/orchestrator"
	"trstctl.com/trstctl/internal/secrettext"
)

// authorizeAuditFeedRequest sets the collector's credential header. A provider
// it does not name is refused before anything is sent: posting the batch
// without credentials would fail at the collector, or reach one that accepts
// anonymous writes.
func authorizeAuditFeedRequest(req *http.Request, provider, scheme, batchID string, token []byte) error {
	if scheme != "" && provider != auditsink.ProviderElastic {
		return orchestrator.DefiniteNoEffect(fmt.Errorf("server: audit feed provider %q has no %q credential scheme", provider, scheme))
	}
	switch provider {
	case auditsink.ProviderSplunkHEC:
		req.Header.Set("Authorization", secrettext.Prefixed("Splunk ", token))
		req.Header.Set("X-Splunk-Request-Channel", batchID)
	case auditsink.ProviderSentinel:
		req.Header.Set("Authorization", secrettext.Prefixed("Bearer ", token))
		req.Header.Set("x-ms-client-request-id", batchID)
	case auditsink.ProviderElastic:
		// P5-L4: an Elasticsearch feed presents its credential as an API key
		// (the default), with basic auth (the reference holds user:password)
		// or as a bearer token.
		switch scheme {
		case "":
			req.Header.Set("Authorization", secrettext.Prefixed("ApiKey ", token))
		case "basic":
			if bytes.IndexByte(token, ':') < 1 {
				return orchestrator.DefiniteNoEffect(fmt.Errorf("server: a basic-auth audit feed credential must be user:password"))
			}
			encoded := make([]byte, base64.StdEncoding.EncodedLen(len(token)))
			base64.StdEncoding.Encode(encoded, token)
			req.Header.Set("Authorization", secrettext.Prefixed("Basic ", encoded))
			secret.Wipe(encoded)
		case "bearer":
			req.Header.Set("Authorization", secrettext.Prefixed("Bearer ", token))
		default:
			return orchestrator.DefiniteNoEffect(fmt.Errorf("server: audit feed credential scheme %q is not api_key, basic or bearer", scheme))
		}
	default:
		return orchestrator.DefiniteNoEffect(fmt.Errorf("server: audit feed provider %q has no credential scheme", provider))
	}
	return nil
}

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
		batch.DestinationID == "" || batch.EndpointURL == "" || (batch.TokenRef == "" && batch.Provider != auditsink.ProviderSyslog) ||
		len(batch.Records) == 0 || batch.StartSequence != batch.Records[0].Sequence ||
		batch.EndSequence != batch.Records[len(batch.Records)-1].Sequence || batch.ChainHead == "" {
		// Retrying cannot repair the batch's own authority; nothing was sent.
		return orchestrator.DefiniteNoEffect(fmt.Errorf("server: audit feed batch authority is incomplete or mismatched"))
	}
	if d.audit == nil {
		return fmt.Errorf("server: collector source reader is unavailable")
	}
	head, err := audit.VerifyChainFrom(batch.PrevHash, batch.Records)
	if err != nil || head != batch.ChainHead {
		return fmt.Errorf("server: collector commitment changed")
	}
	readable, err := d.audit.CollectorDetails(ctx, message.TenantID, batch.Records)
	if err != nil {
		return fmt.Errorf("server: collector source unavailable: %w", err)
	}
	if batch.Provider == auditsink.ProviderSyslog {
		var framed bytes.Buffer
		if err := auditsink.WriteCollectorBatchWithReadable(&framed, batch, readable); err != nil {
			return fmt.Errorf("server: encode audit feed batch: %w", err)
		}
		defer secret.Wipe(framed.Bytes())
		requestID, err := deliverSyslogBatch(ctx, batch, framed.Bytes())
		if err != nil {
			return err
		}
		if err := d.orch.RecordAuditFeedDelivered(ctx, message.TenantID, batch, message.IdempotencyKey, requestID); err != nil {
			return fmt.Errorf("server: record audit feed delivery receipt: %w", err)
		}
		return nil
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
	if err := auditsink.WriteCollectorBatchWithReadable(&body, batch, readable); err != nil {
		return fmt.Errorf("server: encode audit feed batch: %w", err)
	}
	payload := body.Bytes()
	defer secret.Wipe(payload)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, batch.EndpointURL, bytes.NewReader(payload))
	if err != nil {
		return fmt.Errorf("server: build audit feed request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	if batch.Provider == auditsink.ProviderElastic {
		req.Header.Set("Content-Type", "application/x-ndjson")
	}
	req.Header.Set("X-Trstctl-Idempotency-Key", message.IdempotencyKey)
	req.Header.Set("Idempotency-Key", message.IdempotencyKey)
	if err := authorizeAuditFeedRequest(req, batch.Provider, batch.AuthScheme, batch.BatchID, tokenBytes); err != nil {
		return err
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
	if batch.Provider == auditsink.ProviderElastic {
		// A bulk request answers 200 even when items failed; every item must
		// be created or already present (a redelivery) before the batch counts.
		raw, err := io.ReadAll(io.LimitReader(response.Body, 8<<20))
		if err != nil {
			return fmt.Errorf("server: audit feed collector request failed: %w", err)
		}
		failed, status, err := auditsink.ElasticBulkResult(raw)
		secret.Wipe(raw)
		if err != nil {
			return fmt.Errorf("server: audit feed collector returned an unreadable bulk response")
		}
		if failed > 0 {
			return fmt.Errorf("server: audit feed collector refused %d bulk items (first HTTP status %d)", failed, status)
		}
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
	case strings.Contains(text, "collector source") || strings.Contains(text, "collector commitment"):
		return "collector_source_unavailable"
	case strings.Contains(text, "credential reference"):
		return "credential_unavailable"
	case strings.Contains(text, "endpoint rejected"):
		return "endpoint_refused"
	case strings.Contains(text, "bulk items"):
		return "collector_rejected_records"
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
