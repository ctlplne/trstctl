// SPDX-License-Identifier: BUSL-1.1

package api

import (
	"context"
	"encoding/json"
	"net/http"
	"net/url"
	"strings"
	"time"

	googleuuid "github.com/google/uuid"

	"trstctl.com/trstctl/internal/auditsink"
	"trstctl.com/trstctl/internal/authz"
	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/projections"
	"trstctl.com/trstctl/internal/store"
)

const (
	minAuditFeedInterval = 60
	maxAuditFeedBatch    = 500
)

type auditFeedRequest struct {
	Name                 string   `json:"name"`
	Provider             string   `json:"provider"`
	EndpointURL          string   `json:"endpoint_url"`
	TokenRef             string   `json:"token_ref"`
	IntervalSeconds      int      `json:"interval_seconds"`
	BatchSize            int      `json:"batch_size"`
	Enabled              bool     `json:"enabled"`
	AllowPrivateEndpoint bool     `json:"allow_private_endpoint,omitempty"`
	PrivateEgressCIDRs   []string `json:"private_egress_cidrs,omitempty"`
}

type auditFeedResponse struct {
	ID                     string   `json:"id"`
	TenantID               string   `json:"tenant_id"`
	Name                   string   `json:"name"`
	Provider               string   `json:"provider"`
	EndpointURL            string   `json:"endpoint_url"`
	TokenRef               string   `json:"token_ref"`
	IntervalSeconds        int      `json:"interval_seconds"`
	BatchSize              int      `json:"batch_size"`
	Enabled                bool     `json:"enabled"`
	AllowPrivateEndpoint   bool     `json:"allow_private_endpoint"`
	PrivateEgressCIDRs     []string `json:"private_egress_cidrs"`
	Status                 string   `json:"status"`
	LastBatchID            string   `json:"last_batch_id,omitempty"`
	LastBatchStartSequence uint64   `json:"last_batch_start_sequence"`
	LastQueuedSequence     uint64   `json:"last_queued_sequence"`
	LastDeliveredSequence  uint64   `json:"last_delivered_sequence"`
	LastBatchRecordCount   int      `json:"last_batch_record_count"`
	LagRecords             int      `json:"lag_records"`
	Attempts               int      `json:"attempts"`
	LastErrorCode          string   `json:"last_error_code,omitempty"`
	CollectorRequestID     string   `json:"collector_request_id,omitempty"`
	NextRunAt              string   `json:"next_run_at"`
	NextAttemptAt          string   `json:"next_attempt_at,omitempty"`
	LastAttemptAt          string   `json:"last_attempt_at,omitempty"`
	LastDeliveredAt        string   `json:"last_delivered_at,omitempty"`
	UpdatedAt              string   `json:"updated_at"`
}

type auditFeedListResponse struct {
	Items []auditFeedResponse `json:"items"`
	Count int                 `json:"count"`
}

type auditFeedPreviewResponse struct {
	Capability             string           `json:"capability"`
	Ready                  bool             `json:"ready"`
	EffectFree             bool             `json:"effect_free"`
	FeedID                 string           `json:"feed_id"`
	EndpointHost           string           `json:"endpoint_host"`
	ExistingConfiguration  bool             `json:"existing_configuration"`
	CurrentUpdatedAt       string           `json:"current_updated_at,omitempty"`
	RequestFingerprint     string           `json:"request_fingerprint"`
	RequiredPermission     string           `json:"required_permission"`
	NormalizedRequest      auditFeedRequest `json:"normalized_request"`
	Prerequisites          []string         `json:"prerequisites"`
	PreviewWrites          []string         `json:"preview_writes"`
	PreviewExternalEffects []string         `json:"preview_external_effects"`
	ExecutionWrites        []string         `json:"execution_writes"`
	ExecutionEffects       []string         `json:"execution_external_effects"`
	VerificationSteps      []string         `json:"verification_steps"`
	RecoverySteps          []string         `json:"recovery_steps"`
	Warnings               []string         `json:"warnings"`
	Guidance               string           `json:"guidance"`
}

type normalizedAuditFeedConfiguration struct {
	ID           string
	Request      auditFeedRequest
	Destination  projections.AuditFeedDestinationConfigured
	EndpointHost string
}

// previewAuditFeed is a POST-shaped read because the proposed destination is a
// structured body. It shares the execution validator, but writes no event,
// projection, idempotency record, or outbox intent and contacts no collector.
func (a *API) previewAuditFeed(w http.ResponseWriter, r *http.Request) {
	tenantID, ok := a.tenant(r)
	if !ok {
		a.writeProblem(w, problemUnauthorized())
		return
	}
	var body auditFeedRequest
	if err := decodeJSON(r, &body); err != nil {
		a.writeError(w, errWithStatus(http.StatusBadRequest, err))
		return
	}
	configuration, err := a.normalizeAuditFeedConfiguration(r.Context(), tenantID, r.PathValue("id"), body)
	if err != nil {
		a.writeError(w, err)
		return
	}
	existing, found, err := a.store.GetAuditFeed(r.Context(), tenantID, configuration.ID)
	if err != nil {
		a.writeError(w, err)
		return
	}
	fingerprintBody, err := json.Marshal(struct {
		Domain   string           `json:"domain"`
		TenantID string           `json:"tenant_id"`
		FeedID   string           `json:"feed_id"`
		Request  auditFeedRequest `json:"request"`
	}{
		Domain: "trstctl.api.audit-feed-preview.v1", TenantID: tenantID,
		FeedID: configuration.ID, Request: configuration.Request,
	})
	if err != nil {
		a.writeError(w, err)
		return
	}
	plan := auditFeedPreviewResponse{
		Capability: "audit_feed_configuration", Ready: true, EffectFree: true,
		FeedID: configuration.ID, EndpointHost: configuration.EndpointHost,
		ExistingConfiguration: found,
		RequestFingerprint:    crypto.SHA256Hex(fingerprintBody),
		RequiredPermission:    string(authz.AuditWrite),
		NormalizedRequest:     configuration.Request,
		Prerequisites: []string{
			"The credential reference is operator-allowlisted; credential bytes are neither read nor returned by preview.",
			"The destination URL and private-egress boundary satisfy the same server policy used by execution.",
			"Execution requires audit:write and one Idempotency-Key.",
		},
		PreviewWrites: []string{}, PreviewExternalEffects: []string{},
		ExecutionWrites: []string{
			"Append one tenant-scoped audit_feed_destination.configured event.",
			"Project the durable collector instruction and its next schedule time.",
		},
		ExecutionEffects: []string{},
		VerificationSteps: []string{
			"Read GET /api/v1/audit/feeds and confirm the exact destination, credential reference, interval, batch bound, and enabled state.",
			"When delivery begins, follow last_delivered_sequence and collector_request_id; configured is not the same as delivered.",
		},
		RecoverySteps: []string{
			"A failed batch retries with the same durable batch and idempotency key without advancing the delivered cursor.",
			"Disable the feed to stop scheduling new batches while preserving delivery and failure evidence.",
		},
		Warnings: []string{},
		Guidance: "This preview performed no write and made no network call. Saving revalidates the same destination, credential-reference, permission, tenant, and egress boundaries.",
	}
	if found {
		plan.CurrentUpdatedAt = existing.UpdatedAt.UTC().Format(time.RFC3339)
	}
	if configuration.Request.Enabled {
		plan.ExecutionEffects = append(plan.ExecutionEffects,
			"After the schedule becomes due, a bounded outbox worker may deliver exact audit batches to "+configuration.EndpointHost+".")
	} else {
		plan.Warnings = append(plan.Warnings, "The feed will be saved disabled, so no new batch is scheduled until it is enabled in a later reviewed configuration.")
	}
	a.writeJSON(w, http.StatusOK, plan)
}

//trstctl:mutation
func (a *API) putAuditFeed(w http.ResponseWriter, r *http.Request) {
	idempotencyKey := r.Header.Get("Idempotency-Key")
	a.mutate(w, r, idempotencyKey, func(ctx context.Context, tenantID string) (int, any, error) {
		var body auditFeedRequest
		if err := decodeJSON(r, &body); err != nil {
			return 0, nil, errWithStatus(http.StatusBadRequest, err)
		}
		configuration, err := a.normalizeAuditFeedConfiguration(ctx, tenantID, r.PathValue("id"), body)
		if err != nil {
			return 0, nil, err
		}
		feed, err := a.orch.ConfigureAuditFeed(ctx, tenantID, configuration.Destination)
		if err != nil {
			return 0, nil, err
		}
		return http.StatusOK, auditFeedFromStore(feed), nil
	})
}

// normalizeAuditFeedConfiguration is the one security decision shared by
// preview and execution. It returns public configuration only; token_ref remains
// a locator and credential bytes are never resolved on this path.
func (a *API) normalizeAuditFeedConfiguration(ctx context.Context, tenantID, rawID string, body auditFeedRequest) (normalizedAuditFeedConfiguration, error) {
	id := strings.TrimSpace(rawID)
	if parsed, err := googleuuid.Parse(id); err != nil || parsed == googleuuid.Nil {
		return normalizedAuditFeedConfiguration{}, errStatus(http.StatusBadRequest, "audit feed id must be a non-zero UUID")
	}
	name := strings.TrimSpace(body.Name)
	if name == "" {
		return normalizedAuditFeedConfiguration{}, errStatus(http.StatusBadRequest, "name is required")
	}
	provider, ok := auditsink.NormalizeProvider(body.Provider)
	if !ok {
		return normalizedAuditFeedConfiguration{}, errStatus(http.StatusBadRequest, "provider must be splunk-hec or sentinel")
	}
	endpoint := strings.TrimSpace(body.EndpointURL)
	parsedEndpoint, err := validatedAuditFeedEndpoint(endpoint, body.AllowPrivateEndpoint)
	if err != nil {
		return normalizedAuditFeedConfiguration{}, err
	}
	tokenRef := strings.TrimSpace(body.TokenRef)
	if !strings.HasPrefix(tokenRef, "env:") {
		return normalizedAuditFeedConfiguration{}, errStatus(http.StatusBadRequest, "token_ref must be an operator-approved env:NAME credential reference")
	}
	if err := a.requireOutboundEnvCredentialRefAllowed(tokenRef, "token_ref"); err != nil {
		return normalizedAuditFeedConfiguration{}, err
	}
	if body.IntervalSeconds < minAuditFeedInterval {
		return normalizedAuditFeedConfiguration{}, errStatus(http.StatusBadRequest, "interval_seconds must be at least 60")
	}
	if body.BatchSize < 1 || body.BatchSize > maxAuditFeedBatch {
		return normalizedAuditFeedConfiguration{}, errStatus(http.StatusBadRequest, "batch_size must be between 1 and 500")
	}
	cidrs := cleanAPIStringList(body.PrivateEgressCIDRs)
	if body.AllowPrivateEndpoint {
		if err := a.requirePrivateEgressPermission(ctx, tenantID); err != nil {
			return normalizedAuditFeedConfiguration{}, err
		}
		if len(cidrs) == 0 {
			return normalizedAuditFeedConfiguration{}, errStatus(http.StatusBadRequest, "private_egress_cidrs is required when allow_private_endpoint is true")
		}
		if err := validatePrivateEgressCIDRs(cidrs); err != nil {
			return normalizedAuditFeedConfiguration{}, err
		}
	} else if len(cidrs) != 0 {
		return normalizedAuditFeedConfiguration{}, errStatus(http.StatusBadRequest, "private_egress_cidrs requires allow_private_endpoint")
	}
	normalized := auditFeedRequest{
		Name: name, Provider: provider, EndpointURL: endpoint, TokenRef: tokenRef,
		IntervalSeconds: body.IntervalSeconds, BatchSize: body.BatchSize, Enabled: body.Enabled,
		AllowPrivateEndpoint: body.AllowPrivateEndpoint, PrivateEgressCIDRs: cidrs,
	}
	return normalizedAuditFeedConfiguration{
		ID: id, Request: normalized, EndpointHost: parsedEndpoint.Hostname(),
		Destination: projections.AuditFeedDestinationConfigured{
			ID: id, Name: name, Provider: provider, EndpointURL: endpoint, TokenRef: tokenRef,
			IntervalSeconds: body.IntervalSeconds, BatchSize: body.BatchSize, Enabled: body.Enabled,
			AllowPrivateEndpoint: body.AllowPrivateEndpoint, PrivateEgressCIDRs: cidrs,
		},
	}, nil
}

func validatedAuditFeedEndpoint(endpoint string, allowPrivate bool) (*url.URL, error) {
	parsed, err := url.ParseRequestURI(strings.TrimSpace(endpoint))
	if err != nil || parsed.Host == "" || (parsed.Scheme != "http" && parsed.Scheme != "https") {
		return nil, errStatus(http.StatusBadRequest, "endpoint_url must be an absolute HTTP(S) URL")
	}
	if parsed.User != nil {
		return nil, errStatus(http.StatusBadRequest, "endpoint_url must not contain credentials; use token_ref")
	}
	if !allowPrivate && parsed.Scheme != "https" {
		return nil, errStatus(http.StatusBadRequest, "public endpoint_url must use HTTPS")
	}
	return parsed, nil
}

func (a *API) listAuditFeeds(w http.ResponseWriter, r *http.Request) {
	tenantID, ok := a.tenant(r)
	if !ok {
		a.writeProblem(w, problemUnauthorized())
		return
	}
	feeds, err := a.store.ListAuditFeeds(r.Context(), tenantID)
	if err != nil {
		a.writeError(w, err)
		return
	}
	items := make([]auditFeedResponse, 0, len(feeds))
	for _, feed := range feeds {
		items = append(items, auditFeedFromStore(feed))
	}
	a.writeJSON(w, http.StatusOK, auditFeedListResponse{Items: items, Count: len(items)})
}

func auditFeedFromStore(feed store.AuditFeed) auditFeedResponse {
	errorCode := feed.LastErrorCode
	if feed.EffectiveStatus() == "retrying" && errorCode == "" {
		errorCode = "collector_retry_scheduled"
	}
	out := auditFeedResponse{
		ID: feed.ID, TenantID: feed.TenantID, Name: feed.Name, Provider: feed.Provider,
		EndpointURL: feed.EndpointURL, TokenRef: feed.TokenRef,
		IntervalSeconds: feed.IntervalSeconds, BatchSize: feed.BatchSize, Enabled: feed.Enabled,
		AllowPrivateEndpoint: feed.AllowPrivateEndpoint,
		PrivateEgressCIDRs:   append([]string(nil), feed.PrivateEgressCIDRs...),
		Status:               feed.EffectiveStatus(), LastBatchID: feed.LastBatchID,
		LastBatchStartSequence: feed.LastBatchStartSequence,
		LastQueuedSequence:     feed.LastQueuedSequence, LastDeliveredSequence: feed.LastDeliveredSequence,
		LastBatchRecordCount: feed.LastBatchRecordCount, LagRecords: feed.LagRecords,
		Attempts: feed.OutboxAttempts, LastErrorCode: errorCode,
		CollectorRequestID: feed.LastCollectorRequestID,
		NextRunAt:          feed.NextRunAt.UTC().Format(time.RFC3339),
		UpdatedAt:          feed.UpdatedAt.UTC().Format(time.RFC3339),
	}
	if feed.OutboxNextAttemptAt != nil {
		out.NextAttemptAt = feed.OutboxNextAttemptAt.UTC().Format(time.RFC3339)
	}
	if feed.LastAttemptAt != nil {
		out.LastAttemptAt = feed.LastAttemptAt.UTC().Format(time.RFC3339)
	}
	if feed.LastDeliveredAt != nil {
		out.LastDeliveredAt = feed.LastDeliveredAt.UTC().Format(time.RFC3339)
	}
	return out
}
