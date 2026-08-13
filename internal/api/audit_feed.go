// SPDX-License-Identifier: MPL-2.0

package api

import (
	"context"
	"net/http"
	"net/url"
	"strings"
	"time"

	googleuuid "github.com/google/uuid"

	"trstctl.com/trstctl/internal/auditsink"
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

//trstctl:mutation
func (a *API) putAuditFeed(w http.ResponseWriter, r *http.Request) {
	idempotencyKey := r.Header.Get("Idempotency-Key")
	a.mutate(w, r, idempotencyKey, func(ctx context.Context, tenantID string) (int, any, error) {
		id := strings.TrimSpace(r.PathValue("id"))
		if parsed, err := googleuuid.Parse(id); err != nil || parsed == googleuuid.Nil {
			return 0, nil, errStatus(http.StatusBadRequest, "audit feed id must be a non-zero UUID")
		}
		var body auditFeedRequest
		if err := decodeJSON(r, &body); err != nil {
			return 0, nil, errWithStatus(http.StatusBadRequest, err)
		}
		name := strings.TrimSpace(body.Name)
		if name == "" {
			return 0, nil, errStatus(http.StatusBadRequest, "name is required")
		}
		provider, ok := auditsink.NormalizeProvider(body.Provider)
		if !ok {
			return 0, nil, errStatus(http.StatusBadRequest, "provider must be splunk-hec or sentinel")
		}
		endpoint := strings.TrimSpace(body.EndpointURL)
		if err := validateAuditFeedEndpoint(endpoint, body.AllowPrivateEndpoint); err != nil {
			return 0, nil, err
		}
		tokenRef := strings.TrimSpace(body.TokenRef)
		if !strings.HasPrefix(tokenRef, "env:") {
			return 0, nil, errStatus(http.StatusBadRequest, "token_ref must be an operator-approved env:NAME credential reference")
		}
		if err := a.requireOutboundEnvCredentialRefAllowed(tokenRef, "token_ref"); err != nil {
			return 0, nil, err
		}
		if body.IntervalSeconds < minAuditFeedInterval {
			return 0, nil, errStatus(http.StatusBadRequest, "interval_seconds must be at least 60")
		}
		if body.BatchSize < 1 || body.BatchSize > maxAuditFeedBatch {
			return 0, nil, errStatus(http.StatusBadRequest, "batch_size must be between 1 and 500")
		}
		cidrs := cleanAPIStringList(body.PrivateEgressCIDRs)
		if body.AllowPrivateEndpoint {
			if err := a.requirePrivateEgressPermission(ctx, tenantID); err != nil {
				return 0, nil, err
			}
			if len(cidrs) == 0 {
				return 0, nil, errStatus(http.StatusBadRequest, "private_egress_cidrs is required when allow_private_endpoint is true")
			}
			if err := validatePrivateEgressCIDRs(cidrs); err != nil {
				return 0, nil, err
			}
		} else if len(cidrs) != 0 {
			return 0, nil, errStatus(http.StatusBadRequest, "private_egress_cidrs requires allow_private_endpoint")
		}
		feed, err := a.orch.ConfigureAuditFeed(ctx, tenantID, projections.AuditFeedDestinationConfigured{
			ID: id, Name: name, Provider: provider, EndpointURL: endpoint, TokenRef: tokenRef,
			IntervalSeconds: body.IntervalSeconds, BatchSize: body.BatchSize, Enabled: body.Enabled,
			AllowPrivateEndpoint: body.AllowPrivateEndpoint, PrivateEgressCIDRs: cidrs,
		})
		if err != nil {
			return 0, nil, err
		}
		return http.StatusOK, auditFeedFromStore(feed), nil
	})
}

func validateAuditFeedEndpoint(endpoint string, allowPrivate bool) error {
	parsed, err := url.ParseRequestURI(strings.TrimSpace(endpoint))
	if err != nil || parsed.Host == "" || (parsed.Scheme != "http" && parsed.Scheme != "https") {
		return errStatus(http.StatusBadRequest, "endpoint_url must be an absolute HTTP(S) URL")
	}
	if parsed.User != nil {
		return errStatus(http.StatusBadRequest, "endpoint_url must not contain credentials; use token_ref")
	}
	if !allowPrivate && parsed.Scheme != "https" {
		return errStatus(http.StatusBadRequest, "public endpoint_url must use HTTPS")
	}
	return nil
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
