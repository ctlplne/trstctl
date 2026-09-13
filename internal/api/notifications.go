// SPDX-License-Identifier: MPL-2.0

package api

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"

	guuid "github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/crypto/secret"
	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/notify"
	"trstctl.com/trstctl/internal/orchestrator"
	"trstctl.com/trstctl/internal/projections"
	"trstctl.com/trstctl/internal/store"
)

type notificationResponse struct {
	ID                     string                  `json:"id"`
	TenantID               string                  `json:"tenant_id"`
	Destination            string                  `json:"destination"`
	Kind                   string                  `json:"kind,omitempty"`
	IdentityID             string                  `json:"identity_id,omitempty"`
	OperationID            string                  `json:"operation_id,omitempty"`
	CertificateFingerprint string                  `json:"certificate_fingerprint,omitempty"`
	DeploymentReceiptID    string                  `json:"deployment_receipt_id,omitempty"`
	DeploymentRecordedAt   *time.Time              `json:"deployment_recorded_at,omitempty"`
	CertificateID          string                  `json:"certificate_id,omitempty"`
	Subject                string                  `json:"subject,omitempty"`
	Serial                 string                  `json:"serial,omitempty"`
	NotAfter               *time.Time              `json:"not_after,omitempty"`
	Detail                 string                  `json:"detail,omitempty"`
	Severity               string                  `json:"severity,omitempty"`
	RoutingPolicyID        string                  `json:"routing_policy_id,omitempty"`
	ThresholdDays          *int                    `json:"threshold_days,omitempty"`
	OwnerID                string                  `json:"owner_id,omitempty"`
	OwnerName              string                  `json:"owner_name,omitempty"`
	OwnerEmail             string                  `json:"owner_email,omitempty"`
	EscalationRecipients   []notify.AlertRecipient `json:"escalation_recipients,omitempty"`
	Status                 string                  `json:"status"`
	Attempts               int                     `json:"attempts"`
	LastError              string                  `json:"last_error,omitempty"`
	IdempotencyKey         string                  `json:"idempotency_key,omitempty"`
	CreatedAt              time.Time               `json:"created_at"`
	DeliveredAt            *time.Time              `json:"delivered_at,omitempty"`
	ReadAt                 *time.Time              `json:"read_at,omitempty"`
}

type notificationChannelResponse struct {
	ID                 string `json:"id"`
	ChannelType        string `json:"channel_type,omitempty"`
	Label              string `json:"label"`
	Category           string `json:"category"`
	Configured         bool   `json:"configured"`
	Enabled            bool   `json:"enabled"`
	Delivery           string `json:"delivery"`
	Description        string `json:"description"`
	Source             string `json:"source,omitempty"`
	EndpointConfigured bool   `json:"endpoint_configured,omitempty"`
	CredentialRef      string `json:"credential_ref,omitempty"`
	SecretHandling     string `json:"secret_handling,omitempty"`
}

type notificationChannelList struct {
	Items []notificationChannelResponse `json:"items"`
}

type notificationChannelRequest struct {
	ID            string `json:"id,omitempty"`
	ChannelType   string `json:"channel_type,omitempty"`
	Label         string `json:"label,omitempty"`
	EndpointURL   string `json:"endpoint_url,omitempty"`
	CredentialRef string `json:"credential_ref,omitempty"`
	Enabled       *bool  `json:"enabled,omitempty"`
}

type notificationRoutingPolicyRequest struct {
	ID                 string              `json:"id,omitempty"`
	Name               string              `json:"name"`
	ScopeKind          string              `json:"scope_kind,omitempty"`
	ScopeRef           string              `json:"scope_ref,omitempty"`
	ChannelsBySeverity map[string][]string `json:"channels_by_severity"`
	DefaultChannels    []string            `json:"default_channels"`
	OwnerRef           string              `json:"owner_ref,omitempty"`
	OwnerEmail         string              `json:"owner_email,omitempty"`
	DigestInterval     int                 `json:"digest_interval_seconds,omitempty"`
	DigestTimezone     string              `json:"digest_timezone,omitempty"`
}

type notificationRoutingPolicyResponse struct {
	ID                 string                            `json:"id"`
	TenantID           string                            `json:"tenant_id"`
	Name               string                            `json:"name"`
	ScopeKind          string                            `json:"scope_kind"`
	ScopeRef           string                            `json:"scope_ref,omitempty"`
	ChannelsBySeverity map[string][]string               `json:"channels_by_severity"`
	DefaultChannels    []string                          `json:"default_channels"`
	OwnerRef           string                            `json:"owner_ref,omitempty"`
	OwnerEmail         string                            `json:"owner_email,omitempty"`
	DigestInterval     int                               `json:"digest_interval_seconds"`
	DigestTimezone     string                            `json:"digest_timezone"`
	DigestPreview      notificationDigestPreviewResponse `json:"digest_preview"`
	CreatedAt          time.Time                         `json:"created_at"`
	UpdatedAt          time.Time                         `json:"updated_at"`
}

type notificationRoutingPreviewResponse struct {
	ResolutionOrder []string                           `json:"resolution_order"`
	Matched         *notificationRoutingPolicyResponse `json:"matched_policy,omitempty"`
	Effective       []string                           `json:"effective_channels"`
	Missing         []string                           `json:"missing_channels"`
	DeliveryReady   bool                               `json:"delivery_ready"`
	Explanation     string                             `json:"explanation"`
}

type notificationRoutingPolicyPreviewResponse struct {
	Capability             string              `json:"capability"`
	Operation              string              `json:"operation"`
	Ready                  bool                `json:"ready"`
	EffectFree             bool                `json:"effect_free"`
	RequestFingerprint     string              `json:"request_fingerprint"`
	Name                   string              `json:"name"`
	ScopeKind              string              `json:"scope_kind"`
	ScopeRef               string              `json:"scope_ref,omitempty"`
	ChannelsBySeverity     map[string][]string `json:"channels_by_severity"`
	DefaultChannels        []string            `json:"default_channels"`
	OwnerRef               string              `json:"owner_ref,omitempty"`
	OwnerEmail             string              `json:"owner_email,omitempty"`
	DigestInterval         int                 `json:"digest_interval_seconds"`
	DigestTimezone         string              `json:"digest_timezone"`
	ConfiguredChannels     []string            `json:"configured_channels"`
	MissingChannels        []string            `json:"missing_channels"`
	Blockers               []string            `json:"blockers"`
	PreviewWrites          []string            `json:"preview_writes"`
	PreviewExternalEffects []string            `json:"preview_external_effects"`
	ExecuteWrites          []string            `json:"execute_writes"`
	ExecuteExternalEffects []string            `json:"execute_external_effects"`
	RecoverySteps          []string            `json:"recovery_steps"`
	VerificationSteps      []string            `json:"verification_steps"`
	SecretDataHandling     string              `json:"secret_data_handling"`
}

type notificationDigestPreviewResponse struct {
	IntervalSeconds int       `json:"interval_seconds"`
	Timezone        string    `json:"timezone"`
	NextRunAt       time.Time `json:"next_run_at"`
}

type notificationChannelTestRequest struct {
	Subject         string `json:"subject,omitempty"`
	Severity        string `json:"severity,omitempty"`
	Detail          string `json:"detail,omitempty"`
	RoutingPolicyID string `json:"routing_policy_id,omitempty"`
	CredentialRef   string `json:"credential_ref,omitempty"`
	OwnerEmail      string `json:"owner_email,omitempty"`
}

type notificationChannelTestResponse struct {
	ChannelID      string    `json:"channel_id"`
	Destination    string    `json:"destination"`
	OutboxID       int64     `json:"outbox_id"`
	Status         string    `json:"status"`
	CredentialRef  string    `json:"credential_ref,omitempty"`
	SecretHandling string    `json:"secret_handling"`
	IdempotencyKey string    `json:"idempotency_key"`
	QueuedAt       time.Time `json:"queued_at"`
}

func (a *API) listNotificationChannels(w http.ResponseWriter, r *http.Request) {
	tenantID, ok := a.tenant(r)
	if !ok {
		a.writeProblem(w, problemUnauthorized())
		return
	}
	items, err := a.notificationChannelsForTenant(r.Context(), tenantID)
	if err != nil {
		a.writeError(w, err)
		return
	}
	a.writeJSON(w, http.StatusOK, notificationChannelList{Items: items})
}

func (a *API) getNotificationChannel(w http.ResponseWriter, r *http.Request) {
	tenantID, ok := a.tenant(r)
	if !ok {
		a.writeProblem(w, problemUnauthorized())
		return
	}
	id := canonicalNotificationChannelID(r.PathValue("id"))
	if id == "" {
		a.writeError(w, errStatus(http.StatusBadRequest, "notification channel id is required"))
		return
	}
	if a.store != nil {
		row, err := a.store.GetNotificationChannel(r.Context(), tenantID, id)
		if err == nil {
			a.writeJSON(w, http.StatusOK, toNotificationChannelResponse(row))
			return
		}
		if !store.IsNotFound(err) {
			a.writeError(w, err)
			return
		}
	}
	for _, channel := range notificationChannelCatalog(a.notificationChannels) {
		if channel.ID == id {
			a.writeJSON(w, http.StatusOK, channel)
			return
		}
	}
	a.writeError(w, errStatus(http.StatusNotFound, "notification channel not found"))
}

//trstctl:mutation
func (a *API) createNotificationChannel(w http.ResponseWriter, r *http.Request) {
	idempotencyKey := r.Header.Get("Idempotency-Key")
	a.mutate(w, r, idempotencyKey, func(ctx context.Context, tenantID string) (int, any, error) {
		channel, err := a.decodeNotificationChannelRequest(r, tenantID, "")
		if err != nil {
			return 0, nil, err
		}
		created, err := a.appendNotificationChannelUpsert(ctx, tenantID, channel)
		if err != nil {
			return 0, nil, err
		}
		return http.StatusCreated, toNotificationChannelResponse(created), nil
	})
}

//trstctl:mutation
func (a *API) updateNotificationChannel(w http.ResponseWriter, r *http.Request) {
	idempotencyKey := r.Header.Get("Idempotency-Key")
	pathID := canonicalNotificationChannelID(r.PathValue("id"))
	if pathID == "" {
		a.writeError(w, errStatus(http.StatusBadRequest, "notification channel id is required"))
		return
	}
	a.mutate(w, r, idempotencyKey, func(ctx context.Context, tenantID string) (int, any, error) {
		if a.store == nil {
			return 0, nil, errStatus(http.StatusServiceUnavailable, "notification channel store is not configured")
		}
		if _, err := a.store.GetNotificationChannel(ctx, tenantID, pathID); err != nil {
			return 0, nil, err
		}
		channel, err := a.decodeNotificationChannelRequest(r, tenantID, pathID)
		if err != nil {
			return 0, nil, err
		}
		updated, err := a.appendNotificationChannelUpsert(ctx, tenantID, channel)
		if err != nil {
			return 0, nil, err
		}
		return http.StatusOK, toNotificationChannelResponse(updated), nil
	})
}

//trstctl:mutation
func (a *API) deleteNotificationChannel(w http.ResponseWriter, r *http.Request) {
	idempotencyKey := r.Header.Get("Idempotency-Key")
	id := canonicalNotificationChannelID(r.PathValue("id"))
	if id == "" {
		a.writeError(w, errStatus(http.StatusBadRequest, "notification channel id is required"))
		return
	}
	a.mutate(w, r, idempotencyKey, func(ctx context.Context, tenantID string) (int, any, error) {
		if a.store == nil || a.log == nil {
			return 0, nil, errStatus(http.StatusServiceUnavailable, "notification channel store is not configured")
		}
		if _, err := a.store.GetNotificationChannel(ctx, tenantID, id); err != nil {
			return 0, nil, err
		}
		payload, err := json.Marshal(projections.NotificationChannelDeleted{ID: id})
		if err != nil {
			return 0, nil, err
		}
		ev, err := a.log.Append(ctx, events.Event{
			Type:     projections.EventNotificationChannelDeleted,
			TenantID: tenantID,
			Data:     payload,
		})
		if err != nil {
			return 0, nil, err
		}
		if err := projections.New(a.store).Apply(ctx, ev); err != nil {
			return 0, nil, err
		}
		return http.StatusNoContent, nil, nil
	})
}

func (a *API) decodeNotificationChannelRequest(r *http.Request, tenantID, pathID string) (store.NotificationChannel, error) {
	if a.store == nil || a.log == nil {
		return store.NotificationChannel{}, errStatus(http.StatusServiceUnavailable, "notification channel store is not configured")
	}
	var req notificationChannelRequest
	if err := decodeJSON(r, &req); err != nil {
		return store.NotificationChannel{}, errWithStatus(http.StatusBadRequest, err)
	}
	id := canonicalNotificationChannelID(pathID)
	if id == "" {
		id = canonicalNotificationChannelID(req.ID)
	}
	channelType := canonicalNotificationChannelID(req.ChannelType)
	if channelType == "" {
		channelType = id
	}
	if id == "" {
		return store.NotificationChannel{}, errStatus(http.StatusBadRequest, "notification channel id is required")
	}
	if !notificationChannelFamilySupported(id) || !notificationChannelFamilySupported(channelType) {
		return store.NotificationChannel{}, errStatus(http.StatusBadRequest, "unsupported notification channel")
	}
	if id != channelType {
		return store.NotificationChannel{}, errStatus(http.StatusBadRequest, "notification channel id must match channel_type")
	}
	enabled := true
	if req.Enabled != nil {
		enabled = *req.Enabled
	}
	endpointURL := strings.TrimSpace(req.EndpointURL)
	if enabled && endpointURL == "" {
		return store.NotificationChannel{}, errStatus(http.StatusBadRequest, "endpoint_url is required for enabled notification channels")
	}
	if endpointURL != "" {
		parsed, err := url.Parse(endpointURL)
		if err != nil || parsed.Scheme == "" || parsed.Host == "" {
			return store.NotificationChannel{}, errStatus(http.StatusBadRequest, "endpoint_url must be an absolute URL")
		}
		if parsed.Scheme != "http" && parsed.Scheme != "https" {
			return store.NotificationChannel{}, errStatus(http.StatusBadRequest, "endpoint_url must use http or https")
		}
		if parsed.User != nil {
			return store.NotificationChannel{}, errStatus(http.StatusBadRequest, "endpoint_url must not contain userinfo credentials")
		}
	}
	label := strings.TrimSpace(req.Label)
	if label == "" {
		label = notificationChannelDefaultLabel(id)
	}
	if label == "" {
		label = id
	}
	if len(label) > 120 {
		return store.NotificationChannel{}, errStatus(http.StatusBadRequest, "notification channel label must be 120 characters or fewer")
	}
	credentialRef := strings.TrimSpace(req.CredentialRef)
	if credentialRef != "" && !strings.Contains(credentialRef, "://") {
		return store.NotificationChannel{}, errStatus(http.StatusBadRequest, "credential_ref must be an opaque URI reference")
	}
	return store.NotificationChannel{
		TenantID:      tenantID,
		ID:            id,
		ChannelType:   channelType,
		Label:         label,
		EndpointURL:   endpointURL,
		CredentialRef: credentialRef,
		Enabled:       enabled,
	}, nil
}

func (a *API) appendNotificationChannelUpsert(ctx context.Context, tenantID string, channel store.NotificationChannel) (store.NotificationChannel, error) {
	payload, err := json.Marshal(projections.NotificationChannelUpserted{
		ID:            channel.ID,
		ChannelType:   channel.ChannelType,
		Label:         channel.Label,
		EndpointURL:   channel.EndpointURL,
		CredentialRef: channel.CredentialRef,
		Enabled:       channel.Enabled,
	})
	if err != nil {
		return store.NotificationChannel{}, err
	}
	ev, err := a.log.Append(ctx, events.Event{
		Type:     projections.EventNotificationChannelUpserted,
		TenantID: tenantID,
		Data:     payload,
	})
	if err != nil {
		return store.NotificationChannel{}, err
	}
	if err := projections.New(a.store).Apply(ctx, ev); err != nil {
		return store.NotificationChannel{}, err
	}
	return a.store.GetNotificationChannel(ctx, tenantID, channel.ID)
}

func (a *API) listNotificationRoutingPolicies(w http.ResponseWriter, r *http.Request) {
	tenantID, ok := a.tenant(r)
	if !ok {
		a.writeProblem(w, problemUnauthorized())
		return
	}
	if a.store == nil {
		a.writeError(w, errStatus(http.StatusServiceUnavailable, "notification routing policy store is not configured"))
		return
	}
	rows, err := a.store.ListNotificationRoutingPolicies(r.Context(), tenantID)
	if err != nil {
		a.writeError(w, err)
		return
	}
	items := make([]notificationRoutingPolicyResponse, 0, len(rows))
	for _, row := range rows {
		items = append(items, toNotificationRoutingPolicyResponse(row))
	}
	a.writeJSON(w, http.StatusOK, listResponse{Items: items})
}

func (a *API) getNotificationRoutingPolicy(w http.ResponseWriter, r *http.Request) {
	tenantID, ok := a.tenant(r)
	if !ok {
		a.writeProblem(w, problemUnauthorized())
		return
	}
	if a.store == nil {
		a.writeError(w, errStatus(http.StatusServiceUnavailable, "notification routing policy store is not configured"))
		return
	}
	id, err := notificationRoutingPolicyPathID(r)
	if err != nil {
		a.writeError(w, err)
		return
	}
	row, err := a.store.GetNotificationRoutingPolicy(r.Context(), tenantID, id)
	if err != nil {
		a.writeError(w, err)
		return
	}
	a.writeJSON(w, http.StatusOK, toNotificationRoutingPolicyResponse(row))
}

func (a *API) previewNotificationRouting(w http.ResponseWriter, r *http.Request) {
	tenantID, ok := a.tenant(r)
	if !ok {
		a.writeProblem(w, problemUnauthorized())
		return
	}
	if a.store == nil {
		a.writeError(w, errStatus(http.StatusServiceUnavailable, "notification routing policy store is not configured"))
		return
	}
	selector := store.NotificationRoutingSelector{
		Workspace: strings.TrimSpace(r.URL.Query().Get("workspace")),
		OwnerRef:  strings.TrimSpace(r.URL.Query().Get("owner_ref")),
		AssetRef:  strings.TrimSpace(r.URL.Query().Get("asset_ref")),
	}
	severity, err := normalizeNotificationSeverity(r.URL.Query().Get("severity"))
	if err != nil {
		a.writeError(w, err)
		return
	}
	policy, found, err := a.store.ResolveEffectiveNotificationRoutingPolicy(r.Context(), tenantID, selector)
	if err != nil {
		a.writeError(w, err)
		return
	}
	response := notificationRoutingPreviewResponse{
		ResolutionOrder: []string{"asset", "owner", "workspace", "global"},
		Effective:       []string{},
		Missing:         []string{},
		DeliveryReady:   false,
		Explanation:     "No automatic rule matches this asset. The alert will use the server's explicit fallback, if one exists.",
	}
	if found {
		view := toNotificationRoutingPolicyResponse(policy)
		response.Matched = &view
		response.Effective = notify.RoutingPolicy{ChannelsBySeverity: policy.ChannelsBySeverity, DefaultChannels: policy.DefaultChannels}.EffectiveAlertChannels(severity)
		channels, loadErr := a.notificationChannelsForTenant(r.Context(), tenantID)
		if loadErr != nil {
			a.writeError(w, loadErr)
			return
		}
		ready := make(map[string]bool, len(channels))
		for _, channel := range channels {
			if channel.Configured && channel.Enabled {
				ready[strings.ToLower(strings.TrimSpace(channel.ID))] = true
			}
		}
		for _, name := range response.Effective {
			if !ready[strings.ToLower(strings.TrimSpace(name))] {
				response.Missing = append(response.Missing, name)
			}
		}
		response.DeliveryReady = len(response.Effective) > 0 && len(response.Missing) == 0
		response.Explanation = fmt.Sprintf("The %s rule %q wins because it is the most specific match. It sends %s alerts to %d channel(s).", policy.ScopeKind, policy.Name, severity, len(response.Effective))
	}
	a.writeJSON(w, http.StatusOK, response)
}

// previewNotificationRoutingPolicy validates and normalizes the exact draft
// the operator is looking at. It neither appends the policy event nor queues a
// channel test, so clients can review the real plan before the mutation.
func (a *API) previewNotificationRoutingPolicy(w http.ResponseWriter, r *http.Request) {
	tenantID, ok := a.tenant(r)
	if !ok {
		a.writeProblem(w, problemUnauthorized())
		return
	}
	policy, err := a.decodeNotificationRoutingPolicyRequest(r, tenantID, "")
	if err != nil {
		a.writeError(w, err)
		return
	}
	configured, missing, err := a.notificationRoutingPolicyReadiness(r.Context(), tenantID, policy)
	if err != nil {
		a.writeError(w, err)
		return
	}
	blockers := make([]string, 0, 1)
	if len(missing) > 0 {
		blockers = append(blockers, "Configure and enable every requested channel before saving this automatic route: "+strings.Join(missing, ", ")+".")
	}
	fingerprint, err := notificationRoutingPolicyFingerprint(policy)
	if err != nil {
		a.writeError(w, err)
		return
	}
	a.writeJSON(w, http.StatusOK, notificationRoutingPolicyPreviewResponse{
		Capability: "F29", Operation: "save_notification_routing_policy", Ready: len(blockers) == 0, EffectFree: true,
		RequestFingerprint: "sha256:" + fingerprint,
		Name:               policy.Name, ScopeKind: policy.ScopeKind, ScopeRef: policy.ScopeRef,
		ChannelsBySeverity: policy.ChannelsBySeverity, DefaultChannels: policy.DefaultChannels,
		OwnerRef: policy.OwnerRef, OwnerEmail: policy.OwnerEmail,
		DigestInterval: policy.DigestInterval, DigestTimezone: policy.DigestTimezone,
		ConfiguredChannels: configured, MissingChannels: missing, Blockers: blockers,
		PreviewWrites: []string{}, PreviewExternalEffects: []string{},
		ExecuteWrites: []string{
			"Append one tenant-scoped notification.routing_policy.upserted source event.",
			"Project that event into the tenant notification routing read model.",
		},
		ExecuteExternalEffects: []string{},
		RecoverySteps: []string{
			"Update or delete the routing policy through its idempotent API, then preview the effective route again.",
			"If a delivery exhausts its bounded retries, inspect the dead-letter row and requeue it only after correcting the channel.",
		},
		VerificationSteps: []string{
			"Read the saved policy and preview the effective asset-to-owner-to-workspace-to-global route.",
			"Queue a redacted channel test, then verify the outbox delivery result or dead-letter evidence.",
		},
		SecretDataHandling: "Routing policies contain channel identifiers and owner metadata, never channel credential values. Channel tests retain only redacted credential-reference evidence.",
	})
}

func notificationRoutingPolicyChannels(policy store.NotificationRoutingPolicy) []string {
	seen := make(map[string]bool)
	for _, channelID := range policy.DefaultChannels {
		seen[channelID] = true
	}
	for _, channels := range policy.ChannelsBySeverity {
		for _, channelID := range channels {
			seen[channelID] = true
		}
	}
	out := make([]string, 0, len(seen))
	for channelID := range seen {
		out = append(out, channelID)
	}
	sort.Strings(out)
	return out
}

func (a *API) notificationRoutingPolicyReadiness(ctx context.Context, tenantID string, policy store.NotificationRoutingPolicy) ([]string, []string, error) {
	channels, err := a.notificationChannelsForTenant(ctx, tenantID)
	if err != nil {
		return nil, nil, err
	}
	configured := make([]string, 0, len(channels))
	ready := make(map[string]bool, len(channels))
	for _, channel := range channels {
		if !channel.Configured || !channel.Enabled {
			continue
		}
		configured = append(configured, channel.ID)
		ready[channel.ID] = true
	}
	sort.Strings(configured)
	requested := notificationRoutingPolicyChannels(policy)
	missing := make([]string, 0, len(requested))
	for _, channelID := range requested {
		if !ready[channelID] {
			missing = append(missing, channelID)
		}
	}
	return configured, missing, nil
}

func (a *API) requireNotificationRoutingPolicyReady(ctx context.Context, tenantID string, policy store.NotificationRoutingPolicy) error {
	_, missing, err := a.notificationRoutingPolicyReadiness(ctx, tenantID, policy)
	if err != nil {
		return err
	}
	if len(missing) > 0 {
		return errStatus(http.StatusConflict, "configure and enable every requested notification channel before saving this route: "+strings.Join(missing, ", "))
	}
	return nil
}

func notificationRoutingPolicyFingerprint(policy store.NotificationRoutingPolicy) (string, error) {
	normalized := struct {
		Name               string              `json:"name"`
		ScopeKind          string              `json:"scope_kind"`
		ScopeRef           string              `json:"scope_ref,omitempty"`
		ChannelsBySeverity map[string][]string `json:"channels_by_severity"`
		DefaultChannels    []string            `json:"default_channels"`
		OwnerRef           string              `json:"owner_ref,omitempty"`
		OwnerEmail         string              `json:"owner_email,omitempty"`
		DigestInterval     int                 `json:"digest_interval_seconds"`
		DigestTimezone     string              `json:"digest_timezone"`
	}{
		Name: policy.Name, ScopeKind: policy.ScopeKind, ScopeRef: policy.ScopeRef,
		ChannelsBySeverity: policy.ChannelsBySeverity, DefaultChannels: policy.DefaultChannels,
		OwnerRef: policy.OwnerRef, OwnerEmail: policy.OwnerEmail,
		DigestInterval: policy.DigestInterval, DigestTimezone: policy.DigestTimezone,
	}
	encoded, err := json.Marshal(normalized)
	if err != nil {
		return "", err
	}
	return crypto.SHA256Hex(encoded), nil
}

//trstctl:mutation
func (a *API) createNotificationRoutingPolicy(w http.ResponseWriter, r *http.Request) {
	idempotencyKey := r.Header.Get("Idempotency-Key")
	a.mutate(w, r, idempotencyKey, func(ctx context.Context, tenantID string) (int, any, error) {
		policy, err := a.decodeNotificationRoutingPolicyRequest(r, tenantID, "")
		if err != nil {
			return 0, nil, err
		}
		if err := a.requireNotificationRoutingPolicyReady(ctx, tenantID, policy); err != nil {
			return 0, nil, err
		}
		created, err := a.appendNotificationRoutingPolicyUpsert(ctx, tenantID, policy)
		if err != nil {
			return 0, nil, err
		}
		return http.StatusCreated, toNotificationRoutingPolicyResponse(created), nil
	})
}

//trstctl:mutation
func (a *API) updateNotificationRoutingPolicy(w http.ResponseWriter, r *http.Request) {
	idempotencyKey := r.Header.Get("Idempotency-Key")
	pathID, err := notificationRoutingPolicyPathID(r)
	if err != nil {
		a.writeError(w, err)
		return
	}
	a.mutate(w, r, idempotencyKey, func(ctx context.Context, tenantID string) (int, any, error) {
		if a.store == nil {
			return 0, nil, errStatus(http.StatusServiceUnavailable, "notification routing policy store is not configured")
		}
		if _, err := a.store.GetNotificationRoutingPolicy(ctx, tenantID, pathID); err != nil {
			return 0, nil, err
		}
		policy, err := a.decodeNotificationRoutingPolicyRequest(r, tenantID, pathID)
		if err != nil {
			return 0, nil, err
		}
		if err := a.requireNotificationRoutingPolicyReady(ctx, tenantID, policy); err != nil {
			return 0, nil, err
		}
		updated, err := a.appendNotificationRoutingPolicyUpsert(ctx, tenantID, policy)
		if err != nil {
			return 0, nil, err
		}
		return http.StatusOK, toNotificationRoutingPolicyResponse(updated), nil
	})
}

//trstctl:mutation
func (a *API) deleteNotificationRoutingPolicy(w http.ResponseWriter, r *http.Request) {
	idempotencyKey := r.Header.Get("Idempotency-Key")
	id, err := notificationRoutingPolicyPathID(r)
	if err != nil {
		a.writeError(w, err)
		return
	}
	a.mutate(w, r, idempotencyKey, func(ctx context.Context, tenantID string) (int, any, error) {
		if a.store == nil || a.log == nil {
			return 0, nil, errStatus(http.StatusServiceUnavailable, "notification routing policy store is not configured")
		}
		if _, err := a.store.GetNotificationRoutingPolicy(ctx, tenantID, id); err != nil {
			return 0, nil, err
		}
		payload, err := json.Marshal(projections.NotificationRoutingPolicyDeleted{ID: id})
		if err != nil {
			return 0, nil, err
		}
		ev, err := a.log.Append(ctx, events.Event{
			Type:     projections.EventNotificationRoutingPolicyDeleted,
			TenantID: tenantID,
			Data:     payload,
		})
		if err != nil {
			return 0, nil, err
		}
		if err := projections.New(a.store).Apply(ctx, ev); err != nil {
			return 0, nil, err
		}
		return http.StatusNoContent, nil, nil
	})
}

//trstctl:mutation
func (a *API) testNotificationChannel(w http.ResponseWriter, r *http.Request) {
	idempotencyKey := r.Header.Get("Idempotency-Key")
	channelID := strings.TrimSpace(r.PathValue("id"))
	principal, err := requestPrincipalSubject(r.Context())
	if err != nil {
		a.writeError(w, err)
		return
	}
	var req notificationChannelTestRequest
	if err := decodeJSON(r, &req); err != nil {
		a.writeError(w, errWithStatus(http.StatusBadRequest, err))
		return
	}
	severity, err := normalizeNotificationSeverity(req.Severity)
	if err != nil {
		a.writeError(w, err)
		return
	}
	subject := strings.TrimSpace(req.Subject)
	if subject == "" {
		subject = "Notification channel test"
	}
	detail := strings.TrimSpace(req.Detail)
	if detail == "" {
		detail = "Operator-requested notification channel test"
	}
	routingPolicyID := strings.TrimSpace(req.RoutingPolicyID)
	if routingPolicyID != "" {
		if _, err := guuid.Parse(routingPolicyID); err != nil {
			a.writeError(w, errStatus(http.StatusBadRequest, "routing_policy_id must be a UUID"))
			return
		}
	}
	ownerEmail := strings.TrimSpace(req.OwnerEmail)
	credentialRef := strings.TrimSpace(req.CredentialRef)
	binding, err := notificationChannelTestBinding(principal, r.Method, r.URL.EscapedPath(), channelID, severity, subject, detail, routingPolicyID, ownerEmail, credentialRef)
	if err != nil {
		a.writeError(w, err)
		return
	}
	tenantID, ok := a.tenant(r)
	if !ok {
		a.writeProblem(w, problemUnauthorized())
		return
	}
	operationID := "notification.test:" + crypto.SHA256Hex([]byte(tenantID+"\x00"+idempotencyKey))
	// Consult the event-sourced authority before the bounded API recorder claims
	// the raw key. Otherwise a hostile changed replay after recorder GC could leave
	// a new bound cache row that temporarily poisons the legitimate command.
	if _, _, err := a.notificationChannelTestReplay(r.Context(), tenantID, operationID, channelID, binding, idempotencyKey); err != nil {
		a.writeError(w, err)
		return
	}
	a.mutateDurableBound(w, r, idempotencyKey, binding, func(ctx context.Context, tenantID string) (int, any, error) {
		if replay, found, err := a.notificationChannelTestReplay(ctx, tenantID, operationID, channelID, binding, idempotencyKey); err != nil {
			return 0, nil, err
		} else if found {
			return http.StatusAccepted, replay, nil
		}
		channel, err := a.notificationChannelForTest(ctx, tenantID, channelID)
		if err != nil {
			return 0, nil, err
		}
		if a.store == nil || a.log == nil || a.notificationOutbox == nil {
			return 0, nil, errStatus(http.StatusServiceUnavailable, "notification test outbox is not configured")
		}
		configuredCredential := firstNonEmpty(credentialRef, channel.CredentialRef)
		alert := notify.Alert{
			Kind:                 notify.KindNotificationChannelTest,
			TenantID:             tenantID,
			OperationID:          operationID,
			RequestBinding:       binding,
			CredentialConfigured: strings.TrimSpace(configuredCredential) != "",
			Subject:              subject,
			Detail:               detail,
			Severity:             severity,
			RoutingPolicyID:      routingPolicyID,
			TargetChannel:        channel.ID,
			OwnerEmail:           ownerEmail,
		}
		payload, err := json.Marshal(alert)
		if err != nil {
			return 0, nil, err
		}
		command, err := json.Marshal(projections.NotificationTestQueued{
			ID: operationID, RequestBinding: binding, ChannelID: channel.ID,
			Destination:          notify.DestinationTest,
			EffectLane:           notify.DestinationTest + ":channel:" + channel.ID,
			CredentialConfigured: alert.CredentialConfigured,
			Payload:              append(json.RawMessage(nil), payload...),
		})
		if err != nil {
			return 0, nil, err
		}
		ev, err := a.log.Append(ctx, events.Event{
			ID:       "notification.test.queued:" + strings.TrimPrefix(operationID, "notification.test:"),
			Type:     projections.EventNotificationTestQueued,
			TenantID: tenantID,
			Data:     command,
		})
		if err != nil {
			return 0, nil, err
		}
		if err := projections.New(a.store).Apply(ctx, ev); err != nil {
			if errors.Is(err, store.ErrIdempotencyConflict) {
				return 0, nil, orchestrator.ErrIdempotencyConflict
			}
			return 0, nil, err
		}
		authoritative, err := a.store.GetNotificationTestOperation(ctx, tenantID, operationID)
		if err != nil {
			return 0, nil, err
		}
		if !crypto.ConstantTimeEqual([]byte(authoritative.RequestBinding), []byte(binding)) {
			return 0, nil, orchestrator.ErrIdempotencyConflict
		}
		return http.StatusAccepted, notificationChannelTestOperationResponse(authoritative, idempotencyKey), nil
	})
}

func (a *API) notificationChannelTestReplay(ctx context.Context, tenantID, operationID, channelID, binding, rawKey string) (notificationChannelTestResponse, bool, error) {
	if a.store == nil {
		return notificationChannelTestResponse{}, false, nil
	}
	op, err := a.store.GetNotificationTestOperation(ctx, tenantID, operationID)
	if errors.Is(err, pgx.ErrNoRows) {
		return notificationChannelTestResponse{}, false, nil
	}
	if err != nil {
		return notificationChannelTestResponse{}, false, err
	}
	if op.ID != operationID || op.Destination != notify.DestinationTest ||
		op.ChannelID != channelID ||
		!crypto.ConstantTimeEqual([]byte(op.RequestBinding), []byte(binding)) {
		return notificationChannelTestResponse{}, false, errStatus(http.StatusConflict, "Idempotency-Key was already used for a different authenticated notification command")
	}
	return notificationChannelTestOperationResponse(op, rawKey), true, nil
}

func notificationChannelTestOperationResponse(op store.NotificationTestOperation, rawKey string) notificationChannelTestResponse {
	credentialRef := ""
	if op.CredentialConfigured {
		credentialRef = "redacted"
	}
	return notificationChannelTestResponse{ // #nosec G101 -- identifier/constant matching the secret-name heuristic; no credential value present (CWE-798)
		ChannelID: op.ChannelID, Destination: op.Destination, OutboxID: op.OutboxID,
		Status: "queued", CredentialRef: credentialRef,
		SecretHandling: "credential reference redacted; tenant channel endpoint metadata is read only by the delivery worker",
		IdempotencyKey: rawKey, QueuedAt: op.QueuedAt.UTC(),
	}
}

func notificationChannelTestBinding(principal, method, path, channelID, severity, subject, detail, routingPolicyID, ownerEmail, credentialRef string) (string, error) {
	command := struct {
		Operation       string `json:"operation"`
		Principal       string `json:"principal"`
		Method          string `json:"method"`
		Path            string `json:"path"`
		ChannelID       string `json:"channel_id"`
		Severity        string `json:"severity"`
		Subject         string `json:"subject"`
		Detail          string `json:"detail"`
		RoutingPolicyID string `json:"routing_policy_id"`
		OwnerEmail      string `json:"owner_email"`
		CredentialRef   string `json:"credential_ref"`
	}{
		Operation: "notification.channel_test", Principal: principal,
		Method: method, Path: path, ChannelID: channelID, Severity: severity,
		Subject: subject, Detail: detail, RoutingPolicyID: routingPolicyID, OwnerEmail: ownerEmail,
		CredentialRef: credentialRef,
	}
	encoded, err := json.Marshal(command)
	if err != nil {
		return "", err
	}
	defer secret.Wipe(encoded)
	return crypto.SHA256Hex(encoded), nil
}

func (a *API) listNotifications(w http.ResponseWriter, r *http.Request) {
	tenantID, ok := a.tenant(r)
	if !ok {
		a.writeProblem(w, problemUnauthorized())
		return
	}
	if a.store == nil {
		a.writeError(w, errStatus(http.StatusServiceUnavailable, "notification inbox is not configured"))
		return
	}
	limit, after, status, err := notificationPageParams(r)
	if err != nil {
		a.writeError(w, err)
		return
	}
	rows, err := a.store.ListNotificationOutboxPage(r.Context(), tenantID, after, limit, status)
	if err != nil {
		a.writeError(w, err)
		return
	}
	items := make([]notificationResponse, 0, len(rows))
	for _, row := range rows {
		items = append(items, toNotificationResponse(row))
	}
	next := ""
	if len(rows) == limit {
		next = encodeNotificationCursor(rows[len(rows)-1].ID)
	}
	a.writeJSON(w, http.StatusOK, listResponse{Items: items, NextCursor: next})
}

func (a *API) getNotification(w http.ResponseWriter, r *http.Request) {
	tenantID, ok := a.tenant(r)
	if !ok {
		a.writeProblem(w, problemUnauthorized())
		return
	}
	if a.store == nil {
		a.writeError(w, errStatus(http.StatusServiceUnavailable, "notification inbox is not configured"))
		return
	}
	id, err := notificationPathID(r)
	if err != nil {
		a.writeError(w, err)
		return
	}
	row, err := a.store.GetNotificationOutbox(r.Context(), tenantID, id)
	if err != nil {
		a.writeError(w, err)
		return
	}
	a.writeJSON(w, http.StatusOK, toNotificationResponse(row))
}

//trstctl:mutation
func (a *API) markNotificationRead(w http.ResponseWriter, r *http.Request) {
	idempotencyKey := r.Header.Get("Idempotency-Key")
	id, err := notificationPathID(r)
	if err != nil {
		a.writeError(w, err)
		return
	}
	a.mutate(w, r, idempotencyKey, func(ctx context.Context, tenantID string) (int, any, error) {
		if a.store == nil || a.log == nil {
			return 0, nil, errStatus(http.StatusServiceUnavailable, "notification inbox is not configured")
		}
		if _, err := a.store.GetNotificationOutbox(ctx, tenantID, id); err != nil {
			return 0, nil, err
		}
		readAt := time.Now().UTC()
		payload, err := json.Marshal(projections.NotificationRead{OutboxID: id, ReadAt: readAt})
		if err != nil {
			return 0, nil, err
		}
		ev, err := a.log.Append(ctx, events.Event{
			Type:     projections.EventNotificationRead,
			TenantID: tenantID,
			Data:     payload,
		})
		if err != nil {
			return 0, nil, err
		}
		if err := projections.New(a.store).Apply(ctx, ev); err != nil {
			return 0, nil, err
		}
		row, err := a.store.GetNotificationOutbox(ctx, tenantID, id)
		if err != nil {
			return 0, nil, err
		}
		return http.StatusOK, toNotificationResponse(row), nil
	})
}

//trstctl:mutation
func (a *API) requeueNotification(w http.ResponseWriter, r *http.Request) {
	idempotencyKey := r.Header.Get("Idempotency-Key")
	id, err := notificationPathID(r)
	if err != nil {
		a.writeError(w, err)
		return
	}
	a.mutate(w, r, idempotencyKey, func(ctx context.Context, tenantID string) (int, any, error) {
		if a.store == nil {
			return 0, nil, errStatus(http.StatusServiceUnavailable, "notification inbox is not configured")
		}
		row, err := a.store.RequeueNotificationOutbox(ctx, tenantID, id)
		if err != nil {
			if errors.Is(err, store.ErrNotificationAlreadyProcessing) || errors.Is(err, store.ErrNotificationNotDead) {
				return 0, nil, errStatus(http.StatusConflict, err.Error())
			}
			return 0, nil, err
		}
		return http.StatusOK, toNotificationResponse(row), nil
	})
}

func (a *API) decodeNotificationRoutingPolicyRequest(r *http.Request, tenantID, pathID string) (store.NotificationRoutingPolicy, error) {
	if a.store == nil || a.log == nil {
		return store.NotificationRoutingPolicy{}, errStatus(http.StatusServiceUnavailable, "notification routing policy store is not configured")
	}
	var req notificationRoutingPolicyRequest
	if err := decodeJSON(r, &req); err != nil {
		return store.NotificationRoutingPolicy{}, errWithStatus(http.StatusBadRequest, err)
	}
	id := strings.TrimSpace(pathID)
	if id == "" {
		id = strings.TrimSpace(req.ID)
	}
	if id == "" {
		id = guuid.NewString()
	}
	if _, err := guuid.Parse(id); err != nil {
		return store.NotificationRoutingPolicy{}, errStatus(http.StatusBadRequest, "notification routing policy id must be a UUID")
	}
	name := strings.TrimSpace(req.Name)
	if name == "" {
		return store.NotificationRoutingPolicy{}, errStatus(http.StatusBadRequest, "notification routing policy name is required")
	}
	if len(name) > 120 {
		return store.NotificationRoutingPolicy{}, errStatus(http.StatusBadRequest, "notification routing policy name must be 120 characters or fewer")
	}
	supported := a.supportedNotificationChannels()
	matrix := make(map[string][]string, len(req.ChannelsBySeverity))
	for severity, channels := range req.ChannelsBySeverity {
		canonical, err := normalizeNotificationSeverity(severity)
		if err != nil {
			return store.NotificationRoutingPolicy{}, err
		}
		normalized, err := normalizeRoutingChannels(channels, supported)
		if err != nil {
			return store.NotificationRoutingPolicy{}, err
		}
		if len(normalized) > 0 {
			matrix[canonical] = normalized
		}
	}
	defaults, err := normalizeRoutingChannels(req.DefaultChannels, supported)
	if err != nil {
		return store.NotificationRoutingPolicy{}, err
	}
	if len(matrix) == 0 && len(defaults) == 0 {
		return store.NotificationRoutingPolicy{}, errStatus(http.StatusBadRequest, "notification routing policy requires at least one channel")
	}
	ownerEmail := strings.TrimSpace(req.OwnerEmail)
	if ownerEmail != "" && strings.ContainsAny(ownerEmail, " \t\r\n") {
		return store.NotificationRoutingPolicy{}, errStatus(http.StatusBadRequest, "owner_email must be one email-like token")
	}
	interval := req.DigestInterval
	if interval == 0 {
		interval = 86400
	}
	if interval < 3600 || interval > 604800 {
		return store.NotificationRoutingPolicy{}, errStatus(http.StatusBadRequest, "digest_interval_seconds must be between 3600 and 604800")
	}
	timezone := strings.TrimSpace(req.DigestTimezone)
	if timezone == "" {
		timezone = "UTC"
	}
	if _, err := time.LoadLocation(timezone); err != nil {
		return store.NotificationRoutingPolicy{}, errStatus(http.StatusBadRequest, "digest_timezone must be a valid time zone")
	}
	scopeKind := strings.ToLower(strings.TrimSpace(req.ScopeKind))
	if scopeKind == "" {
		scopeKind = "manual"
	}
	scopeRef := strings.TrimSpace(req.ScopeRef)
	switch scopeKind {
	case "manual", "global":
		if scopeRef != "" {
			return store.NotificationRoutingPolicy{}, errStatus(http.StatusBadRequest, "manual and global routing policies cannot have scope_ref")
		}
	case "workspace":
		if !supportedNotificationWorkspace(scopeRef) {
			return store.NotificationRoutingPolicy{}, errStatus(http.StatusBadRequest, "workspace scope_ref must name one served workspace")
		}
	case "owner":
		if !strings.HasPrefix(scopeRef, "owner/") || len(scopeRef) <= len("owner/") {
			return store.NotificationRoutingPolicy{}, errStatus(http.StatusBadRequest, "owner scope_ref must use owner/<id>")
		}
	case "asset":
		if !strings.Contains(scopeRef, "/") || strings.HasSuffix(scopeRef, "/") {
			return store.NotificationRoutingPolicy{}, errStatus(http.StatusBadRequest, "asset scope_ref must use kind/<id>")
		}
	default:
		return store.NotificationRoutingPolicy{}, errStatus(http.StatusBadRequest, "scope_kind must be manual, global, workspace, owner, or asset")
	}
	return store.NotificationRoutingPolicy{
		ID:                 id,
		TenantID:           tenantID,
		Name:               name,
		ScopeKind:          scopeKind,
		ScopeRef:           scopeRef,
		ChannelsBySeverity: matrix,
		DefaultChannels:    defaults,
		OwnerRef:           strings.TrimSpace(req.OwnerRef),
		OwnerEmail:         ownerEmail,
		DigestInterval:     interval,
		DigestTimezone:     timezone,
	}, nil
}

func (a *API) appendNotificationRoutingPolicyUpsert(ctx context.Context, tenantID string, policy store.NotificationRoutingPolicy) (store.NotificationRoutingPolicy, error) {
	payload, err := json.Marshal(projections.NotificationRoutingPolicyUpserted{
		ID:                 policy.ID,
		Name:               policy.Name,
		ScopeKind:          policy.ScopeKind,
		ScopeRef:           policy.ScopeRef,
		ChannelsBySeverity: policy.ChannelsBySeverity,
		DefaultChannels:    policy.DefaultChannels,
		OwnerRef:           policy.OwnerRef,
		OwnerEmail:         policy.OwnerEmail,
		DigestInterval:     policy.DigestInterval,
		DigestTimezone:     policy.DigestTimezone,
	})
	if err != nil {
		return store.NotificationRoutingPolicy{}, err
	}
	ev, err := a.log.Append(ctx, events.Event{
		Type:     projections.EventNotificationRoutingPolicyUpserted,
		TenantID: tenantID,
		Data:     payload,
	})
	if err != nil {
		return store.NotificationRoutingPolicy{}, err
	}
	if err := projections.New(a.store).Apply(ctx, ev); err != nil {
		return store.NotificationRoutingPolicy{}, err
	}
	return a.store.GetNotificationRoutingPolicy(ctx, tenantID, policy.ID)
}

func (a *API) notificationChannelsForTenant(ctx context.Context, tenantID string) ([]notificationChannelResponse, error) {
	items := notificationChannelCatalog(a.notificationChannels)
	if a.store == nil {
		return items, nil
	}
	rows, err := a.store.ListNotificationChannels(ctx, tenantID)
	if err != nil {
		return nil, err
	}
	byID := make(map[string]int, len(items)+len(rows))
	for i := range items {
		byID[items[i].ID] = i
	}
	for _, row := range rows {
		response := toNotificationChannelResponse(row)
		if idx, ok := byID[response.ID]; ok {
			items[idx] = response
			continue
		}
		byID[response.ID] = len(items)
		items = append(items, response)
	}
	return items, nil
}

func (a *API) supportedNotificationChannels() map[string]bool {
	out := map[string]bool{}
	for _, channel := range notificationChannelCatalog(a.notificationChannels) {
		out[channel.ID] = true
	}
	return out
}

func (a *API) notificationChannelForTest(ctx context.Context, tenantID, raw string) (notificationChannelResponse, error) {
	id := canonicalNotificationChannelID(raw)
	if id == "" {
		return notificationChannelResponse{}, errStatus(http.StatusBadRequest, "notification channel id is required")
	}
	if a.store != nil {
		row, err := a.store.GetNotificationChannel(ctx, tenantID, id)
		if err == nil {
			ch := toNotificationChannelResponse(row)
			if !ch.Configured {
				return notificationChannelResponse{}, errStatus(http.StatusConflict, "notification channel is disabled")
			}
			return ch, nil
		}
		if !store.IsNotFound(err) {
			return notificationChannelResponse{}, err
		}
	}
	for _, channel := range notificationChannelCatalog(a.notificationChannels) {
		if channel.ID != id {
			continue
		}
		if !channel.Configured {
			return notificationChannelResponse{}, errStatus(http.StatusConflict, "notification channel is supported but not configured")
		}
		return channel, nil
	}
	return notificationChannelResponse{}, errStatus(http.StatusBadRequest, "unsupported notification channel")
}

func toNotificationChannelResponse(ch store.NotificationChannel) notificationChannelResponse {
	id := canonicalNotificationChannelID(ch.ID)
	channelType := canonicalNotificationChannelID(ch.ChannelType)
	if channelType == "" {
		channelType = id
	}
	return notificationChannelResponse{ // #nosec G101 -- identifier/constant matching the secret-name heuristic; no credential value present (CWE-798)
		ID:                 id,
		ChannelType:        channelType,
		Label:              firstNonEmpty(strings.TrimSpace(ch.Label), notificationChannelDefaultLabel(id), id),
		Category:           notificationChannelCategory(channelType),
		Configured:         ch.Enabled && strings.TrimSpace(ch.EndpointURL) != "",
		Enabled:            ch.Enabled,
		Delivery:           "tenant-authored notification.* outbox fanout",
		Description:        notificationChannelDescription(channelType),
		Source:             "tenant",
		EndpointConfigured: strings.TrimSpace(ch.EndpointURL) != "",
		CredentialRef:      redactCredentialRef(ch.CredentialRef),
		SecretHandling:     "credential reference redacted; tenant channel endpoint metadata is read only by the delivery worker",
	}
}

func normalizeNotificationSeverity(raw string) (string, error) {
	severity := strings.ToLower(strings.TrimSpace(raw))
	switch severity {
	case "":
		return notify.AlertSeverityInformational, nil
	case "info":
		return notify.AlertSeverityInformational, nil
	case notify.AlertSeverityLow, notify.AlertSeverityInformational, notify.AlertSeverityWarning, notify.AlertSeverityCritical:
		return severity, nil
	default:
		return "", errStatus(http.StatusBadRequest, "severity must be low, informational, warning, or critical")
	}
}

func normalizeRoutingChannels(channels []string, supported map[string]bool) ([]string, error) {
	seen := make(map[string]bool, len(channels))
	out := make([]string, 0, len(channels))
	for _, raw := range channels {
		id := canonicalNotificationChannelID(raw)
		if id == "" {
			continue
		}
		if !supported[id] {
			return nil, errStatus(http.StatusBadRequest, "unsupported notification channel "+id)
		}
		if seen[id] {
			continue
		}
		seen[id] = true
		out = append(out, id)
	}
	return out, nil
}

func notificationRoutingPolicyPathID(r *http.Request) (string, error) {
	id := strings.TrimSpace(r.PathValue("id"))
	if _, err := guuid.Parse(id); err != nil {
		return "", errStatus(http.StatusBadRequest, "notification routing policy id must be a UUID")
	}
	return id, nil
}

func toNotificationRoutingPolicyResponse(p store.NotificationRoutingPolicy) notificationRoutingPolicyResponse {
	interval := p.DigestInterval
	if interval <= 0 {
		interval = 86400
	}
	timezone := p.DigestTimezone
	if timezone == "" {
		timezone = "UTC"
	}
	return notificationRoutingPolicyResponse{
		ID:                 p.ID,
		TenantID:           p.TenantID,
		Name:               p.Name,
		ScopeKind:          firstNonEmpty(p.ScopeKind, "manual"),
		ScopeRef:           p.ScopeRef,
		ChannelsBySeverity: copyChannelMatrix(p.ChannelsBySeverity),
		DefaultChannels:    append([]string(nil), p.DefaultChannels...),
		OwnerRef:           p.OwnerRef,
		OwnerEmail:         p.OwnerEmail,
		DigestInterval:     interval,
		DigestTimezone:     timezone,
		DigestPreview: notificationDigestPreviewResponse{
			IntervalSeconds: interval,
			Timezone:        timezone,
			NextRunAt:       nextDigestPreview(p.UpdatedAt, interval),
		},
		CreatedAt: p.CreatedAt,
		UpdatedAt: p.UpdatedAt,
	}
}

func supportedNotificationWorkspace(workspace string) bool {
	switch workspace {
	case "certificate-lifecycle", "machine-workload-trust", "secrets-access", "software-trust", "trust-operations":
		return true
	default:
		return false
	}
}

func copyChannelMatrix(in map[string][]string) map[string][]string {
	out := make(map[string][]string, len(in))
	for k, v := range in {
		out[k] = append([]string(nil), v...)
	}
	return out
}

func nextDigestPreview(anchor time.Time, intervalSeconds int) time.Time {
	if intervalSeconds <= 0 {
		intervalSeconds = 86400
	}
	interval := time.Duration(intervalSeconds) * time.Second
	if anchor.IsZero() {
		return time.Now().UTC().Add(interval)
	}
	next := anchor.UTC().Add(interval)
	now := time.Now().UTC()
	if next.After(now) {
		return next
	}
	behind := now.Sub(next)
	steps := int64(behind/interval) + 1
	return next.Add(time.Duration(steps) * interval)
}

func redactCredentialRef(raw string) string {
	if strings.TrimSpace(raw) == "" {
		return ""
	}
	return "redacted"
}

func notificationPageParams(r *http.Request) (limit int, after int64, status string, err error) {
	limit, err = pageLimit(r)
	if err != nil {
		return 0, 0, "", errStatus(http.StatusBadRequest, err.Error())
	}
	if c := r.URL.Query().Get("cursor"); c != "" {
		after, err = decodeNotificationCursor(c)
		if err != nil {
			return 0, 0, "", errStatus(http.StatusBadRequest, "invalid cursor")
		}
	}
	status, err = parseNotificationStatus(r.URL.Query().Get("status"))
	if err != nil {
		return 0, 0, "", err
	}
	return limit, after, status, nil
}

func parseNotificationStatus(raw string) (string, error) {
	status := strings.ToLower(strings.TrimSpace(raw))
	switch status {
	case "", "pending", "sent", "dead", "read":
		return status, nil
	default:
		return "", errStatus(http.StatusBadRequest, "status must be pending, sent, dead, or read")
	}
}

func notificationPathID(r *http.Request) (int64, error) {
	id, err := strconv.ParseInt(strings.TrimSpace(r.PathValue("id")), 10, 64)
	if err != nil || id <= 0 {
		return 0, errStatus(http.StatusBadRequest, "notification id must be a positive integer")
	}
	return id, nil
}

func encodeNotificationCursor(id int64) string {
	return base64.RawURLEncoding.EncodeToString([]byte(strconv.FormatInt(id, 10)))
}

func decodeNotificationCursor(cursor string) (int64, error) {
	raw, err := base64.RawURLEncoding.DecodeString(cursor)
	if err != nil {
		return 0, err
	}
	id, err := strconv.ParseInt(string(raw), 10, 64)
	if err != nil || id < 0 {
		return 0, errors.New("invalid notification cursor")
	}
	return id, nil
}

func toNotificationResponse(row store.NotificationOutboxRecord) notificationResponse {
	var alert notify.Alert
	_ = json.Unmarshal(row.Payload, &alert)
	var notAfter *time.Time
	if !alert.NotAfter.IsZero() {
		t := alert.NotAfter
		notAfter = &t
	}
	return notificationResponse{
		ID:                     strconv.FormatInt(row.ID, 10),
		TenantID:               row.TenantID,
		Destination:            row.Destination,
		Kind:                   alert.Kind,
		IdentityID:             alert.IdentityID,
		OperationID:            alert.OperationID,
		CertificateFingerprint: alert.CertificateFingerprint,
		DeploymentReceiptID:    alert.DeploymentReceiptID,
		DeploymentRecordedAt:   alert.DeploymentRecordedAt,
		CertificateID:          alert.CertificateID,
		Subject:                alert.Subject,
		Serial:                 alert.Serial,
		NotAfter:               notAfter,
		Detail:                 alert.Detail,
		Severity:               alert.Severity,
		RoutingPolicyID:        alert.RoutingPolicyID,
		ThresholdDays:          alert.ThresholdDays,
		OwnerID:                alert.OwnerID,
		OwnerName:              alert.OwnerName,
		OwnerEmail:             alert.OwnerEmail,
		EscalationRecipients:   append([]notify.AlertRecipient(nil), alert.EscalationRecipients...),
		Status:                 row.Status,
		Attempts:               row.Attempts,
		LastError:              row.LastError,
		IdempotencyKey:         row.IdempotencyKey,
		CreatedAt:              row.CreatedAt,
		DeliveredAt:            row.DeliveredAt,
		ReadAt:                 row.ReadAt,
	}
}

func notificationChannelCatalog(configured []string) []notificationChannelResponse {
	configuredSet := make(map[string]bool, len(configured))
	for _, name := range configured {
		id := canonicalNotificationChannelID(name)
		if id != "" {
			configuredSet[id] = true
		}
	}
	base := []notificationChannelResponse{
		{ID: "email", Label: "Email", Category: "smtp", Description: "SMTP email alert delivery"},
		{ID: "slack", Label: "Slack", Category: "chat", Description: "Slack incoming-webhook alert delivery"},
		{ID: "msteams", Label: "Microsoft Teams", Category: "chat", Description: "Microsoft Teams incoming-webhook alert delivery"},
		{ID: "sms", Label: "SMS", Category: "mobile", Description: "SMS gateway alert delivery"},
		{ID: "siem", Label: "SIEM", Category: "security", Description: "Security-event collector alert delivery"},
		{ID: "pagerduty", Label: "PagerDuty", Category: "incident", Description: "PagerDuty Events API alert delivery"},
		{ID: "opsgenie", Label: "OpsGenie", Category: "incident", Description: "OpsGenie alert delivery"},
		{ID: "webhook", Label: "Webhook", Category: "webhook", Description: "Generic HMAC-signed webhook alert delivery"},
	}
	seen := make(map[string]bool, len(base))
	for i := range base {
		base[i].Configured = configuredSet[base[i].ID]
		base[i].Enabled = base[i].Configured
		base[i].ChannelType = base[i].ID
		base[i].Source = "process"
		base[i].Delivery = "notification.* outbox fanout"
		seen[base[i].ID] = true
	}
	for _, name := range configured {
		id := canonicalNotificationChannelID(name)
		if id == "" || seen[id] {
			continue
		}
		base = append(base, notificationChannelResponse{
			ID: id, Label: id, Category: "custom", Configured: true,
			Enabled: true, ChannelType: id, Source: "process",
			Delivery: "notification.* outbox fanout", Description: "Custom registered notification sink",
		})
		seen[id] = true
	}
	return base
}

func notificationChannelFamilySupported(id string) bool {
	id = canonicalNotificationChannelID(id)
	for _, channel := range notificationChannelCatalog(nil) {
		if channel.ID == id {
			return true
		}
	}
	return false
}

func notificationChannelDefaultLabel(id string) string {
	id = canonicalNotificationChannelID(id)
	for _, channel := range notificationChannelCatalog(nil) {
		if channel.ID == id {
			return channel.Label
		}
	}
	return ""
}

func notificationChannelCategory(id string) string {
	id = canonicalNotificationChannelID(id)
	for _, channel := range notificationChannelCatalog(nil) {
		if channel.ID == id {
			return channel.Category
		}
	}
	return "custom"
}

func notificationChannelDescription(id string) string {
	id = canonicalNotificationChannelID(id)
	for _, channel := range notificationChannelCatalog(nil) {
		if channel.ID == id {
			return channel.Description
		}
	}
	return "Tenant-authored notification sink"
}

func canonicalNotificationChannelID(name string) string {
	id := strings.ToLower(strings.TrimSpace(name))
	compact := strings.NewReplacer(" ", "", "-", "", "_", "").Replace(id)
	switch compact {
	case "teams", "microsoftteams", "msftteams", "msteams":
		return "msteams"
	default:
		return id
	}
}
