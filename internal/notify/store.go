package notify

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/netsec"
	"trstctl.com/trstctl/internal/projections"
	"trstctl.com/trstctl/internal/store"
)

// StorePolicyResolver adapts the tenant-scoped PostgreSQL read model to the
// dispatcher PolicyResolver interface.
type StorePolicyResolver struct {
	store *store.Store
}

// NewStorePolicyResolver builds a PostgreSQL-backed notification routing
// resolver. A nil store behaves like no policy, preserving fan-out.
func NewStorePolicyResolver(s *store.Store) *StorePolicyResolver {
	return &StorePolicyResolver{store: s}
}

// ResolveNotificationPolicy loads one tenant's policy. Missing policy ids fall
// back to fan-out; datastore errors fail dispatch so the outbox retries later.
func (r *StorePolicyResolver) ResolveNotificationPolicy(ctx context.Context, tenantID, policyID string) (RoutingPolicy, bool, error) {
	if r == nil || r.store == nil || strings.TrimSpace(tenantID) == "" || strings.TrimSpace(policyID) == "" {
		return RoutingPolicy{}, false, nil
	}
	p, err := r.store.GetNotificationRoutingPolicy(ctx, tenantID, policyID)
	if err != nil {
		if store.IsNotFound(err) {
			return RoutingPolicy{}, false, nil
		}
		return RoutingPolicy{}, false, err
	}
	return RoutingPolicy{
		TenantID:           p.TenantID,
		ID:                 p.ID,
		ChannelsBySeverity: p.ChannelsBySeverity,
		DefaultChannels:    p.DefaultChannels,
	}, true, nil
}

// StoreChannelResolver adapts tenant-authored channel configs to dispatcher
// notifiers. It resolves endpoint metadata and credential references from the
// tenant-scoped read model; credential values are never read or returned here.
type StoreChannelResolver struct {
	store                  *store.Store
	client                 HTTPDoer
	skipEndpointValidation bool
}

// NewStoreChannelResolver builds a PostgreSQL-backed notification channel
// resolver. A nil store behaves like no tenant-authored channels.
func NewStoreChannelResolver(s *store.Store) *StoreChannelResolver {
	return &StoreChannelResolver{
		store:  s,
		client: netsec.SafeClient(10 * time.Second),
	}
}

// SetHTTPClient injects an HTTP client for tests, where httptest endpoints use
// loopback HTTP. Production callers should use the default SSRF-safe client.
func (r *StoreChannelResolver) SetHTTPClient(c HTTPDoer) {
	if r == nil || c == nil {
		return
	}
	r.client = c
	r.skipEndpointValidation = true
}

// ResolveNotificationChannels returns enabled tenant-authored channels matching
// names. When names is empty it returns every enabled tenant-authored channel.
func (r *StoreChannelResolver) ResolveNotificationChannels(ctx context.Context, tenantID string, names []string) ([]Notifier, error) {
	if r == nil || r.store == nil || strings.TrimSpace(tenantID) == "" {
		return nil, nil
	}
	wanted := make(map[string]bool, len(names))
	for _, name := range names {
		id := normalizeChannelName(name)
		if id != "" {
			wanted[id] = true
		}
	}
	var rows []store.NotificationChannel
	var err error
	if len(wanted) == 1 {
		for id := range wanted {
			var ch store.NotificationChannel
			ch, err = r.store.GetNotificationChannel(ctx, tenantID, id)
			if err != nil {
				if store.IsNotFound(err) {
					return nil, nil
				}
				return nil, err
			}
			rows = []store.NotificationChannel{ch}
		}
	} else {
		rows, err = r.store.ListNotificationChannels(ctx, tenantID)
		if err != nil {
			return nil, err
		}
	}
	out := make([]Notifier, 0, len(rows))
	for _, ch := range rows {
		id := normalizeChannelName(ch.ID)
		if id == "" || !ch.Enabled || strings.TrimSpace(ch.EndpointURL) == "" {
			continue
		}
		if len(wanted) > 0 && !wanted[id] {
			continue
		}
		out = append(out, tenantHTTPChannel{
			id:                     id,
			endpoint:               strings.TrimSpace(ch.EndpointURL),
			client:                 r.client,
			skipEndpointValidation: r.skipEndpointValidation,
		})
	}
	return out, nil
}

// HTTPDoer is the minimal HTTP client seam used by tenant-authored channels.
type HTTPDoer interface {
	Do(*http.Request) (*http.Response, error)
}

type tenantHTTPChannel struct {
	id                     string
	endpoint               string
	client                 HTTPDoer
	skipEndpointValidation bool
}

func (c tenantHTTPChannel) Name() string { return c.id }

func (c tenantHTTPChannel) Notify(ctx context.Context, alert Alert) error {
	if !c.skipEndpointValidation {
		if err := netsec.ValidatePublicHTTPSURL(c.endpoint); err != nil {
			return fmt.Errorf("tenant channel %q: validate endpoint: %w", c.id, err)
		}
	}
	payload, err := json.Marshal(alert)
	if err != nil {
		return fmt.Errorf("tenant channel %q: marshal alert: %w", c.id, err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.endpoint, bytes.NewReader(payload))
	if err != nil {
		return fmt.Errorf("tenant channel %q: invalid endpoint", c.id)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Trstctl-Notification-Channel", c.id)
	client := c.client
	if client == nil {
		client = netsec.SafeClient(10 * time.Second)
	}
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("tenant channel %q: request failed", c.id)
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 1024))
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("tenant channel %q: endpoint returned HTTP %d", c.id, resp.StatusCode)
	}
	return nil
}

// StoreThresholdDedupLedger adapts the event-sourced notification threshold
// delivery projection to the dispatcher dedup interface.
type StoreThresholdDedupLedger struct {
	store     *store.Store
	log       *events.Log
	projector *projections.Projector
}

// NewStoreThresholdDedupLedger builds a PostgreSQL/event-log-backed threshold
// delivery ledger. The event log remains the source of truth; the PostgreSQL
// table is projected for fast dispatch checks.
func NewStoreThresholdDedupLedger(s *store.Store, log *events.Log) *StoreThresholdDedupLedger {
	var projector *projections.Projector
	if s != nil {
		projector = projections.New(s)
	}
	return &StoreThresholdDedupLedger{store: s, log: log, projector: projector}
}

// HasThresholdNotificationOnChannel consults the tenant-scoped projected ledger.
func (l *StoreThresholdDedupLedger) HasThresholdNotificationOnChannel(ctx context.Context, tenantID, subject string, threshold int, channel string) (bool, error) {
	if l == nil || l.store == nil {
		return false, nil
	}
	return l.store.HasThresholdNotificationOnChannel(ctx, tenantID, subject, threshold, channel)
}

// RecordThresholdNotificationOnChannel appends and immediately projects a
// notification.threshold.delivered event.
func (l *StoreThresholdDedupLedger) RecordThresholdNotificationOnChannel(ctx context.Context, rec ThresholdNotificationDelivery) error {
	if l == nil || l.store == nil {
		return nil
	}
	if l.log == nil || l.projector == nil {
		return fmt.Errorf("notify: threshold dedup ledger requires event log and projector")
	}
	payload, err := json.Marshal(projections.NotificationThresholdDelivered{
		Subject: rec.Subject, ThresholdDays: rec.ThresholdDays, Channel: rec.Channel, SentAt: rec.SentAt,
	})
	if err != nil {
		return err
	}
	ev, err := l.log.Append(ctx, events.Event{
		Type: projections.EventNotificationThresholdDelivered, TenantID: rec.TenantID, Data: payload,
	})
	if err != nil {
		return err
	}
	return l.projector.Apply(ctx, ev)
}
