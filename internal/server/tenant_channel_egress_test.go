// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"context"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"sync/atomic"
	"testing"

	"github.com/jackc/pgx/v5"

	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/egress"
	"trstctl.com/trstctl/internal/netsec"
	"trstctl.com/trstctl/internal/store"
)

func TestTenantNotificationFactoryUsesOnlyTheRowsTenantGrant(t *testing.T) {
	policy := tenantNotificationEgress{"a": {netip.MustParsePrefix("10.40.0.0/16")}}
	factory := policy.factory(nil)
	for _, tc := range []struct {
		tenant, endpoint string
		allowed          bool
	}{
		{"a", "https://10.40.0.9/hook", true},
		{"b", "https://10.40.0.9/hook", false},
		{"a", "https://10.41.0.9/hook", false},
		{"a", "http://10.40.0.9/hook", false},
		{"a", "https://169.254.169.254/hook", false},
		{"a", "https://[fd00:ec2::254]/hook", false},
	} {
		ch, err := factory(store.NotificationChannel{ID: "webhook", TenantID: tc.tenant, EndpointURL: tc.endpoint}, nil, nil)
		if (err == nil) != tc.allowed {
			t.Fatalf("factory %s %s: %v", tc.tenant, tc.endpoint, err)
		}
		if ch != nil {
			ch.Release()
		}
	}
	client := policy.client("a", nil)
	if err := client.CheckRedirect(httptest.NewRequest(http.MethodGet, "https://10.41.0.9/hook", nil), []*http.Request{httptest.NewRequest(http.MethodGet, "https://10.40.0.9/hook", nil)}); !errors.Is(err, netsec.ErrSSRFBlocked) {
		t.Fatalf("redirect outside grant: %v", err)
	}
	guard, err := egress.NewGuard(egress.Config{Enabled: true})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := policy.client("a", guard).Get("https://10.40.0.9/hook"); !errors.Is(err, egress.ErrBlocked) {
		t.Fatalf("air-gap bypass: %v", err)
	}
}

// This uses an owned TLS listener on a real private interface, not a client
// that rewrites requests to loopback. Only the throwaway CA trust is injected;
// the production client's resolved-address guard and redirects stay installed.
func TestServedTenantPrivateWebhookDeliversOverGuardedTLS(t *testing.T) {
	addresses, err := net.InterfaceAddrs()
	if err != nil {
		t.Fatal(err)
	}
	var address netip.Addr
	for _, candidate := range addresses {
		p, err := netip.ParsePrefix(candidate.String())
		if err == nil && p.Addr().Is4() && p.Addr().IsPrivate() {
			address = p.Addr()
			break
		}
	}
	if !address.IsValid() {
		t.Skip("live private TLS delivery needs a private IPv4 interface")
	}
	listener, err := net.Listen("tcp", net.JoinHostPort(address.String(), "0"))
	if err != nil {
		t.Fatal(err)
	}
	var deliveries atomic.Int32
	sink := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.Header.Get("X-Trstctl-Notification-Channel") != "webhook" {
			t.Error("unexpected webhook request")
		}
		deliveries.Add(1)
		w.WriteHeader(http.StatusAccepted)
	}))
	_ = sink.Listener.Close()
	sink.Listener = listener
	sink.StartTLS()
	defer sink.Close()
	grant := []config.TenantPrivateEgress{{TenantID: servedTestTenant, CIDRs: []string{netip.PrefixFrom(address, 32).String()}}}
	h := newOperatingServedHarness(t, config.Protocols{}, func(d *Deps) { d.NotificationTenantEgress = grant })
	client := h.srv.tenantNotificationEgress.client(h.tenant, nil)
	transport := client.Transport.(*http.Transport)
	transport.TLSClientConfig.RootCAs = sink.Client().Transport.(*http.Transport).TLSClientConfig.RootCAs
	transport.TLSClientConfig.ServerName = "example.com" // httptest's server certificate SAN.
	h.srv.notificationTenantChannels.SetHTTPClient(client)
	tok := seedScopedToken(t, h.store, h.tenant, "notifications:read", "notifications:write")
	status, body := secretsReqKey(t, h, http.MethodPost, "/api/v1/notification-channels", tok, "a223-create-live", map[string]any{"id": "webhook", "channel_type": "webhook", "endpoint_url": sink.URL + "/hook", "enabled": true})
	if status != http.StatusCreated {
		t.Fatalf("create = %d %s", status, body)
	}
	status, body = secretsReqKey(t, h, http.MethodPost, "/api/v1/notification-channels/webhook/test", tok, "a223-deliver-live", map[string]any{"subject": "Private webhook", "severity": "critical"})
	if status != http.StatusAccepted {
		t.Fatalf("test = %d %s", status, body)
	}
	if err := h.srv.Drain(context.Background()); err != nil {
		t.Fatal(err)
	}
	if got := deliveries.Load(); got != 1 {
		t.Fatalf("private TLS receiver saw %d deliveries, want 1", got)
	}
	var receipts int
	if err := h.store.WithTenant(t.Context(), h.tenant, func(tx pgx.Tx) error {
		return tx.QueryRow(t.Context(), `SELECT count(*) FROM notification_delivery_receipts WHERE tenant_id = $1 AND channel = 'webhook'`, h.tenant).Scan(&receipts)
	}); err != nil {
		t.Fatal(err)
	}
	if receipts != 1 {
		t.Fatalf("durable webhook receipts = %d, want 1", receipts)
	}
	// Without this tenant's grant, the very same socket is refused by the
	// real dialer before TLS, rather than inheriting another tenant's policy.
	other := h.srv.tenantNotificationEgress.client("22222222-2222-2222-2222-222222222222", nil)
	_, err = other.Get(sink.URL + "/hook")
	if !errors.Is(err, netsec.ErrSSRFBlocked) {
		t.Fatalf("other tenant dial = %v, want SSRF refusal", err)
	}
	if deliveries.Load() != 1 {
		t.Fatal("ungranted tenant reached the receiver")
	}
}
