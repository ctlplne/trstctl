// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"sync/atomic"
	"testing"

	"trstctl.com/trstctl/internal/api"
	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/events"
)

// A223-L1: a tenant baseline (what a Provider tenant template applies) may
// name a webhook at a private address, decided by the operator's grant for
// the tenant it is applied to. The baseline is validated before any tenant is
// known, and that validation refused every private literal, so a template
// could not carry one even for a granted tenant. It now accepts an address an
// operator could grant (never loopback, link-local, CGNAT or a metadata
// address) and the apply step checks the tenant's own grant: granted, the
// channel is created and delivers over TLS to the private receiver; without
// the grant, that one object fails naming the grant and the rest applies.
func TestServedTenantBaselinePrivateWebhookFollowsTheTenantsGrantA223L1(t *testing.T) {
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
		if r.Method == http.MethodPost && r.Header.Get("X-Trstctl-Notification-Channel") == "webhook" {
			deliveries.Add(1)
		}
		w.WriteHeader(http.StatusAccepted)
	}))
	_ = sink.Listener.Close()
	sink.Listener = listener
	sink.StartTLS()
	defer sink.Close()
	endpoint := sink.URL + "/hook"
	baseline := api.TenantBaseline{
		NotificationChannels: []api.BaselineNotificationChannel{{ChannelType: "webhook", EndpointURL: endpoint}},
		Members:              []api.BaselineMember{{Subject: "a223l1-admin@customer.example", Email: "a223l1-admin@customer.example", Roles: []string{"operator"}}},
	}

	for _, granted := range []bool{false, true} {
		t.Run(map[bool]string{false: "no grant", true: "granted"}[granted], func(t *testing.T) {
			h := newOperatingServedHarness(t, config.Protocols{}, func(d *Deps) {
				if granted {
					d.NotificationTenantEgress = []config.TenantPrivateEgress{{TenantID: servedTestTenant, CIDRs: []string{netip.PrefixFrom(address, 32).String()}}}
				}
			})
			// Before a tenant is known, the private address is one an operator
			// could grant; what no grant can open stays refused.
			if err := h.srv.api.ValidateTenantBaseline(baseline); err != nil {
				t.Fatalf("a baseline naming a grantable private webhook was refused before any tenant: %v", err)
			}
			for _, refused := range []string{"http://" + net.JoinHostPort(address.String(), "443") + "/hook", "https://127.0.0.1/hook",
				"https://169.254.169.254/latest", "https://[fd00:ec2::254]/hook", "https://100.64.0.9/hook"} {
				bad := api.TenantBaseline{NotificationChannels: []api.BaselineNotificationChannel{{ChannelType: "webhook", EndpointURL: refused}}}
				if err := h.srv.api.ValidateTenantBaseline(bad); err == nil {
					t.Fatalf("a baseline webhook at %s was accepted", refused)
				}
			}

			ctx := events.ContextWithActor(t.Context(), events.Actor{Subject: "provider:ops@provider.example"})
			applied, err := h.srv.api.ApplyTenantBaseline(ctx, h.tenant, "a223-l1", baseline)
			if err != nil {
				t.Fatalf("apply the baseline: %v", err)
			}
			outcomes := map[string]api.BaselineObjectResult{}
			for _, r := range applied.Results {
				outcomes[r.Kind] = r
			}
			channel, member := outcomes[api.BaselineKindNotificationChannel], outcomes[api.BaselineKindMember]
			if member.Outcome != api.BaselineCreated {
				t.Fatalf("the member object = %s (%s); the other objects still apply", member.Outcome, member.Error)
			}
			if !granted {
				if channel.Outcome != api.BaselineFailed || !strings.Contains(channel.Error, "operator-granted private range for this tenant") || applied.Complete {
					t.Fatalf("an ungranted tenant's private webhook = %s (%q), complete=%v; want that object refused naming the grant", channel.Outcome, channel.Error, applied.Complete)
				}
				if _, err := h.store.GetNotificationChannel(t.Context(), h.tenant, "webhook"); err == nil {
					t.Fatal("the refused webhook channel was written")
				}
				return
			}
			if channel.Outcome != api.BaselineCreated || !applied.Complete {
				t.Fatalf("a granted tenant's private webhook = %s (%q), complete=%v", channel.Outcome, channel.Error, applied.Complete)
			}
			// The channel the baseline wrote delivers through the tenant's
			// own guarded client to the private receiver, over TLS.
			client := h.srv.tenantNotificationEgress.client(h.tenant, nil)
			transport := client.Transport.(*http.Transport)
			transport.TLSClientConfig.RootCAs = sink.Client().Transport.(*http.Transport).TLSClientConfig.RootCAs
			transport.TLSClientConfig.ServerName = "example.com" // httptest's server certificate SAN.
			h.srv.notificationTenantChannels.SetHTTPClient(client)
			tok := seedScopedToken(t, h.store, h.tenant, "notifications:read", "notifications:write")
			status, body := secretsReqKey(t, h, http.MethodPost, "/api/v1/notification-channels/webhook/test", tok, "a223l1-deliver",
				map[string]any{"subject": "Private webhook from a baseline", "severity": "critical"})
			if status != http.StatusAccepted {
				t.Fatalf("test the baseline's channel = %d %s", status, body)
			}
			if err := h.srv.Drain(context.Background()); err != nil {
				t.Fatal(err)
			}
			if got := deliveries.Load(); got != 1 {
				t.Fatalf("the private TLS receiver saw %d deliveries, want 1", got)
			}
		})
	}
}
