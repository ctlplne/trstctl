// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"fmt"
	"net/http"
	"net/netip"
	"strings"
	"time"

	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/crypto/secret"
	"trstctl.com/trstctl/internal/egress"
	"trstctl.com/trstctl/internal/netsec"
	"trstctl.com/trstctl/internal/notify"
	"trstctl.com/trstctl/internal/notify/tenantchannel"
	"trstctl.com/trstctl/internal/store"
)

// tenantNotificationEgress is a validated snapshot of deployment configuration.
// The same snapshot admits channel endpoints and guards each delivery's dial.
type tenantNotificationEgress map[string][]netip.Prefix

func (s *Server) configureTenantNotificationEgress(d Deps) error {
	prefixes, err := config.NotificationTenantPrivatePrefixes(d.NotificationTenantEgress)
	if err != nil {
		return fmt.Errorf("server: tenant notification egress: %w", err)
	}
	s.tenantNotificationEgress = prefixes
	return nil
}

func (p tenantNotificationEgress) validate(tenantID, endpoint string) error {
	if err := netsec.ValidatePublicHTTPSURLWithOptions(strings.TrimSpace(endpoint), netsec.SafeClientOptions{AllowPrivateCIDRs: p[tenantID]}); err != nil {
		return fmt.Errorf("endpoint must use HTTPS and a public address or an operator-granted private range for this tenant: %w", err)
	}
	return nil
}

func (p tenantNotificationEgress) factory(guard *egress.Guard) notify.ChannelFactory {
	return func(row store.NotificationChannel, credential *secret.Buffer, client notify.HTTPDoer) (notify.EphemeralNotifier, error) {
		if client == nil {
			if err := p.validate(row.TenantID, row.EndpointURL); err != nil {
				if credential != nil {
					credential.Destroy()
				}
				return nil, err
			}
			client = p.client(row.TenantID, guard)
		}
		return tenantchannel.Build(row, credential, client)
	}
}

func (p tenantNotificationEgress) client(tenantID string, guard *egress.Guard) *http.Client {
	client := netsec.SafeClientWithOptions(10*time.Second, netsec.SafeClientOptions{AllowPrivateCIDRs: p[tenantID]})
	if guard.Enabled() {
		client.Transport = guard.WrapTransport(client.Transport)
	}
	return client
}
