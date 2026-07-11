// SPDX-License-Identifier: MPL-2.0

package server

import (
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strings"
	"time"

	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/crypto/secret"
	"trstctl.com/trstctl/internal/egress"
	"trstctl.com/trstctl/internal/netsec"
	"trstctl.com/trstctl/internal/notify"
	"trstctl.com/trstctl/internal/notify/opsgenie"
	"trstctl.com/trstctl/internal/notify/pagerduty"
)

const (
	pagerDutyEventsV2Endpoint = "https://events.pagerduty.com/v2/enqueue"
	opsGenieAlertsV2Endpoint  = "https://api.opsgenie.com/v2/alerts"
)

// incidentNotificationChannelsFromConfig constructs the two native incident
// channels on the production buildRunDeps call graph. It loads credential files
// once, moves the owned bytes into locked channel buffers, and wipes every
// transient copy before returning.
func incidentNotificationChannelsFromConfig(cfg config.Notifications, guard *egress.Guard) ([]notify.Notifier, error) {
	// Inline credentials are consumed by this constructor. Each channel takes an
	// owned copy into locked memory; keeping the config slice alive afterward
	// would leave a second dumpable copy in the control-plane heap (AN-8).
	defer secret.Wipe(cfg.PagerDuty.RoutingKey)
	defer secret.Wipe(cfg.OpsGenie.APIKey)
	var channels []notify.Notifier
	closeOnError := func() { closeNotificationChannels(channels) }

	if cfg.PagerDuty.Enabled {
		key, err := notificationSecret(cfg.PagerDuty.RoutingKey, cfg.PagerDuty.RoutingKeyFile, "PagerDuty routing key")
		if err != nil {
			return nil, err
		}
		defer secret.Wipe(key)
		endpoint := nonemptyString(strings.TrimSpace(cfg.PagerDuty.Endpoint), pagerDutyEventsV2Endpoint)
		client, err := incidentNotificationHTTPClient(endpoint, cfg.PagerDuty.TimeoutDuration, cfg.PagerDuty.AllowPrivateCIDRs, cfg.PagerDuty.AllowInsecureHTTP, guard)
		if err != nil {
			return nil, fmt.Errorf("pagerduty: %w", err)
		}
		channel, err := pagerduty.New(key, pagerduty.WithEndpoint(endpoint), pagerduty.WithHTTPClient(client))
		if err != nil {
			return nil, err
		}
		channels = append(channels, channel)
	}

	if cfg.OpsGenie.Enabled {
		key, err := notificationSecret(cfg.OpsGenie.APIKey, cfg.OpsGenie.APIKeyFile, "OpsGenie API key")
		if err != nil {
			closeOnError()
			return nil, err
		}
		defer secret.Wipe(key)
		endpoint := nonemptyString(strings.TrimSpace(cfg.OpsGenie.Endpoint), opsGenieAlertsV2Endpoint)
		client, err := incidentNotificationHTTPClient(endpoint, cfg.OpsGenie.TimeoutDuration, cfg.OpsGenie.AllowPrivateCIDRs, cfg.OpsGenie.AllowInsecureHTTP, guard)
		if err != nil {
			closeOnError()
			return nil, fmt.Errorf("opsgenie: %w", err)
		}
		channel, err := opsgenie.New(key, opsgenie.WithEndpoint(endpoint), opsgenie.WithHTTPClient(client))
		if err != nil {
			closeOnError()
			return nil, err
		}
		channels = append(channels, channel)
	}
	return channels, nil
}

func closeNotificationChannelsOnError(channels []notify.Notifier, buildErr error) {
	if buildErr != nil {
		closeNotificationChannels(channels)
	}
}

func closeNotificationChannels(channels []notify.Notifier) {
	for _, channel := range channels {
		if closer, ok := channel.(interface{ Close() }); ok {
			closer.Close()
		}
	}
}

type notificationTimeout func() (time.Duration, error)

func incidentNotificationHTTPClient(endpoint string, timeoutValue notificationTimeout, rawCIDRs []string, allowInsecureHTTP bool, guard *egress.Guard) (*http.Client, error) {
	timeout, err := timeoutValue()
	if err != nil || timeout <= 0 {
		if err == nil {
			err = fmt.Errorf("timeout must be positive")
		}
		return nil, fmt.Errorf("invalid timeout: %w", err)
	}
	prefixes := make([]netip.Prefix, 0, len(rawCIDRs))
	for _, raw := range rawCIDRs {
		prefix, err := netip.ParsePrefix(strings.TrimSpace(raw))
		if err != nil {
			return nil, fmt.Errorf("invalid allow_private_cidrs entry %q: %w", raw, err)
		}
		prefixes = append(prefixes, prefix)
	}
	opts := netsec.SafeClientOptions{AllowPrivateCIDRs: prefixes}
	u, err := url.Parse(endpoint)
	if err != nil || u.Host == "" {
		return nil, fmt.Errorf("endpoint must be an absolute URL")
	}
	switch u.Scheme {
	case "https":
		if err := netsec.ValidatePublicHTTPSURLWithOptions(endpoint, opts); err != nil {
			return nil, fmt.Errorf("validate endpoint: %w", err)
		}
	case "http":
		if !allowInsecureHTTP || !notificationLoopbackHost(u.Hostname()) {
			return nil, fmt.Errorf("endpoint must use https; explicit insecure http is allowed only for loopback development/emulators")
		}
	default:
		return nil, fmt.Errorf("endpoint has unsupported scheme %q", u.Scheme)
	}
	client := netsec.SafeClientWithOptions(timeout, opts)
	if guard != nil && guard.Enabled() {
		client.Transport = guard.WrapTransport(client.Transport)
	}
	return client, nil
}

func notificationLoopbackHost(host string) bool {
	if strings.EqualFold(strings.TrimSpace(host), "localhost") {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

func nonemptyString(values ...string) string {
	for _, value := range values {
		if value != "" {
			return value
		}
	}
	return ""
}
