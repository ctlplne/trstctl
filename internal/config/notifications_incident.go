// SPDX-License-Identifier: BUSL-1.1

package config

import (
	"fmt"
	"net"
	"net/url"
	"strings"
	"time"

	"trstctl.com/trstctl/internal/netsec"
)

const defaultIncidentNotificationTimeout = 10 * time.Second

// NotificationPagerDuty configures PagerDuty Events API v2 incident delivery.
// RoutingKey is byte-native authority material; RoutingKeyFile is preferred for
// production so the credential does not appear in a JSON configuration document.
type NotificationPagerDuty struct {
	Enabled           bool     `json:"enabled,omitempty"`
	Endpoint          string   `json:"endpoint,omitempty"`
	RoutingKey        []byte   `json:"routing_key,omitempty"`
	RoutingKeyFile    string   `json:"routing_key_file,omitempty"`
	Timeout           string   `json:"timeout,omitempty"`
	AllowPrivateCIDRs []string `json:"allow_private_cidrs,omitempty"`
	AllowInsecureHTTP bool     `json:"allow_insecure_http,omitempty"`
}

// TimeoutDuration parses the PagerDuty request deadline. Empty selects the
// bounded production default.
func (c NotificationPagerDuty) TimeoutDuration() (time.Duration, error) {
	return incidentNotificationTimeout(c.Timeout)
}

// NotificationOpsGenie configures OpsGenie Alert API delivery. APIKey is
// byte-native authority material; APIKeyFile is preferred for production.
type NotificationOpsGenie struct {
	Enabled           bool     `json:"enabled,omitempty"`
	Endpoint          string   `json:"endpoint,omitempty"`
	APIKey            []byte   `json:"api_key,omitempty"`
	APIKeyFile        string   `json:"api_key_file,omitempty"`
	Timeout           string   `json:"timeout,omitempty"`
	AllowPrivateCIDRs []string `json:"allow_private_cidrs,omitempty"`
	AllowInsecureHTTP bool     `json:"allow_insecure_http,omitempty"`
}

// TimeoutDuration parses the OpsGenie request deadline. Empty selects the
// bounded production default.
func (c NotificationOpsGenie) TimeoutDuration() (time.Duration, error) {
	return incidentNotificationTimeout(c.Timeout)
}

func incidentNotificationTimeout(raw string) (time.Duration, error) {
	if strings.TrimSpace(raw) == "" {
		return defaultIncidentNotificationTimeout, nil
	}
	return time.ParseDuration(raw)
}

// setIncidentNotificationEnv is called by config.go's notification overlay. It
// stays separate so the two native incident channels do not make that central
// file carry their field-by-field construction rules.
func setIncidentNotificationEnv(getenv func(string) string, pagerDuty *NotificationPagerDuty, opsGenie *NotificationOpsGenie) {
	if pagerDuty != nil {
		setBool(getenv, "TRSTCTL_NOTIFICATIONS_PAGERDUTY_ENABLED", &pagerDuty.Enabled)
		setString(getenv, "TRSTCTL_NOTIFICATIONS_PAGERDUTY_ENDPOINT", &pagerDuty.Endpoint)
		setBytes(getenv, "TRSTCTL_NOTIFICATIONS_PAGERDUTY_ROUTING_KEY", &pagerDuty.RoutingKey)
		setString(getenv, "TRSTCTL_NOTIFICATIONS_PAGERDUTY_ROUTING_KEY_FILE", &pagerDuty.RoutingKeyFile)
		setString(getenv, "TRSTCTL_NOTIFICATIONS_PAGERDUTY_TIMEOUT", &pagerDuty.Timeout)
		setCSV(getenv, "TRSTCTL_NOTIFICATIONS_PAGERDUTY_ALLOW_PRIVATE_CIDRS", &pagerDuty.AllowPrivateCIDRs)
		setBool(getenv, "TRSTCTL_NOTIFICATIONS_PAGERDUTY_ALLOW_INSECURE_HTTP", &pagerDuty.AllowInsecureHTTP)
	}
	if opsGenie != nil {
		setBool(getenv, "TRSTCTL_NOTIFICATIONS_OPSGENIE_ENABLED", &opsGenie.Enabled)
		setString(getenv, "TRSTCTL_NOTIFICATIONS_OPSGENIE_ENDPOINT", &opsGenie.Endpoint)
		setBytes(getenv, "TRSTCTL_NOTIFICATIONS_OPSGENIE_API_KEY", &opsGenie.APIKey)
		setString(getenv, "TRSTCTL_NOTIFICATIONS_OPSGENIE_API_KEY_FILE", &opsGenie.APIKeyFile)
		setString(getenv, "TRSTCTL_NOTIFICATIONS_OPSGENIE_TIMEOUT", &opsGenie.Timeout)
		setCSV(getenv, "TRSTCTL_NOTIFICATIONS_OPSGENIE_ALLOW_PRIVATE_CIDRS", &opsGenie.AllowPrivateCIDRs)
		setBool(getenv, "TRSTCTL_NOTIFICATIONS_OPSGENIE_ALLOW_INSECURE_HTTP", &opsGenie.AllowInsecureHTTP)
	}
}

func validateIncidentNotifications(pagerDuty NotificationPagerDuty, opsGenie NotificationOpsGenie) []error {
	var errs []error
	if pagerDuty.Enabled {
		errs = append(errs, validateIncidentNotification(
			"notifications.pagerduty", pagerDuty.Endpoint, pagerDuty.Timeout,
			pagerDuty.AllowPrivateCIDRs, pagerDuty.AllowInsecureHTTP,
			len(pagerDuty.RoutingKey) > 0, pagerDuty.RoutingKeyFile,
		)...)
		if len(pagerDuty.RoutingKey) > 0 && strings.TrimSpace(pagerDuty.RoutingKeyFile) != "" {
			errs = append(errs, fmt.Errorf("notifications.pagerduty.routing_key and routing_key_file are mutually exclusive"))
		}
	}
	if opsGenie.Enabled {
		errs = append(errs, validateIncidentNotification(
			"notifications.opsgenie", opsGenie.Endpoint, opsGenie.Timeout,
			opsGenie.AllowPrivateCIDRs, opsGenie.AllowInsecureHTTP,
			len(opsGenie.APIKey) > 0, opsGenie.APIKeyFile,
		)...)
		if len(opsGenie.APIKey) > 0 && strings.TrimSpace(opsGenie.APIKeyFile) != "" {
			errs = append(errs, fmt.Errorf("notifications.opsgenie.api_key and api_key_file are mutually exclusive"))
		}
	}
	return errs
}

func validateIncidentNotification(name, endpoint, timeout string, privateCIDRs []string, allowInsecureHTTP, hasInlineCredential bool, credentialFile string) []error {
	var errs []error
	if !hasInlineCredential && strings.TrimSpace(credentialFile) == "" {
		errs = append(errs, fmt.Errorf("%s requires its credential bytes or credential file when enabled", name))
	}
	d, err := incidentNotificationTimeout(timeout)
	if err != nil {
		errs = append(errs, fmt.Errorf("%s.timeout %q is invalid: %w", name, timeout, err))
	} else if d <= 0 {
		errs = append(errs, fmt.Errorf("%s.timeout must be positive", name))
	}
	for _, raw := range privateCIDRs {
		if _, err := netsec.ParseEgressAllowPrefix(raw); err != nil {
			errs = append(errs, fmt.Errorf("%s.allow_private_cidrs entry %q is invalid: %w", name, raw, err))
		}
	}
	if strings.TrimSpace(endpoint) == "" {
		return errs // package default is the official public endpoint
	}
	u, err := url.Parse(endpoint)
	if err != nil || u.Host == "" {
		return append(errs, fmt.Errorf("%s.endpoint %q must be an absolute URL", name, endpoint))
	}
	if u.Scheme == "https" {
		return errs
	}
	if u.Scheme != "http" || !allowInsecureHTTP || !isIncidentLoopbackHost(u.Hostname()) {
		errs = append(errs, fmt.Errorf("%s.endpoint must use https; explicit insecure http is allowed only for loopback development/emulators", name))
	}
	return errs
}

func isIncidentLoopbackHost(host string) bool {
	if strings.EqualFold(strings.TrimSpace(host), "localhost") {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}
