// SPDX-License-Identifier: BUSL-1.1

package config

import (
	"fmt"
	"net/url"
	"strings"

	"trstctl.com/trstctl/internal/netsec"
)

// validateNotificationEgress checks one operator channel's private-egress
// policy (A99): every allow_private_cidrs entry must be an exact network
// address, and a non-HTTPS endpoint is accepted only as loopback insecure HTTP
// under allow_insecure_http. It is the Slack/Teams/SMS/SIEM twin of the
// incident channels' validation; an empty endpoint is reported elsewhere.
func validateNotificationEgress(name, endpointField, endpoint string, privateCIDRs []string, allowInsecureHTTP bool) []error {
	var errs []error
	for _, raw := range privateCIDRs {
		if _, err := netsec.ParseEgressAllowPrefix(raw); err != nil {
			errs = append(errs, fmt.Errorf("%s.allow_private_cidrs entry %q is invalid: %w", name, raw, err))
		}
	}
	endpoint = strings.TrimSpace(endpoint)
	if endpoint == "" {
		return errs
	}
	u, err := url.Parse(endpoint)
	if err != nil || u.Host == "" {
		return append(errs, fmt.Errorf("%s.%s %q must be an absolute URL", name, endpointField, endpoint))
	}
	if u.Scheme == "https" {
		return errs
	}
	if u.Scheme != "http" || !allowInsecureHTTP || !isIncidentLoopbackHost(u.Hostname()) {
		errs = append(errs, fmt.Errorf("%s.%s must use https; explicit insecure http is allowed only for loopback development/emulators", name, endpointField))
	}
	return errs
}
