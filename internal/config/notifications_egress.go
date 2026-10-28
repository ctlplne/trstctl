// SPDX-License-Identifier: BUSL-1.1

package config

import (
	"errors"
	"fmt"
	"net"
	"net/netip"
	"net/url"
	"strings"

	"github.com/google/uuid"

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

// TenantPrivateEgress grants one tenant's notification channels the named
// private networks (A223). It lives in deployment configuration, so only the
// operator sets it; loopback and link-local networks are never granted.
type TenantPrivateEgress struct {
	TenantID string   `json:"tenant_id"`
	CIDRs    []string `json:"cidrs"`
	Reason   string   `json:"reason,omitempty"`
}

func validateTenantPrivateEgress(grants []TenantPrivateEgress) []error {
	var errs []error
	seen := map[string]bool{}
	for i, grant := range grants {
		name := fmt.Sprintf("notifications.tenant_private_egress[%d]", i)
		parsedID, parseErr := uuid.Parse(strings.TrimSpace(grant.TenantID))
		id := parsedID.String()
		if parseErr != nil || parsedID == uuid.Nil {
			errs = append(errs, fmt.Errorf("%s.tenant_id %q must be a tenant id", name, grant.TenantID))
		} else if seen[id] {
			errs = append(errs, fmt.Errorf("%s.tenant_id %s is granted twice; keep one entry per tenant", name, id))
		}
		seen[id] = true
		if len(grant.CIDRs) == 0 {
			errs = append(errs, fmt.Errorf("%s.cidrs must name at least one private network", name))
		}
		for _, raw := range grant.CIDRs {
			prefix, err := netsec.ParseEgressAllowPrefix(raw)
			if err != nil {
				errs = append(errs, fmt.Errorf("%s.cidrs entry %q is invalid: %w", name, raw, err))
				continue
			}
			if !tenantPrivatePrefix(prefix) {
				errs = append(errs, fmt.Errorf("%s.cidrs entry %q is not a private network a tenant may be granted", name, raw))
			}
		}
	}
	return errs
}

// NotificationTenantPrivatePrefixes validates and copies the deployment's grants.
// Canonical UUID keys prevent alternate UUID spellings from creating two policies.
func NotificationTenantPrivatePrefixes(grants []TenantPrivateEgress) (map[string][]netip.Prefix, error) {
	if errs := validateTenantPrivateEgress(grants); len(errs) > 0 {
		return nil, errors.Join(errs...)
	}
	out := make(map[string][]netip.Prefix, len(grants))
	for _, grant := range grants {
		id, _ := uuid.Parse(strings.TrimSpace(grant.TenantID))
		for _, raw := range grant.CIDRs {
			prefix, _ := netsec.ParseEgressAllowPrefix(raw)
			out[id.String()] = append(out[id.String()], prefix)
		}
	}
	return out, nil
}

func tenantPrivatePrefix(prefix netip.Prefix) bool {
	// Check the entire range, not only its first address: 10.0.0.0/7 also
	// contains public addresses. A grant cannot include a metadata endpoint.
	metadata := netip.MustParseAddr("fd00:ec2::254")
	if prefix.Contains(metadata) {
		return false
	}
	for _, raw := range []string{"10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "fc00::/7"} {
		allowed := netip.MustParsePrefix(raw)
		if prefix.Bits() >= allowed.Bits() && allowed.Contains(prefix.Addr()) {
			return !netsec.HardBlockedIP(net.IP(prefix.Addr().AsSlice()))
		}
	}
	return false
}
