// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"net/url"
	"strings"

	"github.com/google/uuid"

	"trstctl.com/trstctl/internal/crypto"
)

// tenantBoundPlatformRevocationProfile prevents a deployment-wide URL for one
// trstctl tenant's public responder from being stamped on another tenant's
// leaf. Operator-owned issuer-wide responders remain untouched. A literal
// {tenant_id} in a configured path is also expanded for new deployments.
func tenantBoundPlatformRevocationProfile(base crypto.LeafProfile, tenantID string) crypto.LeafProfile {
	base.EnforceBoundSubject = true
	base.CRLDistributionPoints = append([]string(nil), base.CRLDistributionPoints...)
	base.OCSPServers = append([]string(nil), base.OCSPServers...)
	for i, raw := range base.CRLDistributionPoints {
		base.CRLDistributionPoints[i] = tenantBoundRevocationURL(raw, "crl", tenantID)
	}
	for i, raw := range base.OCSPServers {
		base.OCSPServers[i] = tenantBoundRevocationURL(raw, "ocsp", tenantID)
	}
	return base
}

// platformFullCRLScopes names only the tenant routes on the platform's own
// public responder. An issuer-wide external CDP is a different publisher and
// cannot make this tenant's partial CRL complete for every tenant under the
// shared CA. Without a tenant route, a private tenant URI keeps the published
// CRL explicitly scoped; clients need an external issuer-wide list instead.
func platformFullCRLScopes(base crypto.LeafProfile, tenantID string) []string {
	bound := tenantBoundPlatformRevocationProfile(base, tenantID)
	var scopes []string
	seen := make(map[string]struct{})
	for _, raw := range bound.CRLDistributionPoints {
		u, err := url.Parse(raw)
		if err != nil || u.Scheme == "" || u.Host == "" || u.User != nil {
			continue
		}
		parts := strings.Split(u.Path, "/")
		if len(parts) < 3 || parts[len(parts)-2] != "crl" {
			continue
		}
		last := parts[len(parts)-1]
		if last != tenantID && last != tenantID+".crl" {
			continue
		}
		if _, exists := seen[raw]; !exists {
			seen[raw] = struct{}{}
			scopes = append(scopes, raw)
		}
	}
	if len(scopes) == 0 {
		return []string{"urn:trstctl:tenant-crl:" + tenantID}
	}
	return scopes
}

func tenantBoundRevocationURL(raw, kind, tenantID string) string {
	parsed, err := url.Parse(raw)
	if err != nil || parsed.Scheme == "" || parsed.Host == "" || parsed.User != nil {
		return raw
	}
	parts := strings.Split(parsed.Path, "/")
	if len(parts) < 3 || parts[len(parts)-2] != kind {
		return raw
	}
	last := parts[len(parts)-1]
	suffix := ""
	if kind == "crl" && strings.HasSuffix(last, ".crl") {
		last = strings.TrimSuffix(last, ".crl")
		suffix = ".crl"
	}
	if last != "{tenant_id}" {
		if _, err := uuid.Parse(last); err != nil {
			return raw
		}
	}
	parts[len(parts)-1] = tenantID + suffix
	parsed.Path = strings.Join(parts, "/")
	parsed.RawPath = ""
	return parsed.String()
}
