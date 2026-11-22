// SPDX-License-Identifier: BUSL-1.1

package authmethod

import (
	"net/url"
	"strings"

	"github.com/google/uuid"
)

// AzureTenantFromIssuer recognizes a tenant-specific Entra v2 issuer or the
// legacy STS issuer. Common, organizations and consumers are not tenant pins.
// A caller must still compare the signed tid claim to the returned tenant.
func AzureTenantFromIssuer(issuer string) string {
	u, err := url.Parse(issuer)
	if err != nil || u.Scheme != "https" || u.Hostname() == "" || u.User != nil ||
		u.Opaque != "" || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" || u.EscapedPath() != u.Path {
		return ""
	}
	path := strings.TrimSuffix(u.Path, "/")
	parts := strings.Split(strings.TrimPrefix(path, "/"), "/")
	if len(parts) != 1 && (len(parts) != 2 || parts[1] != "v2.0") {
		return ""
	}
	id, err := uuid.Parse(parts[0])
	if err != nil || id == uuid.Nil || !strings.EqualFold(parts[0], id.String()) {
		return ""
	}
	return id.String()
}
