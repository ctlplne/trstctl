// SPDX-License-Identifier: BUSL-1.1

package editionseam

import (
	"time"

	"trstctl.com/trstctl/internal/api"
	"trstctl.com/trstctl/internal/auth"
	"trstctl.com/trstctl/internal/config"
)

// TenantAuthFactory is attached once by the commercial composition root. OIDC,
// session persistence and HTTP authentication hooks remain core-owned.
type TenantAuthFactory func(TenantAuthDeps) (TenantAuthConfig, error)
type TenantAuthDeps struct {
	SAML             config.SAML
	LDAP             config.LDAP
	SCIM             config.SCIM
	Secure           bool
	NewSessionIssuer func([]byte, time.Duration) *auth.SessionIssuer
}
type TenantAuthConfig struct {
	SAML *api.AuthConfig
	LDAP *api.AuthConfig
	SCIM *api.SCIMConfig
}
