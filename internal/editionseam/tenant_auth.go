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
	Kerberos         config.Kerberos
	SCIM             config.SCIM
	Secure           bool
	NewSessionIssuer func([]byte, time.Duration) *auth.SessionIssuer
	// SAMLEncryptionCertDER and SAMLEncryptionKeyPKCS8 are the service
	// provider's assertion-encryption identity (A77), loaded by the core from
	// auth.saml.sp_key_file; nil when none is configured. The factory copies
	// what it keeps; the core wipes these after the call.
	SAMLEncryptionCertDER  []byte
	SAMLEncryptionKeyPKCS8 []byte
}
type TenantAuthConfig struct {
	SAML     *api.AuthConfig
	LDAP     *api.AuthConfig
	Kerberos *api.AuthConfig
	SCIM     *api.SCIMConfig
}
