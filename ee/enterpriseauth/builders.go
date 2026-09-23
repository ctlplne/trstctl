// SPDX-License-Identifier: LicenseRef-trstctl-EE

package enterpriseauth

import (
	"errors"
	"fmt"
	"os"
	"strings"
	"time"

	"trstctl.com/trstctl/internal/api"
	"trstctl.com/trstctl/internal/auth"
	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/crypto"
	cryptosamlsp "trstctl.com/trstctl/internal/crypto/samlsp"
	"trstctl.com/trstctl/internal/crypto/secretfile"
	"trstctl.com/trstctl/internal/editionseam"
)

// Build constructs tenant SAML, LDAP and SCIM only after the licensed attach seam
// supplies this factory. Core provides the durable browser-session issuer.
func Build(d editionseam.TenantAuthDeps) (editionseam.TenantAuthConfig, error) {
	var out editionseam.TenantAuthConfig
	if (d.SAML.Enabled || d.LDAP.Enabled) && d.NewSessionIssuer == nil {
		return out, errors.New("enterprise auth requires the core browser-session issuer")
	}
	var err error
	out.SAML, err = buildSAMLAuthConfig(d.SAML, d.Secure, d.NewSessionIssuer)
	if err != nil {
		return out, err
	}
	out.LDAP, err = buildLDAPAuthConfig(d.LDAP, d.Secure, d.NewSessionIssuer)
	if err != nil {
		return out, err
	}
	out.SCIM, err = buildSCIMConfig(d.SCIM)
	return out, err
}

func buildSAMLAuthConfig(s config.SAML, secure bool, newSessionIssuer func([]byte, time.Duration) *auth.SessionIssuer) (*api.AuthConfig, error) {
	if !s.Enabled {
		return nil, nil
	}
	if err := s.ValidateEnabled(); err != nil {
		return nil, fmt.Errorf("server: SAML login enabled but misconfigured (fail closed): %w", err)
	}
	metadata, err := loadSAMLMetadata(s)
	if err != nil {
		return nil, err
	}
	provider, err := cryptosamlsp.NewServiceProvider(cryptosamlsp.Config{
		EntityID:       s.EntityID,
		MetadataURL:    s.MetadataURL,
		ACSURL:         s.ACSURL,
		IDPMetadataXML: metadata,
	})
	if err != nil {
		return nil, fmt.Errorf("server: configure SAML SP: %w", err)
	}
	secret, err := loadOrCreateNamedSessionSecret("auth.saml.session_secret_file", s.SessionSecretFile)
	if err != nil {
		return nil, err
	}
	ttl, err := s.SessionTTLDuration()
	if err != nil {
		return nil, fmt.Errorf("server: auth.saml.session_ttl: %w", err)
	}
	sessions := newSessionIssuer(secret, ttl)
	mapper := tenantMapperFromSAMLConfig(s)
	verifier := SAMLVerifier{
		Provider:         provider,
		SubjectAttribute: s.SubjectAttribute,
		EmailAttribute:   s.EmailAttribute,
		TenantClaim:      s.TenantClaim,
		GroupsClaim:      s.GroupsClaim,
	}
	cfg := &api.AuthConfig{
		SAMLEnabled:        s.Enabled,
		TenantClaim:        s.TenantClaim,
		GroupsClaim:        s.GroupsClaim,
		ClaimIsTenant:      s.ClaimIsTenant,
		TenantMappings:     samlMappingsForAPI(s),
		AllowDefaultTenant: s.AllowDefaultTenant,
		DefaultTenant:      s.DefaultTenant,
		DefaultRoles:       s.DefaultRoles,
		SAMLLoginRedirect: func(relayState string) (string, string, error) {
			redirect, err := verifier.LoginRedirect(relayState)
			if err != nil {
				return "", "", err
			}
			return redirect.URL, redirect.RequestID, nil
		},
		VerifySAMLResponse: verifier.Verify,
		ResolveSAMLTenant:  mapper.ResolveTenant,
		SAMLMetadata:       verifier.MetadataXML,
		Sessions:           sessions,
		LoginRedirect:      s.LoginRedirect,
		Secure:             secure,
	}
	return cfg, nil
}

func buildLDAPAuthConfig(l config.LDAP, secure bool, newSessionIssuer func([]byte, time.Duration) *auth.SessionIssuer) (*api.AuthConfig, error) {
	if !l.Enabled {
		return nil, nil
	}
	if err := l.ValidateEnabled(); err != nil {
		return nil, fmt.Errorf("server: LDAP login enabled but misconfigured (fail closed): %w", err)
	}
	var bindPassword []byte
	var err error
	if strings.TrimSpace(l.BindPasswordFile) != "" {
		bindPassword, err = secretfile.Load(l.BindPasswordFile)
		if err != nil {
			return nil, fmt.Errorf("server: read auth.ldap.bind_password_file %q: %w", l.BindPasswordFile, err)
		}
	}
	secret, err := loadOrCreateNamedSessionSecret("auth.ldap.session_secret_file", l.SessionSecretFile)
	if err != nil {
		return nil, err
	}
	ttl, err := l.SessionTTLDuration()
	if err != nil {
		return nil, fmt.Errorf("server: auth.ldap.session_ttl: %w", err)
	}
	timeout, err := l.TimeoutDuration()
	if err != nil {
		return nil, fmt.Errorf("server: auth.ldap.timeout: %w", err)
	}
	sessions := newSessionIssuer(secret, ttl)
	mapper := tenantMapperFromLDAPConfig(l)
	verifier := LDAPVerifier{
		URL:                l.URL,
		UserDNTemplate:     l.UserDNTemplate,
		BindDN:             l.BindDN,
		BindPassword:       bindPassword,
		UserSearchBaseDN:   l.UserSearchBaseDN,
		UserFilter:         l.UserFilter,
		GroupSearchBaseDN:  l.GroupSearchBaseDN,
		GroupFilter:        l.GroupFilter,
		GroupNameAttribute: l.GroupNameAttribute,
		EmailAttribute:     l.EmailAttribute,
		Timeout:            timeout,
	}
	cfg := &api.AuthConfig{
		LDAPEnabled:        l.Enabled,
		TenantMappings:     ldapMappingsForAPI(l),
		AllowDefaultTenant: l.AllowDefaultTenant,
		DefaultTenant:      l.DefaultTenant,
		DefaultRoles:       l.DefaultRoles,
		VerifyLDAPLogin:    verifier.Verify,
		ResolveLDAPTenant:  mapper.ResolveTenant,
		Sessions:           sessions,
		LoginRedirect:      l.LoginRedirect,
		Secure:             secure,
	}
	return cfg, nil
}

func samlMappingsForAPI(s config.SAML) []api.AuthTenantMapping {
	out := make([]api.AuthTenantMapping, 0, len(s.TenantMappings))
	for _, m := range s.TenantMappings {
		out = append(out, api.AuthTenantMapping{
			Subject: m.Subject, Claim: m.Claim, Group: m.Group,
			TenantID: m.TenantID, Roles: append([]string(nil), m.Roles...),
		})
	}
	return out
}

func ldapMappingsForAPI(l config.LDAP) []api.AuthTenantMapping {
	out := make([]api.AuthTenantMapping, 0, len(l.TenantMappings))
	for _, m := range l.TenantMappings {
		out = append(out, api.AuthTenantMapping{
			Subject: m.Subject, Claim: m.Claim, Group: m.Group,
			TenantID: m.TenantID, Roles: append([]string(nil), m.Roles...),
		})
	}
	return out
}

func tenantMapperFromSAMLConfig(s config.SAML) auth.TenantMapper {
	mappings := make([]auth.TenantMapping, 0, len(s.TenantMappings))
	for _, m := range s.TenantMappings {
		mappings = append(mappings, auth.TenantMapping{
			Subject: m.Subject, Claim: m.Claim, Group: m.Group,
			TenantID: m.TenantID, Roles: m.Roles,
		})
	}
	return auth.TenantMapper{
		Mappings:      mappings,
		ClaimIsTenant: s.ClaimIsTenant,
		DefaultTenant: s.DefaultTenant,
		DefaultRoles:  s.DefaultRoles,
		AllowDefault:  s.AllowDefaultTenant,
	}
}

func tenantMapperFromLDAPConfig(l config.LDAP) auth.TenantMapper {
	mappings := make([]auth.TenantMapping, 0, len(l.TenantMappings))
	for _, m := range l.TenantMappings {
		mappings = append(mappings, auth.TenantMapping{
			Subject: m.Subject, Claim: m.Claim, Group: m.Group,
			TenantID: m.TenantID, Roles: m.Roles,
		})
	}
	return auth.TenantMapper{
		Mappings:      mappings,
		DefaultTenant: l.DefaultTenant,
		DefaultRoles:  l.DefaultRoles,
		AllowDefault:  l.AllowDefaultTenant,
	}
}

func loadSAMLMetadata(s config.SAML) (string, error) {
	switch {
	case strings.TrimSpace(s.IDPMetadataXML) != "":
		return s.IDPMetadataXML, nil
	case strings.TrimSpace(s.IDPMetadataFile) != "":
		data, err := os.ReadFile(s.IDPMetadataFile)
		if err != nil {
			return "", fmt.Errorf("server: read auth.saml.idp_metadata_file %q: %w", s.IDPMetadataFile, err)
		}
		return string(data), nil
	default:
		return "", errors.New("server: auth.saml requires idp_metadata_file or idp_metadata_xml")
	}
}

func loadOrCreateNamedSessionSecret(field, path string) ([]byte, error) {
	if strings.TrimSpace(path) == "" {
		return nil, fmt.Errorf("server: %s is required to persist the session secret", field)
	}
	secret, err := secretfile.LoadOrCreate(path, func() ([]byte, error) {
		return crypto.RandomBytes(32)
	})
	if err != nil {
		return nil, fmt.Errorf("server: load session secret %q: %w", path, err)
	}
	if len(secret) < 32 {
		return nil, fmt.Errorf("server: session secret %q is too short (%d bytes); want >= 32", path, len(secret))
	}
	return secret, nil
}
