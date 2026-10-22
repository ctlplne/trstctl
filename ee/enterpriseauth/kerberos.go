// SPDX-License-Identifier: LicenseRef-trstctl-EE

package enterpriseauth

import (
	"fmt"
	"net/http"
	"strings"
	"time"

	"trstctl.com/trstctl/internal/api"
	"trstctl.com/trstctl/internal/auth"
	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/crypto/kerberos"
)

// KerberosVerifier turns a verified Kerberos identity into the same
// auth.Claims shape the other login paths produce (A79), so tenant mapping and
// session issuance stay one path: the subject is the principal (user@REALM),
// the issuer is the realm, and Active Directory PAC group SIDs become groups.
type KerberosVerifier struct {
	Service *kerberos.Service
}

// Login wraps next in the SPNEGO negotiation.
func (v KerberosVerifier) Login(next func(http.ResponseWriter, *http.Request, auth.Claims)) http.Handler {
	return v.Service.Handler(func(w http.ResponseWriter, r *http.Request, id kerberos.Identity) {
		next(w, r, auth.Claims{
			Subject: id.Principal, Issuer: id.Realm, Groups: append([]string(nil), id.GroupSIDs...),
			IssuedAt: id.AuthTime.Unix(),
		})
	})
}

func buildKerberosAuthConfig(k config.Kerberos, secure bool, newSessionIssuer func([]byte, time.Duration) *auth.SessionIssuer) (*api.AuthConfig, error) {
	if !k.Enabled {
		return nil, nil
	}
	if err := k.ValidateEnabled(); err != nil {
		return nil, fmt.Errorf("server: Kerberos login enabled but misconfigured (fail closed): %w", err)
	}
	skew, err := k.MaxClockSkewDuration()
	if err != nil {
		return nil, fmt.Errorf("server: auth.kerberos.max_clock_skew: %w", err)
	}
	service, err := kerberos.New(kerberos.Config{
		KeytabFile: k.KeytabFile, ServicePrincipal: strings.TrimSpace(k.ServicePrincipal), Realm: k.Realm, MaxClockSkew: skew,
	})
	if err != nil {
		return nil, fmt.Errorf("server: auth.kerberos: %w", err)
	}
	secret, err := loadOrCreateNamedSessionSecret("auth.kerberos.session_secret_file", k.SessionSecretFile)
	if err != nil {
		return nil, err
	}
	ttl, err := k.SessionTTLDuration()
	if err != nil {
		return nil, fmt.Errorf("server: auth.kerberos.session_ttl: %w", err)
	}
	mapper := tenantMapperFromKerberosConfig(k)
	verifier := KerberosVerifier{Service: service}
	return &api.AuthConfig{
		KerberosEnabled:       true,
		KerberosLogin:         verifier.Login,
		ResolveKerberosTenant: mapper.ResolveTenant,
		TenantMappings:        kerberosMappingsForAPI(k),
		AllowDefaultTenant:    k.AllowDefaultTenant,
		DefaultTenant:         k.DefaultTenant,
		DefaultRoles:          k.DefaultRoles,
		Sessions:              newSessionIssuer(secret, ttl),
		LoginRedirect:         k.LoginRedirect,
		Secure:                secure,
	}, nil
}

func kerberosMappingsForAPI(k config.Kerberos) []api.AuthTenantMapping {
	out := make([]api.AuthTenantMapping, 0, len(k.TenantMappings))
	for _, m := range k.TenantMappings {
		out = append(out, api.AuthTenantMapping{
			Subject: m.Subject, Claim: m.Claim, Group: m.Group,
			TenantID: m.TenantID, Roles: append([]string(nil), m.Roles...),
		})
	}
	return out
}

func tenantMapperFromKerberosConfig(k config.Kerberos) auth.TenantMapper {
	mappings := make([]auth.TenantMapping, 0, len(k.TenantMappings))
	for _, m := range k.TenantMappings {
		mappings = append(mappings, auth.TenantMapping{
			Subject: m.Subject, Claim: m.Claim, Group: m.Group,
			TenantID: m.TenantID, Roles: m.Roles,
		})
	}
	return auth.TenantMapper{
		Mappings:      mappings,
		DefaultTenant: k.DefaultTenant,
		DefaultRoles:  k.DefaultRoles,
		AllowDefault:  k.AllowDefaultTenant,
	}
}
