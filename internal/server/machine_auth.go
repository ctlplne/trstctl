package server

import (
	"fmt"
	"os"
	"strings"

	"trstctl.com/trstctl/internal/authmethod"
	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/crypto"
)

type configuredMachineAuthMethod struct {
	cfg  config.MachineAuthMethod
	jwks crypto.JWKS
}

func machineAuthMethodsFromConfig(cfgs []config.MachineAuthMethod) (func(tenantID string) []authmethod.Method, error) {
	if len(cfgs) == 0 {
		return nil, nil
	}
	configured := make([]configuredMachineAuthMethod, 0, len(cfgs))
	for i, cfg := range cfgs {
		cfg.Name = strings.TrimSpace(cfg.Name)
		cfg.TenantID = strings.TrimSpace(cfg.TenantID)
		cfg.TenantClaim = strings.TrimSpace(cfg.TenantClaim)
		var jwks crypto.JWKS
		if cfg.Name != "aws-iam" {
			parsed, err := loadMachineAuthJWKS(cfg)
			if err != nil {
				return nil, fmt.Errorf("machine_auth[%d] %s: %w", i, cfg.Name, err)
			}
			jwks = parsed
		}
		configured = append(configured, configuredMachineAuthMethod{cfg: cfg, jwks: jwks})
	}
	return func(tenantID string) []authmethod.Method {
		out := make([]authmethod.Method, 0, len(configured))
		for _, cm := range configured {
			if cm.cfg.TenantID != "" && cm.cfg.TenantID != tenantID {
				continue
			}
			if method := cm.methodForTenant(tenantID); method != nil {
				out = append(out, method)
			}
		}
		return out
	}, nil
}

func (cm configuredMachineAuthMethod) methodForTenant(tenantID string) authmethod.Method {
	c := cm.cfg
	switch c.Name {
	case "kubernetes":
		return authmethod.KubernetesSATMethod{
			JWKS:                   cm.jwks,
			Issuer:                 c.Issuer,
			Audience:               c.Audience,
			TenantID:               tenantID,
			TenantClaim:            c.TenantClaim,
			AllowedNamespaces:      boolMap(c.AllowedNamespaces),
			AllowedServiceAccounts: boolMap(c.AllowedServiceAccounts),
			Scopes:                 append([]string(nil), c.Scopes...),
		}
	case "aws-iam":
		return authmethod.AWSIAMMethod{
			TenantID:        tenantID,
			Client:          authmethod.HTTPSignedSTSClient{Endpoint: c.STSEndpoint},
			AllowedAccounts: boolMap(c.AllowedAccounts),
			AllowedARNs:     boolMap(c.AllowedARNs),
			Scopes:          append([]string(nil), c.Scopes...),
		}
	case "gcp":
		return authmethod.GCPMethod{
			JWKS:            cm.jwks,
			Issuer:          c.Issuer,
			Audience:        c.Audience,
			TenantID:        tenantID,
			TenantClaim:     c.TenantClaim,
			AllowedProjects: boolMap(c.AllowedProjects),
			Scopes:          append([]string(nil), c.Scopes...),
		}
	case "azure":
		return authmethod.AzureMethod{
			JWKS:                cm.jwks,
			Issuer:              c.Issuer,
			Audience:            c.Audience,
			TenantID:            tenantID,
			TenantClaim:         c.TenantClaim,
			AllowedAzureTenants: boolMap(c.AllowedAzureTenants),
			PrincipalClaim:      c.SubjectClaim,
			Scopes:              append([]string(nil), c.Scopes...),
		}
	case "oidc":
		return authmethod.OIDCMethod{
			JWKS:            cm.jwks,
			Issuer:          c.Issuer,
			Audience:        c.Audience,
			TenantID:        tenantID,
			TenantClaim:     c.TenantClaim,
			PrincipalPrefix: c.PrincipalPrefix,
		}
	case "jwt":
		return authmethod.JWTMethod{
			JWKS:            cm.jwks,
			Issuer:          c.Issuer,
			Audience:        c.Audience,
			TenantID:        tenantID,
			TenantClaim:     c.TenantClaim,
			SubjectClaim:    c.SubjectClaim,
			Scopes:          append([]string(nil), c.Scopes...),
			ScopesClaim:     c.ScopesClaim,
			PrincipalPrefix: c.PrincipalPrefix,
		}
	default:
		return nil
	}
}

func loadMachineAuthJWKS(cfg config.MachineAuthMethod) (crypto.JWKS, error) {
	switch {
	case strings.TrimSpace(cfg.JWKSJSON) != "":
		return crypto.ParseJWKS([]byte(cfg.JWKSJSON))
	case strings.TrimSpace(cfg.JWKSFile) != "":
		data, err := os.ReadFile(cfg.JWKSFile)
		if err != nil {
			return crypto.JWKS{}, fmt.Errorf("read jwks_file %q: %w", cfg.JWKSFile, err)
		}
		return crypto.ParseJWKS(data)
	default:
		return crypto.JWKS{}, fmt.Errorf("jwks_file or jwks_json is required")
	}
}

func boolMap(values []string) map[string]bool {
	if len(values) == 0 {
		return nil
	}
	out := make(map[string]bool, len(values))
	for _, v := range values {
		v = strings.TrimSpace(v)
		if v != "" {
			out[v] = true
		}
	}
	if len(out) == 0 {
		return nil
	}
	return out
}
