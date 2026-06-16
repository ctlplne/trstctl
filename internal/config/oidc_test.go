package config

import (
	"strings"
	"testing"
)

// fullOIDC returns a minimal, valid enabled OIDC block (loopback endpoints so the
// https check's loopback exemption applies).
func fullOIDC() OIDC {
	return OIDC{
		Enabled:           true,
		Issuer:            "https://idp.example.com",
		ClientID:          "trstctl-ui",
		AuthEndpoint:      "https://idp.example.com/authorize",
		TokenEndpoint:     "https://idp.example.com/token",
		RedirectURI:       "https://app.example.com/auth/callback",
		JWKSJSON:          `{"keys":[]}`,
		SessionSecretFile: "/var/lib/trstctl/session.secret",
		TenantClaim:       "tenant",
		ClaimIsTenant:     true,
	}
}

// TestOIDCDisabledNeedsNoConfig: a disabled OIDC block never blocks startup.
func TestOIDCDisabledNeedsNoConfig(t *testing.T) {
	c := Default()
	c.Auth.OIDC = OIDC{Enabled: false} // entirely unconfigured
	if err := c.Validate(); err != nil {
		t.Fatalf("disabled OIDC must not fail validation: %v", err)
	}
}

// TestOIDCEnabledFailsClosed: an enabled-but-misconfigured OIDC block is a hard
// startup error (the fail-closed gate). Each missing essential is rejected.
func TestOIDCEnabledFailsClosed(t *testing.T) {
	cases := map[string]func(o *OIDC){
		"missing issuer":         func(o *OIDC) { o.Issuer = "" },
		"missing client_id":      func(o *OIDC) { o.ClientID = "" },
		"missing auth_endpoint":  func(o *OIDC) { o.AuthEndpoint = "" },
		"missing token_endpoint": func(o *OIDC) { o.TokenEndpoint = "" },
		"missing redirect_uri":   func(o *OIDC) { o.RedirectURI = "" },
		"missing session secret": func(o *OIDC) { o.SessionSecretFile = "" },
		"no jwks":                func(o *OIDC) { o.JWKSJSON = ""; o.JWKSFile = "" },
		"non-https endpoint":     func(o *OIDC) { o.AuthEndpoint = "http://idp.example.com/authorize" },
		"no tenant mapping at all": func(o *OIDC) {
			o.TenantClaim = ""
			o.ClaimIsTenant = false
			o.TenantMappings = nil
			o.AllowDefaultTenant = false
		},
	}
	for name, mut := range cases {
		t.Run(name, func(t *testing.T) {
			c := Default()
			o := fullOIDC()
			mut(&o)
			c.Auth.OIDC = o
			if err := c.Validate(); err == nil {
				t.Fatalf("%s: enabled OIDC must fail validation (fail closed)", name)
			}
		})
	}
}

// TestOIDCEnabledValidPasses: a fully-configured enabled block validates.
func TestOIDCEnabledValidPasses(t *testing.T) {
	c := Default()
	c.Auth.OIDC = fullOIDC()
	if err := c.Validate(); err != nil {
		t.Fatalf("fully configured OIDC must validate: %v", err)
	}
}

// TestOIDCLoopbackHTTPAllowed: an http endpoint on a loopback host is permitted
// (RFC 8252 native-app loopback), so a local/dev IdP works, while http on a
// non-loopback host is rejected.
func TestOIDCLoopbackHTTPAllowed(t *testing.T) {
	c := Default()
	o := fullOIDC()
	o.Issuer = "http://127.0.0.1:9000"
	o.AuthEndpoint = "http://127.0.0.1:9000/authorize"
	o.TokenEndpoint = "http://127.0.0.1:9000/token"
	o.RedirectURI = "http://127.0.0.1:8443/auth/callback"
	c.Auth.OIDC = o
	if err := c.Validate(); err != nil {
		t.Fatalf("loopback http endpoints must be allowed: %v", err)
	}

	o.AuthEndpoint = "http://idp.public.example/authorize" // non-loopback http
	c.Auth.OIDC = o
	if err := c.Validate(); err == nil {
		t.Fatal("http on a non-loopback host must be rejected")
	}
}

// TestOIDCEnvOverlay: the scalar OIDC knobs overlay from the environment.
func TestOIDCEnvOverlay(t *testing.T) {
	env := map[string]string{
		"TRSTCTL_AUTH_OIDC_ENABLED":             "true",
		"TRSTCTL_AUTH_OIDC_ISSUER":              "https://idp.env.example",
		"TRSTCTL_AUTH_OIDC_CLIENT_ID":           "env-client",
		"TRSTCTL_AUTH_OIDC_AUTH_ENDPOINT":       "https://idp.env.example/authorize",
		"TRSTCTL_AUTH_OIDC_TOKEN_ENDPOINT":      "https://idp.env.example/token",
		"TRSTCTL_AUTH_OIDC_REDIRECT_URI":        "https://app.env.example/auth/callback",
		"TRSTCTL_AUTH_OIDC_JWKS_FILE":           "/etc/trstctl/jwks.json",
		"TRSTCTL_AUTH_OIDC_SESSION_SECRET_FILE": "/etc/trstctl/session.secret",
		"TRSTCTL_AUTH_OIDC_TENANT_CLAIM":        "org",
		"TRSTCTL_AUTH_OIDC_CLAIM_IS_TENANT":     "true",
	}
	cfg, err := Load(func(k string) string { return env[k] })
	if err != nil {
		t.Fatalf("Load with OIDC env: %v", err)
	}
	o := cfg.Auth.OIDC
	if !o.Enabled || o.Issuer != "https://idp.env.example" || o.ClientID != "env-client" || o.TenantClaim != "org" || !o.ClaimIsTenant {
		t.Fatalf("OIDC env overlay did not apply: %+v", o)
	}
	if !strings.HasSuffix(o.SessionSecretFile, "session.secret") {
		t.Errorf("session secret file = %q", o.SessionSecretFile)
	}
}
