package docs

import (
	"strings"
	"testing"
)

func TestOIDCProviderRunbooksStayRealityBound(t *testing.T) {
	config := read(t, "../internal/config/config.go")
	auth := read(t, "../internal/auth/oidc.go")
	server := read(t, "../internal/server/auth.go")

	for _, env := range oidcRunbookEnvVars() {
		if !strings.Contains(config, `"`+env+`"`) {
			t.Fatalf("OIDC runbook env var %s is not read by internal/config/config.go", env)
		}
	}
	for _, anchor := range []string{"code_challenge_method", "PKCEChallengeMethodS256"} {
		if !strings.Contains(auth, anchor) {
			t.Fatalf("internal/auth/oidc.go no longer anchors mandatory PKCE S256 (%q missing); revisit the OIDC runbook test", anchor)
		}
	}
	for _, anchor := range []string{"OIDCLogoutVerifier", "VerifyOIDCLogoutToken", "auth.oidc, ref, client_secret"} {
		if !strings.Contains(server, anchor) && !strings.Contains(config, anchor) {
			t.Fatalf("served OIDC hardening anchor %q is missing; revisit the OIDC runbook test", anchor)
		}
	}

	platform := read(t, "features/platform-and-api.md")
	if !strings.Contains(platform, "../operator/oidc-runbooks/index.md") {
		t.Fatal("features/platform-and-api.md must link to the per-IdP OIDC runbook index")
	}

	index := read(t, "operator/oidc-runbooks/index.md")
	for _, page := range oidcRunbookPages() {
		if !strings.Contains(index, page.path) {
			t.Errorf("OIDC runbook index should link %s", page.path)
		}
		body := read(t, "operator/oidc-runbooks/"+page.path)
		low := strings.ToLower(body)
		if !strings.Contains(low, strings.ToLower(page.name)) {
			t.Errorf("%s should name %s", page.path, page.name)
		}
		for _, env := range oidcRunbookEnvVars() {
			if !strings.Contains(body, env) {
				t.Errorf("%s missing real OIDC setting %s", page.path, env)
			}
		}
		for _, marker := range []string{
			"/auth/callback",
			"/auth/oidc/back-channel-logout",
			"pkce s256",
			"confidential client",
			"authorization response `iss`",
			"tenant-scoped credential store",
		} {
			if !strings.Contains(low, marker) {
				t.Errorf("%s missing hardened OIDC marker %q", page.path, marker)
			}
		}
		if strings.Contains(body, "TRSTCTL_AUTH_OIDC_CLIENT_SECRET=") {
			t.Errorf("%s should not teach plaintext TRSTCTL_AUTH_OIDC_CLIENT_SECRET; use tenant/ref secret storage", page.path)
		}
	}
}

type oidcRunbookPage struct {
	name string
	path string
}

func oidcRunbookPages() []oidcRunbookPage {
	return []oidcRunbookPage{
		{name: "Keycloak", path: "keycloak.md"},
		{name: "Authentik", path: "authentik.md"},
		{name: "Okta", path: "okta.md"},
		{name: "Auth0", path: "auth0.md"},
		{name: "Entra", path: "entra-id.md"},
		{name: "Google", path: "google-workspace.md"},
	}
}

func oidcRunbookEnvVars() []string {
	return []string{
		"TRSTCTL_AUTH_OIDC_ENABLED",
		"TRSTCTL_AUTH_OIDC_ISSUER",
		"TRSTCTL_AUTH_OIDC_AUTHORIZATION_RESPONSE_ISS_PARAMETER_SUPPORTED",
		"TRSTCTL_AUTH_OIDC_CLIENT_ID",
		"TRSTCTL_AUTH_OIDC_CLIENT_SECRET_TENANT",
		"TRSTCTL_AUTH_OIDC_CLIENT_SECRET_REF",
		"TRSTCTL_AUTH_OIDC_AUTH_ENDPOINT",
		"TRSTCTL_AUTH_OIDC_TOKEN_ENDPOINT",
		"TRSTCTL_AUTH_OIDC_REDIRECT_URI",
		"TRSTCTL_AUTH_OIDC_JWKS_FILE",
		"TRSTCTL_AUTH_OIDC_SESSION_SECRET_FILE",
		"TRSTCTL_AUTH_OIDC_TENANT_CLAIM",
		"TRSTCTL_AUTH_OIDC_GROUPS_CLAIM",
	}
}
