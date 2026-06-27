package docs

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestC11FeatureDocsReflectParitySurfaces(t *testing.T) {
	for _, anchor := range []struct {
		file    string
		needles []string
	}{
		{"../internal/protocols/acme/acme.go", []string{"trust_authenticated", "WithAccountOrderLimiter"}},
		{"../internal/protocols/est/dispatcher.go", []string{"/serverkeygen", "est-mtls", "PathID"}},
		{"../internal/protocols/est/est.go", []string{"VerifyESTChannelBinding", "ChannelBindingRequired"}},
		{"../internal/protocols/scep/scep.go", []string{"ChallengeValidator", "MaxEnrollmentsPerDevice"}},
		{"../internal/mdm/intune_challenge.go", []string{"ErrIntuneChallengeReplay", "ValidateIntuneSCEPChallenge"}},
		{"../internal/api/api.go", []string{"/api/v1/certificates/bulk-revoke", "/api/v1/discovery/findings/{id}/claim", "/api/v1/notifications/{id}/requeue", "/api/v1/mcp/tools/{tool}"}},
		{"../internal/crypto/revocation.go", []string{"ValidRevocationReasons", "SignDelegatedOCSPResponseWithNonce", "OCSP nonce"}},
		{"../internal/server/revocation.go", []string{"ETag", "If-None-Match"}},
		{"../internal/mcpserver/mcpserver.go", []string{"RESTToolName", "WithRESTTools"}},
	} {
		body := read(t, anchor.file)
		for _, needle := range anchor.needles {
			if !strings.Contains(body, needle) {
				t.Fatalf("%s no longer contains code anchor %q; revisit C11 docs reality test", anchor.file, needle)
			}
		}
	}

	for _, rel := range []string{
		"../internal/ca/vaultpki/vaultpki.go",
		"../internal/ca/globalsign/globalsign.go",
		"../internal/ca/entrust/entrust.go",
		"../internal/ca/shellca/shellca.go",
		"../internal/connector/caddy/caddy.go",
		"../internal/connector/traefik/traefik.go",
		"../internal/connector/envoy/envoy.go",
		"../internal/connector/postfix/postfix.go",
		"../internal/discovery/cloudsecret/awssm/awssm.go",
		"../internal/discovery/cloudsecret/gcpsm/gcpsm.go",
		"../web/src/components/wizard/StepShell.tsx",
		"../web/src/components/CommandPalette.tsx",
		"../web/src/pages/Notifications.tsx",
	} {
		if _, err := os.Stat(filepath.FromSlash(rel)); err != nil {
			t.Fatalf("C11 docs code anchor %s missing: %v", rel, err)
		}
	}

	cases := []struct {
		file    string
		needles []string
	}{
		{"features/acme-and-dns.md", []string{"trust_authenticated", "account-keyed order/hour limiter", "GET /directory", "**Served**"}},
		{"features/enrollment-protocols.md", []string{"EST `/serverkeygen`", "RFC 9266", "tls-server-end-point", "per-profile PathID", "mTLS sibling route", "Intune JWS challenge", "single-use replay cache", "per-device rate limiter", "per-profile SCEP RA"}},
		{"features/issuance-and-cas.md", []string{"RFC 5280 named revocation reason", "/api/v1/certificates/bulk-revoke", "OCSP nonce", "ETag", "If-None-Match", "Vault PKI", "GlobalSign", "Entrust", "shell CA"}},
		{"features/deployment-connectors.md", []string{"Caddy", "Traefik", "Envoy", "Postfix", "Dovecot"}},
		{"features/discovery-and-inventory.md", []string{"/api/v1/discovery/findings/{id}/claim", "/api/v1/discovery/findings/{id}/dismiss", "investigating", "AWS Secrets Manager", "GCP Secret Manager", "reserved-IP"}},
		{"features/policy-and-governance.md", []string{"severity-to-channel routing matrix", "EffectiveAlertChannels", "per-(subject, threshold, channel)", "/api/v1/notifications/{id}/requeue"}},
		{"features/graph-query-ai.md", []string{"route-backed REST MCP tools", "rest_list_notifications", "MCP-vs-REST parity CI guard"}},
		{"web-console.md", []string{"issuer catalog", "Test connection", "operations queue", "Notifications inbox", "Team column", "issuance-rate chart", "CTA empty states", "onboarding carousel", "server-side record search"}},
		{"limitations.md", []string{"ACME trust_authenticated", "SCEP Intune challenge", "notification routing matrix", "MCP-vs-REST parity guard", "onboarding carousel"}},
	}
	for _, tc := range cases {
		body := read(t, tc.file)
		for _, needle := range tc.needles {
			if !strings.Contains(body, needle) {
				t.Errorf("%s missing C11 parity docs marker %q", tc.file, needle)
			}
		}
	}

	for _, stale := range []struct {
		file   string
		phrase string
	}{
		{"features/acme-and-dns.md", "mounting it on the public control-plane endpoint"},
		{"features/acme-and-dns.md", "Serving status: the ACME server and validators are implemented and tested"},
		{"features/enrollment-protocols.md", "MDM challenge (F56) | **Library-complete**, tested"},
	} {
		if strings.Contains(read(t, stale.file), stale.phrase) {
			t.Errorf("%s still contains stale served-status phrase %q", stale.file, stale.phrase)
		}
	}
}
