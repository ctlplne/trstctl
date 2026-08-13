// SPDX-License-Identifier: MPL-2.0

package docs

import (
	"os"
	"strings"
	"testing"
)

func TestAUD58DocumentsServedProviderWorkforceAuthorityAndExactLimits(t *testing.T) {
	t.Parallel()
	read := func(name string) string {
		t.Helper()
		raw, err := os.ReadFile(name)
		if err != nil {
			t.Fatal(err)
		}
		return string(raw)
	}

	configuration := read("configuration.md")
	for _, marker := range []string{
		"TRSTCTL_PROVIDER_OIDC_MFA_CLAIM",
		"TRSTCTL_PROVIDER_SAML_IDP_METADATA_FILE",
		"TRSTCTL_PROVIDER_SAML_SESSION_SECRET_FILE",
		"TRSTCTL_PROVIDER_SCIM_TOKEN_FILE",
		"/provider/scim/v2",
	} {
		if !strings.Contains(configuration, marker) {
			t.Errorf("configuration.md does not document %q", marker)
		}
	}

	editions := read("editions.md")
	for _, marker := range []string{
		"/provider/v1/auth/saml/{login,acs,metadata}",
		"POST /provider/v1/auth/logout",
		"GET /provider/v1/operators",
		"GET /provider/v1/access/customers",
		"/delegations",
		"/revocations",
		"/role",
		"last use",
		"revocation evidence",
	} {
		if !strings.Contains(editions, marker) {
			t.Errorf("editions.md does not document %q", marker)
		}
	}

	limitations := read("limitations.md")
	for _, stale := range []string{
		"SAML federation and SCIM provisioning are NOT built",
		"delegation administration remains an offline",
	} {
		if strings.Contains(limitations, stale) {
			t.Errorf("limitations.md retains stale AUD-58 claim %q", stale)
		}
	}
	for _, exactLimit := range []string{"SCIM Bulk", "group remove/replace", "active:false"} {
		if !strings.Contains(limitations, exactLimit) {
			t.Errorf("limitations.md does not state exact Provider limit %q", exactLimit)
		}
	}
}
