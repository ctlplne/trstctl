// SPDX-License-Identifier: BUSL-1.1

package outboundcred_test

import (
	"net/http"
	"os"
	"regexp"
	"slices"
	"strings"
	"testing"

	"trstctl.com/trstctl/internal/discovery/sourcecatalog"
	"trstctl.com/trstctl/internal/outboundcred"
)

// CR-008: a binding may name only the sixteen integration kinds whose stored
// configuration resolves an env reference. Every other source kind is refused
// when the bindings load, so no binding can reach a credential through a kind
// that never reads one (an OAuth or access-key action reading a provider
// connection stored beside a manual or ssh_trust finding).
func TestBindingsNameOnlyTheKindsThatResolveEnvReferences(t *testing.T) {
	want := []string{
		"audit_feed", "azure_machine_identity", "cloud_access_key", "cloud_certificate", "cloud_kms_key",
		"cloud_machine_change", "cloud_machine_entitlement", "cloud_network_path", "cloud_secret", "gcp_machine_identity",
		"load_balancer_tls", "oauth_grant", "response_integration", "secret_repo", "secret_store", "secret_third_party",
	}
	if got := outboundcred.Integrations(); !slices.Equal(got, want) {
		t.Fatalf("bindable kinds = %v, want %v", got, want)
	}
	// The source kinds among them are real catalog kinds (no typo binds nothing).
	for _, kind := range want {
		switch kind {
		case outboundcred.IntegrationAuditFeed, outboundcred.IntegrationResponseIntegration, outboundcred.IntegrationCloudMachineChange,
			outboundcred.IntegrationSecretThirdParty, outboundcred.IntegrationSecretRepository:
			continue
		}
		if _, ok := sourcecatalog.Find(kind); !ok {
			t.Errorf("bindable source kind %q is not in the source catalog", kind)
		}
	}
	// Every other catalog kind is refused when the bindings load.
	refused := 0
	for _, kind := range sourcecatalog.Kinds() {
		if slices.Contains(want, kind) {
			continue
		}
		refused++
		b := outboundcred.Binding{Ref: "env:CR008_TOKEN", TenantID: "11111111-1111-4111-8111-111111111111", Integrations: []string{kind}, Origins: []string{"https://collector.example"}}
		if err := b.Validate(); err == nil {
			t.Errorf("a binding for source kind %q, which never resolves an env reference, was accepted", kind)
		}
	}
	if refused == 0 {
		t.Fatal("the source catalog offered no other kind to refuse")
	}
	// The configuration reference lists exactly these kinds.
	doc, err := os.ReadFile("../../docs/configuration.md")
	if err != nil {
		t.Fatal(err)
	}
	var row string
	for _, line := range strings.Split(string(doc), "\n") {
		if strings.HasPrefix(line, "| `integrations` |") {
			row = line
			break
		}
	}
	if row == "" {
		t.Fatal("docs/configuration.md has no `integrations` row in the bindings table")
	}
	var documented []string
	for _, m := range regexp.MustCompile("`([a-z_]+)`").FindAllStringSubmatch(row, -1) {
		if m[1] != "integrations" {
			documented = append(documented, m[1])
		}
	}
	slices.Sort(documented)
	documented = slices.Compact(documented)
	if !slices.Equal(documented, want) {
		t.Fatalf("docs/configuration.md lists %v, want %v", documented, want)
	}
}

// CR-008: a refusal names the integration and origin it refused, never the
// reference, raw or normalized (CR-405 class), and the process-wide default
// HTTP client is never pinned.
func TestRefusalsNeverQuoteTheReferenceAndDefaultClientIsNeverPinned(t *testing.T) {
	const tenant = "11111111-1111-4111-8111-111111111111"
	b, err := outboundcred.New([]outboundcred.Binding{{Ref: "env:CR008_SECRET_NAME", TenantID: tenant,
		Integrations: []string{outboundcred.IntegrationCloudSecret}, Origins: []string{"https://vault.example"}}})
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct{ ref, tenant, integration, destination string }{
		{"env:CR008_SECRET_NAME", "22222222-2222-4222-8222-222222222222", outboundcred.IntegrationCloudSecret, "https://vault.example"},
		{"env:CR008_SECRET_NAME", tenant, outboundcred.IntegrationAuditFeed, "https://vault.example"},
		{"env:CR008_SECRET_NAME", tenant, outboundcred.IntegrationCloudSecret, "https://collector.example/x"},
		{" env:CR008_SECRET_NAME ", tenant, outboundcred.IntegrationCloudSecret, "not a url"},
		{"env:CR008_SECRET_NAME", tenant, outboundcred.IntegrationCloudSecret, "https://cr008user:cr008pass@vault.example"},
		{"file:/etc/CR008_SECRET_NAME", tenant, outboundcred.IntegrationCloudSecret, "https://vault.example"},
	} {
		_, err := b.Authorize(tc.ref, tc.tenant, tc.integration, tc.destination)
		if err == nil {
			t.Fatalf("%+v was authorized", tc)
		}
		if strings.Contains(err.Error(), "CR008_SECRET_NAME") {
			t.Errorf("the refusal quotes the reference: %v", err)
		}
		// Nor the destination it refused to parse or bind: it may carry
		// credentials of its own.
		if strings.Contains(err.Error(), "not a url") || strings.Contains(err.Error(), "cr008pass") {
			t.Errorf("the refusal echoes the destination: %v", err)
		}
	}
	if err := outboundcred.PinClient(http.DefaultClient, []string{"https://vault.example"}); err == nil {
		t.Fatal("http.DefaultClient was pinned")
	}
	// RELP has no default port, so a binding origin without one could never
	// match a destination; it fails startup instead.
	relp := outboundcred.Binding{Ref: "env:CR008_SECRET_NAME", TenantID: tenant, Integrations: []string{outboundcred.IntegrationAuditFeed},
		Origins: []string{"relp+tls://collector.example"}}
	if err := relp.Validate(); err == nil {
		t.Fatal("a relp+tls origin without a port was accepted")
	}
	relp.Origins = []string{"relp+tls://collector.example:2514"}
	if err := relp.Validate(); err != nil {
		t.Fatalf("a relp+tls origin with its port was refused: %v", err)
	}
}
