// SPDX-License-Identifier: BUSL-1.1

package outboundcred_test

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"trstctl.com/trstctl/internal/cloudentitlements/azureiam"
	"trstctl.com/trstctl/internal/outboundcred"
	"trstctl.com/trstctl/internal/secretscan"
)

const (
	ownerTenant = "c8000000-0000-4000-8000-000000000001"
	otherTenant = "c8000000-0000-4000-8000-000000000002"
)

func TestBindingValidateNamesEachRequiredPart(t *testing.T) {
	good := outboundcred.Binding{Ref: "env:TRSTCTL_GRAPH_TOKEN_FILE", TenantID: ownerTenant, // #nosec G101 -- a reference name, no credential value (CWE-798)
		Integrations: []string{azureiam.SourceKind}, Origins: []string{"https://graph.microsoft.com"}}
	if err := good.Validate(); err != nil {
		t.Fatalf("a complete binding was refused: %v", err)
	}
	// Each refusal names the field it is about.
	for name, tc := range map[string]struct {
		mutate func(*outboundcred.Binding)
		field  string
	}{
		"bare env name":         {func(b *outboundcred.Binding) { b.Ref = "TRSTCTL_GRAPH_TOKEN_FILE" }, "ref"},
		"empty env name":        {func(b *outboundcred.Binding) { b.Ref = "env:" }, "ref"},
		"env name with a space": {func(b *outboundcred.Binding) { b.Ref = "env:TRSTCTL GRAPH" }, "ref"},
		"no tenant":             {func(b *outboundcred.Binding) { b.TenantID = "" }, "tenant_id"},
		"tenant not a UUID":     {func(b *outboundcred.Binding) { b.TenantID = "all-tenants" }, "tenant_id"},
		"no integration":        {func(b *outboundcred.Binding) { b.Integrations = nil }, "integrations"},
		"unknown integration":   {func(b *outboundcred.Binding) { b.Integrations = []string{"anything"} }, "integrations"},
		"no origin":             {func(b *outboundcred.Binding) { b.Origins = nil }, "origins"},
		"origin with a path":    {func(b *outboundcred.Binding) { b.Origins = []string{"https://graph.microsoft.com/v1.0"} }, "origins"},
		"origin with a query":   {func(b *outboundcred.Binding) { b.Origins = []string{"https://graph.microsoft.com?x=1"} }, "origins"},
		"origin with userinfo":  {func(b *outboundcred.Binding) { b.Origins = []string{"https://user@graph.microsoft.com"} }, "origins"},
		"origin without host":   {func(b *outboundcred.Binding) { b.Origins = []string{"https://"} }, "origins"},
		"unsupported scheme":    {func(b *outboundcred.Binding) { b.Origins = []string{"ftp://files.example"} }, "origins"},
		"port out of range":     {func(b *outboundcred.Binding) { b.Origins = []string{"https://graph.microsoft.com:70000"} }, "origins"},
	} {
		b := good
		b.Integrations = append([]string(nil), good.Integrations...)
		b.Origins = append([]string(nil), good.Origins...)
		tc.mutate(&b)
		err := b.Validate()
		if err == nil {
			t.Errorf("%s: binding accepted", name)
			continue
		}
		if !strings.HasPrefix(err.Error(), tc.field+" ") {
			t.Errorf("%s: the refusal %q does not name %s", name, err, tc.field)
		}
	}
}

func TestCanonicalOriginRemovesOnlyTheDefaultPort(t *testing.T) {
	for raw, want := range map[string]string{
		"HTTPS://Graph.Microsoft.com:443":     "https://graph.microsoft.com",
		"https://graph.microsoft.com/":        "https://graph.microsoft.com",
		"https://vault.example:8200":          "https://vault.example:8200",
		"http://127.0.0.1:80":                 "http://127.0.0.1",
		"http://127.0.0.1:4566":               "http://127.0.0.1:4566",
		"syslog+tls://collector.example":      "syslog+tls://collector.example",
		"syslog+tls://collector.example:6514": "syslog+tls://collector.example",
		"relp+tls://collector.example:2514":   "relp+tls://collector.example:2514",
		"https://[::1]:8443":                  "https://[::1]:8443",
		"https://[::1]:443":                   "https://[::1]",
	} {
		got, err := outboundcred.CanonicalOrigin(raw)
		if err != nil || got != want {
			t.Errorf("CanonicalOrigin(%q) = %q, %v; want %q", raw, got, err, want)
		}
	}
	if got, err := outboundcred.DestinationOrigin("https://hec.example:8088/services/collector/event"); err != nil || got != "https://hec.example:8088" {
		t.Errorf("DestinationOrigin kept the path or lost the port: %q, %v", got, err)
	}
}

func TestAuthorizeKeepsAReferenceWithItsTenantIntegrationAndOrigins(t *testing.T) {
	const ref = "env:TRSTCTL_VAULT_TOKEN" // #nosec G101 -- a reference name, no credential value (CWE-798)
	bindings, err := outboundcred.New([]outboundcred.Binding{
		{Ref: ref, TenantID: ownerTenant, Integrations: []string{"cloud_secret"}, Origins: []string{"https://vault.owner.example:8200"}},
		{Ref: ref, TenantID: ownerTenant, Integrations: []string{"cloud_secret", "secret_store"}, Origins: []string{"https://vault-dr.owner.example:8200"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	origins, err := bindings.Authorize(" env:TRSTCTL_VAULT_TOKEN ", ownerTenant, "cloud_secret", "https://vault.owner.example:8200/v1/secret/metadata/tls")
	if err != nil {
		t.Fatalf("the bound use was refused: %v", err)
	}
	if strings.Join(origins, ",") != "https://vault-dr.owner.example:8200,https://vault.owner.example:8200" {
		t.Fatalf("bound origins = %v", origins)
	}
	if origins, err := bindings.Authorize(ref, ownerTenant, "secret_store"); err != nil || len(origins) != 1 || origins[0] != "https://vault-dr.owner.example:8200" {
		t.Fatalf("secret_store origins = %v, %v", origins, err)
	}
	refusals := map[string]func() error{
		"another tenant": func() error {
			_, err := bindings.Authorize(ref, otherTenant, "cloud_secret")
			return err
		},
		"another integration": func() error {
			_, err := bindings.Authorize(ref, ownerTenant, "audit_feed", "https://vault.owner.example:8200")
			return err
		},
		"an unbound origin": func() error {
			_, err := bindings.Authorize(ref, ownerTenant, "cloud_secret", "https://collector.example/v1/secret")
			return err
		},
		"an origin bound only for another integration": func() error {
			_, err := bindings.Authorize(ref, ownerTenant, "secret_store", "https://vault.owner.example:8200")
			return err
		},
		"the same host on another port": func() error {
			_, err := bindings.Authorize(ref, ownerTenant, "cloud_secret", "https://vault.owner.example:9200")
			return err
		},
		"an unbound reference": func() error {
			_, err := bindings.Authorize("env:TRSTCTL_OTHER", ownerTenant, "cloud_secret")
			return err
		},
		"a nil binding set": func() error {
			_, err := (*outboundcred.Bindings)(nil).Authorize(ref, ownerTenant, "cloud_secret")
			return err
		},
	}
	for name, refuse := range refusals {
		if err := refuse(); !errors.Is(err, outboundcred.ErrNotBound) {
			t.Errorf("%s: err = %v, want ErrNotBound", name, err)
		}
	}
	// Another tenant learns nothing about whether the reference exists for anyone.
	_, otherErr := bindings.Authorize(ref, otherTenant, "cloud_secret")
	_, missingErr := bindings.Authorize("env:TRSTCTL_VAULT_TOKEN_UNKNOWN", otherTenant, "cloud_secret")
	if strings.ReplaceAll(otherErr.Error(), "TRSTCTL_VAULT_TOKEN", "X") != strings.ReplaceAll(missingErr.Error(), "TRSTCTL_VAULT_TOKEN_UNKNOWN", "X") {
		t.Fatalf("a refusal for another tenant differs from one for an unknown reference: %q vs %q", otherErr, missingErr)
	}
}

func TestPinClientRefusesEveryOtherOriginBeforeDialing(t *testing.T) {
	var bound, other atomic.Int32
	boundServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		bound.Add(1)
		if r.URL.Path == "/redirect" {
			http.Redirect(w, r, "/ok", http.StatusFound)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	defer boundServer.Close()
	otherServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		other.Add(1)
		w.WriteHeader(http.StatusNoContent)
	}))
	defer otherServer.Close()
	client := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return nil }}
	if err := outboundcred.PinClient(client, []string{boundServer.URL}); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{"/ok", "/redirect"} {
		resp, err := client.Get(boundServer.URL + path)
		if err != nil {
			t.Fatalf("bound origin %s refused: %v", path, err)
		}
		_ = resp.Body.Close()
	}
	if _, err := client.Get(otherServer.URL + "/token"); !errors.Is(err, outboundcred.ErrNotBound) {
		t.Fatalf("a request to another origin = %v, want ErrNotBound", err)
	}
	if other.Load() != 0 || bound.Load() != 3 {
		t.Fatalf("requests reached bound=%d other=%d; want 3 and 0", bound.Load(), other.Load())
	}
	// A second pin keeps the first: the client then reaches only origins both allow.
	if err := outboundcred.PinClient(client, []string{otherServer.URL}); err != nil {
		t.Fatal(err)
	}
	if _, err := client.Get(otherServer.URL + "/token"); !errors.Is(err, outboundcred.ErrNotBound) || other.Load() != 0 {
		t.Fatalf("a second pin widened the first: %v, other=%d", err, other.Load())
	}
	if err := outboundcred.PinClient(client, nil); err == nil {
		t.Fatal("pinning to no origin was accepted")
	}
}

func TestScanIntegrationKindsAreTheirSourceKinds(t *testing.T) {
	if outboundcred.IntegrationSecretThirdParty != secretscan.ThirdPartySourceKind || outboundcred.IntegrationSecretRepository != secretscan.RepositorySourceKind {
		t.Fatal("a scan integration kind differs from the source kind its declarations are stored under")
	}
	for _, kind := range []string{azureiam.SourceKind, "cloud_secret", "secret_store", outboundcred.IntegrationAuditFeed,
		outboundcred.IntegrationResponseIntegration, outboundcred.IntegrationCloudMachineChange, secretscan.ThirdPartySourceKind} {
		if !outboundcred.KnownIntegration(kind) {
			t.Errorf("%s is not a known integration kind", kind)
		}
	}
	if outboundcred.KnownIntegration("") || outboundcred.KnownIntegration("*") {
		t.Fatal("an empty or wildcard integration kind is known")
	}
}
