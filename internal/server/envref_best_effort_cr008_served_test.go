// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"reflect"
	"slices"
	"strings"
	"testing"

	"trstctl.com/trstctl/internal/authz"
	"trstctl.com/trstctl/internal/cloudentitlements/azureiam"
	"trstctl.com/trstctl/internal/cloudentitlements/gcpiam"
	"trstctl.com/trstctl/internal/config"
)

// CR-008 (design D2, review item 2): for the generic discovery kinds the API's
// declaration check is best-effort. It reads exact-case *_ref keys and takes
// destinations only from sibling endpoint and URL keys, while the worker decodes
// keys case-insensitively and derives some destinations from other fields. A
// declaration that slips past the API that way is stored, and the worker's pin
// refuses it with nothing sent.
func TestServedBestEffortDeclarationsAreRefusedByTheWorkersPinCR008(t *testing.T) {
	const (
		vaultRef  = "env:TRSTCTL_CR008B_VAULT_TOKEN" // #nosec G101 -- reference names only (CWE-798)
		keyIDRef  = "env:TRSTCTL_CR008B_AWS_KEY_ID"  // #nosec G101 -- reference names only (CWE-798)
		secretRef = "env:TRSTCTL_CR008B_AWS_SECRET"  // #nosec G101 -- reference names only (CWE-798)
		vaultVal  = "cr008b-owner-vault-value"       // #nosec G101 -- fabricated fixture value (CWE-798)
		keyIDVal  = "AKIACR008BOWNERREADER"          // #nosec G101 -- fabricated fixture value (CWE-798)
	)
	t.Setenv(strings.TrimPrefix(vaultRef, "env:"), vaultVal)
	t.Setenv(strings.TrimPrefix(keyIDRef, "env:"), keyIDVal)
	t.Setenv(strings.TrimPrefix(secretRef, "env:"), "cr008b-aws-secret-value")
	var other cr008Collector
	otherVault := httptest.NewServer(other.handler(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusForbidden) }))
	defer otherVault.Close()
	var owner cr008Collector
	ownerVault := httptest.NewServer(owner.handler(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusForbidden) }))
	defer ownerVault.Close()
	h := newOperatingServedHarness(t, config.Protocols{},
		bindOutboundEnvCredentialRefs("cloud_secret", []string{ownerVault.URL}, vaultRef),
		bindOutboundEnvCredentialRefs("cloud_certificate", []string{"https://acm.us-east-1.amazonaws.com"}, keyIDRef, secretRef))
	writer := seedScopedTokenSubject(t, h.store, h.tenant, "cr008b-discovery", "discovery:read", "discovery:write", string(authz.PrivateEgress))
	ctx := t.Context()
	for _, tc := range []struct {
		name, kind string
		cfg        map[string]any
		// origin is the destination the pinned client refused.
		origin string
	}{
		// The reference hides behind a key the API reads only in exact case;
		// the worker's decoder matches it case-insensitively.
		{"a case-variant reference key", "cloud_secret", map[string]any{"providers": []map[string]any{{
			"provider": "hashicorp-vault", "vault_url": otherVault.URL, "allow_private_endpoint": true,
			"private_egress_cidrs": []string{serviceNowSinkCIDR(t, otherVault.URL)}, "Token_Ref": vaultRef, "mount": "secret", "path_prefix": "tls",
		}}}, otherVault.URL},
		// No endpoint key: the worker derives the destination from the region,
		// which the binding does not name. The pin refuses before any DNS lookup.
		{"a region-derived destination", "cloud_certificate", map[string]any{"providers": []map[string]any{{
			"provider": "aws-acm", "region": "cr008-unbound-1", "access_key_id_ref": keyIDRef, "secret_access_key_ref": secretRef,
		}}}, "https://acm.cr008-unbound-1.amazonaws.com"},
	} {
		status, body := secretsReqKey(t, h, http.MethodPost, "/api/v1/discovery/sources", writer, "cr008b-source-"+tc.kind, map[string]any{
			"kind": tc.kind, "name": "CR-008 " + tc.name, "config": tc.cfg})
		var source struct {
			ID string `json:"id"`
		}
		if status != http.StatusCreated || json.Unmarshal(body, &source) != nil || source.ID == "" {
			t.Fatalf("%s: the declaration was not stored (the API check is best-effort here): %d %s", tc.name, status, body)
		}
		status, body = secretsReqKey(t, h, http.MethodPost, "/api/v1/discovery/runs", writer, "cr008b-run-"+tc.kind, map[string]any{"source_id": source.ID})
		var run struct {
			ID string `json:"id"`
		}
		if status != http.StatusCreated || json.Unmarshal(body, &run) != nil || run.ID == "" {
			t.Fatalf("%s: queue the run: %d %s", tc.name, status, body)
		}
		if err := h.srv.Drain(ctx); err != nil {
			t.Fatal(err)
		}
		got, err := h.store.GetDiscoveryRun(ctx, h.tenant, run.ID)
		if err != nil {
			t.Fatal(err)
		}
		// The pinned client's own refusal, naming the destination it refused.
		if got.Status == "succeeded" || !strings.Contains(got.Error, "is outside the origins the credential is bound to") ||
			!strings.Contains(got.Error, tc.origin) {
			t.Errorf("%s: the worker's pin did not refuse it: %s (%s)", tc.name, got.Status, got.Error)
		}
	}
	if other.received(vaultVal) || other.requests() != 0 {
		t.Fatalf("an origin the binding does not name received %d requests", other.requests())
	}
}

// CR-008 (design D3, review item 7): the machine-identity workers check a token
// file's binding against azureiam.Endpoints and gcpiam.Endpoints, then hand the
// file to collectors that dial their configuration's endpoint fields. Every such
// field, set or defaulted, is in that set, so a collector cannot reach an origin
// the binding was never checked against, and a new endpoint field fails here
// until the set names it.
func TestMachineIdentityCollectorsDialOnlyTheEndpointsTheirBindingChecksCR008(t *testing.T) {
	fields := func(cfg any) (map[string]string, []string) {
		v := reflect.ValueOf(cfg).Elem()
		set := map[string]string{}
		var all []string
		for i := range v.NumField() {
			f := v.Type().Field(i)
			// A destination field: its JSON name ends in _endpoint, _url, _uri
			// or _host, or its Go name in Endpoint, URL, URI or Host.
			tag, _, _ := strings.Cut(f.Tag.Get("json"), ",")
			destination := strings.HasSuffix(tag, "_endpoint") || strings.HasSuffix(tag, "_url") ||
				strings.HasSuffix(tag, "_uri") || strings.HasSuffix(tag, "_host") ||
				strings.HasSuffix(f.Name, "Endpoint") || strings.HasSuffix(f.Name, "URL") || strings.HasSuffix(f.Name, "URI") ||
				strings.HasSuffix(f.Name, "Host")
			if f.Type.Kind() != reflect.String || !destination {
				continue
			}
			url := "https://" + strings.ToLower(f.Name) + ".cr008.example"
			v.Field(i).SetString(url)
			set[f.Name] = url
			all = append(all, url)
		}
		slices.Sort(all)
		return set, all
	}
	azure := azureiam.Config{}
	azureFields, azureAll := fields(&azure)
	if len(azureFields) != 2 {
		t.Fatalf("azureiam.Config endpoint fields = %v; review which the collector dials and extend Endpoints", azureFields)
	}
	if got := slices.Sorted(slices.Values(azureiam.Endpoints(azure))); !slices.Equal(got, azureAll) {
		t.Fatalf("azureiam.Endpoints = %v, want every endpoint field %v", got, azureAll)
	}
	defaults := azureiam.Defaults(azureiam.Config{})
	if got := azureiam.Endpoints(azureiam.Config{}); !slices.Equal(got, []string{defaults.GraphEndpoint, defaults.ARMEndpoint}) || got[0] == "" || got[1] == "" {
		t.Fatalf("azureiam.Endpoints of an empty config = %v, want the defaults the collector dials", got)
	}
	// Activity is read from Cloud Logging only with a lookback; then the
	// logging endpoint is in the checked set too.
	gcp := gcpiam.Config{ActivityLookbackDays: 30}
	gcpFields, gcpAll := fields(&gcp)
	if len(gcpFields) != 3 {
		t.Fatalf("gcpiam.Config endpoint fields = %v; review which the collector dials and extend Endpoints", gcpFields)
	}
	if got := slices.Sorted(slices.Values(gcpiam.Endpoints(gcp))); !slices.Equal(got, gcpAll) {
		t.Fatalf("gcpiam.Endpoints = %v, want every endpoint field %v", got, gcpAll)
	}
	gcp.ActivityLookbackDays = 0
	if got := gcpiam.Endpoints(gcp); slices.Contains(got, gcpFields["LoggingEndpoint"]) || len(got) != 2 {
		t.Fatalf("gcpiam.Endpoints without a lookback = %v, want IAM and Resource Manager only", got)
	}
	gcpDefaults := gcpiam.Defaults(gcpiam.Config{})
	if got := gcpiam.Endpoints(gcpiam.Config{ActivityLookbackDays: 1}); !slices.Equal(got,
		[]string{gcpDefaults.IAMEndpoint, gcpDefaults.ResourceManagerEndpoint, gcpDefaults.LoggingEndpoint}) {
		t.Fatalf("gcpiam.Endpoints of an empty config = %v, want the defaults the collector dials", got)
	}
}
