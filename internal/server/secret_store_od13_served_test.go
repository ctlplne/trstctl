// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"bytes"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"os"
	"strings"
	"testing"

	"trstctl.com/trstctl/internal/authz"
	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/crypto/ctlog/ctlogtest"
	"trstctl.com/trstctl/internal/discovery/cloudsecret/secretstoretest"
)

// od13Harness runs secret_store sources through the served API and reads
// their runs and findings.
type od13Harness struct {
	t   *testing.T
	h   *servedHarness
	tok string
}

type od13Run struct {
	ID            string `json:"id"`
	Status        string `json:"status"`
	TargetResults []struct {
		Target string `json:"target"`
		Status string `json:"status"`
		Error  string `json:"error"`
	} `json:"target_results"`
}

func (o *od13Harness) run(name string, providers ...map[string]any) (string, od13Run) {
	t := o.t
	t.Helper()
	status, body := secretsReq(t, o.h, http.MethodPost, "/api/v1/discovery/sources", o.tok, map[string]any{
		"name": name, "kind": "secret_store", "config": map[string]any{"providers": providers}})
	var source struct {
		ID string `json:"id"`
	}
	if status != http.StatusCreated || json.Unmarshal(body, &source) != nil {
		t.Fatalf("create %s: %d %s", name, status, body)
	}
	status, body = secretsReq(t, o.h, http.MethodPost, "/api/v1/discovery/runs", o.tok, map[string]any{"source_id": source.ID})
	var run od13Run
	if status != http.StatusCreated || json.Unmarshal(body, &run) != nil {
		t.Fatalf("run %s: %d %s", name, status, body)
	}
	if err := o.h.srv.Drain(t.Context()); err != nil {
		t.Fatalf("drain %s: %v", name, err)
	}
	status, body = secretsReq(t, o.h, http.MethodGet, "/api/v1/discovery/runs/"+run.ID, o.tok, nil)
	if status != http.StatusOK || json.Unmarshal(body, &run) != nil {
		t.Fatalf("read run %s: %d %s", name, status, body)
	}
	return source.ID, run
}

// findings counts a source's findings by provider/kind and returns the raw
// findings response for value checks.
func (o *od13Harness) findings(sourceID string) (map[string]int, []byte) {
	t := o.t
	t.Helper()
	status, body := secretsReq(t, o.h, http.MethodGet, "/api/v1/discovery/findings?source_kind=secret_store&limit=100", o.tok, nil)
	var list struct {
		Items []struct {
			SourceID string         `json:"source_id"`
			Kind     string         `json:"kind"`
			Metadata map[string]any `json:"metadata"`
		} `json:"items"`
	}
	if status != http.StatusOK || json.Unmarshal(body, &list) != nil {
		t.Fatalf("findings: %d %s", status, body)
	}
	got := map[string]int{}
	for _, f := range list.Items {
		if f.SourceID == sourceID {
			provider, _ := f.Metadata["provider"].(string)
			got[provider+"/"+f.Kind]++
		}
	}
	return got, body
}

func od13At(t *testing.T, url string, fields map[string]any) map[string]any {
	fields["endpoint"], fields["allow_private_endpoint"], fields["private_egress_cidrs"] = url, true, []string{serviceNowSinkCIDR(t, url)}
	return fields
}

// OD-13 Done-when (stand-ins): one served secret_store source reads
// Infisical (Universal Auth), Conjur (a host's API key), Akeyless (an API-key
// access ID) and Bitwarden Secrets Manager (a machine account token whose key
// decrypts names) as metadata only, reaching no value endpoint; with content
// inspection a certificate and an API key in each store become findings and
// no value is kept; and the source catalog lists every served secret-store
// provider.
func TestServedSecretStoresInfisicalConjurAkeylessBitwardenOD13(t *testing.T) {
	der, _, err := ctlogtest.IssueCert("stores.od13.example", "stores.od13.example")
	if err != nil {
		t.Fatal(err)
	}
	certPEM := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
	apiKey := "gl" + "pat-" + strings.Repeat("Od13Served", 3)[:24]
	bwsToken := "0." + "5b3c1a2e-9f40-4d1b-8a6e-2c7d9e0f1a2b" + "." + "od13ServedClientSecret" + ":" + "AAECAwQFBgcICQoLDA0ODw=="
	const bwsOrg = "8e2f4c1a-7b3d-4e9f-a1c2-3d4e5f6a7b8c"

	inf := secretstoretest.NewInfisical("ua-client", "ua-secret", []secretstoretest.InfisicalProject{{ID: "p-1", Name: "payments", Environments: []string{"dev"}}},
		[]secretstoretest.InfisicalSecret{
			{Project: "p-1", Environment: "dev", Path: "/", Key: "DB_PASSWORD", Value: "plain"},
			{Project: "p-1", Environment: "dev", Path: "/tls", Key: "TLS_CERT", Value: certPEM},
			{Project: "p-1", Environment: "dev", Path: "/tls", Key: "DEPLOY_TOKEN", Value: apiKey},
		})
	t.Cleanup(inf.Close)
	cj := secretstoretest.NewConjur("od13", "host/apps/discovery", "host-api-key", []secretstoretest.ConjurVariable{
		{ID: "apps/db/password", Value: "plain", Visible: true},
		{ID: "apps/tls/cert", Value: certPEM, Visible: true},
		{ID: "apps/tls/deploy-token", Value: apiKey, Visible: true},
	})
	t.Cleanup(cj.Close)
	akl := secretstoretest.NewAkeyless("p-access-id", "access-key", []secretstoretest.AkeylessItem{
		{Name: "/apps/db/password", Value: "plain"}, {Name: "/apps/tls/cert", Value: certPEM}, {Name: "/apps/tls/deploy-token", Value: apiKey},
	})
	t.Cleanup(akl.Close)
	bws := secretstoretest.NewBitwardenSecretsManager(bwsToken, bwsOrg, bytes.Repeat([]byte{0x33}, 64), []secretstoretest.BitwardenSecret{
		{ID: "a1000000-0000-4000-8000-000000000001", Key: "DB_PASSWORD", Value: "plain", Project: "payments"},
		{ID: "a1000000-0000-4000-8000-000000000002", Key: "TLS_CERT", Value: certPEM, Project: "payments"},
		{ID: "a1000000-0000-4000-8000-000000000003", Key: "DEPLOY_TOKEN", Value: apiKey},
	})
	t.Cleanup(bws.Close)
	for env, value := range map[string]string{
		"TRSTCTL_OD13_INF": "ua-secret", "TRSTCTL_OD13_CJ": "host-api-key", "TRSTCTL_OD13_AKL": "access-key", "TRSTCTL_OD13_BWS": bwsToken,
	} {
		t.Setenv(env, value)
	}
	h := newOperatingServedHarness(t, config.Protocols{}, allowOutboundEnvCredentialRefs("env:TRSTCTL_OD13_INF", "env:TRSTCTL_OD13_CJ", "env:TRSTCTL_OD13_AKL", "env:TRSTCTL_OD13_BWS"))
	o := &od13Harness{t: t, h: h, tok: seedScopedToken(t, h.store, h.tenant, "discovery:read", "discovery:write", "secrets:read", string(authz.PrivateEgress))}
	providers := func(inspect bool) []map[string]any {
		return []map[string]any{
			od13At(t, inf.URL(), map[string]any{"provider": "infisical", "client_id": "ua-client", "client_secret_ref": "env:TRSTCTL_OD13_INF", "inspect_content": inspect}),                                      // #nosec G101 -- credential references to fabricated fixture values (CWE-798)
			od13At(t, cj.URL(), map[string]any{"provider": "conjur", "account": "od13", "login": "host/apps/discovery", "api_key_ref": "env:TRSTCTL_OD13_CJ", "path_prefix": "apps", "inspect_content": inspect}), // #nosec G101 -- credential references to fabricated fixture values (CWE-798)
			od13At(t, akl.URL(), map[string]any{"provider": "akeyless", "client_id": "p-access-id", "client_secret_ref": "env:TRSTCTL_OD13_AKL", "path_prefix": "/apps", "inspect_content": inspect}),             // #nosec G101 -- credential references to fabricated fixture values (CWE-798)
			od13At(t, bws.URL(), map[string]any{"provider": "bitwarden-secrets-manager", "identity_endpoint": bws.URL(), "token_ref": "env:TRSTCTL_OD13_BWS", "inspect_content": inspect}),                        // #nosec G101 -- credential references to fabricated fixture values (CWE-798)
		}
	}
	names := []string{"infisical", "conjur", "akeyless", "bitwarden-secrets-manager"}

	sourceID, run := o.run("od13-metadata", providers(false)...)
	if run.Status != "succeeded" || len(run.TargetResults) != 4 {
		t.Fatalf("metadata run = %+v", run)
	}
	got, body := o.findings(sourceID)
	for _, provider := range names {
		if got[provider+"/cloud_secret_resource"] != 3 || got[provider+"/x509_certificate"] != 0 || got[provider+"/secret_store_api_key"] != 0 {
			t.Fatalf("metadata-only findings of %s = %v", provider, got)
		}
	}
	for _, value := range []string{apiKey, "BEGIN CERTIFICATE", secretstoretest.InfisicalHiddenValue} {
		if bytes.Contains(body, []byte(value)) {
			t.Fatalf("the metadata-only findings carry %q", value)
		}
	}
	for name, seen := range map[string][]string{"infisical": inf.Seen(), "conjur": cj.Seen(), "akeyless": akl.Seen(), "bitwarden": bws.Seen()} {
		for _, call := range seen {
			if strings.Contains(call, "viewSecretValue=true") || strings.HasPrefix(call, "GET /secrets/") ||
				call == "POST /get-secret-value" || call == "POST /secrets/get-by-ids" {
				t.Fatalf("a metadata-only %s run reached a value endpoint: %s", name, call)
			}
		}
	}

	sourceID, run = o.run("od13-inspect", providers(true)...)
	if run.Status != "succeeded" || len(run.TargetResults) != 4 {
		t.Fatalf("inspect run = %+v", run)
	}
	got, body = o.findings(sourceID)
	for _, provider := range names {
		if got[provider+"/x509_certificate"] != 1 || got[provider+"/secret_store_api_key"] != 1 {
			t.Fatalf("inspected findings of %s = %v", provider, got)
		}
	}
	if bytes.Contains(body, []byte(apiKey)) || bytes.Contains(body, []byte("BEGIN CERTIFICATE")) {
		t.Fatal("the inspected findings carry a stored value")
	}

	// The Secrets posture shows each store's discovery configured by the two
	// secret_store sources, with no sync target.
	status, raw := secretsReq(t, h, http.MethodGet, "/api/v1/secrets/cloud-secret-managers", o.tok, nil)
	var posture struct {
		Providers []struct {
			ID                   string `json:"id"`
			DiscoveryConfigured  bool   `json:"discovery_configured"`
			DiscoverySourceCount int    `json:"discovery_source_count"`
			SyncSupported        bool   `json:"sync_supported"`
		} `json:"providers"`
	}
	if status != http.StatusOK || json.Unmarshal(raw, &posture) != nil {
		t.Fatalf("posture = %d %s", status, raw)
	}
	seen := 0
	for _, p := range posture.Providers {
		for _, provider := range names {
			if p.ID == provider {
				seen++
				if !p.DiscoveryConfigured || p.DiscoverySourceCount != 2 || p.SyncSupported {
					t.Fatalf("posture row %+v", p)
				}
			}
		}
	}
	if seen != 4 {
		t.Fatalf("posture rows for the four stores = %d (%s)", seen, raw)
	}

	// The source catalog lists the served secret-store providers.
	status, raw = secretsReq(t, h, http.MethodGet, "/api/v1/discovery/capabilities", o.tok, nil)
	var catalog struct {
		Items []struct {
			Kind      string `json:"kind"`
			Providers []struct {
				ID string `json:"id"`
			} `json:"providers"`
		} `json:"items"`
	}
	if status != http.StatusOK || json.Unmarshal(raw, &catalog) != nil {
		t.Fatalf("catalog = %d %s", status, raw)
	}
	var ids []string
	for _, item := range catalog.Items {
		if item.Kind == "secret_store" {
			for _, p := range item.Providers {
				ids = append(ids, p.ID)
			}
		}
	}
	if strings.Join(ids, ",") != servedSecretStoreProviders {
		t.Fatalf("secret_store providers = %v", ids)
	}
	t.Logf("OD13_STANDIN_OK providers=%d", len(ids))
}

// servedSecretStoreProviders is the source catalog's secret-store provider
// list: the six of A173, the four of OD-13 and the two of OD-14.
const servedSecretStoreProviders = "aws-secrets-manager,gcp-secret-manager,azure-key-vault,hashicorp-vault,github-actions,gitlab-ci," +
	"infisical,conjur,akeyless,1password-connect,doppler,bitwarden-secrets-manager"

// OD-13 Done-when (official images): the same served source against the
// official Infisical (v0.167.8) and CyberArk Conjur (1.27.0) images, pinned
// by digest and seeded by runners/od13-lab-proof.sh: a Universal Auth
// identity with the Viewer role and a host with read and execute on its
// variables inventory them as metadata only, then find the seeded
// certificate and API key with content inspection, keeping no value. The
// lab passes its endpoints and credentials in the environment; without
// them the test skips.
func TestServedSecretStoresAgainstOfficialInfisicalAndConjurImagesOD13(t *testing.T) {
	need := []string{"TRSTCTL_OD13_INFISICAL_URL", "TRSTCTL_OD13_INFISICAL_CLIENT_ID", "TRSTCTL_OD13_INFISICAL_CLIENT_SECRET",
		"TRSTCTL_OD13_INFISICAL_PROJECT", "TRSTCTL_OD13_CONJUR_URL", "TRSTCTL_OD13_CONJUR_ACCOUNT", "TRSTCTL_OD13_CONJUR_LOGIN",
		"TRSTCTL_OD13_CONJUR_API_KEY", "TRSTCTL_OD13_LAB_API_KEY"}
	for _, name := range need {
		if os.Getenv(name) == "" {
			t.Skipf("the OD-13 lab is not running (%s unset); runners/od13-lab-proof.sh starts it", name)
		}
	}
	h := newOperatingServedHarness(t, config.Protocols{}, allowOutboundEnvCredentialRefs("env:TRSTCTL_OD13_INFISICAL_CLIENT_SECRET", "env:TRSTCTL_OD13_CONJUR_API_KEY"))
	o := &od13Harness{t: t, h: h, tok: seedScopedToken(t, h.store, h.tenant, "discovery:read", "discovery:write", string(authz.PrivateEgress))}
	providers := func(inspect bool) []map[string]any {
		return []map[string]any{
			od13At(t, os.Getenv("TRSTCTL_OD13_INFISICAL_URL"), map[string]any{"provider": "infisical", "client_id": os.Getenv("TRSTCTL_OD13_INFISICAL_CLIENT_ID"),
				"client_secret_ref": "env:TRSTCTL_OD13_INFISICAL_CLIENT_SECRET", "project": os.Getenv("TRSTCTL_OD13_INFISICAL_PROJECT"), "inspect_content": inspect}), // #nosec G101 -- credential references to lab fixture values (CWE-798)
			od13At(t, os.Getenv("TRSTCTL_OD13_CONJUR_URL"), map[string]any{"provider": "conjur", "account": os.Getenv("TRSTCTL_OD13_CONJUR_ACCOUNT"),
				"login": os.Getenv("TRSTCTL_OD13_CONJUR_LOGIN"), "api_key_ref": "env:TRSTCTL_OD13_CONJUR_API_KEY", "path_prefix": "apps", "inspect_content": inspect}), // #nosec G101 -- credential references to lab fixture values (CWE-798)
		}
	}
	sourceID, run := o.run("od13-lab-metadata", providers(false)...)
	if run.Status != "succeeded" || len(run.TargetResults) != 2 {
		t.Fatalf("metadata run = %+v", run)
	}
	got, body := o.findings(sourceID)
	// The lab seeds four Infisical secrets (three in dev, one in prod) and
	// four Conjur variables the host may read (one of them empty).
	if got["infisical/cloud_secret_resource"] != 4 || got["conjur/cloud_secret_resource"] != 4 || got["infisical/x509_certificate"]+got["conjur/x509_certificate"] != 0 {
		t.Fatalf("metadata-only findings = %v", got)
	}
	labKey := os.Getenv("TRSTCTL_OD13_LAB_API_KEY")
	for _, value := range []string{labKey, "BEGIN CERTIFICATE", "<hidden-by-infisical>"} {
		if bytes.Contains(body, []byte(value)) {
			t.Fatalf("the metadata-only findings carry %q", value)
		}
	}
	sourceID, run = o.run("od13-lab-inspect", providers(true)...)
	if run.Status != "succeeded" || len(run.TargetResults) != 2 {
		t.Fatalf("inspect run = %+v", run)
	}
	got, body = o.findings(sourceID)
	for _, provider := range []string{"infisical", "conjur"} {
		if got[provider+"/x509_certificate"] != 1 || got[provider+"/secret_store_api_key"] != 1 {
			t.Fatalf("inspected findings of %s = %v", provider, got)
		}
	}
	if bytes.Contains(body, []byte(labKey)) || bytes.Contains(body, []byte("BEGIN CERTIFICATE")) {
		t.Fatal("the inspected findings carry a stored value")
	}
	t.Logf("OD13_OFFICIAL_IMAGES_OK infisical=%d conjur=%d", got["infisical/cloud_secret_resource"], got["conjur/cloud_secret_resource"])
}
