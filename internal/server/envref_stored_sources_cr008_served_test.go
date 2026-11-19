// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"bytes"
	"encoding/json"
	"encoding/pem"
	"io"
	"net/http"
	"net/http/httptest"
	"net/http/httputil"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	googleuuid "github.com/google/uuid"
	"trstctl.com/trstctl/internal/cloudentitlements/assessment"
	"trstctl.com/trstctl/internal/cloudentitlements/awsiam"
	"trstctl.com/trstctl/internal/cloudentitlements/awspolicy"
	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/store"
)

// cr008Collector records the headers and bodies that reach a collector, so a
// test can tell whether any credential value was sent to it.
type cr008Collector struct {
	mu   sync.Mutex
	seen []string
}

func (c *cr008Collector) handler(respond http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var all bytes.Buffer
		_ = r.Header.Write(&all)
		// Basic credentials travel base64-encoded; record them decoded too.
		if user, pass, ok := r.BasicAuth(); ok {
			all.WriteString("basic " + user + ":" + pass + "\n")
		}
		body, _ := io.ReadAll(io.LimitReader(r.Body, 1<<20))
		all.Write(body)
		c.mu.Lock()
		c.seen = append(c.seen, all.String())
		c.mu.Unlock()
		r.Body = io.NopCloser(bytes.NewReader(body))
		respond(w, r)
	}
}

func (c *cr008Collector) received(value string) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	for _, request := range c.seen {
		if strings.Contains(request, value) {
			return true
		}
	}
	return false
}

func (c *cr008Collector) requests() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.seen)
}

// CR-008 (design §4): the worker is the guarantee. For each discovery family
// whose stored configuration resolves an env reference, a declaration stored
// without the API's check is run twice: once by another tenant naming the owner
// tenant's reference, once by the owner tenant sending it to an origin the
// operator did not bind. The worker refuses both with nothing sent. Where a
// family reaches a second destination (GCP Policy Analyzer for service-account
// keys, Bitwarden's identity service, which receives the access token's client
// secret in a form body), only that second destination is the other party's
// collector.
func TestServedStoredSourcesSendNothingOutsideTheirBindingCR008(t *testing.T) {
	const (
		graphRef   = "env:TRSTCTL_CR008D_GRAPH_TOKEN_FILE"       // #nosec G101 -- reference names only (CWE-798)
		armRef     = "env:TRSTCTL_CR008D_ARM_TOKEN_FILE"         // #nosec G101 -- reference names only (CWE-798)
		gcpMIRef   = "env:TRSTCTL_CR008D_GCP_TOKEN_FILE"         // #nosec G101 -- reference names only (CWE-798)
		awsRef     = "env:TRSTCTL_CR008D_AWS_STS_SESSION_FILE"   // #nosec G101 -- reference names only (CWE-798)
		vaultRef   = "env:TRSTCTL_CR008D_VAULT_TOKEN"            // #nosec G101 -- reference names only (CWE-798)
		gcpSMRef   = "env:TRSTCTL_CR008D_GCP_SM_TOKEN"           // #nosec G101 -- reference names only (CWE-798)
		gcpKeysRef = "env:TRSTCTL_CR008D_GCP_KEYS_TOKEN"         // #nosec G101 -- reference names only (CWE-798)
		bwsRef     = "env:TRSTCTL_CR008D_BITWARDEN_ACCESS_TOKEN" // #nosec G101 -- reference names only (CWE-798)

		azureTenant  = "c8000000-0000-4000-8000-0000000000d1"
		subscription = "c8000000-0000-4000-8000-0000000000d2"
		principal    = "c8000000-0000-4000-8000-0000000000d3"
		// The GCP stand-in answers only this bearer token.
		gcpKeysValue = "m3l1-read-token"
		bwsSecret    = "cr008BitwardenClientSecretD" // #nosec G101 -- fabricated fixture value; no value is real (CWE-798)
	)
	// Fabricated values, never real credentials.
	values := map[string]string{ // #nosec G101 -- fabricated fixture values; the test needs the shape, no value is real (CWE-798)
		"Azure Graph token":         "cr008d-graph-reader-value",
		"Azure ARM token":           "cr008d-arm-reader-value",
		"GCP token":                 "cr008d-gcp-reader-value",
		"AWS key ID":                "ASIACR008DOWNERREADER",
		"AWS session token":         "cr008d-sts-session-value",
		"Vault token":               "cr008d-owner-vault-value",
		"GCP SM token":              "cr008d-gcp-secret-manager-value",
		"GCP service-account token": gcpKeysValue,
		"Bitwarden client secret":   bwsSecret,
	}
	dir := t.TempDir()
	file := func(ref, name string, value []byte) {
		t.Helper()
		path := filepath.Join(dir, name)
		if err := os.WriteFile(path, value, 0o600); err != nil {
			t.Fatal(err)
		}
		t.Setenv(strings.TrimPrefix(ref, "env:"), path)
	}
	file(graphRef, "graph", []byte(values["Azure Graph token"]))
	file(armRef, "arm", []byte(values["Azure ARM token"]))
	file(gcpMIRef, "gcp", []byte(values["GCP token"]))
	session, err := json.Marshal(map[string]any{"Credentials": map[string]any{ // #nosec G101 -- fabricated fixture values; no value is real (CWE-798)
		"AccessKeyId": values["AWS key ID"], "SecretAccessKey": "cr008d-sts-secret-value", "SessionToken": values["AWS session token"],
		"Expiration": time.Now().UTC().Add(time.Hour).Format(time.RFC3339),
	}})
	if err != nil {
		t.Fatal(err)
	}
	file(awsRef, "aws-session.json", session)
	t.Setenv(strings.TrimPrefix(vaultRef, "env:"), values["Vault token"])
	t.Setenv(strings.TrimPrefix(gcpSMRef, "env:"), values["GCP SM token"])
	t.Setenv(strings.TrimPrefix(gcpKeysRef, "env:"), gcpKeysValue)
	t.Setenv(strings.TrimPrefix(bwsRef, "env:"), "0."+"5b3c1a2e-9f40-4d1b-8a6e-2c7d9e0f1a2c"+"."+bwsSecret+":"+"AAECAwQFBgcICQoLDA0ODw==")

	// The other party's collectors: one over TLS for the machine-identity
	// readers, one over HTTP for the secret stores.
	var other cr008Collector
	otherTLS := httptest.NewTLSServer(other.handler(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.URL.Path == "/v1.0/organization" {
			_ = json.NewEncoder(w).Encode(map[string]any{"value": []any{map[string]any{"id": azureTenant}}})
			return
		}
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer otherTLS.Close()
	otherPlain := httptest.NewServer(other.handler(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusForbidden)
	}))
	defer otherPlain.Close()
	otherCA := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: otherTLS.TLS.Certificates[0].Certificate[0]}))
	loopback := []string{serviceNowSinkCIDR(t, otherPlain.URL)}
	// The owner's own first destinations: its GCP IAM (a stand-in that answers
	// the key listing, so the reader goes on to Policy Analyzer) and its
	// Bitwarden API.
	var denyActivity atomic.Bool
	gcpStandIn := m3l1GCPStandIn(t, &denyActivity)
	gcpTarget, err := url.Parse(gcpStandIn.URL)
	if err != nil {
		t.Fatal(err)
	}
	// Counted in front of the stand-in, so a test can tell whether the owner's
	// token was used there for another tenant.
	var ownerGCPRequests cr008Collector
	ownerGCP := httptest.NewServer(ownerGCPRequests.handler(httputil.NewSingleHostReverseProxy(gcpTarget).ServeHTTP))
	defer ownerGCP.Close()
	var ownerBitwarden cr008Collector
	ownerBitwardenServer := httptest.NewServer(ownerBitwarden.handler(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusForbidden)
	}))
	defer ownerBitwardenServer.Close()
	var ownerVault cr008Collector
	ownerVaultServer := httptest.NewServer(ownerVault.handler(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusForbidden)
	}))
	defer ownerVaultServer.Close()

	h := newOperatingServedHarness(t, config.Protocols{},
		bindOutboundEnvCredentialRefs("azure_machine_identity", []string{"https://graph.microsoft.com"}, graphRef),
		bindOutboundEnvCredentialRefs("azure_machine_identity", []string{"https://management.azure.com"}, armRef),
		bindOutboundEnvCredentialRefs("gcp_machine_identity", []string{"https://iam.googleapis.com", "https://cloudresourcemanager.googleapis.com"}, gcpMIRef),
		bindOutboundEnvCredentialRefs(assessment.SourceKind, []string{"https://iam.amazonaws.com"}, awsRef),
		bindOutboundEnvCredentialRefs("cloud_secret", []string{ownerVaultServer.URL}, vaultRef),
		bindOutboundEnvCredentialRefs("cloud_secret", []string{"https://secretmanager.googleapis.com"}, gcpSMRef),
		// The service-account key reader's binding names the IAM origin only, not
		// Policy Analyzer; Bitwarden's names the API origin only, not the identity
		// service.
		bindOutboundEnvCredentialRefs("cloud_access_key", []string{ownerGCP.URL}, gcpKeysRef),
		bindOutboundEnvCredentialRefs("secret_store", []string{ownerBitwardenServer.URL}, bwsRef))
	owner := h.tenant
	otherTenant := googleuuid.NewString()
	registerServedTenantID(t, h, otherTenant, "CR-008 second tenant")
	ctx := t.Context()

	const (
		tenantRefusal = "has not bound it to this tenant"
		// The binding's origin check or the pinned client refuses the owner.
		originRefusal = "has not bound it to send to"
		pinRefusal    = "is outside the origins the credential is bound to"
	)
	ownerStandIns := func() int { return ownerGCPRequests.requests() + ownerBitwarden.requests() + ownerVault.requests() }
	// Another tenant aimed at the owner's own bound Vault: only the tenant check
	// stands between them.
	vaultAtOwner, err := json.Marshal(map[string]any{"providers": []map[string]any{{"provider": "hashicorp-vault", "vault_url": ownerVaultServer.URL,
		"allow_private_endpoint": true, "private_egress_cidrs": loopback, "token_ref": vaultRef, "mount": "secret", "path_prefix": "tls"}}})
	if err != nil {
		t.Fatal(err)
	}
	runStored := func(tenantID, kind, name string, raw []byte) store.DiscoveryRun {
		t.Helper()
		source, err := h.srv.orch.UpsertDiscoverySource(ctx, tenantID, store.DiscoverySource{Kind: kind, Name: name, Config: raw})
		if err != nil {
			t.Fatalf("%s: store the declaration: %v", name, err)
		}
		run, err := h.srv.orch.QueueDiscoveryRun(ctx, tenantID, store.DiscoveryRun{SourceID: source.ID})
		if err != nil {
			t.Fatalf("%s: queue the run: %v", name, err)
		}
		if err := h.srv.Drain(ctx); err != nil {
			t.Fatal(err)
		}
		got, err := h.store.GetDiscoveryRun(ctx, tenantID, run.ID)
		if err != nil {
			t.Fatal(err)
		}
		return got
	}
	if got := runStored(otherTenant, "cloud_secret", "cr008 stored vault at the owner's origin", vaultAtOwner); got.Status == "succeeded" ||
		!strings.Contains(got.Error, tenantRefusal) || ownerVault.requests() != 0 {
		t.Errorf("another tenant's Vault source aimed at the owner's bound Vault was not refused by the tenant check: %s (%s), %d requests there",
			got.Status, got.Error, ownerVault.requests())
	}

	families := []struct {
		kind, name string
		cfg        any
	}{
		{"azure_machine_identity", "azure", map[string]any{
			"azure_tenant_id": azureTenant, "subscription_id": subscription, "service_principal_ids": []string{principal},
			"graph_token_file_ref": graphRef, "arm_token_file_ref": armRef,
			"graph_endpoint": otherTLS.URL, "arm_endpoint": otherTLS.URL, "ca_pem": otherCA,
			"allow_private_endpoint": true, "private_egress_cidrs": loopback,
		}},
		{"gcp_machine_identity", "gcp-machine-identity", map[string]any{
			"project": "owner-project", "service_accounts": []string{"orders@owner-project.iam.gserviceaccount.com"}, "token_file_ref": gcpMIRef,
			"iam_endpoint": otherTLS.URL, "resource_manager_endpoint": otherTLS.URL, "logging_endpoint": otherTLS.URL, "ca_pem": otherCA,
			"allow_private_endpoint": true, "private_egress_cidrs": loopback,
		}},
		{assessment.SourceKind, "aws-entitlements", assessment.SourceConfig{
			Endpoint: otherTLS.URL, CAPEM: otherCA, SessionFileRef: awsRef, AllowPrivateEndpoint: true, PrivateEgressCIDRs: loopback,
			Principals: []awsiam.Selection{{Kind: awspolicy.IAMUser, Name: "owner-workload"}},
			Input: assessment.Input{Checks: []assessment.Check{{PrincipalARN: "arn:aws:iam::111122223333:user/owner-workload", Action: "s3:GetObject",
				Resource: "arn:aws:s3:::owner-bucket/object", ResourceAccountID: "111122223333"}}},
		}},
		{"cloud_secret", "vault", map[string]any{"providers": []map[string]any{{"provider": "hashicorp-vault", "vault_url": otherPlain.URL,
			"allow_private_endpoint": true, "private_egress_cidrs": loopback, "token_ref": vaultRef, "mount": "secret", "path_prefix": "tls"}}}},
		{"cloud_secret", "gcp-secret-manager", map[string]any{"providers": []map[string]any{{"provider": "gcp-secret-manager", "project": "owner-project",
			"endpoint": otherPlain.URL, "allow_private_endpoint": true, "private_egress_cidrs": loopback, "token_ref": gcpSMRef}}}},
		{"cloud_access_key", "gcp-service-account-keys", map[string]any{"providers": []map[string]any{{"provider": "gcp-iam", "project": "p",
			"endpoint": ownerGCP.URL, "activity_endpoint": otherPlain.URL, "allow_private_endpoint": true, "private_egress_cidrs": loopback,
			"token_ref": gcpKeysRef}}}},
		{"secret_store", "bitwarden", map[string]any{"providers": []map[string]any{{"provider": "bitwarden-secrets-manager",
			"endpoint": ownerBitwardenServer.URL, "identity_endpoint": otherPlain.URL, "allow_private_endpoint": true, "private_egress_cidrs": loopback,
			"token_ref": bwsRef}}}},
	}
	for _, family := range families {
		for _, scenario := range []struct{ who, tenantID string }{{"another tenant", otherTenant}, {"the owner to an unbound origin", owner}} {
			before, ownerBefore := other.requests(), ownerStandIns()
			raw, err := json.Marshal(family.cfg)
			if err != nil {
				t.Fatal(err)
			}
			got := runStored(scenario.tenantID, family.kind, "cr008 stored "+family.name+" "+scenario.who, raw)
			// Another tenant is refused by the tenant check itself; the owner by
			// the origin check or the pinned client.
			refused := strings.Contains(got.Error, tenantRefusal)
			if scenario.tenantID == owner {
				refused = strings.Contains(got.Error, originRefusal) || strings.Contains(got.Error, pinRefusal)
			}
			if got.Status == "succeeded" || !strings.Contains(got.Error, "not bound to this use") || !refused {
				t.Errorf("%s, %s: the worker did not refuse a reference outside its binding: %s (%s)", family.name, scenario.who, got.Status, got.Error)
			}
			if n := other.requests() - before; n != 0 {
				t.Errorf("%s, %s: the other party's collector received %d requests", family.name, scenario.who, n)
			}
			if n := ownerStandIns() - ownerBefore; scenario.tenantID == otherTenant && n != 0 {
				t.Errorf("%s, %s: the owner's own origins received %d requests for another tenant", family.name, scenario.who, n)
			}
		}
	}
	for what, value := range values {
		if other.received(value) {
			t.Errorf("the other party's collector received the owner tenant's %s", what)
		}
	}
}
