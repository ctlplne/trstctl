// SPDX-License-Identifier: BUSL-1.1
package server

import (
	"bytes"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	googleuuid "github.com/google/uuid"
	"trstctl.com/trstctl/internal/authz"
	"trstctl.com/trstctl/internal/cloudentitlements/assessment"
	"trstctl.com/trstctl/internal/cloudentitlements/awsiam"
	"trstctl.com/trstctl/internal/cloudentitlements/awspolicy"
	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/store"
)

// envCredentialCollector records what reaches a test collector, so the test can
// tell whether any credential value was sent to it.
type envCredentialCollector struct {
	mu   sync.Mutex
	seen []string
}

func (c *envCredentialCollector) record(r *http.Request) {
	var all bytes.Buffer
	_ = r.Header.Write(&all)
	c.mu.Lock()
	c.seen = append(c.seen, all.String())
	c.mu.Unlock()
}

func (c *envCredentialCollector) received(value string) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	for _, headers := range c.seen {
		if strings.Contains(headers, value) {
			return true
		}
	}
	return false
}

// CR-008: an operator-approved env credential reference belongs to one tenant, the
// integrations that may use it and the exact origins it may be sent to. A second
// tenant on the same control plane cannot name it in its own integrations, the
// owner tenant cannot send it to an origin or integration the operator did not
// approve, and the worker checks the approval again before it reads the value, so
// a declaration stored without that check sends nothing.
func TestServedEnvCredentialRefsStayWithTheirTenantIntegrationAndOrigin(t *testing.T) {
	const (
		graphRef  = "env:TRSTCTL_CR008_GRAPH_TOKEN_FILE"
		armRef    = "env:TRSTCTL_CR008_ARM_TOKEN_FILE"
		gcpRef    = "env:TRSTCTL_CR008_GCP_TOKEN_FILE"
		awsRef    = "env:TRSTCTL_CR008_AWS_STS_SESSION_FILE"
		vaultRef  = "env:TRSTCTL_CR008_VAULT_TOKEN"
		gcpSMRef  = "env:TRSTCTL_CR008_GCP_SM_TOKEN"
		splunkRef = "env:TRSTCTL_CR008_SPLUNK_HEC_TOKEN"
		jiraRef   = "env:TRSTCTL_CR008_JIRA_TOKEN"
		retired   = "env:TRSTCTL_CR008_RETIRED_LIST_TOKEN"

		azureTenant  = "c8000000-0000-4000-8000-0000000000a1"
		subscription = "c8000000-0000-4000-8000-0000000000a2"
		principal    = "c8000000-0000-4000-8000-0000000000a3"
	)
	// Fabricated values, never real credentials. The token files are owner-only,
	// as the docs tell the operator to provision them.
	values := map[string]string{ // #nosec G101 -- fabricated fixture values; the test needs the shape, no value is real (CWE-798)
		"Azure Graph token": "cr008-graph-reader-value-0001",
		"Azure ARM token":   "cr008-arm-reader-value-0002",
		"GCP token":         "cr008-gcp-reader-value-0003",
		"AWS key ID":        "ASIACR008OWNERREADER1",
		"AWS session token": "cr008-sts-session-value-0004",
		"AWS secret key":    "cr008-sts-secret-value-0005",
		"Vault token":       "cr008-owner-vault-value-0006",
		"GCP SM token":      "cr008-gcp-secret-manager-value-0007",
	}
	dir := t.TempDir()
	writeFile := func(ref, name string, value []byte) {
		t.Helper()
		path := filepath.Join(dir, name)
		if err := os.WriteFile(path, value, 0o600); err != nil {
			t.Fatal(err)
		}
		t.Setenv(strings.TrimPrefix(ref, "env:"), path)
	}
	writeFile(graphRef, "graph", []byte(values["Azure Graph token"]))
	writeFile(armRef, "arm", []byte(values["Azure ARM token"]))
	writeFile(gcpRef, "gcp", []byte(values["GCP token"]))
	session, err := json.Marshal(map[string]any{"Credentials": map[string]any{
		"AccessKeyId": values["AWS key ID"], "SecretAccessKey": values["AWS secret key"], "SessionToken": values["AWS session token"],
		"Expiration": time.Now().UTC().Add(time.Hour).Format(time.RFC3339),
	}})
	if err != nil {
		t.Fatal(err)
	}
	writeFile(awsRef, "aws-session.json", session)
	t.Setenv(strings.TrimPrefix(vaultRef, "env:"), values["Vault token"])
	t.Setenv(strings.TrimPrefix(gcpSMRef, "env:"), values["GCP SM token"])
	t.Setenv(strings.TrimPrefix(splunkRef, "env:"), "cr008-splunk-value-0008")
	t.Setenv(strings.TrimPrefix(jiraRef, "env:"), "cr008-jira-value-0009")
	t.Setenv(strings.TrimPrefix(retired, "env:"), "cr008-retired-list-value-0010")

	// The owner tenant's own Vault, which the operator approved the Vault token for.
	var ownerVault envCredentialCollector
	ownerVaultServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ownerVault.record(r)
		w.WriteHeader(http.StatusForbidden)
	}))
	defer ownerVaultServer.Close()
	// A collector some other party runs. Nothing the operator approved may reach it.
	var other envCredentialCollector
	otherTLS := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		other.record(r)
		w.Header().Set("Content-Type", "application/json")
		if r.URL.Path == "/v1.0/organization" {
			_ = json.NewEncoder(w).Encode(map[string]any{"value": []any{map[string]any{"id": azureTenant}}})
			return
		}
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer otherTLS.Close()
	otherPlain := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		other.record(r)
		w.WriteHeader(http.StatusForbidden)
	}))
	defer otherPlain.Close()
	otherCA := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: otherTLS.TLS.Certificates[0].Certificate[0]}))
	otherTLSCIDR := []string{serviceNowSinkCIDR(t, otherTLS.URL)}
	otherPlainCIDR := []string{serviceNowSinkCIDR(t, otherPlain.URL)}

	// The operator binds each reference to the owner tenant, the integration it
	// serves and the exact origins it is sent to, default endpoints included. The
	// retired process-wide list still names one reference; it approves nothing.
	h := newOperatingServedHarness(t, config.Protocols{},
		bindOutboundEnvCredentialRefs("azure_machine_identity", []string{"https://graph.microsoft.com"}, graphRef),
		bindOutboundEnvCredentialRefs("azure_machine_identity", []string{"https://management.azure.com"}, armRef),
		bindOutboundEnvCredentialRefs("gcp_machine_identity", []string{"https://iam.googleapis.com", "https://cloudresourcemanager.googleapis.com"}, gcpRef),
		bindOutboundEnvCredentialRefs(assessment.SourceKind, []string{"https://iam.amazonaws.com"}, awsRef),
		bindOutboundEnvCredentialRefs("cloud_secret", []string{ownerVaultServer.URL}, vaultRef),
		bindOutboundEnvCredentialRefs("cloud_secret", []string{"https://secretmanager.googleapis.com"}, gcpSMRef),
		bindOutboundEnvCredentialRefs("audit_feed", []string{"https://hec.owner.example"}, splunkRef),
		bindOutboundEnvCredentialRefs("response_integration", []string{"https://jira.owner.example"}, jiraRef),
		func(d *Deps) { d.LegacyOutboundEnvCredentialRefs = []string{retired, vaultRef} })
	owner := h.tenant
	ctx := t.Context()

	declare := func(token, key, kind, name string, cfg any) (int, []byte, string) {
		t.Helper()
		status, body := secretsReqKey(t, h, http.MethodPost, "/api/v1/discovery/sources", token, key, map[string]any{"kind": kind, "name": name, "config": cfg})
		var source struct {
			ID string `json:"id"`
		}
		_ = json.Unmarshal(body, &source)
		return status, body, source.ID
	}
	runSource := func(token, tenantID, key, sourceID string) store.DiscoveryRun {
		t.Helper()
		status, body := secretsReqKey(t, h, http.MethodPost, "/api/v1/discovery/runs", token, key, map[string]any{"source_id": sourceID})
		var run struct {
			ID string `json:"id"`
		}
		if status != http.StatusCreated || json.Unmarshal(body, &run) != nil || run.ID == "" {
			t.Fatalf("queue run for %s: %d %s", sourceID, status, body)
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

	// The owner tenant uses its approved references as approved: the Azure source
	// on the default Microsoft endpoints is accepted, and the Vault token reaches the
	// owner's own Vault.
	ownerWriter := seedScopedTokenSubject(t, h.store, owner, "cr008-owner-discovery", "discovery:read", "discovery:write", string(authz.PrivateEgress))
	if status, body, _ := declare(ownerWriter, "cr008-owner-azure", "azure_machine_identity", "Owner Azure workload inventory", map[string]any{
		"azure_tenant_id": azureTenant, "subscription_id": subscription, "service_principal_ids": []string{principal},
		"graph_token_file_ref": graphRef, "arm_token_file_ref": armRef,
	}); status != http.StatusCreated {
		t.Fatalf("the owner tenant's Azure source on its approved endpoints was refused: %d %s", status, body)
	}
	status, body, vaultSource := declare(ownerWriter, "cr008-owner-vault", "cloud_secret", "Owner Vault inventory", map[string]any{
		"providers": []map[string]any{{"provider": "hashicorp-vault", "vault_url": ownerVaultServer.URL, "allow_private_endpoint": true,
			"private_egress_cidrs": []string{serviceNowSinkCIDR(t, ownerVaultServer.URL)}, "token_ref": vaultRef, "mount": "secret", "path_prefix": "tls"}},
	})
	if status != http.StatusCreated || vaultSource == "" {
		t.Fatalf("the owner tenant's Vault source on its approved origin was refused: %d %s", status, body)
	}
	runSource(ownerWriter, owner, "cr008-owner-vault-run", vaultSource)
	if !ownerVault.received(values["Vault token"]) {
		t.Fatal("the owner tenant's approved Vault token did not reach the owner's approved Vault origin")
	}

	// The owner tenant cannot send its own approved token to an origin the operator
	// did not approve, nor use a reference in an integration it was not approved for.
	if status, body, _ := declare(ownerWriter, "cr008-owner-azure-elsewhere", "azure_machine_identity", "Owner Azure elsewhere", map[string]any{
		"azure_tenant_id": azureTenant, "subscription_id": subscription, "service_principal_ids": []string{principal},
		"graph_token_file_ref": graphRef, "arm_token_file_ref": armRef,
		"graph_endpoint": otherTLS.URL, "arm_endpoint": otherTLS.URL, "ca_pem": otherCA,
		"allow_private_endpoint": true, "private_egress_cidrs": otherTLSCIDR,
	}); status != http.StatusBadRequest || !strings.Contains(string(body), "outbound_env_credential_bindings") {
		t.Errorf("the owner tenant pointed its approved Azure tokens at an origin the operator did not approve: %d %s", status, body)
	}
	if status, body, _ := declare(ownerWriter, "cr008-owner-retired", "cloud_secret", "Owner Vault on the retired list", map[string]any{
		"providers": []map[string]any{{"provider": "hashicorp-vault", "vault_url": ownerVaultServer.URL, "allow_private_endpoint": true,
			"private_egress_cidrs": []string{serviceNowSinkCIDR(t, ownerVaultServer.URL)}, "token_ref": retired, "mount": "secret", "path_prefix": "tls"}},
	}); status != http.StatusBadRequest || !strings.Contains(string(body), "outbound_env_credential_bindings") {
		t.Errorf("a reference only the retired outbound_env_credential_refs list names was accepted: %d %s", status, body)
	}
	ownerAuditor := seedScopedTokenSubject(t, h.store, owner, "cr008-owner-audit", "audit:write", "audit:read")
	if status, body := secretsReq(t, h, http.MethodPost, "/api/v1/audit/feeds/"+googleuuid.NewString()+"/preview", ownerAuditor, map[string]any{
		"name": "Owner HEC", "provider": "splunk-hec", "endpoint_url": "https://hec.owner.example/services/collector/event",
		"token_ref": vaultRef, "interval_seconds": 60, "batch_size": 10, "enabled": true,
	}); status != http.StatusBadRequest || !strings.Contains(string(body), "outbound_env_credential_bindings") ||
		!strings.Contains(string(body), "for the audit_feed integration") {
		t.Errorf("an audit feed accepted a reference the operator approved only for cloud secret discovery: %d %s", status, body)
	}

	// A second tenant on the same control plane, with discovery and private-egress
	// grants in its own tenant only.
	otherTenant := googleuuid.NewString()
	registerServedTenantID(t, h, otherTenant, "Second tenant")
	otherWriter := seedScopedTokenSubject(t, h.store, otherTenant, "cr008-other-discovery", "discovery:read", "discovery:write", string(authz.PrivateEgress))
	for _, tc := range []struct {
		kind string
		cfg  any
	}{
		{"azure_machine_identity", map[string]any{
			"azure_tenant_id": azureTenant, "subscription_id": subscription, "service_principal_ids": []string{principal},
			"graph_token_file_ref": graphRef, "arm_token_file_ref": armRef,
			"graph_endpoint": otherTLS.URL, "arm_endpoint": otherTLS.URL, "ca_pem": otherCA,
			"allow_private_endpoint": true, "private_egress_cidrs": otherTLSCIDR,
		}},
		{"gcp_machine_identity", map[string]any{
			"project": "owner-project", "service_accounts": []string{"orders@owner-project.iam.gserviceaccount.com"}, "token_file_ref": gcpRef,
			"iam_endpoint": otherTLS.URL, "resource_manager_endpoint": otherTLS.URL, "logging_endpoint": otherTLS.URL, "ca_pem": otherCA,
			"allow_private_endpoint": true, "private_egress_cidrs": otherTLSCIDR,
		}},
		{assessment.SourceKind, assessment.SourceConfig{
			Endpoint: otherTLS.URL, CAPEM: otherCA, SessionFileRef: awsRef, AllowPrivateEndpoint: true, PrivateEgressCIDRs: otherTLSCIDR,
			Principals: []awsiam.Selection{{Kind: awspolicy.IAMUser, Name: "owner-workload"}},
			Input: assessment.Input{Checks: []assessment.Check{{PrincipalARN: "arn:aws:iam::111122223333:user/owner-workload", Action: "s3:GetObject",
				Resource: "arn:aws:s3:::owner-bucket/object", ResourceAccountID: "111122223333"}}},
		}},
		{"cloud_secret", map[string]any{"providers": []map[string]any{
			{"provider": "hashicorp-vault", "vault_url": otherPlain.URL, "allow_private_endpoint": true, "private_egress_cidrs": otherPlainCIDR,
				"token_ref": vaultRef, "mount": "secret", "path_prefix": "tls"},
			{"provider": "gcp-secret-manager", "project": "owner-project", "endpoint": otherPlain.URL, "allow_private_endpoint": true,
				"private_egress_cidrs": otherPlainCIDR, "token_ref": gcpSMRef},
		}}},
	} {
		status, body, sourceID := declare(otherWriter, "cr008-other-"+tc.kind, tc.kind, "Second tenant "+tc.kind, tc.cfg)
		if status != http.StatusBadRequest || !strings.Contains(string(body), "outbound_env_credential_bindings") ||
			!strings.Contains(string(body), "has not bound it to this tenant") {
			t.Errorf("%s: the second tenant declared a source naming the owner tenant's approved references: %d %s", tc.kind, status, body)
			if sourceID != "" {
				run := runSource(otherWriter, otherTenant, "cr008-other-run-"+tc.kind, sourceID)
				t.Logf("%s: the second tenant's run ended %s (%s)", tc.kind, run.Status, run.Error)
			}
		}
	}
	// No private grant is needed for a public collector: discovery:write alone.
	publicOnly := seedScopedTokenSubject(t, h.store, otherTenant, "cr008-other-public", "discovery:read", "discovery:write")
	if status, body, _ := declare(publicOnly, "cr008-other-public-azure", "azure_machine_identity", "Second tenant public collector", map[string]any{
		"azure_tenant_id": azureTenant, "subscription_id": subscription, "service_principal_ids": []string{principal},
		"graph_token_file_ref": graphRef, "arm_token_file_ref": armRef,
		"graph_endpoint": "https://collector.second-tenant.example", "arm_endpoint": "https://collector.second-tenant.example",
	}); status != http.StatusBadRequest || !strings.Contains(string(body), "outbound_env_credential_bindings") ||
		!strings.Contains(string(body), "has not bound it to this tenant") {
		t.Errorf("the second tenant declared a public collector naming the owner tenant's approved references: %d %s", status, body)
	}
	// Aimed at the owner's own bound Vault origin, only the API's tenant check
	// refuses the second tenant.
	if status, body, _ := declare(otherWriter, "cr008-other-vault-at-owner", "cloud_secret", "Second tenant at the owner's Vault", map[string]any{
		"providers": []map[string]any{{"provider": "hashicorp-vault", "vault_url": ownerVaultServer.URL, "allow_private_endpoint": true,
			"private_egress_cidrs": []string{serviceNowSinkCIDR(t, ownerVaultServer.URL)}, "token_ref": vaultRef, "mount": "secret", "path_prefix": "tls"}},
	}); status != http.StatusBadRequest || !strings.Contains(string(body), "has not bound it to this tenant") {
		t.Errorf("the second tenant declared a source at the owner's bound Vault naming the owner's reference: %d %s", status, body)
	}
	otherAuditor := seedScopedTokenSubject(t, h.store, otherTenant, "cr008-other-audit", "audit:write", "audit:read")
	if status, body := secretsReq(t, h, http.MethodPost, "/api/v1/audit/feeds/"+googleuuid.NewString()+"/preview", otherAuditor, map[string]any{
		"name": "Second tenant HEC", "provider": "splunk-hec", "endpoint_url": "https://hec.second-tenant.example/services/collector/event",
		"token_ref": splunkRef, "interval_seconds": 60, "batch_size": 10, "enabled": true,
	}); status != http.StatusBadRequest || !strings.Contains(string(body), "outbound_env_credential_bindings") ||
		!strings.Contains(string(body), "has not bound it to this tenant") {
		t.Errorf("the second tenant's audit feed accepted the owner tenant's approved Splunk reference: %d %s", status, body)
	}
	otherResponder := seedScopedTokenSubject(t, h.store, otherTenant, "cr008-other-incidents", "incidents:write")
	if status, body := secretsReq(t, h, http.MethodPost, "/api/v1/incidents/response-integrations/dispatch", otherResponder, map[string]any{
		"title": "Second tenant incident",
		"destinations": []map[string]any{{"provider": "jira", "endpoint_url": "https://jira.second-tenant.example", "token_ref": jiraRef,
			"project_key": "SEC"}},
	}); status != http.StatusBadRequest || !strings.Contains(string(body), "outbound_env_credential_bindings") ||
		!strings.Contains(string(body), "has not bound it to this tenant") {
		t.Errorf("the second tenant's response integration accepted the owner tenant's approved Jira reference: %d %s", status, body)
	}

	// The worker checks the approval again before it reads a value: declarations
	// stored without the API's check (as one made before the operator changed an
	// approval would be) send nothing to an unapproved tenant or origin.
	for _, tc := range []struct {
		tenantID, name, kind string
		cfg                  any
	}{
		{otherTenant, "cr008-stored-other-azure", "azure_machine_identity", map[string]any{
			"azure_tenant_id": azureTenant, "subscription_id": subscription, "service_principal_ids": []string{principal},
			"graph_token_file_ref": graphRef, "arm_token_file_ref": armRef,
			"graph_endpoint": otherTLS.URL, "arm_endpoint": otherTLS.URL, "ca_pem": otherCA,
			"allow_private_endpoint": true, "private_egress_cidrs": otherTLSCIDR,
		}},
		{otherTenant, "cr008-stored-other-vault", "cloud_secret", map[string]any{"providers": []map[string]any{
			{"provider": "hashicorp-vault", "vault_url": otherPlain.URL, "allow_private_endpoint": true, "private_egress_cidrs": otherPlainCIDR,
				"token_ref": vaultRef, "mount": "secret", "path_prefix": "tls"},
		}}},
		{owner, "cr008-stored-owner-vault-elsewhere", "cloud_secret", map[string]any{"providers": []map[string]any{
			{"provider": "hashicorp-vault", "vault_url": otherPlain.URL, "allow_private_endpoint": true, "private_egress_cidrs": otherPlainCIDR,
				"token_ref": vaultRef, "mount": "secret", "path_prefix": "tls"},
		}}},
	} {
		raw, err := json.Marshal(tc.cfg)
		if err != nil {
			t.Fatal(err)
		}
		source, err := h.srv.orch.UpsertDiscoverySource(ctx, tc.tenantID, store.DiscoverySource{Kind: tc.kind, Name: tc.name, Config: raw})
		if err != nil {
			t.Fatalf("%s: store the declaration: %v", tc.name, err)
		}
		run, err := h.srv.orch.QueueDiscoveryRun(ctx, tc.tenantID, store.DiscoveryRun{SourceID: source.ID})
		if err != nil {
			t.Fatalf("%s: queue the run: %v", tc.name, err)
		}
		if err := h.srv.Drain(ctx); err != nil {
			t.Fatal(err)
		}
		got, err := h.store.GetDiscoveryRun(ctx, tc.tenantID, run.ID)
		if err != nil {
			t.Fatal(err)
		}
		t.Logf("%s: stored declaration's run ended %s (%s)", tc.name, got.Status, got.Error)
		if got.Status != "failed" || !strings.Contains(got.Error, "not bound to this use") {
			t.Errorf("%s: the worker did not refuse a reference outside its binding: %s (%s)", tc.name, got.Status, got.Error)
		}
	}

	for what, value := range values {
		if other.received(value) {
			t.Errorf("the second collector received the owner tenant's %s", what)
		}
	}
}
