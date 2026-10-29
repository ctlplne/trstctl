// SPDX-License-Identifier: BUSL-1.1
package server

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"os"
	"slices"
	"testing"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"strings"
	"trstctl.com/trstctl/internal/agent/relay"
	"trstctl.com/trstctl/internal/agent/transport"
	"trstctl.com/trstctl/internal/cli"
	"trstctl.com/trstctl/internal/crypto/mtls"
	"trstctl.com/trstctl/internal/crypto/secret"
	"trstctl.com/trstctl/internal/discovery/adcs"
	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/projections"
	"trstctl.com/trstctl/internal/store"
)

// TestServedADCSNestedEnrollmentAgainstSamba uses a provisioned, owned Samba AD
// fixture. It is intentionally separate from the BER double: unknown matching
// rules can look like empty results. See the AD CS runbook for the fixture.
func TestServedADCSNestedEnrollmentAgainstSamba(t *testing.T) {
	fixturePath := os.Getenv("TRSTCTL_ADCS_SAMBA_FIXTURE")
	if fixturePath == "" {
		t.Skip("set TRSTCTL_ADCS_SAMBA_FIXTURE and TRSTCTL_ADCS_SAMBA_PASSWORD_FILE for real Samba proof")
	}
	raw, err := os.ReadFile(fixturePath) // #nosec G304,G703,G122 -- operator-selected owned integration metadata (CWE-22, CWE-367).
	if err != nil {
		t.Fatal(err)
	}
	var fixture struct {
		DomainDN        string `json:"domain_dn"`
		ConfigurationDN string `json:"configuration_dn"`
		BindDN          string `json:"bind_dn"`
		UserDN          string `json:"user_dn"`
		UserSID         string `json:"user_sid"`
		InnerDN         string `json:"inner_dn"`
		OuterDN         string `json:"outer_dn"`
		Template        string `json:"template"`
	}
	if err := json.Unmarshal(raw, &fixture); err != nil {
		t.Fatal(err)
	}
	password, err := os.ReadFile(os.Getenv("TRSTCTL_ADCS_SAMBA_PASSWORD_FILE")) // #nosec G304,G703,G122 -- explicit owner-selected integration secret path; contents are wiped and never printed (CWE-22, CWE-367).
	if err != nil {
		t.Fatal(err)
	}
	defer secret.Wipe(password)
	if len(password) == 0 || fixture.UserSID == "" || fixture.Template == "" {
		t.Fatal("incomplete owned Samba fixture")
	}
	h := newRoleHarness(t, []string{mtls.AgentRoleNetwork}, adcs.NestedGroupsJobKind)
	ctx := context.Background()
	if _, err := h.client.Heartbeat(ctx, &transport.HeartbeatRequest{AgentID: h.agent, Version: "a228-samba", Status: "active", Executors: &transport.ExecutorReport{Version: "a228-samba", Kinds: []transport.ExecutorKind{{Kind: adcs.NestedGroupsJobKind}}}}); err != nil {
		t.Fatal(err)
	}
	const name = "adcs/a228-samba-reader"         // #nosec G101 -- public logical fixture reference (CWE-798).
	const ref = "secret://adcs/a228-samba-reader" // #nosec G101 -- public reference, never a credential value (CWE-798).
	sealed, err := h.srv.sealTenantSecretForTest(ctx, h.tenant, name, password)
	if err != nil {
		t.Fatal(err)
	}
	seedApplicationSecretFixture(t, h.store, h.tenant, name, sealed)
	token := seedScopedToken(t, h.store, h.tenant, "discovery:read", "discovery:write", "certs:read")
	endpoint := os.Getenv("TRSTCTL_ADCS_SAMBA_URL")
	if endpoint == "" {
		t.Fatal("set TRSTCTL_ADCS_SAMBA_URL to the owned LDAP authority")
	}
	// The retained Samba lab has no public trust anchor. Its explicit lab-only
	// override is visible as DirectoryVerified=false; it proves no production TLS.
	input := map[string]any{"name": "a228-nested-samba", "kind": adcs.SourceKind, "config": map[string]any{"url": endpoint, "configuration_dn": fixture.ConfigurationDN, "bind_dn": fixture.BindDN, "password_ref": ref, "relay_agent_id": agentRowID(h.tenant, h.agent), "nested_groups_enabled": true, "membership_domain_dn": fixture.DomainDN, "insecure_skip_verify": true}}
	code, body := secretsReqKey(t, h.servedHarness, http.MethodPost, "/api/v1/discovery/sources", token, "a228-source", input)
	if code != 201 {
		t.Fatalf("source=%d %s", code, body)
	}
	var source store.DiscoverySource
	if err := json.Unmarshal(body, &source); err != nil {
		t.Fatal(err)
	}
	code, body = secretsReqKey(t, h.servedHarness, http.MethodPost, "/api/v1/discovery/runs", token, "a228-run", map[string]any{"source_id": source.ID})
	if code != 201 && code != 202 {
		t.Fatalf("queue=%d %s", code, body)
	}
	var run store.DiscoveryRun
	if err := json.Unmarshal(body, &run); err != nil {
		t.Fatal(err)
	}
	if err := h.srv.Drain(ctx); err != nil {
		t.Fatal(err)
	}
	channel := &sshCollectionServedChannel{t: t, h: h}
	if count, err := relay.RunOnce(ctx, channel, http.DefaultClient, 1, 120); err != nil || count != 1 {
		t.Fatalf("production relay=%d %v", count, err)
	}
	if len(channel.reports) != 1 {
		t.Fatalf("report count=%d", len(channel.reports))
	}
	reportJSON := []byte(channel.reports[0].Detail)
	if bytes.Contains(reportJSON, password) {
		t.Fatal("directory credential escaped in report")
	}
	var report adcs.InventoryReport
	if err := json.Unmarshal(reportJSON, &report); err != nil {
		t.Fatal(err)
	}
	if report.Status != "succeeded" || report.DirectoryVerified {
		t.Fatalf("Samba read=%s/%s, directory verified=%t", report.Status, report.ErrorCode, report.DirectoryVerified)
	}
	var nested *adcs.EnrollmentMembership
	for _, template := range report.Inventory.Templates {
		if template.Name == fixture.Template {
			nested = template.EnrollmentMembership
		}
	}
	if nested == nil || nested.State != "complete" {
		t.Fatalf("Samba matching-rule evidence incomplete: %+v", nested)
	}
	matched := false
	for _, member := range nested.Members {
		if member.SID == fixture.UserSID {
			matched = slices.Equal(member.Path, []string{fixture.UserDN, fixture.InnerDN, fixture.OuterDN})
		}
	}
	if !matched {
		t.Fatalf("Samba user -> inner -> outer enrollment path absent: %+v", nested)
	}
	current, err := h.store.GetDiscoveryRun(ctx, h.tenant, run.ID)
	if err != nil || current.Status != "succeeded" {
		t.Fatalf("run state=%s err=%v", current.Status, err)
	}
	code, body = secretsReqKey(t, h.servedHarness, http.MethodGet, "/api/v1/posture/adcs", token, "", nil)
	if code != 200 || !bytes.Contains(body, []byte(fixture.UserSID)) || !bytes.Contains(body, []byte(`"enrollment_membership"`)) {
		t.Fatalf("served nested posture missing=%d %s", code, body)
	}
	var cliOut, cliErr bytes.Buffer
	if exit := cli.Run(ctx, []string{"posture", "adcs"}, cli.Env{Server: h.ts.URL, Token: token, Tenant: h.tenant, HTTPClient: h.ts.Client()}, strings.NewReader(""), &cliOut, &cliErr); exit != 0 || !bytes.Contains(cliOut.Bytes(), []byte(fixture.UserSID)) {
		t.Fatalf("nested CLI=%d %s", exit, cliErr.String())
	}
	request := channel.reports[0]
	if response, err := h.client.ReportJobResult(ctx, request); err != nil || !response.ReceiptRecorded {
		t.Fatalf("receipt replay=%+v %v", response, err)
	}
	if err := h.log.Replay(ctx, 0, func(event events.Event) error {
		if event.TenantID == h.tenant && bytes.Contains(event.Data, password) {
			t.Fatalf("event %s exposed bind credential", event.Type)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	// A mutable row must not turn a forged user/path into source-backed posture.
	if err := h.store.WithTenant(ctx, h.tenant, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `UPDATE adcs_template_posture SET observed_template=jsonb_set(observed_template,'{enrollment_membership,members,0,dn}','"CN=Invented,DC=adlab,DC=test"'::jsonb) WHERE tenant_id=$1 AND template=$2`, h.tenant, fixture.Template)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	code, _ = secretsReqKey(t, h.servedHarness, http.MethodGet, "/api/v1/posture/adcs", token, "", nil)
	if code == 200 {
		t.Fatal("SQL-only member became served enrollment evidence")
	}
	if err := h.srv.proj.Rebuild(ctx, h.log); err != nil {
		t.Fatal(err)
	}
	code, body = secretsReqKey(t, h.servedHarness, http.MethodGet, "/api/v1/posture/adcs", token, "", nil)
	if code != 200 || !bytes.Contains(body, []byte(fixture.UserSID)) || bytes.Contains(body, []byte("CN=Invented")) {
		t.Fatalf("nested replay=%d %s", code, body)
	}
	otherTenant := uuid.NewString()
	registerServedTenantID(t, h.servedHarness, otherTenant, "A228 isolation fixture")
	otherToken := seedScopedToken(t, h.store, otherTenant, "discovery:read")
	code, body = secretsReqKey(t, h.servedHarness, http.MethodGet, "/api/v1/posture/adcs", otherToken, "", nil)
	if code != 200 || bytes.Contains(body, []byte(fixture.UserSID)) || bytes.Contains(body, []byte(source.ID)) {
		t.Fatalf("cross-tenant nested evidence=%d %s", code, body)
	}
	if !h.hasEvent(t, projections.EventADCSInventoryObserved) {
		t.Fatal("nested evidence has no immutable observation")
	}
	t.Logf("Samba read-only enrollment path verified for %s; directory identity remains explicitly unverified", fixture.Template)
}
