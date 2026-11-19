// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	googleuuid "github.com/google/uuid"
	"trstctl.com/trstctl/internal/authz"
	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/orchestrator"
	"trstctl.com/trstctl/internal/outboundcred"
	"trstctl.com/trstctl/internal/projections"
)

// CR-008 (design §4): audit feeds and response dispatches stored without the
// API's check send nothing outside their binding, once for another tenant
// naming the owner tenant's references and once for the owner tenant sending
// them to an origin the operator did not bind. An HTTP collector is checked for
// the value. A syslog receiver that requires mutual TLS is checked for the
// owner's client certificate in a handshake: the control plane must neither
// present it to a receiver the operator never bound nor authenticate another
// tenant's feed with it at the owner's own receiver.
func TestServedStoredFeedsAndDispatchesSendNothingOutsideTheirBindingCR008(t *testing.T) {
	restore := syslogFeedTimeout
	syslogFeedTimeout = 2 * time.Second
	t.Cleanup(func() { syslogFeedTimeout = restore })
	const (
		hecRef      = "env:TRSTCTL_CR008F_SPLUNK_HEC_TOKEN"      // #nosec G101 -- reference names only (CWE-798)
		caRef       = "env:TRSTCTL_CR008F_SYSLOG_CA"             // #nosec G101 -- reference names only (CWE-798)
		clientRef   = "env:TRSTCTL_CR008F_SYSLOG_CLIENT"         // #nosec G101 -- reference names only (CWE-798)
		jiraRef     = "env:TRSTCTL_CR008F_JIRA_TOKEN"            // #nosec G101 -- reference names only (CWE-798)
		splunkRef   = "env:TRSTCTL_CR008F_SPLUNK_RESPONSE_TOKEN" // #nosec G101 -- reference names only (CWE-798)
		clientName  = "trstctl-audit-feed.cr008.test"
		ownerOrigin = "https://hec.owner.example"
	)
	values := map[string]string{ // #nosec G101 -- fabricated fixture values; no value is real (CWE-798)
		"Splunk HEC token":      "cr008f-splunk-hec-value",
		"Jira token":            "cr008f-jira-value",
		"Splunk response token": "cr008f-splunk-response-value",
	}
	t.Setenv(strings.TrimPrefix(hecRef, "env:"), values["Splunk HEC token"])
	t.Setenv(strings.TrimPrefix(jiraRef, "env:"), values["Jira token"])
	t.Setenv(strings.TrimPrefix(splunkRef, "env:"), values["Splunk response token"])

	var other cr008Collector
	otherPlain := httptest.NewServer(other.handler(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		_, _ = w.Write([]byte(`{"id":"cr008","key":"SEC-1","text":"Success","code":0}`))
	}))
	defer otherPlain.Close()
	loopback := []string{"127.0.0.1/32", "::1/128"}
	// The owner's own Jira, bound for the owner: another tenant's dispatch aimed
	// at it is stopped by the tenant check alone.
	var ownerJira cr008Collector
	ownerJiraServer := httptest.NewServer(ownerJira.handler(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusCreated)
		_, _ = w.Write([]byte(`{"id":"cr008","key":"SEC-1"}`))
	}))
	defer ownerJiraServer.Close()
	rawOwner, ownerPort := reserveLoopbackReceiver(t)
	rawOther, otherPort := reserveLoopbackReceiver(t)
	h := newOperatingServedHarness(t, config.Protocols{},
		bindOutboundEnvCredentialRefs("audit_feed", []string{ownerOrigin}, hecRef),
		bindOutboundEnvCredentialRefs("audit_feed", []string{"syslog+tls://localhost:" + ownerPort, "relp+tls://localhost:" + ownerPort}, caRef, clientRef),
		bindOutboundEnvCredentialRefs("response_integration", []string{"https://jira.owner.example", "https://splunk.owner.example", ownerJiraServer.URL}, jiraRef, splunkRef))
	ownerReceiver := newP5L2MutualSyslog(t, h, rawOwner)
	otherReceiver := newP5L2MutualSyslog(t, h, rawOther)
	key, err := crypto.GenerateHostSubjectKey(clientName, []string{clientName})
	if err != nil {
		t.Fatal(err)
	}
	defer key.Destroy()
	certPEM, err := h.srv.IssueLeaf(t.Context(), key.CSRDER, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	keyPEM, err := key.PrivateKeyPEM()
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv(strings.TrimPrefix(caRef, "env:"), string(h.caPEM))
	t.Setenv(strings.TrimPrefix(clientRef, "env:"), string(certPEM)+string(keyPEM))
	owner := h.tenant
	otherTenant := googleuuid.NewString()
	registerServedTenantID(t, h, otherTenant, "CR-008 second tenant")
	ctx := t.Context()

	feeds := []struct {
		tenantID, name, provider, endpoint, tokenRef, clientRef string
	}{
		{otherTenant, "HEC, another tenant", "splunk-hec", otherPlain.URL + "/services/collector/event", hecRef, ""},
		{owner, "HEC, unbound origin", "splunk-hec", otherPlain.URL + "/services/collector/event", hecRef, ""},
		{owner, "syslog, unbound receiver", "syslog", "syslog+tls://localhost:" + otherPort, caRef, clientRef},
		{otherTenant, "syslog, the owner's receiver", "syslog", "syslog+tls://localhost:" + ownerPort, caRef, clientRef},
		{owner, "RELP, unbound receiver", "syslog", "relp+tls://localhost:" + otherPort, caRef, clientRef},
		{otherTenant, "RELP, the owner's receiver", "syslog", "relp+tls://localhost:" + ownerPort, caRef, clientRef},
	}
	for _, f := range feeds {
		if _, err := h.srv.orch.ConfigureAuditFeed(ctx, f.tenantID, projections.AuditFeedDestinationConfigured{
			ID: googleuuid.NewString(), Name: "CR-008 stored " + f.name, Provider: f.provider, EndpointURL: f.endpoint, TokenRef: f.tokenRef,
			IntervalSeconds: 300, BatchSize: 100, Enabled: true, AllowPrivateEndpoint: true, PrivateEgressCIDRs: loopback, ClientCertRef: f.clientRef,
		}); err != nil {
			t.Fatalf("%s: store the feed: %v", f.name, err)
		}
	}
	// One audit record in each tenant gives each feed a batch to send.
	for _, tenantID := range []string{owner, otherTenant} {
		token := seedServedAPIToken(t, ctx, h.store, tenantID, "cr008-feed-operator", []string{string(authz.OwnersWrite)})
		if status, body := doBearer(t, h.ts, http.MethodPost, "/api/v1/owners", token, "cr008-feed-owner-"+tenantID, map[string]any{
			"kind": "team", "name": "CR-008 team " + strconv.FormatInt(time.Now().UnixNano(), 10), "email": "cr008@example.test",
		}); status != http.StatusCreated && status != http.StatusOK {
			t.Fatalf("seed an audit record: HTTP %d %s", status, body)
		}
	}
	if _, err := h.store.SystemPool().Exec(ctx,
		`UPDATE audit_feed_destinations SET next_run_at = now() - interval '1 second' WHERE tenant_id = ANY($1)`, []string{owner, otherTenant}); err != nil {
		t.Fatal(err)
	}
	if queued, err := h.srv.RunAuditFeedSchedulerOnce(ctx); err != nil || queued < len(feeds) {
		t.Fatalf("queued %d feed batches (%v), want %d", queued, err, len(feeds))
	}
	for _, tenantID := range []string{otherTenant, owner} {
		if _, err := h.srv.orch.DispatchResponseIntegrations(ctx, tenantID, orchestrator.ResponseIntegrationDispatch{
			ID: googleuuid.NewString(), Title: "CR-008 stored dispatch", Summary: "A dispatch stored without the API's check", Severity: "high",
			RequestedBy: "cr008", Destinations: []orchestrator.ResponseIntegrationDestination{
				{Provider: "jira", EndpointURL: otherPlain.URL, TokenRef: jiraRef, ProjectKey: "SEC", IssueType: "Task", AllowPrivateEndpoint: true, PrivateEgressCIDRs: loopback},
				{Provider: "splunk", EndpointURL: otherPlain.URL + "/services/collector/event", TokenRef: splunkRef, AllowPrivateEndpoint: true, PrivateEgressCIDRs: loopback},
			},
		}); err != nil {
			t.Fatalf("store a response dispatch for %s: %v", tenantID, err)
		}
	}
	if _, err := h.srv.orch.DispatchResponseIntegrations(ctx, otherTenant, orchestrator.ResponseIntegrationDispatch{
		ID: googleuuid.NewString(), Title: "CR-008 stored dispatch at the owner's Jira", Severity: "high", RequestedBy: "cr008",
		Destinations: []orchestrator.ResponseIntegrationDestination{{Provider: "jira", EndpointURL: ownerJiraServer.URL, TokenRef: jiraRef,
			ProjectKey: "SEC", IssueType: "Task", AllowPrivateEndpoint: true, PrivateEgressCIDRs: loopback}},
	}); err != nil {
		t.Fatalf("store another tenant's dispatch at the owner's Jira: %v", err)
	}
	if _, err := h.srv.outbox.Dispatch(ctx, h.srv.obHandler); err != nil {
		t.Fatal(err)
	}

	for what, value := range values {
		if other.received(value) {
			t.Errorf("the other party's collector received the owner tenant's %s", what)
		}
	}
	if n := other.requests(); n != 0 {
		t.Errorf("the other party's collector received %d requests", n)
	}
	if names, refused := otherReceiver.clients(); len(names) != 0 || refused != 0 {
		t.Errorf("a receiver the operator never bound saw handshakes: verified %v, refused %d", names, refused)
	}
	if names, refused := ownerReceiver.clients(); len(names) != 0 || refused != 0 || len(ownerReceiver.sequences()) != 0 {
		t.Errorf("another tenant's feed reached the owner's receiver: verified %v, refused handshakes %d", names, refused)
	}
	if n := ownerJira.requests(); n != 0 {
		t.Errorf("another tenant's dispatch reached the owner's Jira %d times", n)
	}
	// The outbox keeps only an error class, so each stored row is delivered once
	// more by hand to read why the worker refused it; that delivery sends
	// nothing either.
	rows, err := h.store.SystemPool().Query(ctx,
		`SELECT id, tenant_id::text, destination, idempotency_key, payload FROM outbox
		  WHERE tenant_id = ANY($1) AND destination = ANY($2)`, []string{owner, otherTenant},
		[]string{"audit.feed.splunk", "audit.feed.syslog", "response.jira", "response.splunk"})
	if err != nil {
		t.Fatal(err)
	}
	var stored []orchestrator.Message
	for rows.Next() {
		var m orchestrator.Message
		if err := rows.Scan(&m.ID, &m.TenantID, &m.Destination, &m.IdempotencyKey, &m.Payload); err != nil {
			t.Fatal(err)
		}
		stored = append(stored, m)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	if want := len(feeds) + 5; len(stored) != want {
		t.Fatalf("found %d stored feed batches and dispatches, want %d", len(stored), want)
	}
	for _, m := range stored {
		err := h.srv.obHandler.Deliver(ctx, m)
		if !errors.Is(err, outboundcred.ErrNotBound) {
			t.Errorf("%s for %s: the worker did not refuse a reference outside its binding: %v", m.Destination, m.TenantID, err)
			continue
		}
		// Another tenant is stopped by the tenant check itself, the owner by the
		// origin check or the pinned client.
		want := "has not bound it to this tenant"
		if m.TenantID == owner {
			want = "send to"
			if !strings.Contains(err.Error(), want) {
				want = "is outside the origins the credential is bound to"
			}
		}
		if !strings.Contains(err.Error(), want) {
			t.Errorf("%s for %s: refused for the wrong reason: %v", m.Destination, m.TenantID, err)
		}
	}
	if n := ownerJira.requests(); n != 0 {
		t.Errorf("a repeated delivery reached the owner's Jira %d times for another tenant", n)
	}
	if n := other.requests(); n != 0 {
		t.Errorf("a repeated delivery reached the other party's collector %d times", n)
	}
}
