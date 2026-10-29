// SPDX-License-Identifier: BUSL-1.1
package server

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"trstctl.com/trstctl/internal/agent/transport"
	"trstctl.com/trstctl/internal/crypto/mtls"
	"trstctl.com/trstctl/internal/discovery/adcs"
	"trstctl.com/trstctl/internal/store"
)

// This tests the signed-report/immutable-event contract. The relay's separate
// network stand-in proof tests that these HTTP facts come from actual sockets.
func TestServedADCSEndpointProbePagesAdvanceFromRetainedEvidence(t *testing.T) {
	h := newRoleHarness(t, []string{mtls.AgentRoleNetwork}, adcs.EndpointProbeJobKind)
	ctx := t.Context()
	if _, err := h.client.Heartbeat(ctx, &transport.HeartbeatRequest{AgentID: h.agent, Version: "a229", Status: "active", Executors: &transport.ExecutorReport{Version: "a229", Kinds: []transport.ExecutorKind{{Kind: adcs.EndpointProbeJobKind}}}}); err != nil {
		t.Fatal(err)
	}
	config := map[string]any{"url": "ldaps://dc.corp.example", "configuration_dn": "CN=Configuration,DC=corp,DC=example", "bind_dn": "CN=reader,DC=corp,DC=example", "password_ref": "secret://adcs/a229-reader", "relay_agent_id": agentRowID(h.tenant, h.agent), "endpoint_probe": map[string]any{"enabled": true, "dns_suffixes": []string{"corp.example"}}} // #nosec G101 -- public logical reference fixture, no credential value (CWE-798).
	raw, _ := json.Marshal(config)
	source, err := h.srv.orch.UpsertDiscoverySource(ctx, h.tenant, store.DiscoverySource{Kind: adcs.SourceKind, Name: "a229-paged", Config: raw})
	if err != nil {
		t.Fatal(err)
	}
	token := seedScopedToken(t, h.store, h.tenant, "discovery:read", "certs:read")
	queue := func() (*transport.ClaimedJob, adcs.InventoryIntent) {
		t.Helper()
		run, err := h.srv.orch.QueueDiscoveryRun(ctx, h.tenant, store.DiscoveryRun{SourceID: source.ID})
		if err != nil {
			t.Fatal(err)
		}
		if err := h.srv.Drain(ctx); err != nil {
			t.Fatal(err)
		}
		claims, err := h.client.ClaimJobs(ctx, &transport.ClaimJobsRequest{Kinds: []string{adcs.EndpointProbeJobKind}, Limit: 1, LeaseSeconds: 120})
		if err != nil || len(claims.Jobs) != 1 {
			t.Fatalf("claim=%+v %v", claims, err)
		}
		job := claims.Jobs[0]
		var command adcs.InventoryIntent
		if err := json.Unmarshal(job.Payload, &command); err != nil {
			t.Fatal(err)
		}
		if command.ID != run.ID {
			t.Fatal("queue command changed its run")
		}
		return &job, command
	}
	report := func(job *transport.ClaimedJob, command adcs.InventoryIntent, serviceCount int, failed bool) adcs.EndpointProbePage {
		t.Helper()
		result := adcs.InventoryReport{Status: "failed", ErrorCode: "directory_read_failed"}
		var page adcs.EndpointProbePage
		if !failed {
			inventory := adcs.Inventory{Templates: []adcs.Template{{Name: "User", EKUs: []string{adcs.EKUClientAuth}, PublishedBy: []string{"CA00"}}}}
			for index := range serviceCount {
				inventory.EnrollmentServices = append(inventory.EnrollmentServices, adcs.EnrollmentService{Name: fmt.Sprintf("CA%02d", index), DNSName: fmt.Sprintf("ca%02d.corp.example", index), AgentRestrictions: adcs.EnrollmentAgentRestrictions{State: adcs.EvidenceUnobserved, Source: "requires_windows_relay"}})
			}
			var err error
			page, err = adcs.PlanEnrollmentEndpointProbes(command, inventory.EnrollmentServices)
			if err != nil {
				t.Fatal(err)
			}
			inventory.EndpointProbePage = &page
			for index := range inventory.EnrollmentServices {
				service := &inventory.EnrollmentServices[index]
				service.EndpointProbe = page.ServiceCoverage(service.Name)
				for _, target := range page.Targets {
					if target.EnrollmentService == service.Name {
						service.Endpoints = append(service.Endpoints, adcs.EnrollmentEndpoint{Kind: target.Kind, URL: target.URL, Source: target.Source, State: adcs.EndpointAuthenticationNeeded, HTTPStatus: 401, Authentication: []string{"Negotiate"}, TLSVerified: strings.HasPrefix(target.URL, "https://"), ExtendedProtection: adcs.EvidenceUnobserved})
					}
				}
			}
			result = adcs.InventoryReport{Status: "succeeded", Inventory: inventory, DirectoryVerified: true, Findings: adcs.Findings(inventory)}
		}
		wire, _ := json.Marshal(result)
		request := h.report(t, job.JobID, job.Attempt, transport.JobOutcomeExecuted, string(wire), "sha256:a229-contract")
		// Normal execution stores the verified receipt before retiring the claim
		// and returns Accepted=true (agent_jobs.go). ReceiptRecorded is the
		// distinct late/retry acknowledgement (agent_late_receipt.go).
		if response, err := h.client.ReportJobResult(ctx, request); err != nil || response == nil || !response.Accepted || response.LeaseExpiresUnix != 0 {
			t.Fatalf("signed report=%+v %v", response, err)
		}
		var verified int
		if err := h.store.WithTenant(ctx, h.tenant, func(tx pgx.Tx) error {
			return tx.QueryRow(ctx, `SELECT count(*) FROM agent_job_receipts WHERE tenant_id=$1 AND job_id=$2 AND attempt=$3 AND state='verified' AND kind=$4 AND signature<>'' AND statement<>'' AND signer_fingerprint<>''`, h.tenant, job.JobID, job.Attempt, adcs.EndpointProbeJobKind).Scan(&verified)
		}); err != nil || verified != 1 {
			t.Fatalf("durable verified signed receipt count=%d: %v", verified, err)
		}
		if response, err := h.client.ReportJobResult(ctx, request); err != nil || response == nil || response.Accepted || !response.ReceiptRecorded || response.LeaseExpiresUnix != 0 {
			t.Fatalf("receipt retry=%+v %v", response, err)
		}
		return page
	}
	first, command := queue()
	if command.PreviousProbePage != nil {
		t.Fatal("first run invented a cursor")
	}
	page := report(first, command, 10, false)
	if page.Offset != 0 || page.NextOffset != 24 || page.Complete {
		t.Fatalf("page1=%+v", page)
	}
	code, body := secretsReqKey(t, h.servedHarness, http.MethodGet, "/api/v1/posture/adcs", token, "", nil)
	if code != 200 || !bytes.Contains(body, []byte(`"source":"ldap_dns"`)) || !bytes.Contains(body, []byte(`"next_offset":24`)) || !bytes.Contains(body, []byte(`"state":"not_in_page"`)) || !bytes.Contains(body, []byte("ADCS-ENDPOINT-PROBE-INCOMPLETE")) {
		t.Fatalf("served page evidence=%d %s", code, body)
	}
	firstRows, err := h.store.ListADCSEnrollmentServicePosture(ctx, h.tenant, 500)
	if err != nil || len(firstRows) == 0 {
		t.Fatalf("first source rows=%d: %v", len(firstRows), err)
	}
	// A replay must restore the same page facts without a mutable cursor table.
	if err := h.srv.proj.Rebuild(ctx, h.log); err != nil {
		t.Fatal(err)
	}
	second, command := queue()
	if command.PreviousProbePage == nil || command.PreviousProbePage.NextOffset != 24 {
		t.Fatalf("next cursor=%+v", command.PreviousProbePage)
	}
	report(second, command, 10, true)
	retry, command := queue()
	if command.PreviousProbePage == nil || command.PreviousProbePage.NextOffset != 24 {
		t.Fatal("failed attempt skipped its page")
	}
	page = report(retry, command, 10, false)
	if page.Offset != 24 || page.NextOffset != 0 || page.Complete {
		t.Fatalf("page2=%+v", page)
	}
	next, command := queue()
	page = report(next, command, 11, false)
	if page.Offset != 0 || page.TotalTargets != 44 {
		t.Fatal("changed estate did not reset its plan")
	}
	if err := h.store.WithTenant(ctx, h.tenant, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `UPDATE adcs_enrollment_service_posture SET observed_service=jsonb_set(observed_service,'{endpoint_probe,next_offset}','0'::jsonb) WHERE tenant_id=$1 AND service=$2`, h.tenant, "CA00")
		return err
	}); err != nil {
		t.Fatal(err)
	}
	code, _ = secretsReqKey(t, h.servedHarness, http.MethodGet, "/api/v1/posture/adcs", token, "", nil)
	if code == 200 {
		t.Fatal("SQL-only probe coverage became served evidence")
	}
	if err := h.srv.proj.Rebuild(ctx, h.log); err != nil {
		t.Fatal(err)
	}
	code, body = secretsReqKey(t, h.servedHarness, http.MethodGet, "/api/v1/posture/adcs", token, "", nil)
	if code != 200 || !bytes.Contains(body, []byte(`"next_offset":24`)) {
		t.Fatalf("replayed probe=%d %s", code, body)
	}
	latestRows, err := h.store.ListADCSEnrollmentServicePosture(ctx, h.tenant, 500)
	if err != nil || len(latestRows) == 0 {
		t.Fatalf("latest source rows=%d: %v", len(latestRows), err)
	}
	// One request must not retain a full observation for every distinct source.
	// Alternate two independently retained, correctly timestamped observations;
	// validation must still work after the previous entry is evicted.
	cache := map[string]adcsEndpointObservation{}
	for index := range 8 {
		row := firstRows[0]
		if index%2 == 1 {
			row = latestRows[0]
		}
		if _, err := h.srv.boundADCSEndpointEvidence(ctx, h.tenant, row, cache); err != nil {
			t.Fatal(err)
		}
		if len(cache) > 1 {
			t.Fatalf("request retains %d full observations; want at most one", len(cache))
		}
	}
	other := uuid.NewString()
	registerServedTenantID(t, h.servedHarness, other, "a229 isolation")
	otherToken := seedScopedToken(t, h.store, other, "discovery:read", "certs:read")
	code, body = secretsReqKey(t, h.servedHarness, http.MethodGet, "/api/v1/posture/adcs", otherToken, "", nil)
	if code != 200 || bytes.Contains(body, []byte("corp.example")) || bytes.Contains(body, []byte(source.ID)) {
		t.Fatalf("tenant isolation=%d %s", code, body)
	}
}
