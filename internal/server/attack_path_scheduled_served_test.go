// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"encoding/json"
	"net/http"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/authz"
	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/discovery/netpath"
	"trstctl.com/trstctl/internal/discovery/netpath/gcpnetpath/computetest"
)

// A167-L4: a scheduled cloud_network_path run re-validates the endpoints the
// exposure posture names, so a firewall change in the account reaches the
// posture without an operator asking; and a second account that does not
// hold an address cannot hide the verdict of the account that does. Before,
// every full run of the source failed and pointed the operator at the
// posture.
func TestServedScheduledCloudPathRunRevalidatesThePostureA167L4(t *testing.T) {
	const token = "stand-in-compute-token" // #nosec G101 -- a stand-in fixture value, not a credential (CWE-798)
	prod := computetest.New("a167l4-prod", token)
	t.Cleanup(prod.Close)
	prod.Add([]computetest.Instance{
		{Name: "api-1", Zone: "us-central1-a", Network: "prod", NatIP: "203.0.113.60", Tags: []string{"https-server"}},
		{Name: "jobs-1", Zone: "us-central1-a", Network: "prod", NatIP: "203.0.113.61", Tags: []string{"jobs"}},
	}, []computetest.Firewall{
		{Name: "allow-https", Network: "prod", Direction: "INGRESS", Priority: 1000, SourceRanges: []string{"0.0.0.0/0"}, TargetTags: []string{"https-server"},
			Allowed: []map[string]any{{"IPProtocol": "tcp", "ports": []string{"443"}}}},
	}, []computetest.Route{
		{Name: "default-route-internet", Network: "prod", DestRange: "0.0.0.0/0", Priority: 1000, NextHopGateway: netpath.DefaultInternetGateway},
	})
	// A second project that holds neither address.
	other := computetest.New("a167l4-other", token)
	t.Cleanup(other.Close)
	t.Setenv("TRSTCTL_A167L4_GCP_TOKEN", token)
	h := newOperatingServedHarness(t, config.Protocols{}, allowOutboundEnvCredentialRefs("env:TRSTCTL_A167L4_GCP_TOKEN"))
	ctx := t.Context()
	writer := seedScopedToken(t, h.store, h.tenant, "discovery:read", "discovery:write", "nhi:read", string(authz.PrivateEgress))
	reader := seedScopedToken(t, h.store, h.tenant, "nhi:read")

	const api, jobs = "22222222-2222-2222-2222-2222222b1641", "22222222-2222-2222-2222-2222222b1642"
	now := time.Now().UTC()
	seedDiscoveryPostureFindingWithIDs(t, h.store, h.tenant, "22222222-2222-2222-2222-2222222b164a", "22222222-2222-2222-2222-2222222b164c",
		api, now, map[string]any{"public_endpoint": "https://203.0.113.60/api"})
	seedDiscoveryPostureFindingWithIDs(t, h.store, h.tenant, "22222222-2222-2222-2222-2222222b164b", "22222222-2222-2222-2222-2222222b164d",
		jobs, now, map[string]any{"public_endpoint": "https://203.0.113.61/jobs"})

	createSource := func(name, project, endpoint, key string) string {
		t.Helper()
		status, body := secretsReqKey(t, h, http.MethodPost, "/api/v1/discovery/sources", writer, key, map[string]any{
			"name": name, "kind": "cloud_network_path", "config": map[string]any{"providers": []map[string]any{{ // #nosec G101 -- token_ref is a non-secret environment locator (CWE-798)
				"provider": "gcp-compute", "project": project, "endpoint": endpoint,
				"allow_private_endpoint": true, "private_egress_cidrs": []string{serviceNowSinkCIDR(t, endpoint)},
				"token_ref": "env:TRSTCTL_A167L4_GCP_TOKEN",
			}}},
		})
		var source struct {
			ID string `json:"id"`
		}
		if status != http.StatusCreated || json.Unmarshal(body, &source) != nil || source.ID == "" {
			t.Fatalf("create %s: %d %s", name, status, body)
		}
		return source.ID
	}
	schedule := func(sourceID, name string) {
		t.Helper()
		status, body := secretsReqKey(t, h, http.MethodPost, "/api/v1/discovery/schedules", writer, "a167l4-schedule-"+name,
			map[string]any{"source_id": sourceID, "name": name, "interval_seconds": 3600, "enabled": true})
		if status != http.StatusCreated {
			t.Fatalf("create schedule %s: %d %s", name, status, body)
		}
	}
	verdicts := func() map[string]string {
		t.Helper()
		status, body := secretsReq(t, h, http.MethodGet, "/api/v1/nhi/posture/exposure", reader, nil)
		var posture struct {
			Findings []attackPathPostureRow `json:"findings"`
		}
		if status != http.StatusOK || json.Unmarshal(body, &posture) != nil {
			t.Fatalf("posture = %d %s", status, body)
		}
		out := map[string]string{}
		for _, row := range posture.Findings {
			if row.InventoryID == "finding/"+api || row.InventoryID == "finding/"+jobs {
				out[row.InventoryID] = ""
				if row.AttackPath != nil {
					out[row.InventoryID] = row.AttackPath.Status
				}
			}
		}
		return out
	}

	prodSource := createSource("gcp-a167l4-prod", "a167l4-prod", prod.URL(), "a167l4-source-prod")
	schedule(prodSource, "a167l4-prod-hourly")
	if n, err := h.srv.RunDiscoverySchedulerOnce(ctx); err != nil || n < 1 {
		t.Fatalf("scheduler queued %d runs: %v", n, err)
	}
	if err := h.srv.Drain(ctx); err != nil {
		t.Fatalf("drain: %v", err)
	}
	run, err := h.store.GetLatestDiscoveryRunForSource(ctx, h.tenant, prodSource)
	if err != nil || run.Status != "succeeded" || run.RequestedBy != discoverySchedulerActor || run.Discovered != 1 {
		t.Fatalf("scheduled run = %+v %v; want a succeeded scheduler run with one open address", run, err)
	}
	if got := verdicts(); got["finding/"+api] != "open" || got["finding/"+jobs] != "blocked" {
		t.Fatalf("posture after the scheduled run = %v; want api open, jobs blocked", got)
	}

	// The other project's scheduled run finds neither address; its verdicts
	// are recorded but do not hide the prod project's.
	otherSource := createSource("gcp-a167l4-other", "a167l4-other", other.URL(), "a167l4-source-other")
	schedule(otherSource, "a167l4-other-hourly")
	if n, err := h.srv.RunDiscoverySchedulerOnce(ctx); err != nil || n < 1 {
		t.Fatalf("scheduler queued %d runs for the other project: %v", n, err)
	}
	if err := h.srv.Drain(ctx); err != nil {
		t.Fatalf("drain: %v", err)
	}
	if run, err := h.store.GetLatestDiscoveryRunForSource(ctx, h.tenant, otherSource); err != nil || run.Status != "succeeded" || run.Discovered != 0 {
		t.Fatalf("other project's run = %+v %v", run, err)
	}
	if got := verdicts(); got["finding/"+api] != "open" || got["finding/"+jobs] != "blocked" {
		t.Fatalf("posture after the other project's run = %v; want the prod verdicts kept", got)
	}
}
