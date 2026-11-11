// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"encoding/json"
	"net/http"
	"slices"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/authz"
	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/discovery/netpath"
	"trstctl.com/trstctl/internal/discovery/netpath/gcpnetpath/computetest"
)

// A167-L3: an open attack path is the cloud account's own confirmation that
// the internet reaches an exposed endpoint, so the record's exposure finding
// rises with it: to high with the cloud_path_open finding type and a higher
// risk score, to critical when the endpoint also authenticates weakly. A
// blocked verdict leaves the finding as it was. Before, the verdict was shown
// beside an unchanged severity and risk score.
func TestServedOpenAttackPathRaisesExposureSeverityA167L3(t *testing.T) {
	const token = "stand-in-compute-token" // #nosec G101 -- a stand-in fixture value, not a credential (CWE-798)
	compute := computetest.New("a167l3-project", token)
	t.Cleanup(compute.Close)
	compute.Add([]computetest.Instance{
		{Name: "api-1", Zone: "us-central1-a", Network: "prod", NatIP: "203.0.113.50", Tags: []string{"https-server"}},
		{Name: "hook-1", Zone: "us-central1-a", Network: "prod", NatIP: "203.0.113.51", Tags: []string{"https-server"}},
		{Name: "batch-1", Zone: "us-central1-a", Network: "prod", NatIP: "203.0.113.52", Tags: []string{"batch"}},
	}, []computetest.Firewall{
		{Name: "allow-https", Network: "prod", Direction: "INGRESS", Priority: 1000, SourceRanges: []string{"0.0.0.0/0"}, TargetTags: []string{"https-server"},
			Allowed: []map[string]any{{"IPProtocol": "tcp", "ports": []string{"443"}}}},
	}, []computetest.Route{
		{Name: "default-route-internet", Network: "prod", DestRange: "0.0.0.0/0", Priority: 1000, NextHopGateway: netpath.DefaultInternetGateway},
	})
	t.Setenv("TRSTCTL_A167L3_GCP_TOKEN", token)
	h := newOperatingServedHarness(t, config.Protocols{}, allowOutboundEnvCredentialRefs("env:TRSTCTL_A167L3_GCP_TOKEN"))
	ctx := t.Context()
	writer := seedScopedToken(t, h.store, h.tenant, "discovery:read", "discovery:write", "nhi:read", string(authz.PrivateEgress))
	reader := seedScopedToken(t, h.store, h.tenant, "nhi:read")

	const api, hook, batch = "22222222-2222-2222-2222-2222222b1631", "22222222-2222-2222-2222-2222222b1632", "22222222-2222-2222-2222-2222222b1633"
	now := time.Now().UTC()
	for i, record := range []struct {
		id   string
		meta map[string]any
	}{
		{api, map[string]any{"public_endpoint": "https://203.0.113.50/api"}},
		{hook, map[string]any{"public_endpoint": "https://203.0.113.51/hook", "auth_mode": "none"}},
		{batch, map[string]any{"public_endpoint": "https://203.0.113.52/batch"}},
	} {
		suffix := string(rune('a' + i))
		seedDiscoveryPostureFindingWithIDs(t, h.store, h.tenant, "22222222-2222-2222-2222-2222222b163"+suffix,
			"22222222-2222-2222-2222-2222222b164"+suffix, record.id, now, record.meta)
	}
	type row struct {
		InventoryID  string   `json:"inventory_id"`
		Severity     string   `json:"severity"`
		RiskScore    int      `json:"risk_score"`
		FindingTypes []string `json:"finding_types"`
		AttackPath   *struct {
			Status string `json:"status"`
		} `json:"attack_path"`
	}
	posture := func() map[string]row {
		t.Helper()
		status, body := secretsReq(t, h, http.MethodGet, "/api/v1/nhi/posture/exposure", reader, nil)
		var out struct {
			Findings []row `json:"findings"`
		}
		if status != http.StatusOK || json.Unmarshal(body, &out) != nil {
			t.Fatalf("posture = %d %s", status, body)
		}
		rows := map[string]row{}
		for _, r := range out.Findings {
			rows[r.InventoryID] = r
		}
		return rows
	}
	before := posture()
	for id, want := range map[string]string{api: "medium", hook: "high", batch: "medium"} {
		if got := before["finding/"+id]; got.Severity != want || got.AttackPath != nil {
			t.Fatalf("%s before validation = %+v; want %s with no attack path", id, got, want)
		}
	}

	status, body := secretsReq(t, h, http.MethodPost, "/api/v1/discovery/sources", writer, map[string]any{
		"name": "gcp-a167l3", "kind": "cloud_network_path", "config": map[string]any{"providers": []map[string]any{{ // #nosec G101 -- token_ref is a non-secret environment locator (CWE-798)
			"provider": "gcp-compute", "project": "a167l3-project", "endpoint": compute.URL(),
			"allow_private_endpoint": true, "private_egress_cidrs": []string{serviceNowSinkCIDR(t, compute.URL())},
			"token_ref": "env:TRSTCTL_A167L3_GCP_TOKEN",
		}}},
	})
	var source struct {
		ID string `json:"id"`
	}
	if status != http.StatusCreated || json.Unmarshal(body, &source) != nil || source.ID == "" {
		t.Fatalf("create the gcp-compute source: %d %s", status, body)
	}
	status, body = secretsReqKey(t, h, http.MethodPost, "/api/v1/nhi/posture/exposure/attack-paths", writer, "a167l3-validate",
		map[string]any{"source_id": source.ID, "inventory_ids": []string{"finding/" + api, "finding/" + hook, "finding/" + batch}})
	if status != http.StatusAccepted {
		t.Fatalf("validate = %d %s", status, body)
	}
	if err := h.srv.Drain(ctx); err != nil {
		t.Fatalf("drain: %v", err)
	}
	after := posture()
	for id, w := range map[string]struct {
		path, severity string
		risk           int
		cloudOpen      bool
	}{
		api:   {"open", "high", 88, true},
		hook:  {"open", "critical", 100, true},
		batch: {"blocked", "medium", before["finding/"+batch].RiskScore, false},
	} {
		got := after["finding/"+id]
		if got.AttackPath == nil || got.AttackPath.Status != w.path || got.Severity != w.severity || got.RiskScore != w.risk ||
			slices.Contains(got.FindingTypes, "cloud_path_open") != w.cloudOpen {
			t.Fatalf("%s after validation = %+v; want path %s, severity %s, risk %d, cloud_path_open %v (before: %+v)",
				id, got, w.path, w.severity, w.risk, w.cloudOpen, before["finding/"+id])
		}
	}
	if after["finding/"+api].RiskScore <= before["finding/"+api].RiskScore {
		t.Fatalf("the open path did not raise the risk score: %d -> %d", before["finding/"+api].RiskScore, after["finding/"+api].RiskScore)
	}
}
