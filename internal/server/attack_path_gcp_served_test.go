// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/authz"
	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/discovery/netpath"
	"trstctl.com/trstctl/internal/discovery/netpath/gcpnetpath/computetest"
)

// A167-L1, part 1: a cloud_network_path source can read a Google Cloud
// project. Validating exposed endpoints through it reads the project's
// instances, VPC firewall rules and routes from Compute Engine and names the
// resource that decides each one: open through the firewall rule that admits
// the internet, blocked by the network's implied ingress deny, or blocked
// because the network has no route to the default internet gateway. Before,
// the source refused any provider but aws-ec2.
func TestServedAttackPathValidationReadsAGoogleCloudProjectA167L1(t *testing.T) {
	const token = "stand-in-compute-token" // #nosec G101 -- a stand-in fixture value, not a credential (CWE-798)
	compute := computetest.New("a167l1-project", token)
	t.Cleanup(compute.Close)
	compute.Add([]computetest.Instance{
		{Name: "web-1", Zone: "us-central1-a", Network: "prod", NatIP: "203.0.113.30", Tags: []string{"https-server"}},
		{Name: "db-1", Zone: "us-central1-a", Network: "prod", NatIP: "203.0.113.31", Tags: []string{"db"}},
		{Name: "lab-1", Zone: "us-central1-b", Network: "isolated", NatIP: "203.0.113.32", Tags: []string{"https-server"}},
	}, []computetest.Firewall{
		{Name: "allow-https", Network: "prod", Direction: "INGRESS", Priority: 1000, SourceRanges: []string{"0.0.0.0/0"}, TargetTags: []string{"https-server"},
			Allowed: []map[string]any{{"IPProtocol": "tcp", "ports": []string{"443"}}}},
		{Name: "lab-https", Network: "isolated", Direction: "INGRESS", Priority: 1000, SourceRanges: []string{"0.0.0.0/0"},
			Allowed: []map[string]any{{"IPProtocol": "tcp", "ports": []string{"443"}}}},
	}, []computetest.Route{
		{Name: "default-route-internet", Network: "prod", DestRange: "0.0.0.0/0", Priority: 1000, NextHopGateway: netpath.DefaultInternetGateway},
	})
	t.Setenv("TRSTCTL_A167L1_GCP_TOKEN", token)
	h := newOperatingServedHarness(t, config.Protocols{}, allowOutboundEnvCredentialRefs("env:TRSTCTL_A167L1_GCP_TOKEN"))
	ctx := t.Context()
	writer := seedScopedToken(t, h.store, h.tenant, "discovery:read", "discovery:write", "nhi:read", string(authz.PrivateEgress))
	reader := seedScopedToken(t, h.store, h.tenant, "nhi:read")

	const web, db, lab = "22222222-2222-2222-2222-2222222b1671", "22222222-2222-2222-2222-2222222b1672", "22222222-2222-2222-2222-2222222b1673"
	now := time.Now().UTC()
	for i, record := range []struct{ id, endpoint string }{
		{web, "https://203.0.113.30/api"}, {db, "https://203.0.113.31/db"}, {lab, "https://203.0.113.32/lab"},
	} {
		suffix := string(rune('a' + i))
		seedDiscoveryPostureFindingWithIDs(t, h.store, h.tenant, "22222222-2222-2222-2222-2222222b16a"+suffix,
			"22222222-2222-2222-2222-2222222b16b"+suffix, record.id, now, map[string]any{"public_endpoint": record.endpoint})
	}
	status, body := secretsReq(t, h, http.MethodPost, "/api/v1/discovery/sources", writer, map[string]any{
		"name": "gcp-prod", "kind": "cloud_network_path", "config": map[string]any{"providers": []map[string]any{{ // #nosec G101 -- token_ref is a non-secret environment locator (CWE-798)
			"provider": "gcp-compute", "project": "a167l1-project", "endpoint": compute.URL(),
			"allow_private_endpoint": true, "private_egress_cidrs": []string{serviceNowSinkCIDR(t, compute.URL())},
			"token_ref": "env:TRSTCTL_A167L1_GCP_TOKEN",
		}}},
	})
	var source struct {
		ID string `json:"id"`
	}
	if status != http.StatusCreated || json.Unmarshal(body, &source) != nil || source.ID == "" {
		t.Fatalf("create the gcp-compute source: %d %s", status, body)
	}
	status, body = secretsReqKey(t, h, http.MethodPost, "/api/v1/nhi/posture/exposure/attack-paths", writer, "a167l1-gcp",
		map[string]any{"source_id": source.ID, "inventory_ids": []string{"finding/" + web, "finding/" + db, "finding/" + lab}})
	var queued struct {
		RunID string `json:"run_id"`
	}
	if status != http.StatusAccepted || json.Unmarshal(body, &queued) != nil || queued.RunID == "" {
		t.Fatalf("validate = %d %s", status, body)
	}
	if compute.Gets() != 0 {
		t.Fatal("the request handler read the project; only the outbox worker may")
	}
	if err := h.srv.Drain(ctx); err != nil {
		t.Fatalf("drain: %v", err)
	}
	run, err := h.store.GetDiscoveryRun(ctx, h.tenant, queued.RunID)
	if err != nil || run.Status != "succeeded" || run.Targets != 3 || run.Discovered != 1 {
		t.Fatalf("validation run = %+v %v", run, err)
	}
	status, body = secretsReq(t, h, http.MethodGet, "/api/v1/nhi/posture/exposure", reader, nil)
	var posture struct {
		Findings []attackPathPostureRow `json:"findings"`
	}
	if status != http.StatusOK || json.Unmarshal(body, &posture) != nil {
		t.Fatalf("posture = %d %s", status, body)
	}
	rows := map[string]attackPathPostureRow{}
	for _, row := range posture.Findings {
		rows[row.InventoryID] = row
	}
	for id, w := range map[string]struct{ status, blockedBy, resource string }{
		web: {"open", "", "allow-https"}, db: {"blocked", "firewall", "prod"}, lab: {"blocked", "route", "isolated"},
	} {
		row := rows["finding/"+id]
		if row.AttackPath == nil || len(row.AttackPath.Endpoints) != 1 {
			t.Fatalf("%s attack path = %+v", id, row.AttackPath)
		}
		endpoint := row.AttackPath.Endpoints[0]
		if endpoint.Status != w.status || endpoint.BlockedBy != w.blockedBy || endpoint.Resource != w.resource || endpoint.Reason == "" {
			t.Fatalf("%s endpoint verdict = %+v; want %+v", id, endpoint, w)
		}
	}
	if open := rows["finding/"+web].AttackPath.Endpoints[0]; strings.Join(open.Path, ">") != "web-1>allow-https>default-route-internet>default-internet-gateway" {
		t.Fatalf("open path = %v", open.Path)
	}
}
