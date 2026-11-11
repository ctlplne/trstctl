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
	"trstctl.com/trstctl/internal/discovery/netpath/azurenetpath/networktest"
)

// A167-L1, part 2: a cloud_network_path source can read an Azure
// subscription. Validating exposed endpoints through it reads the public IPs,
// the network interfaces they sit on, the subnets' and interfaces' network
// security groups and the subnets' route tables from Resource Manager, and
// names what decides each address: open through the group that admits the
// internet, blocked by a group's default deny, blocked because a route sends
// the reply to an appliance, or blocked at a Standard public IP that no group
// opens. Before, the source refused any provider but aws-ec2 and gcp-compute.
func TestServedAttackPathValidationReadsAnAzureSubscriptionA167L1(t *testing.T) {
	const subscription = "00000000-0000-0000-0000-0000000a1672"
	const token = "stand-in-arm-token" // #nosec G101 -- a stand-in fixture value, not a credential (CWE-798)
	arm := networktest.New(subscription, token)
	t.Cleanup(arm.Close)
	arm.AddPublicIPs(
		networktest.PublicIP{Name: "pip-web", Address: "203.0.113.40", Interface: "nic-web"},
		networktest.PublicIP{Name: "pip-db", Address: "203.0.113.41", Interface: "nic-db"},
		networktest.PublicIP{Name: "pip-app", Address: "203.0.113.42", Interface: "nic-app"},
		networktest.PublicIP{Name: "pip-bare", Address: "203.0.113.43", Interface: "nic-bare"},
	)
	arm.AddInterfaces(
		networktest.Interface{Name: "nic-web", PrivateIP: "10.0.1.4", VNet: "vnet-prod", Subnet: "web", NSG: "nsg-web"},
		networktest.Interface{Name: "nic-db", PrivateIP: "10.0.2.4", VNet: "vnet-prod", Subnet: "data"},
		networktest.Interface{Name: "nic-app", PrivateIP: "10.0.3.4", VNet: "vnet-prod", Subnet: "inspected", NSG: "nsg-web"},
		networktest.Interface{Name: "nic-bare", PrivateIP: "10.0.4.4", VNet: "vnet-prod", Subnet: "bare"},
	)
	arm.AddSubnets(
		networktest.Subnet{VNet: "vnet-prod", Name: "web"},
		networktest.Subnet{VNet: "vnet-prod", Name: "data", NSG: "nsg-data"},
		networktest.Subnet{VNet: "vnet-prod", Name: "inspected", RouteTable: "rt-inspect"},
		networktest.Subnet{VNet: "vnet-prod", Name: "bare"},
	)
	arm.AddNSGs(
		networktest.NSG{Name: "nsg-web", Rules: []networktest.Rule{{Name: "AllowHTTPS", Priority: 100, Direction: "Inbound", Access: "Allow",
			Protocol: "Tcp", SourceAddressPrefix: "Internet", DestinationAddressPrefix: "*", DestinationPortRange: "443"}}},
		networktest.NSG{Name: "nsg-data"},
	)
	arm.AddRouteTables(networktest.RouteTable{Name: "rt-inspect", Routes: []networktest.Route{
		{Name: "default-to-appliance", AddressPrefix: "0.0.0.0/0", NextHopType: "VirtualAppliance"}}})
	t.Setenv("TRSTCTL_A167L1_ARM_TOKEN", token)
	h := newOperatingServedHarness(t, config.Protocols{}, allowOutboundEnvCredentialRefs("env:TRSTCTL_A167L1_ARM_TOKEN"))
	ctx := t.Context()
	writer := seedScopedToken(t, h.store, h.tenant, "discovery:read", "discovery:write", "nhi:read", string(authz.PrivateEgress))
	reader := seedScopedToken(t, h.store, h.tenant, "nhi:read")

	const web, db, app, bare = "22222222-2222-2222-2222-2222222b1674", "22222222-2222-2222-2222-2222222b1675",
		"22222222-2222-2222-2222-2222222b1676", "22222222-2222-2222-2222-2222222b1677"
	now := time.Now().UTC()
	for i, record := range []struct{ id, endpoint string }{
		{web, "https://203.0.113.40/api"}, {db, "https://203.0.113.41/db"}, {app, "https://203.0.113.42/app"}, {bare, "https://203.0.113.43/legacy"},
	} {
		suffix := string(rune('a' + i))
		seedDiscoveryPostureFindingWithIDs(t, h.store, h.tenant, "22222222-2222-2222-2222-2222222b16c"+suffix,
			"22222222-2222-2222-2222-2222222b16d"+suffix, record.id, now, map[string]any{"public_endpoint": record.endpoint})
	}
	status, body := secretsReq(t, h, http.MethodPost, "/api/v1/discovery/sources", writer, map[string]any{
		"name": "azure-prod", "kind": "cloud_network_path", "config": map[string]any{"providers": []map[string]any{{ // #nosec G101 -- token_ref is a non-secret environment locator (CWE-798)
			"provider": "azure-network", "subscription_id": subscription, "endpoint": arm.URL(),
			"allow_private_endpoint": true, "private_egress_cidrs": []string{serviceNowSinkCIDR(t, arm.URL())},
			"token_ref": "env:TRSTCTL_A167L1_ARM_TOKEN",
		}}},
	})
	var source struct {
		ID string `json:"id"`
	}
	if status != http.StatusCreated || json.Unmarshal(body, &source) != nil || source.ID == "" {
		t.Fatalf("create the azure-network source: %d %s", status, body)
	}
	status, body = secretsReqKey(t, h, http.MethodPost, "/api/v1/nhi/posture/exposure/attack-paths", writer, "a167l1-azure",
		map[string]any{"source_id": source.ID, "inventory_ids": []string{"finding/" + web, "finding/" + db, "finding/" + app, "finding/" + bare}})
	var queued struct {
		RunID string `json:"run_id"`
	}
	if status != http.StatusAccepted || json.Unmarshal(body, &queued) != nil || queued.RunID == "" {
		t.Fatalf("validate = %d %s", status, body)
	}
	if arm.Gets() != 0 {
		t.Fatal("the request handler read the subscription; only the outbox worker may")
	}
	if err := h.srv.Drain(ctx); err != nil {
		t.Fatalf("drain: %v", err)
	}
	run, err := h.store.GetDiscoveryRun(ctx, h.tenant, queued.RunID)
	if err != nil || run.Status != "succeeded" || run.Targets != 4 || run.Discovered != 1 {
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
		web:  {"open", "", "nsg-web"},
		db:   {"blocked", "network_security_group", "nsg-data"},
		app:  {"blocked", "route", "rt-inspect"},
		bare: {"blocked", "public_ip", "pip-bare"},
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
	if path := rows["finding/"+web].AttackPath.Endpoints[0].Path; strings.Join(path, ">") != "nic-web>nsg-web>pip-web" {
		t.Fatalf("open path = %v", path)
	}
}
