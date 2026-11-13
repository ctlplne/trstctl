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
	"trstctl.com/trstctl/internal/discovery/netpath/awsnetpath/ec2test"
)

// A167-L5 Done-when (served): an exposed endpoint at an IPv6 address is
// validated over IPv6 end to end — the posture's bracketed address is found by
// the interface's IPv6 address and judged by IPv6 rules and routes alone. A
// group admitting all of IPv6 global unicast (2000::/3) opens it; a group that
// admits only IPv4 does not; a subnet whose ::/0 route is an egress-only
// internet gateway blocks it at the route table; and a route for 2000::/3
// that leads elsewhere overrides ::/0 to the internet gateway.
func TestServedAttackPathJudgesIPv6EndpointsA167L5(t *testing.T) {
	const (
		accessKey = "AKIAAAAAAAAAAL5"
		secretKey = "served-test-secret-l5" // #nosec G101 -- fabricated fixture credential; the test needs the shape, no value is real (CWE-798)
	)
	stand := ec2test.New(accessKey, secretKey)
	t.Cleanup(stand.Close)
	acl := []ec2test.ACLEntry{
		{Number: 100, Allow: true, Protocol: "6", CIDR: "0.0.0.0/0", FromPort: 443, ToPort: 443},
		{Number: 101, Allow: true, Protocol: "6", CIDR: "::/0", FromPort: 443, ToPort: 443},
		{Number: 32767, Protocol: "-1", CIDR: "0.0.0.0/0"},
		{Number: 32768, Protocol: "-1", CIDR: "::/0"},
		{Number: 100, Egress: true, Allow: true, Protocol: "-1", CIDR: "0.0.0.0/0"},
		{Number: 101, Egress: true, Allow: true, Protocol: "-1", CIDR: "::/0"},
	}
	stand.Seed(
		[]ec2test.Interface{
			{ID: "eni-v6", SubnetID: "subnet-v6", VPCID: "vpc-1", IPv6: "2001:db8:1200::10", Groups: []string{"sg-v6"}, PrivateIP: "10.0.6.10"},
			{ID: "eni-v4rule", SubnetID: "subnet-v6", VPCID: "vpc-1", IPv6: "2001:db8:1200::11", Groups: []string{"sg-v4"}, PrivateIP: "10.0.6.11"},
			{ID: "eni-eigw", SubnetID: "subnet-eigw", VPCID: "vpc-1", IPv6: "2001:db8:1201::10", Groups: []string{"sg-v6"}, PrivateIP: "10.0.7.10"},
			{ID: "eni-override", SubnetID: "subnet-override", VPCID: "vpc-1", IPv6: "2001:db8:1202::10", Groups: []string{"sg-v6"}, PrivateIP: "10.0.8.10"},
		},
		[]ec2test.SecurityGroup{
			{ID: "sg-v6", Inbound: []ec2test.Permission{{Protocol: "tcp", FromPort: 443, ToPort: 443, CIDRs: []string{"2000::/3"}}}},
			{ID: "sg-v4", Inbound: []ec2test.Permission{{Protocol: "tcp", FromPort: 443, ToPort: 443, CIDRs: []string{"0.0.0.0/0"}}}},
		},
		[]ec2test.RouteTable{
			{ID: "rtb-v6", VPCID: "vpc-1", Subnets: []string{"subnet-v6"}, Routes: []ec2test.Route{
				{Destination: "10.0.0.0/16", Target: "local"}, {Destination: "::/0", Target: "igw-1"}}},
			{ID: "rtb-eigw", VPCID: "vpc-1", Subnets: []string{"subnet-eigw"}, Routes: []ec2test.Route{
				{Destination: "10.0.0.0/16", Target: "local"}, {Destination: "::/0", Target: "eigw-1"}}},
			{ID: "rtb-override", VPCID: "vpc-1", Subnets: []string{"subnet-override"}, Routes: []ec2test.Route{
				{Destination: "10.0.0.0/16", Target: "local"}, {Destination: "::/0", Target: "igw-1"}, {Destination: "2000::/3", Target: "eigw-1"}}},
		},
		[]ec2test.NetworkACL{{ID: "acl-v6", Subnets: []string{"subnet-v6", "subnet-eigw", "subnet-override"}, Entries: acl}},
	)
	t.Setenv("TRSTCTL_A167L5_EC2_ACCESS_KEY_ID", accessKey)
	t.Setenv("TRSTCTL_A167L5_EC2_SECRET_ACCESS_KEY", secretKey)
	h := newOperatingServedHarness(t, config.Protocols{}, allowOutboundEnvCredentialRefs(
		"env:TRSTCTL_A167L5_EC2_ACCESS_KEY_ID", "env:TRSTCTL_A167L5_EC2_SECRET_ACCESS_KEY"))
	ctx := t.Context()
	writer := seedScopedToken(t, h.store, h.tenant, "discovery:read", "discovery:write", "nhi:read", string(authz.PrivateEgress))
	reader := seedScopedToken(t, h.store, h.tenant, "nhi:read")

	records := []struct{ id, endpoint string }{
		{"22222222-2222-2222-2222-2222222a5671", "https://[2001:db8:1200::10]/api"},
		{"22222222-2222-2222-2222-2222222a5672", "https://[2001:db8:1200::11]/legacy"},
		{"22222222-2222-2222-2222-2222222a5673", "https://[2001:db8:1201::10]/internal"},
		{"22222222-2222-2222-2222-2222222a5674", "https://[2001:db8:1202::10]/override"},
	}
	now := time.Now().UTC()
	for i, record := range records {
		suffix := string("abcd"[i])
		seedDiscoveryPostureFindingWithIDs(t, h.store, h.tenant, "22222222-2222-2222-2222-2222222a56a"+suffix,
			"22222222-2222-2222-2222-2222222a56b"+suffix, record.id, now, map[string]any{"public_endpoint": record.endpoint})
	}
	status, body := secretsReq(t, h, http.MethodPost, "/api/v1/discovery/sources", writer, map[string]any{
		"name": "aws-ec2-ipv6", "kind": "cloud_network_path", "config": map[string]any{"providers": []map[string]any{{ // #nosec G101 -- credential references only (CWE-798)
			"provider": "aws-ec2", "region": "us-east-1", "endpoint": stand.URL(), "elb_endpoint": stand.URL(),
			"allow_private_endpoint": true, "private_egress_cidrs": []string{serviceNowSinkCIDR(t, stand.URL())},
			"access_key_id_ref": "env:TRSTCTL_A167L5_EC2_ACCESS_KEY_ID", "secret_access_key_ref": "env:TRSTCTL_A167L5_EC2_SECRET_ACCESS_KEY",
		}}},
	})
	var source struct {
		ID string `json:"id"`
	}
	if status != http.StatusCreated || json.Unmarshal(body, &source) != nil || source.ID == "" {
		t.Fatalf("create source: %d %s", status, body)
	}
	status, body = secretsReqKey(t, h, http.MethodPost, "/api/v1/nhi/posture/exposure/attack-paths", writer, "a167l5-1", map[string]any{"source_id": source.ID})
	var queued struct {
		RunID     string `json:"run_id"`
		Endpoints []struct {
			Address string `json:"address"`
		} `json:"endpoints"`
	}
	if status != http.StatusAccepted || json.Unmarshal(body, &queued) != nil || queued.RunID == "" || len(queued.Endpoints) != len(records) {
		t.Fatalf("validate = %d %s", status, body)
	}
	if err := h.srv.Drain(ctx); err != nil {
		t.Fatalf("drain: %v", err)
	}
	run, err := h.store.GetDiscoveryRun(ctx, h.tenant, queued.RunID)
	if err != nil || run.Status != "succeeded" || run.Targets != len(records) {
		t.Fatalf("validation run = %+v %v", run, err)
	}
	if run.Discovered != 1 {
		t.Errorf("validation run found %d open paths, want 1", run.Discovered)
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
	want := []struct{ address, status, blockedBy, resource, path, reason string }{
		{"[2001:db8:1200::10]:443", "open", "", "sg-v6", "eni-v6>sg-v6>acl-v6>rtb-v6>igw-1", "from 2000::/3"},
		{"[2001:db8:1200::11]:443", "blocked", "security_group", "sg-v4", "", "from ::/0"},
		{"[2001:db8:1201::10]:443", "blocked", "route", "rtb-eigw", "", "egress-only internet gateway eigw-1"},
		{"[2001:db8:1202::10]:443", "blocked", "route", "rtb-override", "", "replies for 2000::/3"},
	}
	for i, w := range want {
		row := rows["finding/"+records[i].id]
		if row.AttackPath == nil || len(row.AttackPath.Endpoints) != 1 {
			t.Errorf("%s attack path = %+v", records[i].endpoint, row.AttackPath)
			continue
		}
		got := row.AttackPath.Endpoints[0]
		if got.Address != w.address || got.Status != w.status || got.BlockedBy != w.blockedBy || got.Resource != w.resource ||
			strings.Join(got.Path, ">") != w.path || !strings.Contains(got.Reason, w.reason) {
			t.Errorf("%s verdict = %+v, want %+v", records[i].endpoint, got, w)
		}
	}
	if t.Failed() {
		t.FailNow()
	}
	if stand.Calls("DescribeNetworkInterfaces") == 0 || stand.NonDescribeCalls() != 0 || stand.Refused() != 0 {
		t.Fatalf("interface lookups %d, non-describe calls %d, refused signatures %d", stand.Calls("DescribeNetworkInterfaces"), stand.NonDescribeCalls(), stand.Refused())
	}
}
