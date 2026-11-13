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

// A167-L2 Done-when (served): attack-path validation follows the paths A167
// did not. An endpoint on an internet-facing load balancer is judged by the
// load balancer's own listeners and security groups (read, signed and
// read-only, from Elastic Load Balancing): open on a port it listens on,
// blocked at the load balancer on one it does not, and open on a network load
// balancer without security groups. A NAT gateway's address is blocked at the
// NAT gateway; a host whose subnet replies through a NAT gateway is blocked at
// its route table with the NAT gateway named; and a host replying through a
// transit gateway, or one the internet gateway's own route table steers
// through an inspection endpoint, is unknown with that resource named — never
// open, never blocked. Nothing in the account is changed.
func TestServedAttackPathFollowsLoadBalancersNATAndTransitGatewaysA167L2(t *testing.T) {
	const (
		accessKey = "AKIAAAAAAAAAAL2"
		secretKey = "served-test-secret-l2" // #nosec G101 -- fabricated fixture credential; the test needs the shape, no value is real (CWE-798)
	)
	stand := ec2test.New(accessKey, secretKey)
	t.Cleanup(stand.Close)
	allowAll := []ec2test.ACLEntry{{Number: 100, Allow: true, Protocol: "-1", CIDR: "0.0.0.0/0"}, {Number: 100, Egress: true, Allow: true, Protocol: "-1", CIDR: "0.0.0.0/0"}}
	stand.Seed(
		[]ec2test.Interface{
			{ID: "eni-alb", SubnetID: "subnet-lb", VPCID: "vpc-1", PublicIP: "203.0.113.20", Groups: []string{"sg-alb"},
				RequesterManaged: true, Description: "ELB app/web/50dc6c495c0c9188", PrivateIP: "10.0.1.20"},
			{ID: "eni-nlb", SubnetID: "subnet-lb", VPCID: "vpc-1", PublicIP: "203.0.113.21", Type: "network_load_balancer",
				RequesterManaged: true, Description: "ELB net/edge/7f3c2b1a", PrivateIP: "10.0.1.21"},
			{ID: "eni-nat", SubnetID: "subnet-lb", VPCID: "vpc-1", PublicIP: "203.0.113.23", Type: "nat_gateway",
				RequesterManaged: true, Description: "Interface for NAT Gateway nat-0a1b2c3d", PrivateIP: "10.0.1.23"},
			{ID: "eni-hub", SubnetID: "subnet-hub", VPCID: "vpc-1", PublicIP: "203.0.113.24", Groups: []string{"sg-web"}, PrivateIP: "10.0.2.24"},
			{ID: "eni-inspected", SubnetID: "subnet-inspected", VPCID: "vpc-1", PublicIP: "203.0.113.25", Groups: []string{"sg-web"}, PrivateIP: "10.0.3.25"},
			{ID: "eni-private", SubnetID: "subnet-private", VPCID: "vpc-1", PublicIP: "203.0.113.12", Groups: []string{"sg-web"}, PrivateIP: "10.0.4.12"},
		},
		[]ec2test.SecurityGroup{
			{ID: "sg-alb", Inbound: []ec2test.Permission{{Protocol: "tcp", FromPort: 443, ToPort: 443, CIDRs: []string{"0.0.0.0/0"}},
				{Protocol: "tcp", FromPort: 8443, ToPort: 8443, CIDRs: []string{"0.0.0.0/0"}}}},
			{ID: "sg-web", Inbound: []ec2test.Permission{{Protocol: "tcp", FromPort: 443, ToPort: 443, CIDRs: []string{"0.0.0.0/0"}}}},
		},
		[]ec2test.RouteTable{
			{ID: "rtb-main", VPCID: "vpc-1", Main: true, Routes: []ec2test.Route{{Destination: "10.0.0.0/16", Target: "local"}, {Destination: "0.0.0.0/0", Target: "nat-0a1b2c3d"}}},
			{ID: "rtb-lb", VPCID: "vpc-1", Subnets: []string{"subnet-lb", "subnet-inspected"}, Routes: []ec2test.Route{{Destination: "10.0.0.0/16", Target: "local"}, {Destination: "0.0.0.0/0", Target: "igw-1"}}},
			{ID: "rtb-hub", VPCID: "vpc-1", Subnets: []string{"subnet-hub"}, Routes: []ec2test.Route{{Destination: "10.0.0.0/16", Target: "local"}, {Destination: "0.0.0.0/0", Target: "tgw-1"}}},
			{ID: "rtb-edge", VPCID: "vpc-1", Gateways: []string{"igw-1"}, Routes: []ec2test.Route{{Destination: "10.0.0.0/16", Target: "local"}, {Destination: "10.0.3.0/24", Target: "vpce-0abc"}}},
		},
		[]ec2test.NetworkACL{{ID: "acl-1", Subnets: []string{"subnet-lb", "subnet-hub", "subnet-inspected", "subnet-private"}, Entries: allowAll}},
	)
	stand.SeedLoadBalancers(
		ec2test.LoadBalancer{ARN: "arn:aws:elasticloadbalancing:us-east-1:123456789012:loadbalancer/app/web/50dc6c495c0c9188", Name: "web",
			Type: "application", Scheme: "internet-facing", SecurityGroups: []string{"sg-alb"},
			Listeners: []ec2test.Listener{{Port: 80, Protocol: "HTTP"}, {Port: 443, Protocol: "HTTPS"}}},
		ec2test.LoadBalancer{ARN: "arn:aws:elasticloadbalancing:us-east-1:123456789012:loadbalancer/net/edge/7f3c2b1a", Name: "edge",
			Type: "network", Scheme: "internet-facing", Listeners: []ec2test.Listener{{Port: 443, Protocol: "TLS"}}},
	)
	t.Setenv("TRSTCTL_A167L2_EC2_ACCESS_KEY_ID", accessKey)
	t.Setenv("TRSTCTL_A167L2_EC2_SECRET_ACCESS_KEY", secretKey)
	h := newOperatingServedHarness(t, config.Protocols{}, allowOutboundEnvCredentialRefs(
		"env:TRSTCTL_A167L2_EC2_ACCESS_KEY_ID", "env:TRSTCTL_A167L2_EC2_SECRET_ACCESS_KEY"))
	ctx := t.Context()
	writer := seedScopedToken(t, h.store, h.tenant, "discovery:read", "discovery:write", "nhi:read", string(authz.PrivateEgress))
	reader := seedScopedToken(t, h.store, h.tenant, "nhi:read")

	records := []struct{ id, endpoint string }{
		{"22222222-2222-2222-2222-2222222a2671", "https://203.0.113.20/api"},
		{"22222222-2222-2222-2222-2222222a2672", "https://203.0.113.20:8443/admin"},
		{"22222222-2222-2222-2222-2222222a2673", "https://203.0.113.21/edge"},
		{"22222222-2222-2222-2222-2222222a2674", "https://203.0.113.23/egress"},
		{"22222222-2222-2222-2222-2222222a2675", "https://203.0.113.24/hub"},
		{"22222222-2222-2222-2222-2222222a2676", "https://203.0.113.25/inspected"},
		{"22222222-2222-2222-2222-2222222a2677", "https://203.0.113.12/internal"},
	}
	now := time.Now().UTC()
	for i, record := range records {
		suffix := string("abcdef0"[i])
		seedDiscoveryPostureFindingWithIDs(t, h.store, h.tenant, "22222222-2222-2222-2222-2222222a26a"+suffix,
			"22222222-2222-2222-2222-2222222a26b"+suffix, record.id, now, map[string]any{"public_endpoint": record.endpoint})
	}
	status, body := secretsReq(t, h, http.MethodPost, "/api/v1/discovery/sources", writer, map[string]any{
		"name": "aws-ec2-paths", "kind": "cloud_network_path", "config": map[string]any{"providers": []map[string]any{{ // #nosec G101 -- credential references only (CWE-798)
			"provider": "aws-ec2", "region": "us-east-1", "endpoint": stand.URL(), "elb_endpoint": stand.URL(),
			"allow_private_endpoint": true, "private_egress_cidrs": []string{serviceNowSinkCIDR(t, stand.URL())},
			"access_key_id_ref": "env:TRSTCTL_A167L2_EC2_ACCESS_KEY_ID", "secret_access_key_ref": "env:TRSTCTL_A167L2_EC2_SECRET_ACCESS_KEY",
		}}},
	})
	var source struct {
		ID string `json:"id"`
	}
	if status != http.StatusCreated || json.Unmarshal(body, &source) != nil || source.ID == "" {
		t.Fatalf("create source: %d %s", status, body)
	}
	status, body = secretsReqKey(t, h, http.MethodPost, "/api/v1/nhi/posture/exposure/attack-paths", writer, "a167l2-1", map[string]any{"source_id": source.ID})
	var queued struct {
		RunID string `json:"run_id"`
	}
	if status != http.StatusAccepted || json.Unmarshal(body, &queued) != nil || queued.RunID == "" {
		t.Fatalf("validate = %d %s", status, body)
	}
	if err := h.srv.Drain(ctx); err != nil {
		t.Fatalf("drain: %v", err)
	}
	run, err := h.store.GetDiscoveryRun(ctx, h.tenant, queued.RunID)
	if err != nil || run.Status != "succeeded" || run.Targets != len(records) {
		t.Fatalf("validation run = %+v %v", run, err)
	}
	if run.Discovered != 2 {
		t.Errorf("validation run found %d open paths, want 2 (the load balancers' listening ports)", run.Discovered)
	}

	status, body = secretsReq(t, h, http.MethodGet, "/api/v1/nhi/posture/exposure", reader, nil)
	var posture struct {
		Summary struct {
			PathValidated int `json:"path_validated"`
			PathOpen      int `json:"path_open"`
		} `json:"summary"`
		Findings []attackPathPostureRow `json:"findings"`
	}
	if status != http.StatusOK || json.Unmarshal(body, &posture) != nil {
		t.Fatalf("posture = %d %s", status, body)
	}
	rows := map[string]attackPathPostureRow{}
	for _, row := range posture.Findings {
		rows[row.InventoryID] = row
	}
	want := []struct {
		status, blockedBy, resource, path, reason string
	}{
		{"open", "", "sg-alb", "eni-alb>app/web/50dc6c495c0c9188>sg-alb>acl-1>rtb-lb>igw-1", "listens on tcp/443 (HTTPS)"},
		{"blocked", "listener", "app/web/50dc6c495c0c9188", "", "has no listener on tcp/8443 (it listens on tcp/80, tcp/443)"},
		{"open", "", "net/edge/7f3c2b1a", "eni-nlb>net/edge/7f3c2b1a>acl-1>rtb-lb>igw-1", "has no security groups"},
		{"blocked", "nat_gateway", "nat-0a1b2c3d", "", "NAT gateway"},
		{"unknown", "", "tgw-1", "eni-hub>sg-web>acl-1>rtb-hub>tgw-1", "transit gateway tgw-1"},
		{"unknown", "", "vpce-0abc", "eni-inspected>sg-web>acl-1>rtb-lb>vpce-0abc>igw-1", "gateway load balancer endpoint vpce-0abc"},
		{"blocked", "route", "rtb-main", "", "to NAT gateway nat-0a1b2c3d"},
	}
	for i, w := range want {
		row := rows["finding/"+records[i].id]
		if row.AttackPath == nil || row.AttackPath.Status != w.status || len(row.AttackPath.Endpoints) != 1 {
			t.Errorf("%s attack path = %+v, want %s", records[i].endpoint, row.AttackPath, w.status)
			continue
		}
		got := row.AttackPath.Endpoints[0]
		if got.Status != w.status || got.BlockedBy != w.blockedBy || got.Resource != w.resource || strings.Join(got.Path, ">") != w.path ||
			!strings.Contains(got.Reason, w.reason) {
			t.Errorf("%s verdict = %+v, want %+v", records[i].endpoint, got, w)
		}
	}
	if t.Failed() {
		t.FailNow()
	}
	if posture.Summary.PathValidated != len(records) || posture.Summary.PathOpen != 2 {
		t.Fatalf("posture summary = %+v", posture.Summary)
	}
	if stand.Calls("elbv2:DescribeLoadBalancers") == 0 || stand.Calls("elbv2:DescribeListeners") == 0 {
		t.Fatal("the load balancers' listeners were not read from Elastic Load Balancing")
	}
	if stand.NonDescribeCalls() != 0 || stand.Refused() != 0 {
		t.Fatalf("the validation changed the account (%d non-describe calls) or signed badly (%d refused)", stand.NonDescribeCalls(), stand.Refused())
	}
}
