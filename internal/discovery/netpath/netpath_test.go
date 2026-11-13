// SPDX-License-Identifier: BUSL-1.1

package netpath_test

import (
	"net/netip"
	"strings"
	"testing"

	"trstctl.com/trstctl/internal/discovery/netpath"
)

func openConfig() netpath.Config {
	return netpath.Config{
		Interface:  netpath.Interface{ID: "eni-1", SubnetID: "subnet-1", VPCID: "vpc-1", SecurityGroups: []string{"sg-web"}},
		RouteTable: &netpath.RouteTable{ID: "rtb-1", Routes: []netpath.Route{{Destination: "10.0.0.0/16", Target: "local", Active: true}, {Destination: "0.0.0.0/0", Target: "igw-1", Active: true}}},
		NetworkACL: &netpath.NetworkACL{ID: "acl-1", Entries: []netpath.ACLEntry{
			{Number: 100, Protocol: "6", Allow: true, CIDR: "0.0.0.0/0", FromPort: 443, ToPort: 443},
			{Number: 32767, Protocol: "-1", Allow: false, CIDR: "0.0.0.0/0"},
			{Number: 100, Egress: true, Protocol: "6", Allow: true, CIDR: "0.0.0.0/0", FromPort: 1024, ToPort: 65535},
			{Number: 32767, Egress: true, Protocol: "-1", Allow: false, CIDR: "0.0.0.0/0"},
		}},
		SecurityGroups: []netpath.SecurityGroup{{ID: "sg-web", Inbound: []netpath.Permission{
			{Protocol: "tcp", FromPort: 22, ToPort: 22, CIDRs: []string{"198.51.100.0/24"}},
			{Protocol: "tcp", FromPort: 443, ToPort: 443, CIDRs: []string{"0.0.0.0/0"}},
		}}},
	}
}

// A167: the verdict follows the packet — route, network ACL in, network ACL
// return, security group — and names the resource that decided it.
func TestEvaluateNamesTheResourceThatDecides(t *testing.T) {
	ip := netip.MustParseAddr("203.0.113.10")
	if got := netpath.Evaluate(ip, 443, openConfig()); got.Verdict != netpath.Open || got.Resource != "sg-web" || len(got.Path) != 5 {
		t.Fatalf("open path = %+v", got)
	}
	for name, tc := range map[string]struct {
		mutate func(*netpath.Config)
		port   int
		stage  netpath.Stage
		res    string
	}{
		"no internet gateway route": {func(c *netpath.Config) { c.RouteTable.Routes[1].Target = "nat-1" }, 443, netpath.StageRoute, "rtb-1"},
		"network ACL denies first": {func(c *netpath.Config) {
			c.NetworkACL.Entries = append(c.NetworkACL.Entries, netpath.ACLEntry{Number: 90, Protocol: "6", CIDR: "0.0.0.0/0", FromPort: 443, ToPort: 443})
		}, 443, netpath.StageNetworkACL, "acl-1"},
		"network ACL drops the return":               {func(c *netpath.Config) { c.NetworkACL.Entries[2].Allow = false }, 443, netpath.StageNetworkACLOut, "acl-1"},
		"security group admits only a partner range": {func(c *netpath.Config) { c.NetworkACL.Entries[0].Protocol = "-1" }, 22, netpath.StageSecurityGroup, "sg-web"},
	} {
		t.Run(name, func(t *testing.T) {
			cfg := openConfig()
			tc.mutate(&cfg)
			got := netpath.Evaluate(ip, tc.port, cfg)
			if got.Verdict != netpath.Blocked || got.BlockedBy != tc.stage || got.Resource != tc.res {
				t.Fatalf("verdict = %+v, want blocked by %s on %s", got, tc.stage, tc.res)
			}
		})
	}
	// A narrower ACL deny before the internet-wide allow does not close the
	// path for the internet at large.
	cfg := openConfig()
	cfg.NetworkACL.Entries = append(cfg.NetworkACL.Entries, netpath.ACLEntry{Number: 50, Protocol: "6", CIDR: "192.0.2.0/24", FromPort: 443, ToPort: 443})
	if got := netpath.Evaluate(ip, 443, cfg); got.Verdict != netpath.Open {
		t.Fatalf("a narrow deny closed the internet-wide path: %+v", got)
	}
	if got := netpath.Evaluate(ip, 443, netpath.Config{Interface: netpath.Interface{ID: "eni-1"}}); got.Verdict != netpath.Unknown {
		t.Fatalf("missing configuration = %+v, want unknown", got)
	}
}

// A167-L2: a load balancer's address is judged by its listeners and its own
// security groups; a NAT gateway's address admits no connection; replies that
// leave through a NAT gateway, peering connection or virtual private gateway
// are named as the block; and a path through a transit gateway, an inspection
// endpoint or an appliance is unknown, naming it, unless a filter on the way
// blocks it outright.
func TestEvaluateFollowsLoadBalancersNATAndTransitPathsA167L2(t *testing.T) {
	ip := netip.MustParseAddr("203.0.113.20")
	alb := func() netpath.Config {
		cfg := openConfig()
		cfg.NetworkACL.Entries[0] = netpath.ACLEntry{Number: 100, Protocol: "-1", Allow: true, CIDR: "0.0.0.0/0"}
		cfg.SecurityGroups[0].Inbound = append(cfg.SecurityGroups[0].Inbound, netpath.Permission{Protocol: "tcp", FromPort: 8443, ToPort: 8443, CIDRs: []string{"0.0.0.0/0"}})
		cfg.LoadBalancer = &netpath.LoadBalancer{ID: "app/web/50dc6c495c0c9188", Type: "application",
			Listeners: []netpath.Listener{{Port: 80, Protocol: "HTTP"}, {Port: 443, Protocol: "HTTPS"}}}
		return cfg
	}
	got := netpath.Evaluate(ip, 443, alb())
	if got.Verdict != netpath.Open || got.Resource != "sg-web" || strings.Join(got.Path, ">") != "eni-1>app/web/50dc6c495c0c9188>sg-web>acl-1>rtb-1>igw-1" ||
		!strings.Contains(got.Reason, "listens on tcp/443 (HTTPS)") {
		t.Fatalf("listener 443 behind the group = %+v", got)
	}
	got = netpath.Evaluate(ip, 8443, alb())
	if got.Verdict != netpath.Blocked || got.BlockedBy != netpath.StageListener || got.Resource != "app/web/50dc6c495c0c9188" ||
		!strings.Contains(got.Reason, "it listens on tcp/80, tcp/443") {
		t.Fatalf("no listener on 8443, though the group admits it = %+v", got)
	}
	nlb := alb()
	nlb.SecurityGroups = nil
	nlb.LoadBalancer = &netpath.LoadBalancer{ID: "net/edge/7f3c2b1a", Type: "network", Unfiltered: true,
		Listeners: []netpath.Listener{{Port: 443, Protocol: "TLS"}, {Port: 53, Protocol: "UDP"}}}
	got = netpath.Evaluate(ip, 443, nlb)
	if got.Verdict != netpath.Open || got.Resource != "net/edge/7f3c2b1a" || strings.Join(got.Path, ">") != "eni-1>net/edge/7f3c2b1a>acl-1>rtb-1>igw-1" ||
		!strings.Contains(got.Reason, "no security groups") {
		t.Fatalf("a network load balancer without groups = %+v", got)
	}
	if got := netpath.Evaluate(ip, 53, nlb); got.Verdict != netpath.Blocked || got.BlockedBy != netpath.StageListener {
		t.Fatalf("a UDP-only port is no TCP path = %+v", got)
	}
	filtered := alb()
	filtered.SecurityGroups[0].Inbound = filtered.SecurityGroups[0].Inbound[:1]
	if got := netpath.Evaluate(ip, 443, filtered); got.Verdict != netpath.Blocked || got.BlockedBy != netpath.StageSecurityGroup ||
		!strings.Contains(got.Reason, "load balancer app/web/50dc6c495c0c9188") {
		t.Fatalf("the load balancer's own group admits only a partner range = %+v", got)
	}
	if got := netpath.Evaluate(ip, 443, netpath.Config{Interface: netpath.Interface{ID: "eni-nat"}, NATGateway: "nat-0a1b2c3d"}); got.Verdict != netpath.Blocked ||
		got.BlockedBy != netpath.StageNATGateway || got.Resource != "nat-0a1b2c3d" {
		t.Fatalf("a NAT gateway's address = %+v", got)
	}
	for target, want := range map[string]string{"nat-1": "NAT gateway nat-1", "pcx-1": "peering connection pcx-1", "vgw-1": "virtual private gateway vgw-1"} {
		cfg := openConfig()
		cfg.RouteTable.Routes[1].Target = target
		if got := netpath.Evaluate(ip, 443, cfg); got.Verdict != netpath.Blocked || got.BlockedBy != netpath.StageRoute || got.Resource != "rtb-1" ||
			!strings.Contains(got.Reason, want) {
			t.Fatalf("replies to %s = %+v", target, got)
		}
	}
	blackhole := openConfig()
	blackhole.RouteTable.Routes[1].Active = false
	if got := netpath.Evaluate(ip, 443, blackhole); got.Verdict != netpath.Blocked || !strings.Contains(got.Reason, "blackhole") {
		t.Fatalf("a blackhole internet route = %+v", got)
	}
	for target, want := range map[string]string{"tgw-1": "transit gateway tgw-1", "vpce-1": "gateway load balancer endpoint vpce-1", "eni-fw": "the appliance at eni-fw"} {
		cfg := openConfig()
		cfg.RouteTable.Routes[1].Target = target
		got := netpath.Evaluate(ip, 443, cfg)
		if got.Verdict != netpath.Unknown || got.Resource != target || got.Path[len(got.Path)-1] != target || !strings.Contains(got.Reason, want) ||
			!strings.Contains(got.Reason, "security group sg-web admits tcp/443") {
			t.Fatalf("replies through %s = %+v", target, got)
		}
		cfg.NetworkACL.Entries[0].Protocol = "-1"
		if got := netpath.Evaluate(ip, 22, cfg); got.Verdict != netpath.Blocked || got.BlockedBy != netpath.StageSecurityGroup {
			t.Fatalf("a group that blocks decides even through %s: %+v", target, got)
		}
	}
	inspected := openConfig()
	inspected.Interface.PrivateIP = netip.MustParseAddr("10.0.3.10")
	inspected.GatewayRouteTable = &netpath.RouteTable{ID: "rtb-edge", Routes: []netpath.Route{
		{Destination: "10.0.0.0/16", Target: "local", Active: true}, {Destination: "10.0.3.0/24", Target: "vpce-0abc", Active: true}}}
	got = netpath.Evaluate(ip, 443, inspected)
	if got.Verdict != netpath.Unknown || got.Resource != "vpce-0abc" || strings.Join(got.Path, ">") != "eni-1>sg-web>acl-1>rtb-1>vpce-0abc>igw-1" ||
		!strings.Contains(got.Reason, "rtb-edge") || !strings.Contains(got.Reason, "inspection appliances") {
		t.Fatalf("ingress routed through an inspection endpoint = %+v", got)
	}
	inspected.Interface.PrivateIP = netip.MustParseAddr("10.0.4.10")
	if got := netpath.Evaluate(ip, 443, inspected); got.Verdict != netpath.Open {
		t.Fatalf("another subnet's ingress route steered this one = %+v", got)
	}
	inspected.Interface.PrivateIP = netip.MustParseAddr("10.0.3.10")
	inspected.GatewayRouteTable.Routes[1].Active = false
	if got := netpath.Evaluate(ip, 443, inspected); got.Verdict != netpath.Blocked || got.Resource != "rtb-edge" || !strings.Contains(got.Reason, "no longer exists") {
		t.Fatalf("an ingress route to a deleted endpoint = %+v", got)
	}
}
