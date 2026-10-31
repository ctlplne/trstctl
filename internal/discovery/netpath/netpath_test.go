// SPDX-License-Identifier: BUSL-1.1

package netpath_test

import (
	"net/netip"
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
