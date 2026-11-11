// SPDX-License-Identifier: BUSL-1.1

package netpath

import (
	"net/netip"
	"strings"
	"testing"
)

// A167-L1: GCP's answer to "can the internet reach this external address and
// port", from the VPC network's routes and firewall rules, written from
// Google's documented semantics: the default route to the default internet
// gateway carries the traffic, ingress rules apply by network, target tag or
// service account, the lowest priority number decides with a deny winning a
// tie, and an implied rule denies everything else. Only a rule naming the
// internet-wide range decides.
func TestEvaluateGCPFollowsVPCFirewallSemanticsA167L1(t *testing.T) {
	ip := netip.MustParseAddr("34.120.0.10")
	instance := GCPInstance{Name: "web-1", Network: "prod", Tags: []string{"https-server"}, ServiceAccounts: []string{"web@p.iam.gserviceaccount.com"}}
	defaultRoute := GCPRoute{Name: "default-route-abc", Network: "prod", DestRange: "0.0.0.0/0", Priority: 1000, NextHopGateway: DefaultInternetGateway}
	allowHTTPS := GCPFirewall{Name: "allow-https", Network: "prod", Direction: "INGRESS", Priority: 1000,
		SourceRanges: []string{"0.0.0.0/0"}, TargetTags: []string{"https-server"}, Allowed: []GCPProtocolPorts{{Protocol: "tcp", Ports: []string{"443"}}}}
	cases := map[string]struct {
		cfg       GCPConfig
		port      int
		verdict   Verdict
		stage     Stage
		resource  string
		reasonHas string
	}{
		"open through a tagged allow": {GCPConfig{Instance: instance, Routes: []GCPRoute{defaultRoute}, Firewalls: []GCPFirewall{allowHTTPS}}, 443, Open, "", "allow-https", "admits tcp/443"},
		"a port range admits": {GCPConfig{Instance: instance, Routes: []GCPRoute{defaultRoute}, Firewalls: []GCPFirewall{{Name: "range", Network: "prod", Direction: "INGRESS", Priority: 900,
			SourceRanges: []string{"0.0.0.0/0"}, Allowed: []GCPProtocolPorts{{Protocol: "tcp", Ports: []string{"8000-9000"}}}}}}, 8443, Open, "", "range", ""},
		"implied deny when nothing admits the port": {GCPConfig{Instance: instance, Routes: []GCPRoute{defaultRoute}, Firewalls: []GCPFirewall{allowHTTPS}}, 22, Blocked, StageFirewall, "prod", "no firewall rule"},
		"a higher-priority deny wins": {GCPConfig{Instance: instance, Routes: []GCPRoute{defaultRoute}, Firewalls: []GCPFirewall{allowHTTPS,
			{Name: "deny-all-in", Network: "prod", Direction: "INGRESS", Priority: 100, SourceRanges: []string{"0.0.0.0/0"}, Denied: []GCPProtocolPorts{{Protocol: "all"}}}}}, 443, Blocked, StageFirewall, "deny-all-in", "denies"},
		"a deny wins a priority tie": {GCPConfig{Instance: instance, Routes: []GCPRoute{defaultRoute}, Firewalls: []GCPFirewall{allowHTTPS,
			{Name: "deny-443", Network: "prod", Direction: "INGRESS", Priority: 1000, SourceRanges: []string{"0.0.0.0/0"}, Denied: []GCPProtocolPorts{{Protocol: "tcp", Ports: []string{"443"}}}}}}, 443, Blocked, StageFirewall, "deny-443", "denies"},
		"a partner range does not decide": {GCPConfig{Instance: instance, Routes: []GCPRoute{defaultRoute}, Firewalls: []GCPFirewall{{Name: "partner", Network: "prod", Direction: "INGRESS",
			Priority: 10, SourceRanges: []string{"203.0.113.0/24"}, Allowed: []GCPProtocolPorts{{Protocol: "tcp"}}}}}, 443, Blocked, StageFirewall, "prod", "no firewall rule"},
		"a rule for other tags does not apply": {GCPConfig{Instance: instance, Routes: []GCPRoute{defaultRoute}, Firewalls: []GCPFirewall{{Name: "db-only", Network: "prod", Direction: "INGRESS",
			Priority: 10, SourceRanges: []string{"0.0.0.0/0"}, TargetTags: []string{"db"}, Allowed: []GCPProtocolPorts{{Protocol: "tcp"}}}}}, 443, Blocked, StageFirewall, "prod", ""},
		"a service-account target applies": {GCPConfig{Instance: instance, Routes: []GCPRoute{defaultRoute}, Firewalls: []GCPFirewall{{Name: "by-sa", Network: "prod", Direction: "INGRESS",
			Priority: 10, SourceRanges: []string{"0.0.0.0/0"}, TargetServiceAccounts: []string{"web@p.iam.gserviceaccount.com"}, Allowed: []GCPProtocolPorts{{Protocol: "tcp", Ports: []string{"443"}}}}}}, 443, Open, "", "by-sa", ""},
		"a disabled rule and an egress rule do not count": {GCPConfig{Instance: instance, Routes: []GCPRoute{defaultRoute}, Firewalls: []GCPFirewall{
			{Name: "off", Network: "prod", Direction: "INGRESS", Priority: 10, Disabled: true, SourceRanges: []string{"0.0.0.0/0"}, Allowed: []GCPProtocolPorts{{Protocol: "all"}}},
			{Name: "out", Network: "prod", Direction: "EGRESS", Priority: 10, SourceRanges: []string{"0.0.0.0/0"}, Allowed: []GCPProtocolPorts{{Protocol: "all"}}}}}, 443, Blocked, StageFirewall, "prod", ""},
		"another network's rule does not apply": {GCPConfig{Instance: instance, Routes: []GCPRoute{defaultRoute}, Firewalls: []GCPFirewall{{Name: "other-net", Network: "staging", Direction: "INGRESS",
			Priority: 10, SourceRanges: []string{"0.0.0.0/0"}, Allowed: []GCPProtocolPorts{{Protocol: "all"}}}}}, 443, Blocked, StageFirewall, "prod", ""},
		"no default route": {GCPConfig{Instance: instance, Firewalls: []GCPFirewall{allowHTTPS}}, 443, Blocked, StageRoute, "prod", "no route"},
		"a higher-priority route to an appliance": {GCPConfig{Instance: instance, Firewalls: []GCPFirewall{allowHTTPS}, Routes: []GCPRoute{defaultRoute,
			{Name: "via-appliance", Network: "prod", DestRange: "0.0.0.0/0", Priority: 100}}}, 443, Blocked, StageRoute, "via-appliance", "next hop other than"},
		"a tagged route for other instances does not apply": {GCPConfig{Instance: instance, Firewalls: []GCPFirewall{allowHTTPS}, Routes: []GCPRoute{defaultRoute,
			{Name: "nat-only", Network: "prod", DestRange: "0.0.0.0/0", Priority: 100, Tags: []string{"no-ip"}}}}, 443, Open, "", "allow-https", ""},
	}
	for name, tc := range cases {
		got := EvaluateGCP(ip, tc.port, tc.cfg)
		if got.Verdict != tc.verdict || got.BlockedBy != tc.stage || got.Resource != tc.resource || !strings.Contains(got.Reason, tc.reasonHas) {
			t.Errorf("%s: %+v; want %s %s %s (%q)", name, got, tc.verdict, tc.stage, tc.resource, tc.reasonHas)
		}
		if got.Verdict == Open && (len(got.Path) != 4 || got.Path[0] != "web-1" || got.Path[3] != DefaultInternetGateway) {
			t.Errorf("%s: open path %v", name, got.Path)
		}
	}
	// IPv6 is judged against ::/0.
	v6 := EvaluateGCP(netip.MustParseAddr("2600:1900::10"), 443, GCPConfig{Instance: instance,
		Routes:    []GCPRoute{{Name: "default-v6", Network: "prod", DestRange: "::/0", Priority: 1000, NextHopGateway: DefaultInternetGateway}},
		Firewalls: []GCPFirewall{{Name: "v6", Network: "prod", Direction: "INGRESS", Priority: 1000, SourceRanges: []string{"::/0"}, Allowed: []GCPProtocolPorts{{Protocol: "tcp", Ports: []string{"443"}}}}}})
	if v6.Verdict != Open || v6.Resource != "v6" {
		t.Fatalf("an IPv6 external address = %+v; want open through the ::/0 rule", v6)
	}
}
