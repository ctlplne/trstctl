// SPDX-License-Identifier: BUSL-1.1

package netpath

import (
	"net/netip"
	"strings"
	"testing"
)

// A167-L1, part 2: Azure's answer to "can the internet reach this public IP
// and port", written from Azure's documented semantics: groups are processed
// after the public IP is translated to the interface's private address, the
// subnet's group and then the interface's must each admit the traffic with
// their first matching rule by priority (Azure's default rules last), a
// Standard address no group opens stays closed, a Basic one with no group is
// open, and a subnet route that sends the internet-wide range anywhere but
// the Internet breaks the reply. Only a rule naming the internet at large
// decides.
func TestEvaluateAzureFollowsNetworkSecurityGroupSemanticsA167L1(t *testing.T) {
	ip := netip.MustParseAddr("20.30.40.50")
	private := netip.MustParseAddr("10.0.1.4")
	allowHTTPS := AzureSecurityRule{Name: "AllowHTTPS", Priority: 100, Direction: "Inbound", Access: "Allow", Protocol: "Tcp",
		SourcePrefixes: []string{"Internet"}, DestinationPrefixes: []string{"*"}, DestinationPorts: []string{"443"}}
	nsg := func(name string, rules ...AzureSecurityRule) *AzureNSG {
		return &AzureNSG{ID: "/x/" + name, Name: name, Rules: rules}
	}
	base := func() AzureConfig {
		return AzureConfig{PublicIP: "pip-web", PublicIPSKU: "Standard", Interface: "nic-web", PrivateIP: private, Subnet: "web",
			InterfaceNSG: nsg("nsg-web", allowHTTPS)}
	}
	with := func(edit func(*AzureConfig)) AzureConfig {
		cfg := base()
		edit(&cfg)
		return cfg
	}
	cases := map[string]struct {
		cfg       AzureConfig
		port      int
		verdict   Verdict
		stage     Stage
		resource  string
		reasonHas string
	}{
		"open through the interface's group":                      {base(), 443, Open, "", "nsg-web", "AllowHTTPS"},
		"a port the group does not admit falls to DenyAllInBound": {base(), 22, Blocked, StageNetworkSecurityGroup, "nsg-web", "DenyAllInBound"},
		"a port range admits": {with(func(c *AzureConfig) {
			c.InterfaceNSG = nsg("nsg-web", AzureSecurityRule{Name: "Range", Priority: 110, Direction: "Inbound", Access: "Allow", Protocol: "*",
				SourcePrefixes: []string{"*"}, DestinationPrefixes: []string{"10.0.1.0/24"}, DestinationPorts: []string{"8000-9000"}})
		}), 8443, Open, "", "nsg-web", "Range"},
		"a higher-priority deny wins": {with(func(c *AzureConfig) {
			c.InterfaceNSG.Rules = append(c.InterfaceNSG.Rules, AzureSecurityRule{Name: "DenyAll", Priority: 90, Direction: "Inbound", Access: "Deny",
				Protocol: "*", SourcePrefixes: []string{"*"}, DestinationPrefixes: []string{"*"}, DestinationPorts: []string{"*"}})
		}), 443, Blocked, StageNetworkSecurityGroup, "nsg-web", "DenyAll"},
		"the subnet's group decides first": {with(func(c *AzureConfig) {
			c.SubnetNSG = nsg("nsg-subnet")
		}), 443, Blocked, StageNetworkSecurityGroup, "nsg-subnet", "on subnet web"},
		"the subnet's deny is reported before the interface's": {with(func(c *AzureConfig) {
			c.SubnetNSG, c.InterfaceNSG = nsg("nsg-subnet"), nsg("nsg-web")
		}), 443, Blocked, StageNetworkSecurityGroup, "nsg-subnet", "on subnet web"},
		"both groups admit": {with(func(c *AzureConfig) {
			c.SubnetNSG = nsg("nsg-subnet", allowHTTPS)
		}), 443, Open, "", "nsg-web", ""},
		"a partner range does not decide": {with(func(c *AzureConfig) {
			c.InterfaceNSG = nsg("nsg-web", AzureSecurityRule{Name: "Partner", Priority: 100, Direction: "Inbound", Access: "Allow", Protocol: "Tcp",
				SourcePrefixes: []string{"203.0.113.0/24"}, DestinationPrefixes: []string{"*"}, DestinationPorts: []string{"443"}})
		}), 443, Blocked, StageNetworkSecurityGroup, "nsg-web", "DenyAllInBound"},
		"the virtual network tag is not the internet": {with(func(c *AzureConfig) {
			c.InterfaceNSG = nsg("nsg-web", AzureSecurityRule{Name: "VNetOnly", Priority: 100, Direction: "Inbound", Access: "Allow", Protocol: "Tcp",
				SourcePrefixes: []string{"VirtualNetwork"}, DestinationPrefixes: []string{"*"}, DestinationPorts: []string{"443"}})
		}), 443, Blocked, StageNetworkSecurityGroup, "nsg-web", ""},
		"a rule for another destination does not apply": {with(func(c *AzureConfig) {
			c.InterfaceNSG = nsg("nsg-web", AzureSecurityRule{Name: "OtherHost", Priority: 100, Direction: "Inbound", Access: "Allow", Protocol: "Tcp",
				SourcePrefixes: []string{"*"}, DestinationPrefixes: []string{"10.0.2.0/24"}, DestinationPorts: []string{"443"}})
		}), 443, Blocked, StageNetworkSecurityGroup, "nsg-web", ""},
		"an application security group target applies to its members": {with(func(c *AzureConfig) {
			c.InterfaceASGs = []string{"/x/asg-web"}
			c.InterfaceNSG = nsg("nsg-web", AzureSecurityRule{Name: "ToWebTier", Priority: 100, Direction: "Inbound", Access: "Allow", Protocol: "Tcp",
				SourcePrefixes: []string{"Internet"}, DestinationASGs: []string{"/x/asg-web"}, DestinationPorts: []string{"443"}})
		}), 443, Open, "", "nsg-web", "ToWebTier"},
		"an outbound or UDP rule does not count": {with(func(c *AzureConfig) {
			c.InterfaceNSG = nsg("nsg-web",
				AzureSecurityRule{Name: "Out", Priority: 100, Direction: "Outbound", Access: "Allow", Protocol: "*", SourcePrefixes: []string{"*"}, DestinationPrefixes: []string{"*"}, DestinationPorts: []string{"*"}},
				AzureSecurityRule{Name: "Udp", Priority: 110, Direction: "Inbound", Access: "Allow", Protocol: "Udp", SourcePrefixes: []string{"*"}, DestinationPrefixes: []string{"*"}, DestinationPorts: []string{"443"}})
		}), 443, Blocked, StageNetworkSecurityGroup, "nsg-web", ""},
		"a Standard address with no group is closed": {with(func(c *AzureConfig) { c.InterfaceNSG = nil }), 443, Blocked, StagePublicIP, "pip-web", "Standard"},
		"a Basic address with no group is open": {with(func(c *AzureConfig) {
			c.InterfaceNSG, c.PublicIPSKU = nil, "Basic"
		}), 443, Open, "", "pip-web", "Basic"},
		"a route to an appliance breaks the reply": {with(func(c *AzureConfig) {
			c.RouteTable = &AzureRouteTable{ID: "/x/rt-forced", Name: "rt-forced", Routes: []AzureRoute{{Name: "default-to-firewall", AddressPrefix: "0.0.0.0/0", NextHopType: "VirtualAppliance"}}}
		}), 443, Blocked, StageRoute, "rt-forced", "default-to-firewall"},
		"a route to the internet keeps the reply": {with(func(c *AzureConfig) {
			c.RouteTable = &AzureRouteTable{ID: "/x/rt-web", Name: "rt-web", Routes: []AzureRoute{{Name: "internet", AddressPrefix: "0.0.0.0/0", NextHopType: "Internet"},
				{Name: "partner", AddressPrefix: "198.51.100.0/24", NextHopType: "VirtualNetworkGateway"}}}
		}), 443, Open, "", "nsg-web", ""},
		"a load balancer frontend is not read":                {AzureConfig{PublicIP: "pip-lb", PublicIPSKU: "Standard", Attachment: "loadBalancers lb-web"}, 443, Unknown, "", "pip-lb", "loadBalancers lb-web"},
		"a NAT gateway address carries no inbound connection": {AzureConfig{PublicIP: "pip-nat", PublicIPSKU: "Standard", NATGateway: "nat-egress"}, 443, Blocked, StagePublicIP, "pip-nat", "outbound connections only"},
		"an unassociated address answers nothing":             {AzureConfig{PublicIP: "pip-spare", PublicIPSKU: "Standard"}, 443, Blocked, StagePublicIP, "pip-spare", "not associated"},
	}
	for name, tc := range cases {
		got := EvaluateAzure(ip, tc.port, tc.cfg)
		if got.Verdict != tc.verdict || got.BlockedBy != tc.stage || got.Resource != tc.resource || !strings.Contains(got.Reason, tc.reasonHas) {
			t.Errorf("%s: %+v; want %s %s %s (%q)", name, got, tc.verdict, tc.stage, tc.resource, tc.reasonHas)
		}
	}
	open := EvaluateAzure(ip, 443, with(func(c *AzureConfig) {
		c.SubnetNSG = nsg("nsg-subnet", allowHTTPS)
		c.RouteTable = &AzureRouteTable{Name: "rt-web"}
	}))
	if strings.Join(open.Path, ">") != "nic-web>nsg-web>nsg-subnet>rt-web>pip-web" || open.Rule != "AllowHTTPS (priority 100)" {
		t.Fatalf("open path = %v rule %q", open.Path, open.Rule)
	}
	// IPv6 is judged against ::/0, and a group whose own list omits the
	// default rules still ends in DenyAllInBound.
	v6 := netip.MustParseAddr("2603:1030::50")
	if got := EvaluateAzure(v6, 443, with(func(c *AzureConfig) {
		c.InterfaceNSG = nsg("nsg-web", AzureSecurityRule{Name: "V6", Priority: 100, Direction: "Inbound", Access: "Allow", Protocol: "Tcp",
			SourcePrefixes: []string{"::/0"}, DestinationPrefixes: []string{"*"}, DestinationPorts: []string{"443"}})
	})); got.Verdict != Open || got.Resource != "nsg-web" {
		t.Fatalf("an IPv6 address = %+v; want open through the ::/0 rule", got)
	}
	if got := EvaluateAzure(v6, 443, with(func(c *AzureConfig) {
		c.InterfaceNSG = nsg("nsg-web", AzureSecurityRule{Name: "V4Only", Priority: 100, Direction: "Inbound", Access: "Allow", Protocol: "Tcp",
			SourcePrefixes: []string{"0.0.0.0/0"}, DestinationPrefixes: []string{"*"}, DestinationPorts: []string{"443"}})
	})); got.Verdict != Blocked || got.Rule != "DenyAllInBound (priority 65500)" {
		t.Fatalf("an IPv6 address under an IPv4-only rule = %+v; want the default deny", got)
	}
}
