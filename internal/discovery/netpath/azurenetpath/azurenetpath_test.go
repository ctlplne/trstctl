// SPDX-License-Identifier: BUSL-1.1

package azurenetpath_test

import (
	"context"
	"net/netip"
	"strings"
	"testing"

	"trstctl.com/trstctl/internal/discovery/netpath"
	"trstctl.com/trstctl/internal/discovery/netpath/azurenetpath"
	"trstctl.com/trstctl/internal/discovery/netpath/azurenetpath/networktest"
)

const (
	testSubscription = "00000000-0000-0000-0000-00000000a167"
	testToken        = "stand-in-arm-token" // #nosec G101 -- a stand-in fixture value, not a credential (CWE-798)
)

// A167-L1, part 2: the reader finds the public IP across the subscription's
// paginated list, follows it to the interface, the subnet, both groups and
// the route table, and the verdict names what decided; an address no public
// IP holds is not this subscription's; a nextLink that leaves the endpoint
// and a refused token are errors, never verdicts.
func TestReaderJudgesFromResourceManagerA167L1(t *testing.T) {
	srv := networktest.New(testSubscription, testToken)
	defer srv.Close()
	srv.AddPublicIPs(
		networktest.PublicIP{Name: "pip-lb", Address: "20.30.40.49", LoadBalancer: "lb-web"},
		networktest.PublicIP{Name: "pip-web", Address: "20.30.40.50", Interface: "nic-web"},
		networktest.PublicIP{Name: "pip-db", Address: "20.30.40.51", Interface: "nic-db"},
	)
	srv.AddInterfaces(
		networktest.Interface{Name: "nic-web", PrivateIP: "10.0.1.4", VNet: "vnet-prod", Subnet: "web", NSG: "nsg-web"},
		networktest.Interface{Name: "nic-db", PrivateIP: "10.0.2.4", VNet: "vnet-prod", Subnet: "data"},
	)
	srv.AddSubnets(
		networktest.Subnet{VNet: "vnet-prod", Name: "web", RouteTable: "rt-web"},
		networktest.Subnet{VNet: "vnet-prod", Name: "data", NSG: "nsg-data"},
	)
	srv.AddNSGs(
		networktest.NSG{Name: "nsg-web", Rules: []networktest.Rule{{Name: "AllowHTTPS", Priority: 100, Direction: "Inbound", Access: "Allow",
			Protocol: "Tcp", SourceAddressPrefix: "Internet", DestinationAddressPrefix: "*", DestinationPortRange: "443"}}},
		networktest.NSG{Name: "nsg-data"},
	)
	srv.AddRouteTables(networktest.RouteTable{Name: "rt-web", Routes: []networktest.Route{{Name: "internet", AddressPrefix: "0.0.0.0/0", NextHopType: "Internet"}}})
	reader, err := azurenetpath.New(azurenetpath.Config{SubscriptionID: testSubscription, Endpoint: srv.URL(), Token: []byte(testToken), HTTPClient: srv.Client()})
	if err != nil {
		t.Fatal(err)
	}
	defer reader.Close()
	ctx := context.Background()
	got, found, err := reader.Judge(ctx, netip.MustParseAddr("20.30.40.50"), 443)
	if err != nil || !found || got.Verdict != netpath.Open || got.Resource != "nsg-web" || strings.Join(got.Path, ">") != "nic-web>nsg-web>rt-web>pip-web" {
		t.Fatalf("pip-web:443 = %+v found=%v %v; want open through nsg-web", got, found, err)
	}
	if got, _, err := reader.Judge(ctx, netip.MustParseAddr("20.30.40.51"), 443); err != nil || got.Verdict != netpath.Blocked ||
		got.BlockedBy != netpath.StageNetworkSecurityGroup || got.Resource != "nsg-data" || got.Rule != "DenyAllInBound (priority 65500)" {
		t.Fatalf("pip-db:443 = %+v %v; want blocked by the subnet group's default deny", got, err)
	}
	if got, found, err := reader.Judge(ctx, netip.MustParseAddr("20.30.40.49"), 443); err != nil || !found || got.Verdict != netpath.Unknown ||
		!strings.Contains(got.Reason, "loadBalancers lb-web") {
		t.Fatalf("pip-lb:443 = %+v found=%v %v; want unknown, attached to the load balancer", got, found, err)
	}
	if _, found, err := reader.Judge(ctx, netip.MustParseAddr("198.51.100.7"), 443); err != nil || found {
		t.Fatalf("an address no public IP holds: found=%v %v; want not this subscription's", found, err)
	}
	refused, err := azurenetpath.New(azurenetpath.Config{SubscriptionID: testSubscription, Endpoint: srv.URL(), Token: []byte("not-the-token"), HTTPClient: srv.Client()})
	if err != nil {
		t.Fatal(err)
	}
	defer refused.Close()
	if _, _, err := refused.Judge(ctx, netip.MustParseAddr("20.30.40.50"), 443); err == nil {
		t.Fatal("a refused token produced a verdict")
	}
	srv.SetForeignNextLink("https://elsewhere.example")
	if _, _, err := reader.Judge(ctx, netip.MustParseAddr("20.30.40.51"), 443); err == nil || !strings.Contains(err.Error(), "nextLink") {
		t.Fatalf("a nextLink to another host = %v; want refused", err)
	}
	for _, bad := range []string{"", "a/b", "..", "sub?x=1"} {
		if _, err := azurenetpath.New(azurenetpath.Config{SubscriptionID: bad, Token: []byte(testToken)}); err == nil {
			t.Fatalf("subscription %q was accepted", bad)
		}
	}
}
