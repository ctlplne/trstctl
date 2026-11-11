// SPDX-License-Identifier: BUSL-1.1

package gcpnetpath_test

import (
	"context"
	"net/netip"
	"testing"

	"trstctl.com/trstctl/internal/discovery/netpath"
	"trstctl.com/trstctl/internal/discovery/netpath/gcpnetpath"
	"trstctl.com/trstctl/internal/discovery/netpath/gcpnetpath/computetest"
)

const testToken = "stand-in-compute-token" // #nosec G101 -- a stand-in fixture value, not a credential (CWE-798)

// A167-L1: the reader finds the instance holding an external address across
// paginated aggregated lists, reads the network's firewalls and routes across
// their pages, and the verdict names the rule that decided; an address no
// instance holds is not this project's; a refused token is an error, never a
// verdict.
func TestReaderJudgesFromComputeEngineA167L1(t *testing.T) {
	srv := computetest.New("prod-project", testToken)
	defer srv.Close()
	srv.Add([]computetest.Instance{
		{Name: "db-1", Zone: "us-central1-a", Network: "prod", NatIP: "34.120.0.20", Tags: []string{"db"}},
		{Name: "web-1", Zone: "us-central1-b", Network: "prod", NatIP: "34.120.0.10", Tags: []string{"https-server"}},
	}, []computetest.Firewall{
		{Name: "allow-internal", Network: "prod", Direction: "INGRESS", Priority: 65534, SourceRanges: []string{"10.128.0.0/9"}, Allowed: []map[string]any{{"IPProtocol": "all"}}},
		{Name: "allow-https", Network: "prod", Direction: "INGRESS", Priority: 1000, SourceRanges: []string{"0.0.0.0/0"}, TargetTags: []string{"https-server"},
			Allowed: []map[string]any{{"IPProtocol": "tcp", "ports": []string{"443"}}}},
	}, []computetest.Route{
		{Name: "default-route-local", Network: "prod", DestRange: "10.128.0.0/20", Priority: 0},
		{Name: "default-route-internet", Network: "prod", DestRange: "0.0.0.0/0", Priority: 1000, NextHopGateway: netpath.DefaultInternetGateway},
	})
	reader, err := gcpnetpath.New(gcpnetpath.Config{Project: "prod-project", Endpoint: srv.URL(), Token: []byte(testToken), HTTPClient: srv.Client()})
	if err != nil {
		t.Fatal(err)
	}
	defer reader.Close()
	ctx := context.Background()
	got, found, err := reader.Judge(ctx, netip.MustParseAddr("34.120.0.10"), 443)
	if err != nil || !found || got.Verdict != netpath.Open || got.Resource != "allow-https" ||
		len(got.Path) != 4 || got.Path[0] != "web-1" || got.Path[2] != "default-route-internet" {
		t.Fatalf("web-1:443 = %+v found=%v %v; want open through allow-https and the default route", got, found, err)
	}
	if got, _, _ := reader.Judge(ctx, netip.MustParseAddr("34.120.0.20"), 443); got.Verdict != netpath.Blocked || got.BlockedBy != netpath.StageFirewall {
		t.Fatalf("db-1:443 = %+v; want blocked at the firewall (its tag is not https-server)", got)
	}
	if _, found, err := reader.Judge(ctx, netip.MustParseAddr("198.51.100.7"), 443); err != nil || found {
		t.Fatalf("an address no instance holds: found=%v %v; want not this project's", found, err)
	}
	refused, err := gcpnetpath.New(gcpnetpath.Config{Project: "prod-project", Endpoint: srv.URL(), Token: []byte("not-the-token"), HTTPClient: srv.Client()})
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := refused.Judge(ctx, netip.MustParseAddr("34.120.0.10"), 443); err == nil {
		t.Fatal("a refused token produced a verdict")
	}
	if _, err := gcpnetpath.New(gcpnetpath.Config{Project: "a/b", Token: []byte(testToken)}); err == nil {
		t.Fatal("a project with a path separator was accepted")
	}
}
