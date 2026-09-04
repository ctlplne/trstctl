// SPDX-License-Identifier: MPL-2.0

package api

import (
	"reflect"
	"sort"
	"testing"

	"trstctl.com/trstctl/internal/connector"
)

// AUD-33: the served catalog must expose E1 status for the source plan's full
// denominator. Checking only network-relay rows would reproduce the defect: it
// would prove a narrower implementation-owned list while hiding accepted
// families that were never migrated.
func TestConnectorCatalogPublishesTheAcceptedThirteenFamilyParityProgram(t *testing.T) {
	want := []string{
		"a10", "aws-acm", "azure-keyvault", "cisco", "envoy", "f5", "fortigate",
		"gcp-certificate-manager", "kemp", "mysql", "netscaler", "paloalto", "postgresql",
	}
	items := (&API{}).connectorCatalogWithSandbox()
	got := make([]string, 0, len(want))
	counts := map[string]int{}
	for _, item := range items {
		if item.RelayParity != nil {
			got = append(got, item.Name)
			counts[item.RelayParity.Disposition]++
		}
	}
	sort.Strings(got)
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("catalog parity families = %v, want the accepted E1 denominator %v", got, want)
	}
	if counts["migrated"] != 4 || counts["architecture_exception"] != 3 || counts["unimplemented"] != 6 || len(counts) != 3 {
		t.Fatalf("catalog parity dispositions = %v, want migrated=4 architecture_exception=3 unimplemented=6", counts)
	}
}

// A host connector is absent from the control-plane registry by design: its
// privileged work belongs on the target host. That absence must not make the
// operator catalog claim the work runs in the control plane.
func TestConnectorCatalogPublishesShippedVantageWithoutControlPlaneRegistration(t *testing.T) {
	items := (&API{connectorRegistry: connector.NewRegistry()}).connectorCatalogWithSandbox()
	want := map[string]string{
		"apache":  string(connector.VantageHostAgent),
		"f5":      string(connector.VantageNetworkRelay),
		"aws-acm": string(connector.VantageControlPlane),
	}
	for _, item := range items {
		vantage, ok := want[item.Name]
		if !ok {
			continue
		}
		if item.TargetVantage != vantage {
			t.Errorf("catalog %s target_vantage = %q, want %q", item.Name, item.TargetVantage, vantage)
		}
		delete(want, item.Name)
	}
	if len(want) != 0 {
		t.Fatalf("catalog omitted connector vantage assertions: %v", want)
	}
}
