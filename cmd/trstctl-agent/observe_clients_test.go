// SPDX-License-Identifier: BUSL-1.1

package main

import (
	"net/netip"
	"testing"

	"trstctl.com/trstctl/internal/agent/observe"
)

// X1-L7: the saved capture whose server ends the connection first reports
// one connection from one client, counted exactly; an item past 256 distinct
// clients says its count is an estimate.
func TestObservationFindingsCountConnectionsOnceAndSayWhenClientsAreEstimatedX1L7(t *testing.T) {
	items, stats, dropped, err := captureObservations("../../internal/agent/observe/testdata/x1l3-tls13-mlkem.pcap", []uint16{8443}, 64)
	if err != nil {
		t.Fatal(err)
	}
	if len(items) != 1 || stats.Connections != 1 || stats.Unrecognized != 0 {
		t.Fatalf("items %+v, stats %+v", items, stats)
	}
	f := observationFindings("pcap:x1l3-tls13-mlkem.pcap", items, stats, dropped, footprint{})[0]
	if f.Metadata["connections"] != "1" || f.Metadata["clients"] != "1" || f.Metadata["clients_estimated"] != "false" {
		t.Fatalf("finding metadata = %v", f.Metadata)
	}
	busy := observe.Item{Kind: "tls_handshake", Server: netip.MustParseAddrPort("198.51.100.1:443"), Connections: 20_000,
		Clients: 10_012, ClientsEstimated: true, Obs: observe.Observation{Protocol: "tls", TLSVersion: "TLSv1.3"}}
	f = observationFindings("eth0", []observe.Item{busy}, observe.Stats{}, 0, footprint{})[0]
	if f.Metadata["clients"] != "10012" || f.Metadata["clients_estimated"] != "true" {
		t.Fatalf("busy finding metadata = %v", f.Metadata)
	}
}
