// SPDX-License-Identifier: BUSL-1.1

package main

import (
	"testing"
)

// X1-L3: --observe-pcap reads a saved capture's handshakes and reports them
// as an interface's are, under interface pcap:<file name>: the reordered
// real capture's TLS 1.3 X25519MLKEM768 handshake becomes one inventory
// finding with its group, and a port the capture never used reports nothing.
func TestSavedCaptureBecomesObservationFindingsX1L3(t *testing.T) {
	const capture = "../../internal/agent/observe/testdata/x1l3-tls13-mlkem-reordered.pcap"
	items, stats, dropped, err := captureObservations(capture, []uint16{8443}, 64)
	if err != nil {
		t.Fatal(err)
	}
	if len(items) != 1 || stats.Reordered == 0 || stats.OutOfOrder != 0 || dropped != 0 {
		t.Fatalf("items %+v, stats %+v, dropped %d", items, stats, dropped)
	}
	findings := observationFindings("pcap:x1l3-tls13-mlkem-reordered.pcap", items, stats, dropped, footprint{})
	if len(findings) != 1 {
		t.Fatalf("findings = %+v", findings)
	}
	f := findings[0]
	if f.Kind != "tls_handshake" || f.Provenance != "network-observer:pcap:x1l3-tls13-mlkem-reordered.pcap" ||
		f.Metadata["group"] != "X25519MLKEM768" || f.Metadata["pq_hybrid"] != "true" || f.Metadata["tls_version"] != "TLSv1.3" ||
		f.Metadata["server_name"] != "obs.example.test" || f.Metadata["certificate_visible"] != "false" || f.RiskScore != 10 {
		t.Fatalf("finding = %+v", f)
	}
	if none, _, _, err := captureObservations(capture, []uint16{443}, 64); err != nil || len(none) != 0 {
		t.Fatalf("a port the capture never used = %+v, %v", none, err)
	}
	if _, _, _, err := captureObservations("testdata-does-not-exist.pcap", []uint16{443}, 64); err == nil {
		t.Fatal("a missing capture read without error")
	}
}
