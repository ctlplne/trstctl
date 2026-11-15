// SPDX-License-Identifier: BUSL-1.1

package main

import (
	"strings"
	"testing"
)

// X1-L3R: --observe-pcap reads pcapng (dumpcap's real TLS 1.2 capture: one
// finding with its group and its certificate visible) and reads past a gap
// the capture never filled (the same capture missing one segment: the group,
// no certificate, observer_resynced 1), with the hold --observe-hold-segments
// sets; a hold outside 1 to 1024 is refused before the capture is read.
func TestSavedPcapNGAndResynchronizationReachTheFindingsX1L3R(t *testing.T) {
	const dir = "../../internal/agent/observe/testdata/"
	items, stats, dropped, err := captureObservations(dir+"x1l3r-tls12-dumpcap.pcapng", []uint16{8443}, 64)
	if err != nil || len(items) != 1 || stats.Resynced != 0 {
		t.Fatalf("pcapng: items %+v, stats %+v, %v", items, stats, err)
	}
	f := observationFindings("pcap:x1l3r-tls12-dumpcap.pcapng", items, stats, dropped, footprint{})
	if len(f) != 1 || f[0].Kind != "tls_handshake" || f[0].Metadata["tls_version"] != "TLSv1.2" || f[0].Metadata["group"] != "x25519" ||
		f[0].Metadata["certificate_visible"] != "true" || f[0].Metadata["observer_resynced"] != "0" {
		t.Fatalf("pcapng finding = %+v", f)
	}

	const lossy = dir + "x1l3r-tls12-lost-segment.pcap"
	items, stats, dropped, err = captureObservations(lossy, []uint16{8443}, 64)
	if err != nil || len(items) != 1 || stats.Resynced != 1 || stats.OutOfOrder != 0 {
		t.Fatalf("lost segment: items %+v, stats %+v, %v", items, stats, err)
	}
	f = observationFindings("pcap:x1l3r-tls12-lost-segment.pcap", items, stats, dropped, footprint{})
	if len(f) != 1 || f[0].Metadata["group"] != "x25519" || f[0].Metadata["certificate_visible"] != "false" ||
		f[0].Metadata["observer_resynced"] != "1" || f[0].Metadata["observer_drops"] != "0" {
		t.Fatalf("lost-segment finding = %+v", f)
	}

	saved := *observeHoldSegments
	t.Cleanup(func() { *observeHoldSegments = saved })
	for _, bad := range []int{0, 1025} {
		*observeHoldSegments = bad
		if _, _, _, err := captureObservations(lossy, []uint16{8443}, 64); err == nil || !strings.Contains(err.Error(), "the hold is 1 to 1024 segments") {
			t.Fatalf("a hold of %d: %v", bad, err)
		}
	}
	*observeHoldSegments = 1024
	if items, _, _, err := captureObservations(lossy, []uint16{8443}, 64); err != nil || len(items) != 1 {
		t.Fatalf("a hold of 1024: items %+v, %v", items, err)
	}
}
