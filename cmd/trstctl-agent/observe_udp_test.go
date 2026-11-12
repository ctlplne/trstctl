// SPDX-License-Identifier: BUSL-1.1

package main

import (
	"strings"
	"testing"
)

// X1-L4 part 2: a saved capture of a QUIC handshake reports a tls_handshake
// finding for QUIC with the hybrid group it negotiated, and a DTLS 1.2
// capture one per server port with its version, suite and group.
func TestQUICAndDTLSFindingsX1L4(t *testing.T) {
	items, stats, dropped, err := captureObservations("../../internal/agent/observe/testdata/x1l4b-quic-mlkem.pcap", []uint16{8443}, 64)
	if err != nil || len(items) != 1 {
		t.Fatalf("QUIC items %+v err %v", items, err)
	}
	f := observationFindings("pcap:x1l4b-quic-mlkem.pcap", items, stats, dropped, footprint{})[0]
	if f.Kind != "tls_handshake" || !strings.HasPrefix(f.Ref, "quic ") || f.Metadata["protocol"] != "quic" ||
		f.Metadata["tls_version"] != "TLSv1.3" || f.Metadata["group"] != "X25519MLKEM768" || f.Metadata["pq_hybrid"] != "true" ||
		f.Metadata["server_name"] != "quic.x1l4.test" || f.RiskScore != 10 {
		t.Fatalf("QUIC finding = %+v", f)
	}
	items, stats, dropped, err = captureObservations("../../internal/agent/observe/testdata/x1l4b-dtls12.pcap", []uint16{4433, 4434}, 64)
	if err != nil || len(items) != 2 {
		t.Fatalf("DTLS items %+v err %v", items, err)
	}
	for _, f := range observationFindings("pcap:x1l4b-dtls12.pcap", items, stats, dropped, footprint{}) {
		if f.Kind != "tls_handshake" || !strings.HasPrefix(f.Ref, "dtls ") || f.Metadata["protocol"] != "dtls" ||
			f.Metadata["tls_version"] != "DTLSv1.2" || f.Metadata["certificate_visible"] != "true" || f.Fingerprint == "" {
			t.Fatalf("DTLS finding = %+v", f)
		}
	}
}
