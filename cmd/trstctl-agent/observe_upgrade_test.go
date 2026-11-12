// SPDX-License-Identifier: BUSL-1.1

package main

import "testing"

// X1-L4: a TLS session reached by an upgrade reports how it was reached, and
// a database login sent in the clear is a plaintext_protocol finding.
func TestUpgradedSessionFindingsX1L4(t *testing.T) {
	items, stats, dropped, err := captureObservations("../../internal/agent/observe/testdata/x1l4-postgresql.pcap", []uint16{5432}, 64)
	if err != nil || len(items) != 1 {
		t.Fatalf("items %+v err %v", items, err)
	}
	f := observationFindings("pcap:x1l4-postgresql.pcap", items, stats, dropped, footprint{})[0]
	if f.Kind != "tls_handshake" || f.Metadata["upgrade"] != "postgresql-ssl" || f.Metadata["group"] != "secp256r1" ||
		f.Metadata["pq_hybrid"] != "false" || f.RiskScore != 30 {
		t.Fatalf("PostgreSQL TLS finding = %+v", f)
	}
	items, stats, dropped, err = captureObservations("../../internal/agent/observe/testdata/x1l4-mysql-plaintext.pcap", []uint16{3306}, 64)
	if err != nil || len(items) != 1 {
		t.Fatalf("items %+v err %v", items, err)
	}
	f = observationFindings("pcap:x1l4-mysql-plaintext.pcap", items, stats, dropped, footprint{})[0]
	if f.Kind != "plaintext_protocol" || f.Metadata["plaintext_kind"] != "mysql-login" || f.RiskScore != 90 {
		t.Fatalf("MySQL plaintext finding = %+v", f)
	}
}
