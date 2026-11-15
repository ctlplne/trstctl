// SPDX-License-Identifier: BUSL-1.1

package main

import "testing"

// X1-L4R: --observe-pcap reads the real QUIC Retry flow (nginx 1.30.6 with
// quic_retry on) and the real NAT rebinding in the middle of a QUIC handshake
// (Caddy 2.11.4) as one tls_handshake finding each, the second saying the
// observer followed one path by the connection's IDs.
func TestQUICRetryAndPathChangeFindingsX1L4R(t *testing.T) {
	const dir = "../../internal/agent/observe/testdata/"
	for _, tc := range []struct {
		file, suite, followed string
		port                  uint16
	}{
		{"x1l4r-quic-retry.pcap", "TLS_AES_256_GCM_SHA384", "0", 8444},
		{"x1l4r-quic-rebinding.pcap", "TLS_AES_128_GCM_SHA256", "1", 8443},
	} {
		items, stats, dropped, err := captureObservations(dir+tc.file, []uint16{tc.port}, 64)
		if err != nil || len(items) != 1 {
			t.Fatalf("%s: items %+v, stats %+v, %v", tc.file, items, stats, err)
		}
		f := observationFindings("pcap:"+tc.file, items, stats, dropped, footprint{})
		if len(f) != 1 || f[0].Kind != "tls_handshake" || f[0].Metadata["protocol"] != "quic" || f[0].Metadata["tls_version"] != "TLSv1.3" ||
			f[0].Metadata["cipher_suite"] != tc.suite || f[0].Metadata["group"] != "X25519MLKEM768" || f[0].Metadata["server_name"] != "quic.x1l4r.test" ||
			f[0].Metadata["observer_paths_followed"] != tc.followed || f[0].Metadata["pq_hybrid"] != "true" {
			t.Fatalf("%s: findings %+v", tc.file, f)
		}
	}
}
