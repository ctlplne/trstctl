// SPDX-License-Identifier: BUSL-1.1

package observe

import (
	"bytes"
	"os"
	"slices"
	"testing"
	"time"
)

// replayUDPCapture replays a capture through an assembler watching ports
// and returns what it observed.
func replayUDPCapture(t *testing.T, path string, ports ...uint16) ([]Event, Stats) {
	t.Helper()
	f, err := os.Open(path) // #nosec G304 -- the test reads its own fixture (CWE-22)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = f.Close() }()
	var events []Event
	a := NewAssembler(ports, 64, time.Minute, func(e Event) { events = append(events, e) })
	if _, err := ReplayPcap(f, a); err != nil {
		t.Fatal(err)
	}
	a.Flush(time.Now())
	return events, a.Stats()
}

// X1-L4 part 2: real captures (drafts/x1l4b/capture.sh: alpine nginx
// 1.30.6 with HTTP/3 and OpenSSL 3.5.9's s_client -quic; OpenSSL DTLS 1.2
// with a cookie exchange) are read. The QUIC handshake's ClientHello spans
// two Initial packets (OpenSSL's ML-KEM hybrid key share), and the observer
// reads the negotiated group and suite from the server's Initial packet.
func TestReplayedQUICAndDTLSCapturesX1L4(t *testing.T) {
	events, stats := replayUDPCapture(t, "testdata/x1l4b-quic-mlkem.pcap", 8443)
	if len(events) != 1 || stats.Datagrams == 0 {
		t.Fatalf("QUIC capture: %d events, stats %+v", len(events), stats)
	}
	q := events[0].Obs
	if q.Protocol != "quic" || q.TLSVersion != "TLSv1.3" || q.CipherSuite != "TLS_AES_256_GCM_SHA384" || q.Group != "X25519MLKEM768" ||
		q.ServerName != "quic.x1l4.test" || !slices.Contains(q.OfferedGroups, "X25519MLKEM768") || !q.CertificateHidden || !q.PQHybrid() ||
		events[0].Server.Port() != 8443 {
		t.Fatalf("QUIC observation = %+v at %s", q, events[0].Server)
	}

	events, _ = replayUDPCapture(t, "testdata/x1l4b-dtls12.pcap", 4433, 4434)
	if len(events) != 2 {
		t.Fatalf("DTLS capture: %d events; want the handshake on 4433 and the one on 4434", len(events))
	}
	for _, e := range events {
		d := e.Obs
		if d.Protocol != "dtls" || d.TLSVersion != "DTLSv1.2" || d.CipherSuite != "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384" ||
			d.ServerName != "dtls.x1l4.test" || d.Group == "" || len(d.CertificateDER) == 0 {
			t.Fatalf("DTLS observation at %s = %+v", e.Server, d)
		}
		// The server's certificate (CN=quic.x1l4.test), read in the clear;
		// the agent parses it through the crypto boundary.
		if !bytes.Contains(d.CertificateDER, []byte("quic.x1l4.test")) || d.CertificateDER[0] != 0x30 {
			t.Fatalf("DTLS certificate (%d bytes) is not the server's", len(d.CertificateDER))
		}
	}
}
