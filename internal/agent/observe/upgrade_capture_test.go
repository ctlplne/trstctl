// SPDX-License-Identifier: BUSL-1.1

package observe

import (
	"bytes"
	"os"
	"testing"
	"time"
)

// X1-L4: real sessions captured with tcpdump in a Linux container (alpine:
// openssl 3.5.9, PostgreSQL 17.11, MariaDB 11.8.9, OpenLDAP 2.6.15 slapd,
// Python 3.14 behind a minimal STARTTLS responder for the mail protocols;
// clients psql, mariadb, ldapsearch -ZZ and openssl s_client -starttls) are
// read as the TLS each upgrade reached, with its group, and the logins sent
// without TLS as plaintext. PostgreSQL 17's default ssl_ecdh_curve
// (prime256v1) is what keeps its session off the ML-KEM hybrid.
func TestReplayedUpgradeCapturesX1L4(t *testing.T) {
	for _, tc := range []struct {
		capture        string
		port           uint16
		upgrade, group string
		plaintextKind  string
	}{
		{capture: "smtp", port: 587, upgrade: UpgradeSMTP, group: "X25519MLKEM768"},
		{capture: "imap", port: 143, upgrade: UpgradeIMAP, group: "X25519MLKEM768"},
		{capture: "pop3", port: 110, upgrade: UpgradePOP3, group: "X25519MLKEM768"},
		{capture: "ldap", port: 389, upgrade: UpgradeLDAP, group: "X25519MLKEM768"},
		{capture: "postgresql", port: 5432, upgrade: UpgradePostgreSQL, group: "secp256r1"},
		{capture: "mysql", port: 3306, upgrade: UpgradeMySQL, group: "X25519MLKEM768"},
		{capture: "postgresql-plaintext", port: 5432, plaintextKind: "postgresql-startup"},
		{capture: "mysql-plaintext", port: 3306, plaintextKind: "mysql-login"},
	} {
		data, err := os.ReadFile("testdata/x1l4-" + tc.capture + ".pcap")
		if err != nil {
			t.Fatal(err)
		}
		var events []Event
		a := NewAssembler([]uint16{tc.port}, 16, time.Minute, func(e Event) { events = append(events, e) })
		if _, err := ReplayPcap(bytes.NewReader(data), a); err != nil {
			t.Fatalf("%s: %v", tc.capture, err)
		}
		a.Flush(time.Now())
		if len(events) != 1 {
			t.Fatalf("%s: %d observations (%+v), stats %+v; want one", tc.capture, len(events), events, a.Stats())
		}
		obs := events[0].Obs
		if tc.plaintextKind != "" {
			if !obs.Plaintext || obs.PlaintextKind != tc.plaintextKind || obs.TLSVersion != "" {
				t.Fatalf("%s: observation = %+v; want plaintext %s", tc.capture, obs, tc.plaintextKind)
			}
			continue
		}
		if obs.Protocol != "tls" || obs.Upgrade != tc.upgrade || obs.TLSVersion != "TLSv1.3" || obs.Group != tc.group ||
			!obs.CertificateHidden || obs.Plaintext || events[0].Server.Port() != tc.port {
			t.Fatalf("%s: observation = %+v at %s; want TLS 1.3 %s via %s", tc.capture, obs, events[0].Server, tc.group, tc.upgrade)
		}
	}
}
