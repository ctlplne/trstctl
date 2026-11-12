// SPDX-License-Identifier: BUSL-1.1

package observe

import (
	"bytes"
	"encoding/binary"
	"testing"
)

func tls13Server() []byte {
	return bytes.Join([][]byte{serverHello13(0x1302, 0x11ec, nil), record(0x14, []byte{1}), record(0x17, []byte("encrypted"))}, nil)
}

func mysqlGreetingPacket() []byte {
	payload := bytes.Join([][]byte{{0x0a}, []byte("8.4.3\x00"), {1, 0, 0, 0}, make([]byte, 8), {0},
		{0xff, 0xff}, {0xff}, {2, 0}, {0xff, 0xdf}, {21}, make([]byte, 10), make([]byte, 13), []byte("caching_sha2_password\x00")}, nil)
	return append([]byte{byte(len(payload)), 0, 0, 0}, payload...) // #nosec G115 -- bounded test fixture lengths (CWE-190)
}

func mysqlClientPacket(capabilities uint32, payloadLen int) []byte {
	payload := make([]byte, payloadLen)
	binary.LittleEndian.PutUint32(payload, capabilities)
	return append([]byte{byte(payloadLen), 0, 0, 1}, payload...) // #nosec G115 -- bounded test fixture lengths (CWE-190)
}

func pgMessage(code uint32) []byte {
	b := make([]byte, 8)
	binary.BigEndian.PutUint32(b, 8)
	binary.BigEndian.PutUint32(b[4:], code)
	return b
}

func pgStartup() []byte {
	body := append([]byte{0, 3, 0, 0}, []byte("user\x00alice\x00database\x00app\x00\x00")...)
	return append(binary.BigEndian.AppendUint32(nil, uint32(4+len(body))), body...) // #nosec G115 -- bounded test fixture length (CWE-190)
}

func ldapStartTLSRequest() []byte {
	oid := []byte("1.3.6.1.4.1.1466.20037")
	op := append([]byte{0x77, byte(2 + len(oid)), 0x80, byte(len(oid))}, oid...) // #nosec G115 -- bounded test fixture lengths (CWE-190)
	msg := append([]byte{0x02, 0x01, 0x01}, op...)
	return append([]byte{0x30, byte(len(msg))}, msg...) // #nosec G115 -- bounded test fixture lengths (CWE-190)
}

func ldapExtendedResponse() []byte {
	op := []byte{0x78, 0x07, 0x0a, 0x01, 0x00, 0x04, 0x00, 0x04, 0x00}
	msg := append([]byte{0x02, 0x01, 0x01}, op...)
	return append([]byte{0x30, byte(len(msg))}, msg...) // #nosec G115 -- bounded test fixture lengths (CWE-190)
}

// X1-L4: TLS reached inside another protocol is read like direct TLS and
// says how it was reached; a login sent in the clear is a plaintext finding.
func TestParseUpgradedTLSX1L4(t *testing.T) {
	hello := clientHello("db.example.test", 0x11ec, 0x001d)
	for _, tc := range []struct {
		name           string
		client, server []byte
		upgrade        string
	}{
		{"smtp", append([]byte("EHLO client.example.test\r\nSTARTTLS\r\n"), hello...),
			append([]byte("220 mail.example.test ESMTP\r\n250-mail.example.test\r\n250 STARTTLS\r\n220 2.0.0 Ready to start TLS\r\n"), tls13Server()...), UpgradeSMTP},
		{"imap tag 0001", append([]byte("0001 CAPABILITY\r\n0002 STARTTLS\r\n"), hello...),
			append([]byte("* OK IMAP4rev1 ready\r\n* CAPABILITY IMAP4rev1 STARTTLS\r\n0001 OK done\r\n0002 OK Begin TLS\r\n"), tls13Server()...), UpgradeIMAP},
		{"pop3", append([]byte("CAPA\r\nSTLS\r\n"), hello...),
			append([]byte("+OK POP3 ready\r\n+OK\r\nSTLS\r\n.\r\n+OK Begin TLS\r\n"), tls13Server()...), UpgradePOP3},
		{"ldap", append(ldapStartTLSRequest(), hello...), append(ldapExtendedResponse(), tls13Server()...), UpgradeLDAP},
		{"postgresql", append(pgMessage(pgSSLRequest), hello...), append([]byte("S"), tls13Server()...), UpgradePostgreSQL},
		{"postgresql after a refused GSSAPI request", bytes.Join([][]byte{pgMessage(pgGSSENCRequest), pgMessage(pgSSLRequest), hello}, nil),
			append([]byte("NS"), tls13Server()...), UpgradePostgreSQL},
		{"mysql", append(mysqlClientPacket(0x000fa68d|mysqlClientSSL, 32), hello...), append(mysqlGreetingPacket(), tls13Server()...), UpgradeMySQL},
	} {
		obs, ok, done := Parse(tc.client, tc.server)
		if !ok || !done || obs.Protocol != "tls" || obs.Upgrade != tc.upgrade || obs.TLSVersion != "TLSv1.3" ||
			obs.Group != "X25519MLKEM768" || obs.ServerName != "db.example.test" || obs.Plaintext {
			t.Fatalf("%s: observation = %+v ok=%v done=%v", tc.name, obs, ok, done)
		}
		// Before the server's TLS arrives the connection is undecided.
		if _, ok, done := Parse(tc.client, tc.server[:len(tc.server)-len(tls13Server())]); done && ok {
			t.Fatalf("%s: decided before the server's handshake", tc.name)
		}
	}
}

func TestParsePlaintextLoginsX1L4(t *testing.T) {
	for _, tc := range []struct {
		name           string
		client, server []byte
		kind           string
	}{
		{"postgresql startup without a request", pgStartup(), nil, "postgresql-startup"},
		{"postgresql startup after a refused SSLRequest", append(pgMessage(pgSSLRequest), pgStartup()...), []byte("N"), "postgresql-startup"},
		{"mysql login without SSL", mysqlClientPacket(0x000fa68d, 64), mysqlGreetingPacket(), "mysql-login"},
		{"mysql login of 48 bytes (0x30 first)", mysqlClientPacket(0x000fa68d, 48), mysqlGreetingPacket(), "mysql-login"},
		{"smtp auth before STARTTLS", []byte("EHLO c\r\nAUTH PLAIN AGFsaWNlAHNlY3JldA==\r\n"), []byte("220 mail ESMTP\r\n250 AUTH PLAIN\r\n"), "smtp-plaintext"},
		{"imap login", []byte("a1 LOGIN alice secret\r\n"), []byte("* OK ready\r\n"), "imap-plaintext"},
		{"pop3 user", []byte("USER alice\r\n"), []byte("+OK ready\r\n"), "pop3-plaintext"},
	} {
		obs, ok, done := Parse(tc.client, tc.server)
		if !ok || !done || !obs.Plaintext || obs.PlaintextKind != tc.kind || obs.Upgrade != "" {
			t.Fatalf("%s: observation = %+v ok=%v done=%v", tc.name, obs, ok, done)
		}
	}
	// An LDAP StartTLS still waiting for its response reads as the request
	// it is; one the server refused goes on in the clear and is reported so.
	if obs, ok, done := Parse(ldapStartTLSRequest(), nil); !ok || done || obs.Protocol != "ldap" || obs.Plaintext {
		t.Fatalf("waiting LDAP StartTLS = %+v ok=%v done=%v", obs, ok, done)
	}
	if obs, ok, done := Parse(append(ldapStartTLSRequest(), ldapStartTLSRequest()...), nil); !ok || !done || obs.Protocol != "ldap" {
		t.Fatalf("refused LDAP StartTLS = %+v ok=%v done=%v", obs, ok, done)
	}
	// A mail client before its greeting waits; anything else is not decided as mail.
	if _, ok, done := Parse([]byte("EHLO c\r\n"), nil); ok || done {
		t.Fatal("a mail client decided before the greeting")
	}
}
