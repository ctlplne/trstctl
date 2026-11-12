// SPDX-License-Identifier: BUSL-1.1

package observe

import (
	"bytes"
	"encoding/binary"
	"strings"
)

// TLS negotiated inside another protocol (X1-L4). Mail and directory
// protocols upgrade a plaintext session with STARTTLS (SMTP, IMAP), STLS
// (POP3) or the LDAP StartTLS extended operation; PostgreSQL asks with an
// SSLRequest and MySQL with an SSL request packet. The observer recognizes
// each preamble, reads the TLS handshake that follows exactly as it reads a
// direct one, and says how it was reached (Upgrade). A PostgreSQL startup or
// a MySQL login, or a mail login before any upgrade, sent in the clear is a
// plaintext finding instead. The preamble's bytes are read and dropped like
// every other byte.

// Upgrade names.
const (
	UpgradeSMTP       = "smtp-starttls"
	UpgradeIMAP       = "imap-starttls"
	UpgradePOP3       = "pop3-stls"
	UpgradeLDAP       = "ldap-starttls"
	UpgradePostgreSQL = "postgresql-ssl"
	UpgradeMySQL      = "mysql-ssl"
)

// maxPreambleLines bounds how many client lines a mail session may send
// before the observer stops looking for its upgrade.
const maxPreambleLines = 32

// isTLSRecord reports whether b starts a TLS handshake record.
func isTLSRecord(b []byte) bool {
	return len(b) >= 3 && b[0] == 0x16 && b[1] == 0x03 && b[2] <= 0x04
}

// upgradedTLS reads the TLS that starts at client[cOff:] and server[sOff:]
// (sOff < 0: the server's TLS has not been seen yet).
func upgradedTLS(client, server []byte, cOff, sOff int, upgrade string) (Observation, bool, bool) {
	clientTLS := client[cOff:]
	if len(clientTLS) < 3 {
		return Observation{}, false, false
	}
	if !isTLSRecord(clientTLS) {
		return Observation{}, false, true
	}
	var serverTLS []byte
	if sOff >= 0 && sOff <= len(server) {
		serverTLS = server[sOff:]
	}
	obs, ok, done := parseTLS(clientTLS, serverTLS)
	obs.Upgrade = upgrade
	return obs, ok, done
}

// ---------------------------------------------------------------- mail

type mailProtocol struct {
	name, upgrade string
	greetings     []string
	// upgradeCommand and plaintextCommand classify one client line.
	upgradeCommand   func(fields []string) bool
	plaintextCommand func(fields []string) bool
}

var mailProtocols = []mailProtocol{
	{name: "smtp", upgrade: UpgradeSMTP, greetings: []string{"220 ", "220-"},
		upgradeCommand: func(f []string) bool { return len(f) == 1 && strings.EqualFold(f[0], "STARTTLS") },
		plaintextCommand: func(f []string) bool {
			return len(f) > 0 && (strings.EqualFold(f[0], "AUTH") || strings.EqualFold(f[0], "MAIL") || strings.EqualFold(f[0], "DATA"))
		}},
	{name: "imap", upgrade: UpgradeIMAP, greetings: []string{"* OK", "* PREAUTH"},
		upgradeCommand: func(f []string) bool { return len(f) == 2 && strings.EqualFold(f[1], "STARTTLS") },
		plaintextCommand: func(f []string) bool {
			return len(f) > 1 && (strings.EqualFold(f[1], "LOGIN") || strings.EqualFold(f[1], "AUTHENTICATE"))
		}},
	{name: "pop3", upgrade: UpgradePOP3, greetings: []string{"+OK"},
		upgradeCommand: func(f []string) bool { return len(f) == 1 && strings.EqualFold(f[0], "STLS") },
		plaintextCommand: func(f []string) bool {
			return len(f) > 0 && (strings.EqualFold(f[0], "USER") || strings.EqualFold(f[0], "PASS") ||
				strings.EqualFold(f[0], "APOP") || strings.EqualFold(f[0], "AUTH"))
		}},
}

// mailGreeting finds the mail protocol whose greeting the server sent.
func mailGreeting(server []byte) (mailProtocol, bool) {
	for _, p := range mailProtocols {
		for _, g := range p.greetings {
			if bytes.HasPrefix(server, []byte(g)) {
				return p, true
			}
		}
	}
	return mailProtocol{}, false
}

// parseMail reads a mail session's client lines up to its upgrade.
func parseMail(p mailProtocol, client, server []byte) (Observation, bool, bool) {
	offset := 0
	for lines := 0; lines < maxPreambleLines; lines++ {
		end := bytes.Index(client[offset:], []byte("\r\n"))
		if end < 0 {
			return Observation{}, false, len(client) >= MaxDirectionBytes
		}
		fields := strings.Fields(string(client[offset : offset+end]))
		offset += end + 2
		switch {
		case p.upgradeCommand(fields):
			sOff := -1
			if i := bytes.Index(server, []byte("\r\n\x16\x03")); i >= 0 {
				sOff = i + 2
			}
			return upgradedTLS(client, server, offset, sOff, p.upgrade)
		case p.plaintextCommand(fields):
			return Observation{Protocol: p.name, Plaintext: true, PlaintextKind: p.name + "-plaintext"}, true, true
		}
	}
	return Observation{}, false, true
}

func looksLikeMailClient(client []byte) bool {
	for _, verb := range []string{"EHLO ", "HELO ", "CAPA", "STLS", "STARTTLS"} {
		if len(client) >= len(verb) && strings.EqualFold(string(client[:len(verb)]), verb) {
			return true
		}
	}
	return false
}

// ---------------------------------------------------------------- LDAP

// berMessageLength is the total length of the BER element at b[0], or -1
// while it is incomplete or malformed.
func berMessageLength(b []byte) int {
	if len(b) < 2 {
		return -1
	}
	n := int(b[1])
	if n < 0x80 {
		return 2 + n
	}
	octets := n & 0x7f
	if octets == 0 || octets > 4 || len(b) < 2+octets {
		return -1
	}
	length := 0
	for _, c := range b[2 : 2+octets] {
		length = length<<8 | int(c)
	}
	return 2 + octets + length
}

// ldapStartTLS reads the TLS after an LDAP StartTLS request and its response;
// until it starts, the session reads as an LDAP StartTLS request.
func ldapStartTLS(client, server []byte) (Observation, bool, bool) {
	requested := Observation{Protocol: "ldap"}
	cOff := berMessageLength(client)
	if cOff < 0 || cOff > len(client) {
		return requested, true, false
	}
	if len(client) > cOff && client[cOff] == 0x30 {
		return requested, true, true // the server refused; LDAP goes on in the clear
	}
	sOff := -1
	if len(server) > 0 && server[0] == 0x30 {
		if n := berMessageLength(server); n > 0 && n <= len(server) {
			sOff = n
		}
	}
	obs, ok, done := upgradedTLS(client, server, cOff, sOff, UpgradeLDAP)
	if !ok && !done {
		return requested, true, false
	}
	return obs, ok, done
}

// ---------------------------------------------------------------- PostgreSQL

const (
	pgSSLRequest    = 80877103
	pgGSSENCRequest = 80877104
	pgProtocol3     = 3 << 16
)

func isPostgreSQLStart(client []byte) bool {
	if len(client) < 8 {
		return false
	}
	length, code := binary.BigEndian.Uint32(client[0:4]), binary.BigEndian.Uint32(client[4:8])
	return (length == 8 && (code == pgSSLRequest || code == pgGSSENCRequest)) ||
		(length >= 8 && length <= 10000 && code == pgProtocol3)
}

// parsePostgreSQL follows a PostgreSQL connection's encryption requests: an
// SSLRequest the server accepts ('S') leads to TLS; a startup message sent
// in the clear (no request, or one the server refused) is plaintext.
func parsePostgreSQL(client, server []byte) (Observation, bool, bool) {
	plaintext := Observation{Protocol: "postgresql", Plaintext: true, PlaintextKind: "postgresql-startup"}
	cOff, sOff := 0, 0
	for {
		if len(client) < cOff+8 {
			return Observation{}, false, false
		}
		length, code := binary.BigEndian.Uint32(client[cOff:cOff+4]), binary.BigEndian.Uint32(client[cOff+4:cOff+8])
		switch {
		case length == 8 && (code == pgSSLRequest || code == pgGSSENCRequest):
			if len(server) <= sOff {
				return Observation{}, false, false
			}
			answer := server[sOff]
			cOff, sOff = cOff+8, sOff+1
			switch {
			case code == pgSSLRequest && answer == 'S':
				return upgradedTLS(client, server, cOff, sOff, UpgradePostgreSQL)
			case answer == 'N':
				continue // refused: the client may ask again, or start in the clear
			default:
				return Observation{}, false, true // GSSAPI encryption, or not PostgreSQL
			}
		case code == pgProtocol3:
			return plaintext, true, true
		default:
			return Observation{}, false, true
		}
	}
}

// ---------------------------------------------------------------- MySQL

const mysqlClientSSL = 0x0800

// mysqlGreeting returns the length of a MySQL protocol-10 server greeting
// packet at the start of server, or -1.
func mysqlGreeting(server []byte) int {
	if len(server) < 5 || server[3] != 0 || server[4] != 0x0a {
		return -1
	}
	length := int(server[0]) | int(server[1])<<8 | int(server[2])<<16
	if length < 30 || 4+length > len(server) {
		return -1
	}
	return 4 + length
}

// parseMySQL reads the client's first packet after the greeting: an SSL
// request leads to TLS, a login sent without one is plaintext.
func parseMySQL(client, server []byte, greeting int) (Observation, bool, bool) {
	if len(client) < 8 {
		return Observation{}, false, false
	}
	length := int(client[0]) | int(client[1])<<8 | int(client[2])<<16
	if client[3] != 1 || length < 4 {
		return Observation{}, false, true
	}
	capabilities := binary.LittleEndian.Uint32(client[4:8])
	if capabilities&mysqlClientSSL != 0 && length == 32 {
		return upgradedTLS(client, server, 4+length, greeting, UpgradeMySQL)
	}
	return Observation{Protocol: "mysql", Plaintext: true, PlaintextKind: "mysql-login"}, true, true
}
