// SPDX-License-Identifier: BUSL-1.1

// Package observe is the passive network crypto observer (X1). An agent that
// holds the observer role watches a mirrored interface and reads, from the
// first bytes of each connection, only what the handshake states in the
// clear: the TLS version, cipher suite and key-exchange group, the server
// certificate where TLS 1.2 still sends it unencrypted, the SSH key-exchange
// algorithms, and whether a protocol that should be encrypted was not. No
// payload byte is stored or reported; the buffers that held the first bytes
// are dropped once the handshake is read.
package observe

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"strings"
)

// Observation is what one connection's handshake reveals.
type Observation struct {
	Protocol string `json:"protocol"` // tls, quic, dtls, ssh, http, ldap, smtp, imap, pop3, postgresql or mysql
	// TLS
	TLSVersion    string   `json:"tls_version,omitempty"`
	CipherSuite   string   `json:"cipher_suite,omitempty"`
	Group         string   `json:"group,omitempty"`
	OfferedGroups []string `json:"offered_groups,omitempty"`
	ServerName    string   `json:"server_name,omitempty"`
	// CertificateDER is the TLS 1.2 leaf certificate. The caller reads it
	// through the crypto boundary and drops it; it is never reported raw.
	CertificateDER []byte `json:"-"`
	// CertificateHidden is true for TLS 1.3, which encrypts the certificate:
	// the active probe reads the served chain instead.
	CertificateHidden bool `json:"certificate_hidden,omitempty"`
	// Upgrade says how a TLS handshake was reached inside another protocol
	// (X1-L4): smtp-starttls, imap-starttls, pop3-stls, ldap-starttls,
	// postgresql-ssl or mysql-ssl; empty for TLS from the first byte.
	Upgrade string `json:"upgrade,omitempty"`
	// SSH
	SSHClient        string `json:"ssh_client,omitempty"`
	SSHServer        string `json:"ssh_server,omitempty"`
	KexAlgorithm     string `json:"kex_algorithm,omitempty"`
	HostKeyAlgorithm string `json:"host_key_algorithm,omitempty"`
	SSHCipher        string `json:"ssh_cipher,omitempty"`
	// Plaintext marks a connection that carried requests or credentials
	// without encryption; PlaintextKind says which.
	Plaintext     bool   `json:"plaintext,omitempty"`
	PlaintextKind string `json:"plaintext_kind,omitempty"`
}

// MaxDirectionBytes bounds how much of each direction Parse ever needs.
const MaxDirectionBytes = 16 << 10

// Parse reads the first bytes of each direction of one TCP connection. done
// is true once nothing more can be learned (the handshake is read, the
// protocol is not one the observer reads, or the bytes are malformed); ok is
// true when obs describes the connection.
func Parse(client, server []byte) (obs Observation, ok, done bool) {
	switch {
	case len(client) == 0:
		return Observation{}, false, false
	case client[0] == 0x16 && len(client) >= 3 && client[1] == 0x03:
		return parseTLS(client, server)
	case bytes.HasPrefix(client, []byte("SSH-")) || bytes.HasPrefix(server, []byte("SSH-")):
		return parseSSH(client, server)
	case isHTTPRequest(client):
		return Observation{Protocol: "http", Plaintext: true, PlaintextKind: "http-request"}, true, true
	}
	// Server-first protocols are known by their greeting, before any guess
	// from the client's first byte: an IMAP tag or a MySQL packet can start
	// with 0x30 like an LDAP message.
	if greeting := mysqlGreeting(server); greeting > 0 {
		return parseMySQL(client, server, greeting)
	}
	if p, ok := mailGreeting(server); ok {
		return parseMail(p, client, server)
	}
	switch {
	case client[0] == 0x30:
		return parseLDAP(client, server)
	case isPostgreSQLStart(client):
		return parsePostgreSQL(client, server)
	case looksLikeMailClient(client) && len(server) == 0:
		return Observation{}, false, false // the greeting has not been seen yet
	}
	return Observation{}, false, len(client) >= 8
}

var httpMethods = []string{"GET ", "POST ", "PUT ", "HEAD ", "DELETE ", "OPTIONS ", "PATCH ", "CONNECT "}

// isHTTPRequest recognizes an HTTP/1.x request line without keeping it.
func isHTTPRequest(b []byte) bool {
	line, _, found := bytes.Cut(b, []byte("\r\n"))
	if !found {
		return false
	}
	for _, m := range httpMethods {
		if bytes.HasPrefix(line, []byte(m)) {
			return bytes.HasSuffix(line, []byte(" HTTP/1.1")) || bytes.HasSuffix(line, []byte(" HTTP/1.0"))
		}
	}
	return false
}

// ---------------------------------------------------------------- TLS

// helloRetryRandom is the fixed ServerHello.random of a HelloRetryRequest.
var helloRetryRandom = []byte{
	0xCF, 0x21, 0xAD, 0x74, 0xE5, 0x9A, 0x61, 0x11, 0xBE, 0x1D, 0x8C, 0x02, 0x1E, 0x65, 0xB8, 0x91,
	0xC2, 0xA2, 0x11, 0x16, 0x7A, 0xBB, 0x8C, 0x5E, 0x07, 0x9E, 0x09, 0xE2, 0xC8, 0xA8, 0x33, 0x9C,
}

func parseTLS(client, server []byte) (Observation, bool, bool) {
	obs := Observation{Protocol: "tls"}
	clientMsgs, _ := handshakeMessages(client)
	if len(clientMsgs) == 0 || clientMsgs[0].kind != 1 {
		return obs, false, len(client) >= MaxDirectionBytes
	}
	parseClientHello(clientMsgs[0].body, &obs)
	serverMsgs, serverEnded := handshakeMessages(server)
	var hello bool
	for _, m := range serverMsgs {
		switch m.kind {
		case 2: // ServerHello or HelloRetryRequest
			retry := parseServerHello(m.body, &obs)
			hello = !retry
		case 11: // Certificate (TLS 1.2: in the clear)
			if obs.TLSVersion != "TLSv1.3" {
				obs.CertificateDER = firstCertificate(m.body)
			}
		case 12: // ServerKeyExchange: an ECDHE named curve
			if len(m.body) >= 3 && m.body[0] == 0x03 {
				obs.Group = groupName(binary.BigEndian.Uint16(m.body[1:3]))
			}
		case 14: // ServerHelloDone ends the TLS 1.2 server flight
			return obs, hello, true
		}
	}
	if hello && obs.TLSVersion == "TLSv1.3" {
		obs.CertificateHidden = true
		return obs, true, true
	}
	return obs, hello, serverEnded || len(server) >= MaxDirectionBytes
}

// ParseSession reads one TLS session as a host sees it (X5): the client's
// and the server's plaintext handshake bytes, each up to its first record that
// is not a handshake record. It reports the session as Parse would, except
// that a server whose only message in the clear is a HelloRetryRequest — its
// second ServerHello follows a ChangeCipherSpec — still reports the version,
// suite and group that request settled, which the server must keep (RFC 8446
// section 4.1.4), with retry set.
func ParseSession(client, server []byte) (obs Observation, retry, ok bool) {
	if len(client) < 3 || client[0] != 0x16 || client[1] != 0x03 {
		return Observation{}, false, false
	}
	obs, ok, _ = parseTLS(client, server)
	if ok {
		return obs, false, true
	}
	msgs, _ := handshakeMessages(server)
	for _, m := range msgs {
		var scratch Observation
		if m.kind == 2 && parseServerHello(m.body, &scratch) && scratch.TLSVersion == "TLSv1.3" && obs.TLSVersion == "TLSv1.3" {
			obs.CertificateHidden = true
			return obs, true, true
		}
	}
	return obs, false, false
}

type handshakeMessage struct {
	kind byte
	body []byte
}

// handshakeMessages reassembles handshake messages from consecutive TLS
// records, skipping ChangeCipherSpec. ended is true when a record that is
// not a handshake (application data, an alert) shows nothing more will come
// in the clear.
func handshakeMessages(b []byte) (msgs []handshakeMessage, ended bool) {
	var stream []byte
	for len(b) >= 5 {
		kind, length := b[0], int(binary.BigEndian.Uint16(b[3:5]))
		if len(b) < 5+length {
			break
		}
		switch kind {
		case 0x16:
			stream = append(stream, b[5:5+length]...)
		case 0x14:
		default:
			ended = true
		}
		b = b[5+length:]
		if ended {
			break
		}
	}
	for len(stream) >= 4 {
		length := int(stream[1])<<16 | int(stream[2])<<8 | int(stream[3])
		if len(stream) < 4+length {
			break
		}
		msgs = append(msgs, handshakeMessage{kind: stream[0], body: stream[4 : 4+length]})
		stream = stream[4+length:]
	}
	return msgs, ended
}

func parseClientHello(body []byte, obs *Observation) {
	r := reader{b: body}
	r.skip(2 + 32)
	r.skip(int(r.u8()))
	r.skip(int(r.u16()))
	r.skip(int(r.u8()))
	exts := reader{b: r.bytes(int(r.u16()))}
	for exts.ok() && len(exts.b) >= 4 {
		typ, data := exts.u16(), reader{b: exts.bytes(int(exts.u16()))}
		switch typ {
		case 0: // server_name
			list := reader{b: data.bytes(int(data.u16()))}
			if list.u8() == 0 {
				obs.ServerName = string(list.bytes(int(list.u16())))
			}
		case 10: // supported_groups
			groups := reader{b: data.bytes(int(data.u16()))}
			for groups.ok() && len(groups.b) >= 2 {
				if g := groups.u16(); !grease(g) {
					obs.OfferedGroups = append(obs.OfferedGroups, groupName(g))
				}
			}
		}
	}
}

// parseServerHello reads the chosen version, suite and group; it reports
// whether the message was a HelloRetryRequest.
func parseServerHello(body []byte, obs *Observation) bool {
	r := reader{b: body}
	legacy := r.u16()
	random := r.bytes(32)
	r.skip(int(r.u8()))
	suite := r.u16()
	r.skip(1)
	retry := bytes.Equal(random, helloRetryRandom)
	version := legacy
	var group uint16
	exts := reader{b: r.bytes(int(r.u16()))}
	for exts.ok() && len(exts.b) >= 4 {
		typ, data := exts.u16(), reader{b: exts.bytes(int(exts.u16()))}
		switch typ {
		case 43: // supported_versions
			version = data.u16()
		case 51: // key_share: the server's group (or the group a retry asks for)
			group = data.u16()
		}
	}
	if !r.ok() {
		return retry
	}
	obs.TLSVersion, obs.CipherSuite = versionName(version), suiteName(suite)
	if group != 0 {
		obs.Group = groupName(group)
	}
	return retry
}

// firstCertificate returns the leaf of a TLS 1.2 Certificate message.
func firstCertificate(body []byte) []byte {
	r := reader{b: body}
	list := reader{b: r.bytes(int(r.u24()))}
	der := list.bytes(int(list.u24()))
	if !list.ok() || len(der) == 0 {
		return nil
	}
	return append([]byte(nil), der...)
}

func grease(v uint16) bool { return v&0x0f0f == 0x0a0a && v>>8 == v&0xff }

func versionName(v uint16) string {
	switch v {
	case 0x0300:
		return "SSLv3"
	case 0x0301:
		return "TLSv1.0"
	case 0x0302:
		return "TLSv1.1"
	case 0x0303:
		return "TLSv1.2"
	case 0x0304:
		return "TLSv1.3"
	case 0xfeff:
		return "DTLSv1.0"
	case 0xfefd:
		return "DTLSv1.2"
	case 0xfefc:
		return "DTLSv1.3"
	}
	return fmt.Sprintf("0x%04X", v)
}

var groupNames = map[uint16]string{
	0x0017: "secp256r1", 0x0018: "secp384r1", 0x0019: "secp521r1", 0x001d: "x25519", 0x001e: "x448",
	0x0100: "ffdhe2048", 0x0101: "ffdhe3072", 0x0102: "ffdhe4096",
	0x0200: "MLKEM512", 0x0201: "MLKEM768", 0x0202: "MLKEM1024",
	0x11eb: "SecP256r1MLKEM768", 0x11ec: "X25519MLKEM768", 0x11ed: "SecP384r1MLKEM1024",
	0x6399: "X25519Kyber768Draft00",
}

func groupName(g uint16) string {
	if name, ok := groupNames[g]; ok {
		return name
	}
	return fmt.Sprintf("0x%04X", g)
}

var suiteNames = map[uint16]string{
	0x1301: "TLS_AES_128_GCM_SHA256", 0x1302: "TLS_AES_256_GCM_SHA384", 0x1303: "TLS_CHACHA20_POLY1305_SHA256",
	0xc02b: "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256", 0xc02c: "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384",
	0xc02f: "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256", 0xc030: "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
	0xcca8: "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256", 0xcca9: "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256",
	0xc013: "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA", 0xc014: "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA",
	0x009c: "TLS_RSA_WITH_AES_128_GCM_SHA256", 0x009d: "TLS_RSA_WITH_AES_256_GCM_SHA384",
	0x002f: "TLS_RSA_WITH_AES_128_CBC_SHA", 0x0035: "TLS_RSA_WITH_AES_256_CBC_SHA",
	0x000a: "TLS_RSA_WITH_3DES_EDE_CBC_SHA", 0x0005: "TLS_RSA_WITH_RC4_128_SHA",
}

func suiteName(s uint16) string {
	if name, ok := suiteNames[s]; ok {
		return name
	}
	return fmt.Sprintf("0x%04X", s)
}

// ---------------------------------------------------------------- SSH

func parseSSH(client, server []byte) (Observation, bool, bool) {
	obs := Observation{Protocol: "ssh"}
	clientBanner, clientRest, cok := sshBanner(client)
	serverBanner, serverRest, sok := sshBanner(server)
	obs.SSHClient, obs.SSHServer = clientBanner, serverBanner
	if !cok || !sok {
		return obs, false, len(client) >= MaxDirectionBytes || len(server) >= MaxDirectionBytes
	}
	clientKex, cdone := sshKexInit(clientRest)
	serverKex, sdone := sshKexInit(serverRest)
	if !cdone || !sdone {
		return obs, false, len(client) >= MaxDirectionBytes || len(server) >= MaxDirectionBytes
	}
	obs.KexAlgorithm = firstCommon(clientKex[0], serverKex[0])
	obs.HostKeyAlgorithm = firstCommon(clientKex[1], serverKex[1])
	obs.SSHCipher = firstCommon(clientKex[2], serverKex[2])
	return obs, true, true
}

// sshBanner returns the identification string and the bytes after it; a
// server may send other lines first (RFC 4253, section 4.2).
func sshBanner(b []byte) (string, []byte, bool) {
	for len(b) > 0 {
		line, rest, found := bytes.Cut(b, []byte("\n"))
		if !found {
			return "", nil, false
		}
		line = bytes.TrimSuffix(line, []byte("\r"))
		if bytes.HasPrefix(line, []byte("SSH-")) {
			if len(line) > 255 {
				line = line[:255]
			}
			return string(line), rest, true
		}
		b = rest
	}
	return "", nil, false
}

// sshKexInit reads the name-lists of the first (unencrypted) binary packet,
// SSH_MSG_KEXINIT: key exchange, host key and client-to-server cipher.
func sshKexInit(b []byte) ([3][]string, bool) {
	var lists [3][]string
	r := reader{b: b}
	length := int(r.u32())
	packet := reader{b: r.bytes(length)}
	if !r.ok() {
		return lists, false
	}
	padding := int(packet.u8())
	payload := reader{b: packet.bytes(length - 1 - padding)}
	if payload.u8() != 20 {
		return lists, false
	}
	payload.skip(16)
	for i := range lists {
		lists[i] = strings.Split(string(payload.bytes(int(payload.u32()))), ",")
	}
	return lists, payload.ok()
}

// firstCommon is RFC 4253's choice: the first client algorithm the server
// also supports. Extension markers (ext-info-c, kex-strict-*) are skipped.
func firstCommon(client, server []string) string {
	offered := map[string]bool{}
	for _, s := range server {
		offered[s] = true
	}
	for _, c := range client {
		if strings.HasPrefix(c, "ext-info-") || strings.HasPrefix(c, "kex-strict-") {
			continue
		}
		if offered[c] {
			return c
		}
	}
	return ""
}

// ---------------------------------------------------------------- LDAP

// parseLDAP reads the first LDAP message's operation. A connection whose first
// operation is not the StartTLS extended request runs in the clear.
func parseLDAP(client, server []byte) (Observation, bool, bool) {
	r := reader{b: client}
	if r.u8() != 0x30 {
		return Observation{}, false, true
	}
	r.berLength()
	if r.u8() != 0x02 {
		return Observation{}, false, true
	}
	r.skip(int(r.berLength()))
	op := r.u8()
	if !r.ok() {
		return Observation{}, false, len(client) >= 64
	}
	obs := Observation{Protocol: "ldap"}
	switch op {
	case 0x77: // ExtendedRequest; StartTLS upgrades before anything else
		if bytes.Contains(client, []byte("1.3.6.1.4.1.1466.20037")) {
			return ldapStartTLS(client, server)
		}
		obs.Plaintext, obs.PlaintextKind = true, "ldap-extended-request"
	case 0x60: // BindRequest
		obs.Plaintext, obs.PlaintextKind = true, "ldap-bind"
	default:
		obs.Plaintext, obs.PlaintextKind = true, "ldap-request"
	}
	return obs, true, true
}

// ---------------------------------------------------------------- reader

// reader is a bounds-checked big-endian cursor; any short read makes ok
// false and every later read return zero.
type reader struct {
	b   []byte
	bad bool
}

func (r *reader) ok() bool { return !r.bad }

func (r *reader) bytes(n int) []byte {
	if r.bad || n < 0 || n > len(r.b) {
		r.bad = true
		return nil
	}
	out := r.b[:n]
	r.b = r.b[n:]
	return out
}

func (r *reader) skip(n int) { r.bytes(n) }

func (r *reader) u8() byte {
	if b := r.bytes(1); b != nil {
		return b[0]
	}
	return 0
}

func (r *reader) u16() uint16 {
	if b := r.bytes(2); b != nil {
		return binary.BigEndian.Uint16(b)
	}
	return 0
}

func (r *reader) u24() uint32 {
	if b := r.bytes(3); b != nil {
		return uint32(b[0])<<16 | uint32(b[1])<<8 | uint32(b[2])
	}
	return 0
}

func (r *reader) u32() uint32 {
	if b := r.bytes(4); b != nil {
		return binary.BigEndian.Uint32(b)
	}
	return 0
}

// berLength reads a BER definite length.
func (r *reader) berLength() uint32 {
	first := r.u8()
	if first < 0x80 {
		return uint32(first)
	}
	n := int(first & 0x7f)
	if n == 0 || n > 4 {
		r.bad = true
		return 0
	}
	var v uint32
	for i := 0; i < n; i++ {
		v = v<<8 | uint32(r.u8())
	}
	return v
}
