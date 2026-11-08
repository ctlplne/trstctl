// SPDX-License-Identifier: BUSL-1.1

package observe

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"slices"
	"strings"
	"testing"
)

func u16(v int) []byte { return []byte{byte(v >> 8), byte(v)} }                // #nosec G115 -- big-endian packing of bounded test lengths (CWE-190)
func u24(v int) []byte { return []byte{byte(v >> 16), byte(v >> 8), byte(v)} } // #nosec G115 -- big-endian packing of bounded test lengths (CWE-190)

func vec16(b ...[]byte) []byte { j := bytes.Join(b, nil); return append(u16(len(j)), j...) }
func vec8(b []byte) []byte     { return append([]byte{byte(len(b))}, b...) } // #nosec G115 -- test vectors are under 256 bytes (CWE-190)

func ext(typ int, data []byte) []byte { return append(append(u16(typ), u16(len(data))...), data...) }

func handshake(kind byte, body []byte) []byte {
	return append(append([]byte{kind}, u24(len(body))...), body...)
}

func record(kind byte, body []byte) []byte {
	return append(append([]byte{kind, 0x03, 0x03}, u16(len(body))...), body...)
}

func clientHello(sni string, groups ...int) []byte {
	var groupBytes []byte
	for _, g := range groups {
		groupBytes = append(groupBytes, u16(g)...)
	}
	name := append([]byte{0}, vec16([]byte(sni))...)
	exts := bytes.Join([][]byte{
		ext(0, vec16(name)),
		ext(10, vec16(groupBytes)),
		ext(43, vec8(append(u16(0x0304), u16(0x0303)...))),
	}, nil)
	body := bytes.Join([][]byte{u16(0x0303), make([]byte, 32), vec8(nil), vec16(u16(0x1301), u16(0xc02f)), vec8([]byte{0}), vec16(exts)}, nil)
	return record(0x16, handshake(1, body))
}

func serverHello13(suite, group int, random []byte) []byte {
	if random == nil {
		random = make([]byte, 32)
	}
	exts := bytes.Join([][]byte{ext(43, u16(0x0304)), ext(51, append(u16(group), vec16(make([]byte, 8))...))}, nil)
	body := bytes.Join([][]byte{u16(0x0303), random, vec8(nil), u16(suite), {0}, vec16(exts)}, nil)
	return record(0x16, handshake(2, body))
}

func TestParseTLS13HybridGroupWithoutCertificate(t *testing.T) {
	client := clientHello("api.example.test", 0x1a1a, 0x11ec, 0x001d)
	server := bytes.Join([][]byte{
		serverHello13(0x1302, 0x11ec, nil),
		record(0x14, []byte{1}),
		record(0x17, []byte("encrypted extensions, certificate and finished")),
	}, nil)
	if _, ok, done := Parse(client, nil); ok || done {
		t.Fatal("a ClientHello alone already decided the connection")
	}
	obs, ok, done := Parse(client, server)
	if !ok || !done || obs.Protocol != "tls" || obs.TLSVersion != "TLSv1.3" || obs.CipherSuite != "TLS_AES_256_GCM_SHA384" ||
		obs.Group != "X25519MLKEM768" || obs.ServerName != "api.example.test" || !obs.CertificateHidden || obs.CertificateDER != nil ||
		!slices.Equal(obs.OfferedGroups, []string{"X25519MLKEM768", "x25519"}) {
		t.Fatalf("TLS 1.3 observation = %+v ok=%v done=%v", obs, ok, done)
	}
	raw, _ := json.Marshal(obs)
	if strings.Contains(string(raw), "encrypted extensions") {
		t.Fatal("an observation carries payload bytes")
	}
}

func TestParseTLS13HelloRetryUsesTheFinalGroup(t *testing.T) {
	client := clientHello("retry.example.test", 0x001d, 0x11ec)
	server := bytes.Join([][]byte{
		serverHello13(0x1301, 0x11ec, helloRetryRandom),
		record(0x14, []byte{1}),
		serverHello13(0x1301, 0x11ec, nil),
		record(0x17, []byte{0}),
	}, nil)
	obs, ok, done := Parse(client, server)
	if !ok || !done || obs.Group != "X25519MLKEM768" || obs.TLSVersion != "TLSv1.3" {
		t.Fatalf("after a HelloRetryRequest = %+v ok=%v done=%v", obs, ok, done)
	}
	if _, ok, _ := Parse(client, serverHello13(0x1301, 0x11ec, helloRetryRandom)); ok {
		t.Fatal("a HelloRetryRequest alone was read as the negotiated handshake")
	}
}

// TestParseSessionReadsWhatAHostSeesX5 is the host observer's view: each
// direction up to its first record that is not a handshake record. A full
// TLS 1.3 handshake reads as Parse reads it; a server whose only plaintext
// message is a HelloRetryRequest still reports the version, suite and group
// the request settled, flagged as a retry; anything that is not a TLS
// ClientHello is not a session.
func TestParseSessionReadsWhatAHostSeesX5(t *testing.T) {
	client := clientHello("retry.example.test", 0x11ec, 0x0017)
	obs, retry, ok := ParseSession(client, serverHello13(0x1302, 0x11ec, nil))
	if !ok || retry || obs.TLSVersion != "TLSv1.3" || obs.Group != "X25519MLKEM768" || obs.CipherSuite != "TLS_AES_256_GCM_SHA384" ||
		obs.ServerName != "retry.example.test" || !obs.CertificateHidden {
		t.Fatalf("a full TLS 1.3 handshake = %+v retry=%v ok=%v", obs, retry, ok)
	}
	obs, retry, ok = ParseSession(client, serverHello13(0x1301, 0x0017, helloRetryRandom))
	if !ok || !retry || obs.TLSVersion != "TLSv1.3" || obs.Group != "secp256r1" || obs.CipherSuite != "TLS_AES_128_GCM_SHA256" || !obs.CertificateHidden {
		t.Fatalf("a HelloRetryRequest alone = %+v retry=%v ok=%v", obs, retry, ok)
	}
	if _, _, ok := ParseSession(client, nil); ok {
		t.Fatal("a ClientHello alone is not a session")
	}
	if _, _, ok := ParseSession([]byte("GET / HTTP/1.1\r\n"), serverHello13(0x1301, 0x001d, nil)); ok {
		t.Fatal("bytes that are not a ClientHello read as a session")
	}
}

func TestParseTLS12CertificateAndCurve(t *testing.T) {
	leaf := []byte("leaf-certificate-der")
	certMsg := handshake(11, append(u24(3+len(leaf)), append(u24(len(leaf)), leaf...)...))
	ske := handshake(12, append([]byte{0x03}, append(u16(0x0017), 0x41)...))
	sh := handshake(2, bytes.Join([][]byte{u16(0x0303), make([]byte, 32), vec8(nil), u16(0x000a), {0}, vec16(nil)}, nil))
	server := record(0x16, bytes.Join([][]byte{sh, certMsg, ske, handshake(14, nil)}, nil))
	obs, ok, done := Parse(clientHello("legacy.example.test", 0x0017), server)
	if !ok || !done || obs.TLSVersion != "TLSv1.2" || obs.CipherSuite != "TLS_RSA_WITH_3DES_EDE_CBC_SHA" || obs.Group != "secp256r1" ||
		!bytes.Equal(obs.CertificateDER, leaf) || obs.CertificateHidden {
		t.Fatalf("TLS 1.2 observation = %+v ok=%v done=%v", obs, ok, done)
	}
	raw, _ := json.Marshal(obs)
	if strings.Contains(string(raw), "leaf-certificate-der") {
		t.Fatal("an observation serializes the raw certificate")
	}
}

func sshKexInitPacket(kex, hostKey, cipher string) []byte {
	var payload []byte
	payload = append(payload, 20)
	payload = append(payload, make([]byte, 16)...)
	for _, list := range []string{kex, hostKey, cipher, cipher, "hmac-sha2-256", "hmac-sha2-256", "none", "none", "", ""} {
		payload = binary.BigEndian.AppendUint32(payload, uint32(len(list))) // #nosec G115 -- bounded test fixture length (CWE-190)
		payload = append(payload, list...)
	}
	payload = append(payload, 0, 0, 0, 0, 0)
	padding := 8
	packet := append([]byte{byte(padding)}, payload...)
	packet = append(packet, make([]byte, padding)...)
	return append(binary.BigEndian.AppendUint32(nil, uint32(len(packet))), packet...) // #nosec G115 -- bounded test fixture length (CWE-190)
}

func TestParseSSHKeyExchange(t *testing.T) {
	client := append([]byte("SSH-2.0-OpenSSH_9.9\r\n"), sshKexInitPacket("mlkem768x25519-sha256,curve25519-sha256,ext-info-c,kex-strict-c-v00@openssh.com", "ssh-ed25519,rsa-sha2-512", "aes256-gcm@openssh.com")...)
	server := append([]byte("SSH-2.0-OpenSSH_9.9p1 Debian\r\n"), sshKexInitPacket("curve25519-sha256,mlkem768x25519-sha256", "rsa-sha2-512,ssh-ed25519", "aes256-gcm@openssh.com")...)
	obs, ok, done := Parse(client, server)
	if !ok || !done || obs.Protocol != "ssh" || obs.KexAlgorithm != "mlkem768x25519-sha256" || obs.HostKeyAlgorithm != "ssh-ed25519" ||
		obs.SSHCipher != "aes256-gcm@openssh.com" || obs.SSHServer != "SSH-2.0-OpenSSH_9.9p1 Debian" {
		t.Fatalf("SSH observation = %+v ok=%v done=%v", obs, ok, done)
	}
	if _, ok, done := Parse(client, []byte("SSH-2.0-OpenSSH_9.9p1\r\n")); ok || done {
		t.Fatal("SSH was decided before the server's KEXINIT arrived")
	}
}

func TestParsePlaintextHTTPAndLDAP(t *testing.T) {
	obs, ok, done := Parse([]byte("GET /admin/secret?token=abc HTTP/1.1\r\nHost: x\r\n\r\n"), nil)
	if !ok || !done || !obs.Plaintext || obs.PlaintextKind != "http-request" {
		t.Fatalf("HTTP = %+v", obs)
	}
	raw, _ := json.Marshal(obs)
	if strings.Contains(string(raw), "admin") || strings.Contains(string(raw), "token") {
		t.Fatal("the HTTP observation keeps the request")
	}
	// LDAP simple bind: SEQUENCE { messageID 1, [APPLICATION 0] { version 3, name, [0] password } }
	bind := []byte{0x30, 0x1c, 0x02, 0x01, 0x01, 0x60, 0x17, 0x02, 0x01, 0x03, 0x04, 0x08}
	bind = append(bind, "cn=admin"...)
	bind = append(bind, 0x80, 0x08)
	bind = append(bind, "hunter22"...)
	obs, ok, done = Parse(bind, nil)
	if !ok || !done || obs.Protocol != "ldap" || !obs.Plaintext || obs.PlaintextKind != "ldap-bind" {
		t.Fatalf("LDAP bind = %+v", obs)
	}
	raw, _ = json.Marshal(obs)
	if strings.Contains(string(raw), "hunter22") || strings.Contains(string(raw), "cn=admin") {
		t.Fatal("the LDAP observation keeps the bind")
	}
	startTLS := []byte{0x30, 0x1d, 0x02, 0x01, 0x01, 0x77, 0x18, 0x80, 0x16}
	startTLS = append(startTLS, "1.3.6.1.4.1.1466.20037"...)
	if obs, ok, _ := Parse(startTLS, nil); !ok || obs.Plaintext {
		t.Fatalf("StartTLS = %+v", obs)
	}
}

func TestParseRejectsTruncatedAndForeignBytes(t *testing.T) {
	ch := clientHello("x.example.test", 0x001d)
	for i := range ch {
		if obs, ok, _ := Parse(ch[:i], nil); ok {
			t.Fatalf("a %d-byte prefix produced %+v", i, obs)
		}
	}
	if _, ok, done := Parse([]byte("\x00\x01binary-protocol-bytes"), nil); ok || !done {
		t.Fatal("an unknown protocol was not given up on")
	}
}
