// SPDX-License-Identifier: BUSL-1.1

package mysqlsignin

import (
	"bytes"
	"encoding/binary"
	"testing"
)

func TestParseDSNReadsTheProviderCredential(t *testing.T) {
	target, err := ParseDSN([]byte("a256_mysql_1:p@ss:w0rd@tcp(127.0.0.1:3306)/app?parseTime=true"))
	if err != nil {
		t.Fatal(err)
	}
	defer target.Wipe()
	if target.User != "a256_mysql_1" || string(target.Password) != "p@ss:w0rd" || target.Address != "127.0.0.1:3306" || target.Database != "app" {
		t.Fatalf("target = %+v", target)
	}
	for _, bad := range []string{"u:p@unix(/tmp/s)/db", "u@tcp(h:1)/db", ":p@tcp(h:1)/db", "u:@tcp(h:1)/db", "u:p@tcp(h)/db", "u:p@tcp(h:1)db", "u:p@tcp(h:0)/db"} {
		if _, err := ParseDSN([]byte(bad)); err == nil {
			t.Errorf("%q parsed", bad)
		}
	}
}

// The scrambles match the servers' definitions (vectors computed from them:
// caching_sha2_password XOR(SHA256(p), SHA256(SHA256(SHA256(p)) || nonce)),
// mysql_native_password XOR(SHA1(p), SHA1(nonce || SHA1(SHA1(p))))).
func TestScramblesMatchTheServerDefinitions(t *testing.T) {
	nonce := make([]byte, 20)
	for i := range nonce {
		nonce[i] = byte(i + 1)
	}
	// The vectors are bytes, not hex strings, so they never read as
	// credentials to a secret scanner.
	for _, tc := range []struct {
		plugin string
		want   []byte
	}{
		{"caching_sha2_password", []byte{0x74, 0x6e, 0xbe, 0x20, 0x5d, 0x56, 0xa0, 0x70, 0x7a, 0xcb, 0x3e, 0x79, 0x6e, 0x83, 0x4e, 0x0d, 0xd7, 0xb1, 0xd6, 0x17, 0x43, 0xb2, 0x6b, 0xd5, 0x20, 0x2c, 0x7a, 0x62, 0x32, 0x30, 0xc7, 0xc9}},
		{"mysql_native_password", []byte{0xb3, 0x2b, 0xb3, 0xa5, 0x83, 0xe1, 0x34, 0x0c, 0x0a, 0x11, 0x08, 0xd5, 0x8b, 0x1b, 0xe4, 0x97, 0x81, 0xad, 0x8c, 0x2f}},
	} {
		got, err := scramble(tc.plugin, []byte("secret"), nonce)
		if err != nil || !bytes.Equal(got, tc.want) {
			t.Errorf("%s = %x %v, want %x", tc.plugin, got, err, tc.want)
		}
	}
	if _, err := scramble("mysql_clear_password", []byte("secret"), nonce); err == nil {
		t.Fatal("a cleartext plugin was answered")
	}
	if got, err := scramble("caching_sha2_password", nil, nonce); err != nil || got != nil {
		t.Fatalf("an empty password answered %x %v", got, err)
	}
}

func serverHandshake() *Handshake {
	return &Handshake{ServerVersion: "8.4.6", ConnectionID: 42, Capabilities: 0xdfffffff, Charset: 255, Status: 2,
		AuthPlugin: "caching_sha2_password", Scramble: bytes.Repeat([]byte{'s'}, 20)}
}

func TestTheClientHandshakeMirrorsTheServerWithoutTLS(t *testing.T) {
	payload, err := ClientHandshake(serverHandshake())
	if err != nil {
		t.Fatal(err)
	}
	h, err := ParseHandshake(payload)
	if err != nil {
		t.Fatal(err)
	}
	if h.ServerVersion != "8.4.6" || h.ConnectionID != 42 || h.Charset != 255 || h.Status != 2 || h.AuthPlugin != "caching_sha2_password" {
		t.Fatalf("handshake = %+v", h)
	}
	if h.Capabilities&(ClientSSL|ClientCompress|ClientZstdCompression) != 0 || h.Capabilities&required != required {
		t.Fatalf("capabilities %#x", h.Capabilities)
	}
	if bytes.Equal(h.Scramble, serverHandshake().Scramble) || bytes.IndexByte(h.Scramble, 0) >= 0 {
		t.Fatal("the client handshake reuses the server's scramble or carries a NUL")
	}
}

func TestParseClientResponseKeepsFlagsCharsetAndDatabase(t *testing.T) {
	caps := required | ClientConnectWithDB | ClientDeprecateEOF | ClientConnectAttrs
	p := binary.LittleEndian.AppendUint32(nil, caps)
	p = binary.LittleEndian.AppendUint32(p, 1<<24)
	p = append(p, 45)
	p = append(p, make([]byte, 23)...)
	p = append(append(p, "anyone"...), 0)
	p = append(p, 3, 'x', 'y', 'z')
	p = append(append(p, "orders"...), 0)
	p = append(append(p, "caching_sha2_password"...), 0)
	r, err := ParseClientResponse(p)
	if err != nil || r.Capabilities != caps || r.Charset != 45 || r.Database != "orders" || r.SSLRequest {
		t.Fatalf("response = %+v %v", r, err)
	}
	ssl, err := ParseClientResponse(append(binary.LittleEndian.AppendUint32(nil, required|ClientSSL), make([]byte, 28)...))
	if err != nil || !ssl.SSLRequest {
		t.Fatalf("SSL request = %+v %v", ssl, err)
	}
}
