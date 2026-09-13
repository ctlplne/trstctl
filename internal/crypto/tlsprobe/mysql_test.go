// SPDX-License-Identifier: MPL-2.0

package tlsprobe

import (
	"bytes"
	"context"
	"encoding/binary"
	"io"
	"net"
	"strings"
	"testing"
	"time"
)

// A complete protocol-10 greeting with MySQL 8's plugin-auth capability. These
// bytes are public protocol metadata; the probe never uses the scramble to log in.
func mysqlGreetingSeed() []byte {
	b := append([]byte{10}, []byte("8.4.11\x00")...)
	b = append(b, 1, 0, 0, 0)
	b = append(b, []byte("12345678\x00")...)
	b = append(b, 0, 0x8a, 255, 2, 0, 8, 0, 21)
	b = append(b, make([]byte, 10)...)
	b = append(b, []byte("abcdefghijkl\x00caching_sha2_password\x00")...)
	if len(b) > 255 {
		panic("fixed MySQL fixture exceeds one-byte length")
	}
	return append([]byte{byte(len(b) & 0xff), 0, 0, 0}, b...)
}

func TestMySQLSSLRequestConsumesOnlyGreetingAndSendsNoCredentials(t *testing.T) {
	greeting := mysqlGreetingSeed()
	suffix := []byte("must remain unread")
	r := bytes.NewReader(append(bytes.Clone(greeting), suffix...))
	request, err := mysqlSSLRequestPacket(r)
	if err != nil {
		t.Fatal(err)
	}
	if len(request) != 36 || !bytes.Equal(request[:4], []byte{32, 0, 0, 1}) {
		t.Fatalf("invalid TLS request: %x", request)
	}
	if flags := binary.LittleEndian.Uint32(request[4:8]); flags != 0x00088a00 {
		t.Fatalf("capabilities = %#x", flags)
	}
	if request[12] != 255 || !bytes.Equal(request[13:], make([]byte, 23)) {
		t.Fatal("request contains data beyond fixed SSLRequest fields")
	}
	left, _ := io.ReadAll(r)
	if !bytes.Equal(left, suffix) {
		t.Fatal("probe consumed bytes beyond the greeting")
	}
}

func TestMySQLSSLRequestRejectsMalformedAndPlaintextPeers(t *testing.T) {
	seed := mysqlGreetingSeed()
	for size := 0; size < len(seed); size++ {
		if _, err := mysqlSSLRequestPacket(bytes.NewReader(seed[:size])); err == nil {
			t.Fatalf("accepted truncated packet at %d", size)
		}
	}
	for name, mutate := range map[string]func([]byte){
		"wrong sequence": func(b []byte) { b[3] = 1 },
		"oversized":      func(b []byte) { b[0] = 1; b[1] = 16 },
		"empty":          func(b []byte) { b[0] = 0 },
		"old protocol":   func(b []byte) { b[4] = 9 },
		"server error":   func(b []byte) { b[4] = 255 },
		"missing terminator": func(b []byte) {
			for i := 5; i < len(b); i++ {
				b[i] = 'x'
			}
		},
		"bad filler":      func(b []byte) { b[24] = 1 },
		"no protocol 4.1": func(b []byte) { b[26] &^= 2 },
		"no TLS":          func(b []byte) { b[26] &^= 8 },
	} {
		t.Run(name, func(t *testing.T) {
			b := bytes.Clone(seed)
			mutate(b)
			if _, err := mysqlSSLRequestPacket(bytes.NewReader(b)); err == nil {
				t.Fatal("accepted malformed or non-TLS greeting")
			}
		})
	}
	denied := []byte{12, 0, 0, 0, 255, 1, 2, 's', 'e', 'c', 'r', 'e', 't', '-', 'x', 'x'}
	if _, err := mysqlSSLRequestPacket(bytes.NewReader(denied)); err == nil || strings.Contains(err.Error(), "secret") {
		t.Fatalf("server error reflected or accepted: %v", err)
	}
}

func TestMySQLSSLRequestBoundsAStalledGreeting(t *testing.T) {
	client, peer := net.Pipe()
	defer func() { _ = client.Close() }()
	defer func() { _ = peer.Close() }()
	ctx, cancel := context.WithTimeout(t.Context(), 30*time.Millisecond)
	defer cancel()
	start := time.Now()
	if err := MySQLSSLRequest(ctx, client); err == nil {
		t.Fatal("stalled greeting accepted")
	}
	if time.Since(start) > time.Second {
		t.Fatal("greeting exceeded the probe deadline")
	}
}

func FuzzMySQLSSLRequestPacket(f *testing.F) {
	f.Add(mysqlGreetingSeed())
	f.Add([]byte{255, 255, 255, 0})
	f.Add([]byte{1, 0, 0, 0, 255})
	f.Fuzz(func(t *testing.T, b []byte) {
		r := bytes.NewReader(b)
		request, err := mysqlSSLRequestPacket(r)
		if err != nil {
			return
		}
		if len(request) != 36 || !bytes.Equal(request[:4], []byte{32, 0, 0, 1}) || !bytes.Equal(request[13:], make([]byte, 23)) {
			t.Fatal("parser emitted a credential-bearing or malformed TLS request")
		}
		flags := binary.LittleEndian.Uint32(request[4:8])
		if flags&0xa00 != 0xa00 || flags & ^uint32(0x00088a00) != 0 {
			t.Fatal("parser permitted plaintext or unsupported capabilities")
		}
		consumed := len(b) - r.Len()
		if consumed > maxMySQLGreeting+4 || consumed < 5 {
			t.Fatal("unbounded greeting")
		}
	})
}
