// SPDX-License-Identifier: BUSL-1.1
package ldapbind

import (
	"bytes"
	"context"
	ber "github.com/go-asn1-ber/asn1-ber"
	"io"
	"net"
	"syscall"
	"testing"
	"testing/quick"
	"time"
	"trstctl.com/trstctl/internal/crypto/secret"
)

func TestByteBindPacketMatchesReferenceBERDecoder(t *testing.T) {
	if err := quick.Check(func(input []byte) bool {
		if len(input) == 0 {
			input = []byte{0}
		}
		packet, err := newBindPacket(1, "CN=Reader,DC=example", input)
		if err != nil {
			return false
		}
		defer packet.Destroy()
		decoded, err := ber.DecodePacketErr(packet.Bytes())
		if err != nil || len(decoded.Children) != 2 {
			return false
		}
		operation := decoded.Children[1]
		return operation.Tag == 0 && len(operation.Children) == 3 && operation.Children[0].Value == int64(3) && bytes.Equal(operation.Children[2].Data.Bytes(), input)
	}, nil); err != nil {
		t.Fatal(err)
	}
}
func TestByteBindPacketLongFormLengths(t *testing.T) {
	for _, size := range []int{1, 127, 128, 4096, 64 << 10} {
		input := bytes.Repeat([]byte{0xa5}, size)
		packet, err := newBindPacket(2, "CN=Reader,DC=example", input)
		if err != nil {
			t.Fatal(err)
		}
		decoded, err := ber.DecodePacketErr(packet.Bytes())
		if err != nil || len(decoded.Children) != 2 || !bytes.Equal(decoded.Children[1].Children[2].Data.Bytes(), input) {
			packet.Destroy()
			t.Fatalf("LDAP bind length %d changed: %v", size, err)
		}
		packet.Destroy()
		secret.Wipe(input)
	}
}
func TestStartTLSRefusalNeverTransmitsABind(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = listener.Close() }()
	done := make(chan error, 1)
	go func() {
		conn, err := listener.Accept()
		if err != nil {
			done <- err
			return
		}
		defer func() { _ = conn.Close() }()
		_ = conn.SetDeadline(time.Now().Add(time.Second))
		request, err := readLDAPFrame(conn, 4096)
		if err != nil {
			done <- err
			return
		}
		if !bytes.Contains(request, []byte("1.3.6.1.4.1.1466.20037")) {
			done <- io.ErrUnexpectedEOF
			return
		}
		reply := tlv(0x30, append([]byte{0x02, 0x01, 0x01}, tlv(0x78, []byte{0x0a, 0x01, 52, 0x04, 0, 0x04, 0})...))
		if err := writeAll(conn, reply); err != nil {
			done <- err
			return
		}
		var extra [1]byte
		_, err = conn.Read(extra[:])
		switch err {
		case io.EOF:
			err = nil
		case nil:
			err = io.ErrUnexpectedEOF
		}
		done <- err
	}()
	password := []byte("owned-disposable-ldap-canary")
	defer secret.Wipe(password)
	control := func(string, string, syscall.RawConn) error { return nil }
	if conn, err := Dial(t.Context(), "ldap://"+listener.Addr().String(), "CN=Reader,DC=example", password, false, control); err == nil {
		_ = conn.Close()
		t.Fatal("refused StartTLS proceeded to bind")
	}
	if err := <-done; err != nil {
		t.Fatalf("refusal did not close before authentication: %v", err)
	}
}
func TestLDAPDialCancellationJoinsItsConnection(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = listener.Close() }()
	done := make(chan error, 1)
	go func() {
		conn, err := listener.Accept()
		if err != nil {
			done <- err
			return
		}
		defer func() { _ = conn.Close() }()
		_ = conn.SetDeadline(time.Now().Add(time.Second))
		_, err = readLDAPFrame(conn, 4096)
		if err != nil {
			done <- err
			return
		}
		var extra [1]byte
		_, err = conn.Read(extra[:])
		if err == io.EOF {
			err = nil
		}
		done <- err
	}()
	ctx, cancel := context.WithTimeout(t.Context(), 100*time.Millisecond)
	defer cancel()
	if conn, err := Dial(ctx, "ldap://"+listener.Addr().String(), "CN=Reader,DC=example", []byte("disposable"), false, func(string, string, syscall.RawConn) error { return nil }); err == nil {
		_ = conn.Close()
		t.Fatal("cancelled authentication succeeded")
	}
	if err := <-done; err != nil {
		t.Fatalf("cancelled client retained a live directory connection: %v", err)
	}
}
func TestDirectoryReadHasATotalByteBudget(t *testing.T) {
	client, server := net.Pipe()
	bounded := &framedConn{Conn: client, total: maxDirectoryReadBytes - 1}
	done := make(chan struct{})
	go func() { defer close(done); _, _ = server.Write([]byte{0x30, 0x03, 0x02, 0x01, 0x01}) }()
	var out [8]byte
	if _, err := bounded.Read(out[:]); err == nil {
		t.Fatal("cumulative LDAP reply budget was ignored")
	}
	_ = client.Close()
	_ = server.Close()
	<-done
}
