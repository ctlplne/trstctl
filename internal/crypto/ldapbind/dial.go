// SPDX-License-Identifier: BUSL-1.1

// Package ldapbind establishes TLS and a byte-backed LDAPv3 simple bind before
// handing an authenticated connection to the read-only directory client.
package ldapbind

import (
	"context"
	"crypto/tls"
	"errors"
	"io"
	"net"
	"net/url"
	"strings"
	"sync"
	"syscall"
	"time"
	"trstctl.com/trstctl/internal/crypto/mtls"
	"trstctl.com/trstctl/internal/crypto/secret"
)

// Dial never transmits a password before StartTLS/LDAPS succeeds, never follows
// a referral, and owns no password string. The caller owns/wipes password.
func Dial(ctx context.Context, endpoint, dn string, password []byte, insecureLab bool, control func(string, string, syscall.RawConn) error) (net.Conn, error) {
	parsed, err := url.Parse(endpoint)
	if err != nil || (parsed.Scheme != "ldap" && parsed.Scheme != "ldaps") || parsed.Hostname() == "" || parsed.User != nil || (parsed.Path != "" && parsed.Path != "/") || parsed.RawQuery != "" || parsed.Fragment != "" || control == nil {
		return nil, errors.New("LDAP bind requires one scoped LDAP(S) authority")
	}
	if len(password) == 0 || len(password) > 64<<10 || len(dn) == 0 || len(dn) > 4096 {
		return nil, errors.New("LDAP bind identity or credential exceeds its bound")
	}
	port := parsed.Port()
	if port == "" {
		port = "389"
		if parsed.Scheme == "ldaps" {
			port = "636"
		}
	}
	bounded, cancel := context.WithTimeout(ctx, 20*time.Second)
	dialer := net.Dialer{Timeout: 5 * time.Second, Control: control}
	raw, err := dialer.DialContext(bounded, "tcp", net.JoinHostPort(parsed.Hostname(), port))
	if err != nil {
		cancel()
		return nil, errors.New("LDAP directory connection failed")
	}
	ok := false
	defer func() {
		if !ok {
			_ = raw.Close()
		}
	}()
	deadline, _ := bounded.Deadline()
	_ = raw.SetDeadline(deadline)
	stop, done := make(chan struct{}), make(chan struct{})
	go func() {
		defer close(done)
		select {
		case <-bounded.Done():
			_ = raw.Close()
		case <-stop:
		}
	}()
	defer func() { close(stop); <-done; cancel() }()
	messageID := byte(1)
	if parsed.Scheme == "ldap" {
		oid := tlv(0x80, []byte("1.3.6.1.4.1.1466.20037"))
		request := tlv(0x30, append([]byte{0x02, 0x01, messageID}, tlv(0x77, oid)...))
		if err := writeAll(raw, request); err != nil {
			return nil, errors.New("LDAP StartTLS request failed")
		}
		response, err := readLDAPFrame(raw, maxAuthenticationReply)
		if err != nil {
			return nil, errors.New("LDAP StartTLS response failed")
		}
		result := parseLDAPResult(response, messageID, 0x78)
		secret.Wipe(response)
		if result != nil {
			return nil, errors.New("LDAP StartTLS was not granted")
		}
		messageID++
	}
	config := mtls.DirectoryClientTLSConfig(insecureLab)
	config.ServerName = strings.Trim(parsed.Hostname(), "[]")
	encrypted := tls.Client(raw, config)
	if err := encrypted.HandshakeContext(bounded); err != nil {
		return nil, errors.New("LDAP directory TLS verification or handshake failed")
	}
	packet, err := newBindPacket(messageID, dn, password)
	if err != nil {
		return nil, err
	}
	writeErr := packet.Use(func(wire []byte) error { return writeAll(encrypted, wire) })
	packet.Destroy()
	if writeErr != nil {
		return nil, errors.New("LDAP encrypted bind request failed")
	}
	response, err := readLDAPFrame(encrypted, maxAuthenticationReply)
	if err != nil {
		return nil, errors.New("LDAP encrypted bind response failed")
	}
	result := parseLDAPResult(response, messageID, 0x61)
	secret.Wipe(response)
	if result != nil {
		return nil, result
	}
	_ = encrypted.SetDeadline(time.Time{})
	ok = true
	return &framedConn{Conn: encrypted}, nil
}
func writeAll(writer io.Writer, raw []byte) error {
	for len(raw) > 0 {
		n, err := writer.Write(raw)
		if err != nil {
			return err
		}
		if n <= 0 {
			return io.ErrNoProgress
		}
		raw = raw[n:]
	}
	return nil
}

// framedConn bounds each future LDAP result before the library can allocate an
// attacker-declared BER length. It has one frame in flight and no full-body copy.
type framedConn struct {
	net.Conn
	mu        sync.Mutex
	header    []byte
	remaining int
	total     int
}

func (c *framedConn) Read(out []byte) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if len(out) == 0 {
		return 0, nil
	}
	if len(c.header) == 0 && c.remaining == 0 {
		header, size, err := frameHeader(c.Conn, MaxDirectoryFrameBytes)
		if err != nil {
			return 0, err
		}
		if size+len(header) > maxDirectoryReadBytes-c.total {
			return 0, errors.New("LDAP directory read exceeds its total byte bound")
		}
		c.total += size + len(header)
		c.header = header
		c.remaining = size
	}
	if len(c.header) > 0 {
		n := copy(out, c.header)
		c.header = c.header[n:]
		return n, nil
	}
	n, err := c.Conn.Read(out[:min(len(out), c.remaining)])
	c.remaining -= n
	if n == 0 && err == nil {
		return 0, io.ErrNoProgress
	}
	return n, err
}
