// SPDX-License-Identifier: BUSL-1.1
package ldapbind

import (
	"context"
	"errors"
	"net"
	"time"

	"trstctl.com/trstctl/internal/crypto/mtls"
	"trstctl.com/trstctl/internal/crypto/secret"
)

// PinnedTLS is a fixed LDAPS route. A supplied CA replaces system roots.
type PinnedTLS struct {
	Address, ServerName string
	CAPEM               []byte
}

// DialPinned performs exactly one byte-backed bind after certificate validation.
// The returned bounded connection belongs to the caller; it follows no referrals.
func DialPinned(ctx context.Context, route PinnedTLS, dn string, password []byte) (net.Conn, error) {
	bounded, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	packet, err := newBindPacket(1, dn, password)
	if err != nil {
		return nil, err
	}
	defer packet.Destroy()
	raw, err := mtls.DialVerifiedTCP(bounded, route.Address, route.ServerName, route.CAPEM)
	if err != nil {
		return nil, errors.New("LDAP verified TLS connection failed")
	}
	accepted := false
	defer func() {
		if !accepted {
			_ = raw.Close()
		}
	}()
	deadline, _ := bounded.Deadline()
	_ = raw.SetDeadline(deadline)
	stop := context.AfterFunc(bounded, func() { _ = raw.Close() })
	defer stop()
	if err = packet.Use(func(wire []byte) error { return writeAll(raw, wire) }); err != nil {
		return nil, errors.New("LDAP encrypted bind request failed")
	}
	response, err := readLDAPFrame(raw, maxAuthenticationReply)
	if err != nil {
		return nil, errors.New("LDAP encrypted bind response failed")
	}
	defer secret.Wipe(response)
	if err = parseLDAPResult(response, 1, 0x61); err != nil {
		return nil, err
	}
	if bounded.Err() != nil {
		return nil, bounded.Err()
	}
	accepted = true
	return &framedConn{Conn: raw}, nil
}

// ResetADPassword makes one administrative unicodePwd replacement. Only ASCII
// generated passwords are accepted; UTF-16LE is encoded directly in locked memory.
func ResetADPassword(ctx context.Context, route PinnedTLS, adminDN string, adminPassword []byte, accountDN string, password []byte) error {
	packet, err := newADPasswordPacket(accountDN, password)
	if err != nil {
		return err
	}
	defer packet.Destroy()
	bounded, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	raw, err := DialPinned(bounded, route, adminDN, adminPassword)
	if err != nil {
		return err
	}
	defer func() { _ = raw.Close() }()
	stop := context.AfterFunc(bounded, func() { _ = raw.Close() })
	defer stop()
	if err = packet.Use(func(wire []byte) error { return writeAll(raw, wire) }); err != nil {
		return errors.New("AD encrypted password reset request failed")
	}
	response, err := readLDAPFrame(raw, maxAuthenticationReply)
	if err != nil {
		return errors.New("AD encrypted password reset response failed")
	}
	defer secret.Wipe(response)
	return parseLDAPResult(response, 2, 0x67)
}

func newADPasswordPacket(dn string, password []byte) (*secret.Buffer, error) {
	if len(dn) == 0 || len(dn) > 4096 || len(password) < 16 || len(password) > 1024 {
		return nil, errors.New("AD password reset exceeds its bounds")
	}
	for _, v := range password {
		if v < 32 || v > 126 {
			return nil, errors.New("AD generated password must be printable ASCII")
		}
	}
	size := (len(password) + 2) * 2
	header := func(tag byte, n int) []byte { return append([]byte{tag}, lengthBytes(n)...) }
	value := header(0x04, size)
	values := header(0x31, len(value)+size)
	name := tlv(0x04, []byte("unicodePwd"))
	attribute := header(0x30, len(name)+len(values)+len(value)+size)
	change := header(0x30, 3+len(attribute)+len(name)+len(values)+len(value)+size)
	changes := header(0x30, len(change)+3+len(attribute)+len(name)+len(values)+len(value)+size)
	object := tlv(0x04, []byte(dn))
	operation := header(0x66, len(object)+len(changes)+len(change)+3+len(attribute)+len(name)+len(values)+len(value)+size)
	outer := header(0x30, 3+len(operation)+len(object)+len(changes)+len(change)+3+len(attribute)+len(name)+len(values)+len(value)+size)
	prefix := append(outer, 0x02, 0x01, 0x02)
	prefix = append(prefix, operation...)
	prefix = append(prefix, object...)
	prefix = append(prefix, changes...)
	prefix = append(prefix, change...)
	prefix = append(prefix, 0x0a, 0x01, 0x02)
	prefix = append(prefix, attribute...)
	prefix = append(prefix, name...)
	prefix = append(prefix, values...)
	prefix = append(prefix, value...)
	packet, err := secret.New(len(prefix) + size)
	if err != nil {
		return nil, err
	}
	copy(packet.Bytes(), prefix)
	dest := packet.Bytes()[len(prefix):]
	dest[0] = '"'
	for i, v := range password {
		dest[(i+1)*2] = v
	}
	dest[len(dest)-2] = '"'
	return packet, nil
}
