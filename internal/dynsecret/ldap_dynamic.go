// SPDX-License-Identifier: BUSL-1.1

package dynsecret

import (
	"context"
	"errors"
	"fmt"
	"math"
	"time"

	ber "github.com/go-asn1-ber/asn1-ber"
	"github.com/go-ldap/ldap/v3"
)

// A239-L2: LDAP leases that expire in the directory itself. With
// dynamic_entries, a lease's entry is an RFC 2589 dynamic object: it is
// created with objectClass dynamicObject and given the lease's time to live
// with the Refresh extended operation, which a renewal repeats. A directory
// that implements RFC 2589 (OpenLDAP's dds overlay) deletes the entry when its
// time to live runs out, so the lease ends there even when trstctl is down or
// its revocation never runs.

// ldapRefreshOID is RFC 2589's Refresh extended operation.
const ldapRefreshOID = "1.3.6.1.4.1.1466.101.119.1"

// ldapRefreshMaxTTL is the largest time to live RFC 2589 carries (an INTEGER
// of 31 bits, in seconds).
const ldapRefreshMaxTTL = math.MaxInt32

// ldapExtendedConn is a directory connection that sends extended operations
// (go-ldap's *Conn).
type ldapExtendedConn interface {
	Extended(*ldap.ExtendedRequest) (*ldap.ExtendedResponse, error)
}

// ErrLDAPDynamicTTLShortened is a directory that granted a dynamic entry
// less time to live than the lease it backs: it would end the lease early.
var ErrLDAPDynamicTTLShortened = errors.New("dynsecret ldap: the directory granted the dynamic entry less time than the lease")

// refreshEntry asks the directory to keep dynamic entry dn for ttl (the
// Refresh request's value is SEQUENCE { entryName [0] LDAPDN, requestTtl [1]
// INTEGER }, as OpenLDAP's ldap_refresh sends it) and returns the time to
// live the directory granted.
func refreshEntry(conn ldapConn, dn string, ttl time.Duration) (time.Duration, error) {
	ext, ok := conn.(ldapExtendedConn)
	if !ok {
		return 0, errors.New("dynsecret ldap: the directory connection cannot send the RFC 2589 refresh")
	}
	seconds := int64(math.Ceil(ttl.Seconds()))
	if seconds < 1 {
		seconds = 1
	}
	if seconds > ldapRefreshMaxTTL {
		seconds = ldapRefreshMaxTTL
	}
	request := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence, nil, "Refresh request")
	request.AppendChild(ber.NewString(ber.ClassContext, ber.TypePrimitive, 0, dn, "entryName"))
	request.AppendChild(ber.NewInteger(ber.ClassContext, ber.TypePrimitive, 1, seconds, "requestTtl"))
	value := ber.NewString(ber.ClassContext, ber.TypePrimitive, 1, string(request.Bytes()), "requestValue")
	response, err := ext.Extended(ldap.NewExtendedRequest(ldapRefreshOID, value))
	if err != nil {
		return 0, fmt.Errorf("dynsecret ldap: the directory refused the dynamic entry refresh: %w", err)
	}
	granted, err := refreshGrantedTTL(response)
	if err != nil {
		return 0, err
	}
	return time.Duration(granted) * time.Second, nil
}

// refreshGrantedTTL reads the Refresh response's value: SEQUENCE {
// responseTtl [1] INTEGER }.
func refreshGrantedTTL(response *ldap.ExtendedResponse) (int64, error) {
	if response == nil || response.Value == nil {
		return 0, errors.New("dynsecret ldap: the refresh response names no time to live")
	}
	packet, err := ber.DecodePacketErr(response.Value.Data.Bytes())
	if err != nil || len(packet.Children) != 1 || packet.Children[0].Tag != 1 {
		return 0, errors.New("dynsecret ldap: the refresh response is malformed")
	}
	raw := packet.Children[0].Data.Bytes()
	if len(raw) == 0 || len(raw) > 5 || raw[0]&0x80 != 0 {
		return 0, errors.New("dynsecret ldap: the refresh response's time to live is malformed")
	}
	var ttl int64
	for _, b := range raw {
		ttl = ttl<<8 | int64(b)
	}
	return ttl, nil
}

// RefreshCredential moves a dynamic lease entry's expiry with its lease
// (A239-L2): the directory keeps the entry for ttl more. A directory that
// would keep it for less refuses the renewal rather than end the lease early.
func (b *LDAPBackend) RefreshCredential(ctx context.Context, ref string, ttl time.Duration) error {
	if !b.dynamicEntries {
		return nil
	}
	if !b.underUsersDN(ref) || b.isRotationAccount(ref) {
		return errors.New("dynsecret ldap: the lease reference is not a dynamic entry this provider created")
	}
	conn, err := b.connect(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = conn.Close() }()
	granted, err := refreshEntry(conn, ref, ttl)
	if err != nil {
		return err
	}
	if granted < ttl.Truncate(time.Second) {
		return fmt.Errorf("%w (granted %s of %s)", ErrLDAPDynamicTTLShortened, granted, ttl.Truncate(time.Second))
	}
	return nil
}
