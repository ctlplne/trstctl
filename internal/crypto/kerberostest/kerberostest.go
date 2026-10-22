// SPDX-License-Identifier: BUSL-1.1

// Package kerberostest mints Kerberos service keytabs and SPNEGO tokens for
// tests outside the cryptography boundary, the way samltest does for SAML:
// callers get bytes and headers, never ticket or key primitives.
package kerberostest

import (
	"encoding/base64"
	"fmt"
	"time"

	"github.com/jcmturner/gokrb5/v8/client"
	krbconfig "github.com/jcmturner/gokrb5/v8/config"
	"github.com/jcmturner/gokrb5/v8/iana/etypeID"
	"github.com/jcmturner/gokrb5/v8/iana/flags"
	"github.com/jcmturner/gokrb5/v8/keytab"
	"github.com/jcmturner/gokrb5/v8/messages"
	"github.com/jcmturner/gokrb5/v8/spnego"
	"github.com/jcmturner/gokrb5/v8/types"
)

// ServiceKeytab returns the serialized keytab a KDC would export for the
// service principal (for example HTTP/trstctl.lab.test) in realm, keyed from
// password with AES-256.
func ServiceKeytab(servicePrincipal, realm, password string) ([]byte, error) {
	kt := keytab.New()
	if err := kt.AddEntry(servicePrincipal, realm, password, time.Now().Add(-time.Hour), 1, etypeID.AES256_CTS_HMAC_SHA1_96); err != nil {
		return nil, err
	}
	return kt.Marshal()
}

// NegotiateHeader mints the service ticket the KDC would issue to user for
// the service principal, keyed from the same password as ServiceKeytab, and
// wraps it in the SPNEGO token a browser sends: the Authorization header
// value. start is the ticket's authentication time; a start far in the past
// yields an expired ticket.
func NegotiateHeader(servicePrincipal, realm, password, user string, start time.Time) (string, error) {
	kt := keytab.New()
	if err := kt.AddEntry(servicePrincipal, realm, password, start.Add(-time.Hour), 1, etypeID.AES256_CTS_HMAC_SHA1_96); err != nil {
		return "", err
	}
	cname := types.NewPrincipalName(1, user)
	sname := types.NewPrincipalName(3, servicePrincipal)
	ticketFlags := types.NewKrbFlags()
	types.SetFlag(&ticketFlags, flags.Forwardable)
	tkt, sessionKey, err := messages.NewTicket(cname, realm, sname, realm, ticketFlags, kt, etypeID.AES256_CTS_HMAC_SHA1_96, 1,
		start, start, start.Add(time.Hour), start.Add(time.Hour))
	if err != nil {
		return "", err
	}
	conf, err := krbconfig.NewFromString("[libdefaults]\n default_realm = " + realm + "\n")
	if err != nil {
		return "", err
	}
	cl := client.NewWithPassword(user, realm, "unused", conf)
	nt, err := spnego.NewNegTokenInitKRB5(cl, tkt, sessionKey)
	if err != nil {
		return "", err
	}
	token := spnego.SPNEGOToken{Init: true, NegTokenInit: nt}
	raw, err := token.Marshal()
	if err != nil {
		return "", fmt.Errorf("marshal SPNEGO token: %w", err)
	}
	return "Negotiate " + base64.StdEncoding.EncodeToString(raw), nil
}
