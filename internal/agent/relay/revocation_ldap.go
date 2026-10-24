// SPDX-License-Identifier: BUSL-1.1

package relay

import (
	"context"
	"errors"
	"net"
	"net/url"
	"strings"
	"time"

	"github.com/go-ldap/ldap/v3"

	"trstctl.com/trstctl/internal/crypto/mtls"
	"trstctl.com/trstctl/internal/revocationhealth"
)

// LDAP CRL distribution points (A107). AD CS publishes each CA's CRL as the
// certificateRevocationList attribute of an entry under the forest's
// configuration partition and names it in certificates as
// ldap:///CN=<CA>,CN=<host>,CN=CDP,...: no host, the client's own directory.
// A relay reads it through the tenant's AD CS discovery binding: it connects
// to the binding's directory (never a host a certificate names), always under
// TLS because it binds with a credential, reads only entries under the
// binding's configuration DN, and evaluates the bytes as it would an HTTP CRL.

var (
	errLDAPCRLEntryMissing = errors.New("the directory has no entry at that distribution point")
	errLDAPCRLMissing      = errors.New("the entry carries no certificateRevocationList")
)

// crlDirectory reads one entry's CRL from a bound directory.
type crlDirectory interface {
	ReadCRL(ctx context.Context, dn string) ([]byte, error)
	Close() error
}

// openCRLDirectory dials and binds; tests replace it with a stand-in.
var openCRLDirectory = dialCRLDirectory

type ldapCRLDirectory struct {
	conn *ldap.Conn
}

func dialCRLDirectory(binding revocationhealth.LDAPBinding, password []byte) (crlDirectory, error) {
	tlsConfig := mtls.DirectoryClientTLSConfig(binding.InsecureSkipVerify)
	conn, err := ldap.DialURL(binding.URL,
		ldap.DialWithDialer(&net.Dialer{Timeout: adcsDialTimeout}),
		ldap.DialWithTLSConfig(tlsConfig))
	if err != nil {
		return nil, errors.New("could not connect to the directory: " + summarizeTransportError(err))
	}
	if strings.HasPrefix(strings.ToLower(binding.URL), "ldap://") {
		// The CRL is public; the bind credential is not. A plain connection
		// is upgraded or the bind does not happen.
		if err := conn.StartTLS(tlsConfig); err != nil {
			_ = conn.Close()
			return nil, errors.New("the directory would not start TLS, so the relay did not bind")
		}
	}
	if err := conn.Bind(binding.BindDN, string(password)); err != nil {
		_ = conn.Close()
		return nil, errors.New("the directory refused the bind")
	}
	conn.SetTimeout(revocationFetchTimeout)
	return &ldapCRLDirectory{conn: conn}, nil
}

func (d *ldapCRLDirectory) ReadCRL(ctx context.Context, dn string) ([]byte, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	res, err := d.conn.Search(ldap.NewSearchRequest(dn, ldap.ScopeBaseObject, ldap.NeverDerefAliases, 1,
		int(revocationFetchTimeout/time.Second), false, "(objectClass=*)",
		[]string{"certificateRevocationList;binary", "certificateRevocationList"}, nil))
	if err != nil {
		if ldap.IsErrorWithCode(err, ldap.LDAPResultNoSuchObject) {
			return nil, errLDAPCRLEntryMissing
		}
		return nil, err
	}
	if len(res.Entries) != 1 {
		return nil, errLDAPCRLEntryMissing
	}
	for _, attr := range res.Entries[0].Attributes {
		if !strings.HasPrefix(strings.ToLower(attr.Name), "certificaterevocationlist") || len(attr.ByteValues) == 0 {
			continue
		}
		value := attr.ByteValues[0]
		if len(value) > revocationBodyLimit {
			return nil, errRevocationBodyTooLarge
		}
		return append([]byte(nil), value...), nil
	}
	return nil, errLDAPCRLMissing
}

func (d *ldapCRLDirectory) Close() error { return d.conn.Close() }

// probeLDAPCRL reads one LDAP distribution point through the batch's binding.
// directory is nil when the dial or bind failed; directoryErr then says why.
func probeLDAPCRL(ctx context.Context, binding *revocationhealth.LDAPBinding, directory crlDirectory, directoryErr error,
	target revocationhealth.Target, staleWithin time.Duration, finding RevocationFinding) RevocationFinding {
	if binding == nil {
		finding.Status = RevocationUnparseable
		finding.DetailCode = "ldap_binding_missing"
		finding.Detail = "no AD CS discovery source covers this LDAP distribution point; add one for its forest and its relay reads it"
		return finding
	}
	dn, err := revocationhealth.LDAPEndpointDN(target.Endpoint)
	if err != nil {
		finding.Status = RevocationUnparseable
		finding.DetailCode = "invalid_endpoint"
		finding.Detail = "the LDAP distribution point names no entry"
		return finding
	}
	if parsed, err := url.Parse(target.Endpoint); err == nil && parsed.Hostname() != "" {
		if bound, err := url.Parse(binding.URL); err != nil || !strings.EqualFold(parsed.Hostname(), bound.Hostname()) {
			finding.Status = RevocationUnparseable
			finding.DetailCode = "ldap_host_not_bound"
			finding.Detail = "the distribution point names a directory host the AD CS binding does not; the relay reads only the bound directory"
			return finding
		}
	}
	if !revocationhealth.LDAPDNWithin(dn, binding.ConfigurationDN) {
		finding.Status = RevocationUnparseable
		finding.DetailCode = "ldap_dn_outside_binding"
		finding.Detail = "the distribution point lies outside the AD CS binding's configuration partition"
		return finding
	}
	if directory == nil {
		finding.Status = RevocationUnreachable
		finding.DetailCode = "ldap_bind_failed"
		finding.Detail = "the relay could not read the directory"
		if directoryErr != nil {
			finding.Detail += ": " + directoryErr.Error()
		}
		return finding
	}
	started := time.Now()
	body, err := directory.ReadCRL(ctx, dn)
	finding.LatencyMS = time.Since(started).Milliseconds()
	switch {
	case errors.Is(err, errRevocationBodyTooLarge):
		finding.Status = RevocationUnparseable
		finding.DetailCode = "body_too_large"
		finding.Detail = "the CRL exceeds the bounded relay response size"
		return finding
	case errors.Is(err, errLDAPCRLEntryMissing):
		finding.Status = RevocationUnreachable
		finding.DetailCode = "ldap_entry_missing"
		finding.Detail = errLDAPCRLEntryMissing.Error()
		return finding
	case errors.Is(err, errLDAPCRLMissing):
		finding.Status = RevocationUnparseable
		finding.DetailCode = "ldap_crl_missing"
		finding.Detail = errLDAPCRLMissing.Error()
		return finding
	case err != nil:
		finding.Status = RevocationUnreachable
		finding.DetailCode = "ldap_search_failed"
		finding.Detail = "the directory search failed"
		return finding
	}
	return evaluateCRL(body, target, staleWithin, finding)
}
