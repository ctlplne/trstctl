// SPDX-License-Identifier: LicenseRef-trstctl-EE

package enterpriseauth

import (
	"errors"
	"net"
	"net/url"
	"time"

	ldap "github.com/go-ldap/ldap/v3"

	"trstctl.com/trstctl/internal/crypto/mtls"
	"trstctl.com/trstctl/internal/netsec"
)

// dialLDAPWithTrust gives every credentialed Enterprise directory call the
// crypto boundary's runtime distrust check. The only plaintext exception is
// the existing local OpenLDAP test mode, and it cannot reach a remote host.
func dialLDAPWithTrust(endpoint string, timeout time.Duration) (*ldap.Conn, error) {
	parsed, err := url.Parse(endpoint)
	if err != nil || parsed.Hostname() == "" {
		return nil, errors.New("enterpriseauth: LDAP endpoint has no authority")
	}
	opts := []ldap.DialOpt{ldap.DialWithDialer(&net.Dialer{Timeout: timeout})}
	switch parsed.Scheme {
	case "ldaps":
		config := mtls.DirectoryClientTLSConfig(false)
		config.ServerName = parsed.Hostname()
		opts = append(opts, ldap.DialWithTLSConfig(config))
	case "ldap":
		if !netsec.IsLoopbackHost(parsed.Hostname()) {
			return nil, errors.New("enterpriseauth: plaintext LDAP is allowed only on loopback")
		}
	default:
		return nil, errors.New("enterpriseauth: LDAP endpoint must use ldap or ldaps")
	}
	return ldap.DialURL(endpoint, opts...)
}
