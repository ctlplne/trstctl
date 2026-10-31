// SPDX-License-Identifier: BUSL-1.1

package kerberos

import (
	"errors"
	"fmt"
	"net"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"sync"

	"github.com/jcmturner/gokrb5/v8/client"
	krbconfig "github.com/jcmturner/gokrb5/v8/config"
	"github.com/jcmturner/gokrb5/v8/keytab"
	"github.com/jcmturner/gokrb5/v8/spnego"
)

// A158: the client side of domain-integrated HTTP authentication. A relay
// answers AD CS Web Enrollment's Negotiate challenge with a Kerberos service
// ticket obtained from a keytab: the domain account's long-term key as the
// domain issued it, loaded from the secret store. No password is ever held,
// typed or sent, and the ticket is minted per request for the endpoint's own
// service principal.

var (
	realmPattern     = regexp.MustCompile(`^[A-Z0-9](?:[A-Z0-9.-]{0,253}[A-Z0-9])?$`)
	principalPattern = regexp.MustCompile(`^[A-Za-z0-9._$-]{1,256}(?:/[A-Za-z0-9._-]{1,256})?$`)
	spnPattern       = regexp.MustCompile(`^[A-Za-z]{1,32}/[A-Za-z0-9.-]{1,253}$`)
)

// ClientConfig names a domain account whose keytab answers HTTP Negotiate
// challenges.
type ClientConfig struct {
	// Realm is the Kerberos realm (the AD domain in upper case).
	Realm string
	// Principal is the account name without the realm, for example
	// svc-trstctl or host/relay01.
	Principal string
	// KDCs are host:port domain controllers. DNS discovery is off: the relay
	// talks only to the KDCs the operator named.
	KDCs []string
	// Keytab is the keytab file's bytes. The authenticator parses it; the
	// caller wipes its own copy.
	Keytab []byte
	// SPN overrides the service principal; empty means HTTP/<request host>.
	SPN string
}

// ClientAuthenticator sets an SPNEGO (Negotiate) Authorization header from a
// keytab-backed Kerberos client. It satisfies the AD CS Web Enrollment
// transport's Authenticator seam.
type ClientAuthenticator struct {
	mu  sync.Mutex
	cl  *client.Client
	spn string
}

// NewClientAuthenticator validates cfg and prepares a client. It performs no
// network I/O: the first request logs in to a KDC.
func NewClientAuthenticator(cfg ClientConfig) (*ClientAuthenticator, error) {
	realm, principal, spn := strings.TrimSpace(cfg.Realm), strings.TrimSpace(cfg.Principal), strings.TrimSpace(cfg.SPN)
	if !realmPattern.MatchString(realm) {
		return nil, errors.New("kerberos: realm must be the upper-case realm name, such as CORP.EXAMPLE")
	}
	if !principalPattern.MatchString(principal) {
		return nil, errors.New("kerberos: principal must be the account name without the realm")
	}
	if spn != "" && !spnPattern.MatchString(spn) {
		return nil, errors.New("kerberos: spn must look like HTTP/host.example")
	}
	if len(cfg.KDCs) == 0 {
		return nil, errors.New("kerberos: at least one KDC host:port is required")
	}
	var conf strings.Builder
	conf.WriteString("[libdefaults]\n default_realm = " + realm + "\n dns_lookup_kdc = false\n dns_lookup_realm = false\n udp_preference_limit = 1\n[realms]\n " + realm + " = {\n")
	for _, kdc := range cfg.KDCs {
		host, port, err := net.SplitHostPort(strings.TrimSpace(kdc))
		if err != nil || host == "" || strings.ContainsAny(host, " \t\r\n{}=") {
			return nil, fmt.Errorf("kerberos: KDC %q must be host:port", kdc)
		}
		if n, err := strconv.Atoi(port); err != nil || n < 1 || n > 65535 {
			return nil, fmt.Errorf("kerberos: KDC %q has an invalid port", kdc)
		}
		conf.WriteString("  kdc = " + net.JoinHostPort(host, port) + "\n")
	}
	conf.WriteString(" }\n")
	krb5, err := krbconfig.NewFromString(conf.String())
	if err != nil {
		return nil, errors.New("kerberos: client configuration is invalid")
	}
	kt := keytab.New()
	if err := kt.Unmarshal(cfg.Keytab); err != nil {
		return nil, errors.New("kerberos: keytab is not a valid keytab file")
	}
	found := false
	for _, entry := range kt.Entries {
		if entry.Principal.Realm == realm && strings.Join(entry.Principal.Components, "/") == principal {
			found = true
			break
		}
	}
	if !found {
		return nil, fmt.Errorf("kerberos: keytab has no key for %s@%s", principal, realm)
	}
	return &ClientAuthenticator{cl: client.NewWithKeytab(principal, realm, kt, krb5, client.DisablePAFXFAST(true)), spn: spn}, nil
}

// Authorize obtains a service ticket for the endpoint and sets the Negotiate
// header. A single leg suffices: the ticket is the authentication.
func (a *ClientAuthenticator) Authorize(req *http.Request, _ string) error {
	if a == nil || a.cl == nil {
		return errors.New("kerberos: authenticator is not configured")
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	if err := a.cl.AffirmLogin(); err != nil {
		return errors.New("kerberos: the KDC refused the keytab login")
	}
	spn := a.spn
	if spn == "" {
		spn = "HTTP/" + req.URL.Hostname()
	}
	if err := spnego.SetSPNEGOHeader(a.cl, req, spn); err != nil {
		return fmt.Errorf("kerberos: no service ticket for %s", spn)
	}
	return nil
}

// Scheme names the HTTP authentication scheme.
func (a *ClientAuthenticator) Scheme() string { return "Negotiate" }

// Destroy drops the client's tickets and keys.
func (a *ClientAuthenticator) Destroy() {
	if a == nil {
		return
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.cl != nil {
		a.cl.Destroy()
		a.cl = nil
	}
}
