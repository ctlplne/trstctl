// SPDX-License-Identifier: BUSL-1.1

package config

import (
	"errors"
	"net/url"
	"strings"
)

// ValidateExternalSecurity checks the connection before any NATS dial. This
// also serves direct event-log callers that do not load the full app config.
func (n NATS) ValidateExternalSecurity() error {
	if n.URL == "" {
		return errors.New("nats.url is required for an external event log")
	}
	scheme := ""
	for _, raw := range strings.Split(n.URL, ",") {
		u, err := url.Parse(strings.TrimSpace(raw))
		if err != nil || u.Host == "" || (u.Scheme != "tls" && u.Scheme != "nats") ||
			u.Path != "" || u.RawQuery != "" || u.Fragment != "" {
			return errors.New("nats.url must contain only tls://host:port endpoints")
		}
		if u.User != nil {
			return errors.New("nats.url must not contain URL credentials; mount a client identity file")
		}
		if scheme != "" && u.Scheme != scheme {
			return errors.New("external NATS endpoints must use one TLS scheme")
		}
		scheme = u.Scheme
		if u.Scheme != "tls" && !n.AllowPlaintextDev {
			return errors.New("external nats.url requires tls://; plaintext needs nats.allow_plaintext_dev=true for evaluation")
		}
	}
	if (n.TLSCertFile == "") != (n.TLSKeyFile == "") {
		return errors.New("nats.tls_cert_file and nats.tls_key_file must be supplied together")
	}
	if scheme != "tls" && (n.TLSCAFile != "" || n.TLSCertFile != "") {
		return errors.New("NATS TLS files require tls:// endpoints")
	}
	identities := 0
	for _, present := range []bool{n.CredentialsFile != "", n.NKeySeedFile != "", n.TLSCertFile != ""} {
		if present {
			identities++
		}
	}
	if identities > 1 {
		return errors.New("external NATS accepts one client identity: credentials, NKey seed, or mTLS certificate")
	}
	if identities == 0 && !n.AllowPlaintextDev {
		return errors.New("external NATS requires a client identity file (credentials, NKey seed, or mTLS certificate)")
	}
	return nil
}
