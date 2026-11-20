// SPDX-License-Identifier: BUSL-1.1

package dbdsn

import (
	"errors"
	"net"
	"net/netip"
	"slices"
)

const (
	GatewayRouteRevision = 1
	GatewayPlain         = "plaintext"
	GatewayPreferTLS     = "prefer-tls"
	GatewayVerifiedTLS   = "verified-tls"
	OperatorFileSource   = "operator-file"
	TenantStoredSource   = "tenant-stored"
)

var ErrGatewayRoute = errors.New("database gateway requires a current, reviewed connection route")

// GatewayRoute is the public connection authority recorded with one new job.
// For MongoDB, Database is the credential's authentication database.
type GatewayRoute struct {
	Revision     int      `json:"revision"`
	ProviderID   string   `json:"provider_id"`
	Hosts        []string `json:"hosts"`
	Database     string   `json:"database"`
	TLS          string   `json:"tls"`
	Source       string   `json:"source"`
	PrivateCIDRs []string `json:"private_cidrs,omitempty"`
}

func GatewayDriver(kind string) string {
	switch kind {
	case "postgres":
		return Postgres
	case Mongo, MySQL:
		return kind
	default:
		return ""
	}
}

func (r *GatewayRoute) Validate(driver string, explicitTrust bool) error {
	if r == nil || r.Revision != GatewayRouteRevision || r.ProviderID == "" || !identifier(r.ProviderID, 128) ||
		r.Database == "" || !identifier(r.Database, 256) || len(r.Hosts) == 0 || len(r.Hosts) > MaxHosts ||
		r.Source != OperatorFileSource && r.Source != TenantStoredSource || len(r.PrivateCIDRs) > MaxOptions {
		return ErrGatewayRoute
	}
	switch driver {
	case Postgres:
		if len(r.Hosts) != 1 || r.TLS != GatewayPlain && r.TLS != GatewayPreferTLS && r.TLS != GatewayVerifiedTLS {
			return ErrGatewayRoute
		}
	case Mongo:
		if r.TLS != GatewayPlain && r.TLS != GatewayVerifiedTLS {
			return ErrGatewayRoute
		}
	case MySQL:
		if len(r.Hosts) != 1 || r.TLS != GatewayPlain {
			return ErrGatewayRoute
		}
	default:
		return ErrGatewayRoute
	}
	if explicitTrust && r.TLS != GatewayVerifiedTLS {
		return ErrTrust
	}
	seen := make(map[string]bool, len(r.Hosts))
	for _, hostport := range r.Hosts {
		host, port, err := net.SplitHostPort(hostport)
		canonical, canonicalErr := TCPAddress(host, port)
		if err != nil || canonicalErr != nil || canonical != hostport || seen[hostport] {
			return ErrGatewayRoute
		}
		seen[hostport] = true
	}
	for i, raw := range r.PrivateCIDRs {
		prefix, err := netip.ParsePrefix(raw)
		if err != nil || prefix.Bits() == 0 || prefix != prefix.Masked() || raw != prefix.String() ||
			i > 0 && r.PrivateCIDRs[i-1] >= raw {
			return ErrGatewayRoute
		}
	}
	return nil
}

func (r GatewayRoute) Equal(other GatewayRoute) bool {
	return r.Revision == other.Revision && r.ProviderID == other.ProviderID && r.Database == other.Database &&
		r.TLS == other.TLS && r.Source == other.Source && slices.Equal(r.Hosts, other.Hosts) && slices.Equal(r.PrivateCIDRs, other.PrivateCIDRs)
}

// CheckCredential admits the exact bytes that will be sent to sign-in.
// An omitted initial database uses the job's reviewed value.
func (r GatewayRoute) CheckCredential(driver string, value []byte, explicitTrust bool) error {
	if err := r.Validate(driver, explicitTrust); err != nil {
		return err
	}
	target, err := Parse(driver, value, Gateway)
	if err != nil {
		return err
	}
	defer target.Wipe()
	database := target.Database
	if driver == Mongo {
		if database != "" && database != r.Database {
			return ErrGatewayRoute
		}
		database = target.AuthSource
	}
	mode, err := GatewayTLSMode(driver, target, explicitTrust)
	if err != nil || mode != r.TLS || !slices.Equal(r.Hosts, target.Hosts) || database != "" && database != r.Database {
		return ErrGatewayRoute
	}
	return nil
}

// GatewayTLSMode maps the admitted native options to the sign-in behavior the
// gateway can actually enforce, which differs from a database driver.
func GatewayTLSMode(driver string, target Target, explicitTrust bool) (string, error) {
	switch driver {
	case Postgres:
		for key, value := range target.Options {
			if !postgresGatewayOption(key, value) {
				return "", ErrGatewayRoute
			}
		}
		switch target.Options["sslmode"] {
		case "disable", "allow":
			if explicitTrust || target.SystemRoots {
				return "", ErrTrust
			}
			return GatewayPlain, nil
		case "", "prefer":
			if !explicitTrust && !target.SystemRoots {
				return GatewayPreferTLS, nil
			}
		}
		return GatewayVerifiedTLS, nil
	case Mongo:
		if target.SRV || target.Options["loadbalanced"] == "true" {
			return "", ErrGatewayRoute
		}
		if target.Options["tls"] == "true" {
			return GatewayVerifiedTLS, nil
		}
		if !explicitTrust {
			return GatewayPlain, nil
		}
	case MySQL:
		if !explicitTrust {
			return GatewayPlain, nil
		}
	}
	return "", ErrTrust
}

func postgresGatewayOption(key, value string) bool {
	switch key {
	case "sslnegotiation":
		return value == "postgres"
	case "target_session_attrs", "search_path", "statement_timeout", "lock_timeout":
		return false
	default:
		return true
	}
}
