// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"trstctl.com/trstctl/internal/crypto/dbdsn"
	"trstctl.com/trstctl/internal/crypto/secret"
	"trstctl.com/trstctl/internal/dynsecret"
	"trstctl.com/trstctl/internal/netsec"
	"trstctl.com/trstctl/internal/rotation"
	"trstctl.com/trstctl/internal/safefile"
)

var errAdminDSN = errors.New("server: administrator connection reference is unavailable or exceeds its byte bound")

func (o *configuredDynamicBackendOpener) databaseConnection() ([]byte, *dynsecret.DatabaseTransport, error) {
	dsn, err := o.resolve(o.provider.cfg.AdminDSNRef)
	if err != nil {
		return nil, nil, err
	}
	target, err := dbdsn.Parse(o.provider.cfg.Type, dsn, dbdsn.Admin)
	if err != nil {
		return nil, nil, err
	}
	defer target.Wipe()
	transport, err := o.provider.databaseTransport(o.ctx, target)
	if err != nil {
		return nil, nil, err
	}
	return dsn, transport, nil
}

func (p *configuredDynamicProvider) databaseTransport(ctx context.Context, target dbdsn.Target) (*dynsecret.DatabaseTransport, error) {
	policy := netsec.DatabaseDialOptions{
		OperatorFile: strings.HasPrefix(strings.TrimSpace(p.cfg.AdminDSNRef), "file:"),
		CheckName: func(host string) error {
			return p.guard.CheckRequestURL(&url.URL{Scheme: "https", Host: net.JoinHostPort(host, "443")})
		},
	}
	if p.cfg.AllowPrivate {
		policy.PrivateCIDRs = make([]netip.Prefix, 0, len(p.cfg.PrivateEgressCIDRs))
		for _, cidr := range p.cfg.PrivateEgressCIDRs {
			prefix, err := netsec.ParseEgressAllowPrefix(strings.TrimSpace(cidr))
			if err != nil {
				return nil, errors.New("server: invalid database private egress policy")
			}
			policy.PrivateCIDRs = append(policy.PrivateCIDRs, prefix)
		}
	}
	dialer := netsec.NewDatabaseDialer(policy)
	for _, endpoint := range target.Hosts {
		if err := dialer.CheckEndpoint(endpoint); err != nil {
			return nil, errors.New("server: database destination is outside the configured egress policy")
		}
	}
	ca, serverName, err := p.databaseTrust(ctx, target)
	if err != nil {
		return nil, err
	}
	return &dynsecret.DatabaseTransport{Dialer: dialer, CAPEM: ca, ServerName: serverName,
		RoutingEndpoints: p.cfg.DatabaseRoutingEndpoints}, nil
}

// databaseWorkload keeps the provider's administration and workload addresses
// distinct. It returns only the latter's non-secret route and transport.
func (p *configuredDynamicProvider) databaseWorkload(ctx context.Context) (dbdsn.Target, *dynsecret.DatabaseTransport, error) {
	buf, err := p.resolveAdminDSN(ctx)
	if err != nil {
		return dbdsn.Target{}, nil, err
	}
	defer buf.Destroy()
	target, err := dbdsn.Parse(p.cfg.Type, buf.Bytes(), dbdsn.Admin)
	if err != nil {
		return dbdsn.Target{}, nil, err
	}
	target.Wipe()
	target.User, target.Password = "", nil
	transport, err := p.databaseTransport(ctx, target)
	if err != nil {
		return dbdsn.Target{}, nil, err
	}
	switch p.cfg.Type {
	case dbdsn.Postgres:
		if target.Database == "" {
			target.Database = p.cfg.Database
			if target.Database == "" {
				target.Database = "postgres"
			}
		}
	case dbdsn.Mongo:
		target.Database, target.AuthSource = p.cfg.Database, p.cfg.Database
	case dbdsn.MySQL:
		host, port, err := net.SplitHostPort(p.cfg.Addr)
		addr, addressErr := dbdsn.TCPAddress(host, port)
		if err != nil || addressErr != nil || transport.Dialer.CheckEndpoint(addr) != nil {
			return dbdsn.Target{}, nil, dbdsn.ErrGatewayRoute
		}
		target.Hosts, target.Database = []string{addr}, p.cfg.Database
	}
	return target, transport, nil
}

func (p *configuredDynamicProvider) verifyDatabaseWorkload(ctx context.Context, credential []byte) error {
	actual, err := dbdsn.Parse(p.cfg.Type, credential, dbdsn.Credential)
	if err != nil {
		return err
	}
	defer actual.Wipe()
	expected, transport, err := p.databaseWorkload(ctx)
	if err != nil {
		return err
	}
	if expected.SRV != actual.SRV || !slices.Equal(expected.Hosts, actual.Hosts) ||
		actual.Database != "" && expected.Database != actual.Database || expected.AuthSource != actual.AuthSource {
		return errors.New("server: credential does not match the configured database workload route")
	}
	transport.InitialDatabase = expected.Database
	switch p.cfg.Type {
	case dbdsn.Postgres:
		if effectivePostgresMode(actual) != effectivePostgresMode(expected) || actual.SystemRoots != expected.SystemRoots ||
			postgresTLSNegotiation(actual) != postgresTLSNegotiation(expected) {
			return dbdsn.ErrTrust
		}
		return rotation.VerifyPostgresCredentialWithTransport(ctx, credential, "SELECT 1", transport)
	case dbdsn.MySQL:
		return rotation.VerifyMySQLCredentialWithTransport(ctx, credential, transport)
	case dbdsn.Mongo:
		if mongoTLS(actual) != mongoTLS(expected) {
			return dbdsn.ErrTrust
		}
		return dynsecret.VerifyMongoCredentialWithTransport(ctx, credential, transport)
	default:
		return dbdsn.ErrInvalid
	}
}

func effectivePostgresMode(t dbdsn.Target) string {
	if mode := t.Options["sslmode"]; mode != "" {
		return mode
	}
	return "prefer"
}

func postgresTLSNegotiation(t dbdsn.Target) string {
	if t.Options["sslnegotiation"] == "direct" {
		return "direct"
	}
	return "postgres"
}

func mongoTLS(target dbdsn.Target) bool {
	return target.Options["tls"] == "true" || target.SRV && target.Options["tls"] != "false"
}

func (p *configuredDynamicProvider) DynamicSecretDatabaseGatewayRoute(ctx context.Context) (dbdsn.GatewayRoute, []byte, string, error) {
	target, transport, err := p.databaseWorkload(ctx)
	if err != nil {
		return dbdsn.GatewayRoute{}, nil, "", err
	}
	ca, name := transport.CAPEM, transport.ServerName
	explicitTrust := len(ca) != 0 || name != ""
	mode, err := dbdsn.GatewayTLSMode(p.cfg.Type, target, explicitTrust)
	if err != nil {
		return dbdsn.GatewayRoute{}, nil, "", err
	}
	source := dbdsn.TenantStoredSource
	if strings.HasPrefix(strings.TrimSpace(p.cfg.AdminDSNRef), "file:") {
		source = dbdsn.OperatorFileSource
	}
	var cidrs []string
	if p.cfg.AllowPrivate {
		for _, raw := range p.cfg.PrivateEgressCIDRs {
			prefix, err := netsec.ParseEgressAllowPrefix(strings.TrimSpace(raw))
			if err != nil {
				return dbdsn.GatewayRoute{}, nil, "", dbdsn.ErrGatewayRoute
			}
			cidrs = append(cidrs, prefix.String())
		}
		slices.Sort(cidrs)
		cidrs = slices.Compact(cidrs)
	}
	route := dbdsn.GatewayRoute{Revision: dbdsn.GatewayRouteRevision, ProviderID: p.id,
		Hosts: target.Hosts, Database: target.Database, TLS: mode, Source: source, PrivateCIDRs: cidrs}
	if err := route.Validate(p.cfg.Type, explicitTrust); err != nil {
		return dbdsn.GatewayRoute{}, nil, "", err
	}
	return route, ca, name, nil
}

func (p *configuredDynamicProvider) resolveAdminDSN(ctx context.Context) (*secret.Buffer, error) {
	value, err := p.credentials.resolveBounded(ctx, p.tenantID, p.cfg.AdminDSNRef, dbdsn.MaxBytes)
	if err != nil {
		return nil, errAdminDSN
	}
	return value, nil
}

func (p *configuredDynamicProvider) boundedDatabaseCA(ctx context.Context, ref string) ([]byte, error) {
	buf, err := p.credentials.resolveBounded(ctx, p.tenantID, ref, dbdsn.MaxTrustBytes)
	if err != nil {
		return nil, dbdsn.ErrTrust
	}
	defer buf.Destroy()
	if buf.Len() == 0 {
		return nil, dbdsn.ErrTrust
	}
	caPEM, _, err := dbdsn.NormalizeTrust(buf.Bytes(), "")
	return caPEM, err
}

func (p *configuredDynamicProvider) databaseTrust(ctx context.Context, target dbdsn.Target) ([]byte, string, error) {
	var caPEM []byte
	if target.CAFile != "" {
		if p.cfg.TLSCARef != "" || !strings.HasPrefix(strings.TrimSpace(p.cfg.AdminDSNRef), "file:") {
			return nil, "", dbdsn.ErrTrust
		}
		var err error
		caPEM, err = readDatabaseCAFile(ctx, p.cfg.DatabaseCAFileRoot, target.CAFile)
		if err != nil {
			return nil, "", err
		}
		defer secret.Wipe(caPEM)
	} else if p.cfg.TLSCARef != "" {
		if target.SystemRoots || !strings.HasPrefix(strings.TrimSpace(p.cfg.TLSCARef), "file:") {
			return nil, "", dbdsn.ErrTrust
		}
		var err error
		caPEM, err = p.boundedDatabaseCA(ctx, p.cfg.TLSCARef)
		if err != nil {
			return nil, "", err
		}
	}
	return dbdsn.NormalizeTrust(caPEM, p.cfg.TLSServerName)
}

func readDatabaseCAFile(ctx context.Context, directory, name string) ([]byte, error) {
	if !filepath.IsAbs(directory) || ctx.Err() != nil {
		return nil, dbdsn.ErrTrust
	}
	if filepath.IsAbs(name) {
		relative, err := filepath.Rel(directory, name)
		if err != nil {
			return nil, dbdsn.ErrTrust
		}
		name = relative
	}
	if !filepath.IsLocal(name) {
		return nil, dbdsn.ErrTrust
	}
	root, err := os.OpenRoot(directory)
	if err != nil {
		return nil, dbdsn.ErrTrust
	}
	defer func() { _ = root.Close() }()
	pem, err := safefile.ReadRegularFile(ctx, root, name, dbdsn.MaxTrustBytes)
	if err != nil || len(pem) == 0 {
		secret.Wipe(pem)
		return nil, dbdsn.ErrTrust
	}
	return pem, nil
}
