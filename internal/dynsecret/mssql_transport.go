// SPDX-License-Identifier: BUSL-1.1

package dynsecret

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"errors"
	"fmt"
	"maps"
	"net"
	"net/url"
	"slices"
	"strings"
	"time"

	mssql "github.com/microsoft/go-mssqldb"
	"github.com/microsoft/go-mssqldb/msdsn"

	"trstctl.com/trstctl/internal/crypto/dbdsn"
	"trstctl.com/trstctl/internal/crypto/mtls"
	"trstctl.com/trstctl/internal/netsec"
	"trstctl.com/trstctl/internal/secrettext"
)

func OpenMSSQLExecutorWithTransport(ctx context.Context, raw []byte, transport *DatabaseTransport) (*sql.DB, error) {
	target, err := dbdsn.Parse(dbdsn.MSSQL, raw, dbdsn.Admin)
	if err != nil {
		return nil, err
	}
	defer target.Wipe()
	if target.CAFile != "" && len(databaseTransport(transport).CAPEM) == 0 {
		return nil, dbdsn.ErrTrust
	}
	db, err := mssqlProfileDB(mssqlProfileURL(target, target.Database), target.User, target.Password, transport)
	if err != nil {
		return nil, err
	}
	if err := db.PingContext(ctx); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("dynsecret mssql: ping admin connection failed (%s)", mssqlErrorNumber(err))
	}
	return db, nil
}

func mssqlProfileURL(target dbdsn.Target, database string) *url.URL {
	query := make(url.Values)
	for key, value := range target.Options {
		query.Set(key, value)
	}
	if database != "" {
		query.Set("database", database)
	}
	if query.Get("workstation id") == "" {
		query.Set("workstation id", "trstctl")
	}
	query.Set("protocol", "tcp")
	u := &url.URL{Scheme: "sqlserver", Host: target.Hosts[0], RawQuery: query.Encode()}
	mssqlBoundConnection(u)
	return u
}

func mssqlProfileDB(profile *url.URL, user string, password []byte, transport *DatabaseTransport) (*sql.DB, error) {
	if profile == nil || user == "" || len(password) == 0 || strings.ContainsAny(user, "\\\x00\r\n") {
		return nil, dbdsn.ErrInvalid
	}
	policy := databaseTransport(transport)
	// Only the admitted public configuration is passed to msdsn. Do not let
	// it resolve a timezone or a root file named by the input.
	u := *profile
	query := profile.Query()
	location := query.Get("timezone")
	query.Del("timezone")
	u.RawQuery = query.Encode()
	config, err := msdsn.Parse(u.String())
	if err != nil {
		return nil, errors.New("dynsecret mssql: open SQL Server connection failed")
	}
	config.User, config.Password = user, secrettext.String(password)
	config.Parameters[msdsn.UserID], config.Parameters[msdsn.Password] = config.User, config.Password
	if location == "Local" {
		config.Encoding.Timezone = time.Local
	}
	if len(policy.CAPEM) != 0 || policy.ServerName != "" {
		if config.Encryption == msdsn.EncryptionDisabled {
			return nil, dbdsn.ErrTrust
		}
		name := policy.ServerName
		configuredName := query.Get("hostnameincertificate")
		if name != "" && configuredName != "" && !strings.EqualFold(name, configuredName) {
			return nil, dbdsn.ErrTrust
		}
		if name == "" {
			name = configuredName
		}
		config.HostInCertificateProvided = name != ""
		if name == "" {
			name = config.Host
		}
		tlsConfig, err := mtls.VerifiedClientTLSConfig(name, policy.CAPEM)
		if err != nil {
			return nil, dbdsn.ErrTrust
		}
		config.TLSConfig = tlsConfig
		if config.Encryption == msdsn.EncryptionOff {
			config.Encryption = msdsn.EncryptionRequired
		}
	}
	routes := make([]string, 0, len(policy.RoutingEndpoints))
	for _, raw := range policy.RoutingEndpoints {
		host, port, err := net.SplitHostPort(raw)
		canonical, addressErr := dbdsn.TCPAddress(host, port)
		if err != nil || addressErr != nil || len(routes) >= dbdsn.MaxHosts {
			return nil, dbdsn.ErrInvalid
		}
		routes = append(routes, canonical)
	}
	return sql.OpenDB(mssqlProfileConnector{config: config, initial: u.Host, routes: routes, dialer: policy.Dialer}), nil
}

type mssqlProfileConnector struct {
	config  msdsn.Config
	initial string
	routes  []string
	dialer  netsec.DatabaseDialer
}

func (c mssqlProfileConnector) Driver() driver.Driver { return &mssql.Driver{} }

func (c mssqlProfileConnector) Connect(ctx context.Context) (driver.Conn, error) {
	config := c.config
	config.Parameters = maps.Clone(config.Parameters)
	if config.TLSConfig != nil {
		// The Strict handshake can change ALPN on the config it receives.
		config.TLSConfig = config.TLSConfig.Clone()
	}
	native := mssql.NewConnectorConfig(config)
	native.Dialer = &mssqlProfileDial{initial: c.initial, routes: c.routes, dialer: c.dialer}
	return native.Connect(ctx)
}

type mssqlProfileDial struct {
	initial string
	routes  []string
	dialer  netsec.DatabaseDialer
	dials   int
}

// HostName opts into the driver's HostDialer interface. It keeps DNS in our
// bounds and name policy instead of a driver-internal unaudited lookup.
func (d *mssqlProfileDial) HostName() string { return "trstctl" }

func (d *mssqlProfileDial) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	host, port, err := net.SplitHostPort(address)
	endpoint, addressErr := dbdsn.TCPAddress(host, port)
	if err != nil || addressErr != nil || network != "tcp" || d.dials >= 2 {
		return nil, netsec.ErrSSRFBlocked
	}
	if d.dials == 0 && endpoint != d.initial || d.dials == 1 && !slices.Contains(d.routes, endpoint) {
		return nil, netsec.ErrSSRFBlocked
	}
	d.dials++
	return d.dialer.DialContext(ctx, network, endpoint)
}
