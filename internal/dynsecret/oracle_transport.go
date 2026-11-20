// SPDX-License-Identifier: BUSL-1.1

package dynsecret

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"fmt"
	"maps"
	"net"
	"net/url"

	goora "github.com/sijms/go-ora/v2"

	"trstctl.com/trstctl/internal/crypto/dbdsn"
	"trstctl.com/trstctl/internal/crypto/mtls"
	"trstctl.com/trstctl/internal/netsec"
	"trstctl.com/trstctl/internal/secrettext"
)

func OpenOracleExecutorWithTransport(ctx context.Context, raw []byte, transport *DatabaseTransport) (*sql.DB, error) {
	target, err := dbdsn.Parse(dbdsn.Oracle, raw, dbdsn.Admin)
	if err != nil {
		return nil, err
	}
	defer target.Wipe()
	db, err := oracleProfileDB(target, transport)
	if err != nil {
		return nil, err
	}
	if err := db.PingContext(ctx); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("dynsecret oracle: ping admin connection failed (%s)", oracleErrorCode(err))
	}
	return db, nil
}

func oracleProfileDB(target dbdsn.Target, transport *DatabaseTransport) (*sql.DB, error) {
	policy := databaseTransport(transport)
	host, _, _ := net.SplitHostPort(target.Hosts[0])
	if target.CAFile != "" && len(policy.CAPEM) == 0 || policy.ServerName != "" && policy.ServerName != host {
		return nil, dbdsn.ErrTrust
	}
	options := maps.Clone(target.Options)
	secured := options["SSL"] == "true" || len(policy.CAPEM) != 0 || policy.ServerName != ""
	if secured {
		if options["SSL"] == "false" || options["SSL VERIFY"] == "false" {
			return nil, dbdsn.ErrTrust
		}
		options["SSL"], options["SSL VERIFY"] = "true", "true"
	}
	if options["TIMEOUT"] == "" || options["TIMEOUT"] == "0" {
		options["TIMEOUT"] = "15"
	}
	if options["CONNECT TIMEOUT"] == "" || options["CONNECT TIMEOUT"] == "0" {
		options["CONNECT TIMEOUT"] = "10"
	}
	query := make(url.Values, len(options))
	for key, value := range options {
		query.Set(key, value)
	}
	dsn := url.URL{Scheme: "oracle", Host: target.Hosts[0], Path: "/" + target.Database,
		User: url.UserPassword(target.User, secrettext.String(target.Password)), RawQuery: query.Encode()}
	return sql.OpenDB(oracleProfileConnector{dsn: dsn.String(), endpoint: target.Hosts[0], host: host, secured: secured, policy: policy}), nil
}

type oracleProfileConnector struct {
	dsn      string
	endpoint string
	host     string
	secured  bool
	policy   DatabaseTransport
}

func (c oracleProfileConnector) Driver() driver.Driver { return goora.NewConnector("").Driver() }

func (c oracleProfileConnector) Connect(ctx context.Context) (driver.Conn, error) {
	native := goora.NewConnector(c.dsn).(*goora.OracleConnector)
	native.Dialer(&oracleDirectDial{endpoint: c.endpoint, dialer: c.policy.Dialer})
	if c.secured {
		config, err := mtls.VerifiedClientTLSConfig(c.host, c.policy.CAPEM)
		if err != nil {
			return nil, dbdsn.ErrTrust
		}
		native.WithTLSConfig(config)
	}
	return native.Connect(ctx)
}

type oracleDirectDial struct {
	endpoint string
	dialer   netsec.DatabaseDialer
	started  bool
}

func (d *oracleDirectDial) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	if d.started || address != d.endpoint || network != "tcp" {
		return nil, netsec.ErrSSRFBlocked
	}
	d.started = true
	return d.dialer.DialContext(ctx, network, address)
}
