// SPDX-License-Identifier: BUSL-1.1

package dynsecret

import (
	"context"
	"errors"
	"net"
	"os"
	"strconv"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"

	"trstctl.com/trstctl/internal/crypto/dbdsn"
	"trstctl.com/trstctl/internal/crypto/dbtls"
	"trstctl.com/trstctl/internal/secrettext"
)

// Native pgx and pgconn require the private constructor marker that
// ParseConfig sets. During trusted process initialization the pinned parser
// can inspect fixed operator-process metadata, such as its home directory.
// The template disables all file-backed options and never handles a DSN from
// an operation. Every operation copies it and installs its admitted fields.
var postgresTemplate, postgresTemplateErr = newPostgresTemplate()

func newPostgresTemplate() (*pgx.ConnConfig, error) {
	if os.Getenv("PGSERVICE") != "" {
		return nil, errors.New("dynsecret postgres: ambient PGSERVICE is not supported")
	}
	config, err := pgx.ParseConfig("host=127.0.0.1 port=5432 user=trstctl password=placeholder dbname=trstctl " +
		"passfile='' servicefile='' application_name='' connect_timeout=10 sslmode=disable " +
		"sslkey='' sslcert='' sslsni=1 sslrootcert='' sslpassword='' sslnegotiation=postgres " +
		"target_session_attrs=any timezone='' options='' min_protocol_version=3.0 max_protocol_version=3.0 " +
		"channel_binding=prefer require_auth=''")
	if err != nil {
		return nil, errors.New("dynsecret postgres: could not initialize the bounded native profile")
	}
	config.Host, config.Database, config.User, config.Password = "", "", "", ""
	config.TLSConfig, config.Fallbacks, config.RuntimeParams = nil, nil, nil
	config.DialFunc, config.LookupFunc = nil, nil
	return config, nil
}

func postgresDriverConfig(dsn []byte, transport *DatabaseTransport, purpose dbdsn.Purpose) (*pgx.ConnConfig, error) {
	target, err := dbdsn.Parse(dbdsn.Postgres, dsn, purpose)
	if err != nil {
		return nil, err
	}
	defer target.Wipe()
	return postgresTargetConfig(target, transport)
}

func postgresTargetConfig(target dbdsn.Target, transport *DatabaseTransport) (*pgx.ConnConfig, error) {
	if postgresTemplateErr != nil {
		return nil, postgresTemplateErr
	}
	policy := databaseTransport(transport)
	if target.CAFile != "" && len(policy.CAPEM) == 0 {
		return nil, dbdsn.ErrTrust
	}
	config := postgresTemplate.Copy()
	config.User, config.Database = target.User, target.Database
	if config.Database == "" {
		config.Database = policy.InitialDatabase
	}
	if config.Database == "" {
		config.Database = config.User
	}
	config.Password = secrettext.String(target.Password)
	config.RequireAuth = "password,md5,scram-sha-256,none"
	config.DialFunc, config.LookupFunc = policy.Dialer.DialResolved, policy.Dialer.LookupHost
	config.RuntimeParams = make(map[string]string)
	for key, value := range target.Options {
		switch key {
		case "sslmode", "sslnegotiation", "connect_timeout", "target_session_attrs":
		default:
			config.RuntimeParams[key] = value
		}
	}
	if timeout, _ := strconv.Atoi(target.Options["connect_timeout"]); timeout > 0 {
		config.ConnectTimeout = time.Duration(timeout) * time.Second
	}
	if negotiation := target.Options["sslnegotiation"]; negotiation != "" {
		config.SSLNegotiation = negotiation
	}
	switch target.Options["target_session_attrs"] {
	case "read-write":
		config.ValidateConnect = pgconn.ValidateConnectTargetSessionAttrsReadWrite
	case "read-only":
		config.ValidateConnect = pgconn.ValidateConnectTargetSessionAttrsReadOnly
	case "primary":
		config.ValidateConnect = pgconn.ValidateConnectTargetSessionAttrsPrimary
	case "standby":
		config.ValidateConnect = pgconn.ValidateConnectTargetSessionAttrsStandby
	case "prefer-standby":
		config.ValidateConnect = pgconn.ValidateConnectTargetSessionAttrsPreferStandby
	}
	preferTLS := false
	for _, address := range target.Hosts {
		host, port, _ := net.SplitHostPort(address)
		number, _ := strconv.ParseUint(port, 10, 16)
		attempts, err := dbtls.Postgres(target.Options["sslmode"], config.SSLNegotiation, host,
			policy.ServerName, policy.CAPEM, target.SystemRoots)
		if err != nil {
			return nil, err
		}
		preferTLS = preferTLS || len(attempts) == 2 && attempts[0] != nil
		for _, attempt := range attempts {
			if config.Host == "" {
				config.Host, config.Port, config.TLSConfig = host, uint16(number), attempt
			} else {
				config.Fallbacks = append(config.Fallbacks, &pgconn.FallbackConfig{Host: host, Port: uint16(number), TLSConfig: attempt})
			}
		}
	}
	if preferTLS {
		config.DialFunc = dbtls.PostgresPreferDial(config.DialFunc)
	}
	return config, nil
}

func (b *PostgresBackend) connectDriver(ctx context.Context) (*pgconn.PgConn, error) {
	config, err := postgresDriverConfig(b.dsn.Bytes(), b.transport, dbdsn.Admin)
	if err != nil {
		return nil, err
	}
	return pgconn.ConnectConfig(ctx, &config.Config)
}

// OpenPostgresCredential opens the same guarded native profile for a login
// proof, with no permission to supply a CA path.
func OpenPostgresCredential(ctx context.Context, credential []byte, transport *DatabaseTransport) (*pgx.Conn, error) {
	config, err := postgresDriverConfig(credential, transport, dbdsn.Credential)
	if err != nil {
		return nil, err
	}
	conn, err := pgx.ConnectConfig(ctx, config)
	if err != nil {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		return nil, classifyPostgresSignIn(err)
	}
	return conn, nil
}
