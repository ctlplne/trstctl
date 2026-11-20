// SPDX-License-Identifier: BUSL-1.1

package dynsecret

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"net"
	"strconv"
	"time"

	hdb "github.com/SAP/go-hdb/driver"
	"github.com/SAP/go-hdb/driver/dial"
	"trstctl.com/trstctl/internal/crypto/dbdsn"
	"trstctl.com/trstctl/internal/crypto/mtls"
	"trstctl.com/trstctl/internal/netsec"
	"trstctl.com/trstctl/internal/secrettext"
)

func OpenHANAExecutorWithTransport(ctx context.Context, raw []byte, transport *DatabaseTransport) (*sql.DB, error) {
	target, err := dbdsn.Parse(dbdsn.HANA, raw, dbdsn.Admin)
	if err != nil {
		return nil, err
	}
	defer target.Wipe()
	db, err := hanaProfileDB(target, transport)
	if err != nil {
		return nil, err
	}
	if err := db.PingContext(ctx); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("dynsecret hana: ping admin connection failed (%s)", hanaErrorCode(err))
	}
	return db, nil
}

func hanaProfileDB(target dbdsn.Target, transport *DatabaseTransport) (*sql.DB, error) {
	policy := databaseTransport(transport)
	if target.CAFile != "" && len(policy.CAPEM) == 0 {
		return nil, dbdsn.ErrTrust
	}
	config := hdb.NewConnectorConfig()
	config.Host, config.Username = target.Hosts[0], target.User
	config.Password = secrettext.String(target.Password)
	config.DatabaseName, config.ConnectionRouting = "", false
	config.Dialer = hanaProfileDial{endpoint: config.Host, dialer: policy.Dialer}
	config.SQLTrace, config.ProtTrace = hdb.SQLTraceConfig{}, hdb.ProtTraceConfig{}
	config.DefaultSchema = target.Options["defaultSchema"]
	timeout, _ := strconv.Atoi(target.Options["timeout"])
	if timeout == 0 {
		timeout = 15
	}
	config.DialTimeout = time.Duration(timeout) * time.Second
	config.ReadTimeout, config.WriteTimeout = config.DialTimeout, config.DialTimeout
	pingInterval, _ := strconv.Atoi(target.Options["pingInterval"])
	config.PingInterval = time.Duration(pingInterval) * time.Second
	if len(policy.CAPEM) != 0 || policy.ServerName != "" || target.Options["TLSServerName"] != "" || target.Options["TLSInsecureSkipVerify"] != "" {
		name := policy.ServerName
		if option := target.Options["TLSServerName"]; option != "" {
			parsed, _ := dbdsn.HostName(option)
			if name != "" && name != parsed {
				return nil, dbdsn.ErrTrust
			}
			name = parsed
		}
		if name == "" {
			name, _, _ = net.SplitHostPort(config.Host)
		}
		tlsConfig, err := mtls.VerifiedClientTLSConfig(name, policy.CAPEM)
		if err != nil {
			return nil, dbdsn.ErrTrust
		}
		config.TLSConfig = tlsConfig
	}
	connector, err := hdb.NewConfigConnector(config)
	if err != nil {
		return nil, errors.New("dynsecret hana: open native connection failed")
	}
	return sql.OpenDB(connector), nil
}

type hanaProfileDial struct {
	endpoint string
	dialer   netsec.DatabaseDialer
}

func (d hanaProfileDial) DialContext(ctx context.Context, address string, _ dial.DialerOptions) (net.Conn, error) {
	if d.endpoint != address {
		return nil, netsec.ErrSSRFBlocked
	}
	return d.dialer.DialContext(ctx, "tcp", address)
}
