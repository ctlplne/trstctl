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

	"github.com/go-sql-driver/mysql"

	"trstctl.com/trstctl/internal/crypto/dbdsn"
	"trstctl.com/trstctl/internal/crypto/mtls"
	"trstctl.com/trstctl/internal/secrettext"
)

// OpenMySQLExecutorWithTransport opens a MySQL pool from admitted typed
// settings. Its connector cannot grant local-file transfer authority.
func OpenMySQLExecutorWithTransport(ctx context.Context, dsn []byte, transport *DatabaseTransport) (*sql.DB, error) {
	target, err := dbdsn.Parse(dbdsn.MySQL, dsn, dbdsn.Admin)
	if err != nil {
		return nil, err
	}
	defer target.Wipe()
	config, err := mysqlTargetConfig(target, transport)
	if err != nil {
		return nil, err
	}
	connector, err := mysql.NewConnector(config)
	if err != nil {
		return nil, errors.New("dynsecret mysql: open admin connection failed")
	}
	db := sql.OpenDB(connector)
	if err := db.PingContext(ctx); err != nil {
		_ = db.Close()
		// Credential health uses this fixed error class (A258).
		return nil, fmt.Errorf("dynsecret mysql: ping admin connection failed: %w", classifyMySQLSignIn(err))
	}
	return db, nil
}

func mysqlTargetConfig(target dbdsn.Target, transport *DatabaseTransport) (*mysql.Config, error) {
	policy := databaseTransport(transport)
	config := mysql.NewConfig()
	config.User, config.Passwd = target.User, secrettext.String(target.Password)
	config.Net, config.Addr, config.DBName = "tcp", target.Hosts[0], target.Database
	if config.DBName == "" {
		config.DBName = policy.InitialDatabase
	}
	config.DialFunc = policy.Dialer.DialContext
	config.AllowAllFiles = false
	config.TLSConfig = target.Options["tls"]
	if len(policy.CAPEM) != 0 || policy.ServerName != "" {
		if config.TLSConfig == "false" || config.TLSConfig == "skip-verify" {
			return nil, dbdsn.ErrTrust
		}
		serverName := policy.ServerName
		if serverName == "" {
			serverName, _, _ = net.SplitHostPort(config.Addr)
		}
		tlsConfig, err := mtls.VerifiedClientTLSConfig(serverName, policy.CAPEM)
		if err != nil {
			return nil, dbdsn.ErrTrust
		}
		config.TLS = tlsConfig
		config.TLSConfig = ""
	}
	for key, value := range target.Options {
		flag := value == "true" || value == "1"
		switch key {
		case "allowNativePasswords":
			config.AllowNativePasswords = flag
		case "checkConnLiveness":
			config.CheckConnLiveness = flag
		case "clientFoundRows":
			config.ClientFoundRows = flag
		case "columnsWithAlias":
			config.ColumnsWithAlias = flag
		case "interpolateParams":
			config.InterpolateParams = flag
		case "parseTime":
			config.ParseTime = flag
		case "rejectReadOnly":
			config.RejectReadOnly = flag
		case "loc":
			if value == "Local" {
				config.Loc = time.Local
			}
		case "timeout":
			config.Timeout, _ = time.ParseDuration(value)
		case "readTimeout":
			config.ReadTimeout, _ = time.ParseDuration(value)
		case "writeTimeout":
			config.WriteTimeout, _ = time.ParseDuration(value)
		case "maxAllowedPacket":
			config.MaxAllowedPacket, _ = strconv.Atoi(value)
		}
	}
	if collation := target.Options["collation"]; collation != "" {
		config.Collation = collation
	}
	if charset := target.Options["charset"]; charset != "" {
		if err := config.Apply(mysql.Charset(charset, config.Collation)); err != nil {
			return nil, dbdsn.ErrOption
		}
	}
	compress := target.Options["compress"]
	truncate, _ := time.ParseDuration(target.Options["timeTruncate"])
	if err := config.Apply(mysql.EnableCompression(compress == "true" || compress == "1"), mysql.TimeTruncate(truncate)); err != nil {
		return nil, dbdsn.ErrOption
	}
	return config, nil
}
