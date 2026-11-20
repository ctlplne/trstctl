// SPDX-License-Identifier: BUSL-1.1

package pgsignin

import (
	"net"

	"trstctl.com/trstctl/internal/crypto/dbdsn"
)

// ParseDSN admits one TCP host in a libpq keyword string or PostgreSQL URI.
// Certificate paths belong to control-plane configuration, outside the DSN.
func ParseDSN(dsn []byte) (Target, error) {
	profile, err := dbdsn.Parse(dbdsn.Postgres, dsn, dbdsn.Gateway)
	if err != nil {
		return Target{}, err
	}
	host, port, _ := net.SplitHostPort(profile.Hosts[0])
	mode := profile.Options["sslmode"]
	if mode == "" {
		mode = "prefer"
	}
	target := Target{Host: host, Port: port, User: profile.User, Password: profile.Password,
		Database: profile.Database, SSLMode: mode, SystemRoots: profile.SystemRoots, passwordOwner: &profile}
	return target, nil
}
