// SPDX-License-Identifier: BUSL-1.1

package dynsecret

import (
	"github.com/go-sql-driver/mysql"
	"github.com/jackc/pgx/v5/pgconn"

	"trstctl.com/trstctl/internal/secrettext"
)

// CredentialAccount returns the account a PostgreSQL or MySQL connection
// string signs in as: a vaulted two-account role's live account (A261). The
// string is parsed only; nothing connects.
func CredentialAccount(providerType string, credential []byte) (string, bool) {
	var user string
	switch providerType {
	case "postgresql":
		config, err := pgconn.ParseConfig(secrettext.String(credential))
		if err != nil {
			return "", false
		}
		user = config.User
	case "mysql":
		config, err := mysql.ParseDSN(secrettext.String(credential))
		if err != nil {
			return "", false
		}
		user = config.User
	}
	return user, user != ""
}
