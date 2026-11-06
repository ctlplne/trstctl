// SPDX-License-Identifier: BUSL-1.1

package dynsecret

import (
	"encoding/json"
	"github.com/go-sql-driver/mysql"
	"github.com/jackc/pgx/v5/pgconn"
	"strings"

	"trstctl.com/trstctl/internal/secrettext"
)

// CredentialAccount returns the account a database DSN or desktop JSON
// credential signs in as: a vaulted two-account role's live account (A261). The
// string is parsed only; nothing connects.
func CredentialAccount(providerType string, credential []byte) (string, bool) {
	var user string
	switch providerType {
	case "desktop":
		var c struct {
			Username string `json:"username"`
		}
		if len(credential) > 64<<10 || json.Unmarshal(credential, &c) != nil || len(c.Username) > 128 || strings.ContainsAny(c.Username, "\x00\r\n") {
			return "", false
		}
		user = c.Username
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
