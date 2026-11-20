// SPDX-License-Identifier: BUSL-1.1

package dynsecret

import (
	"encoding/json"
	"strings"

	"trstctl.com/trstctl/internal/crypto/dbdsn"
)

// CredentialAccount returns the account a database DSN or desktop JSON
// credential signs in as: a vaulted two-account role's live account (A261). The
// credential is parsed without opening files or a connection.
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
	case dbdsn.Postgres, dbdsn.MySQL:
		target, err := dbdsn.Parse(providerType, credential, dbdsn.Credential)
		if err != nil {
			return "", false
		}
		defer target.Wipe()
		user = target.User
	}
	return user, user != ""
}
