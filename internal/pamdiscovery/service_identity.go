// SPDX-License-Identifier: BUSL-1.1
package pamdiscovery

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"github.com/go-ldap/ldap/v3"
	"strconv"
	"strings"
	"unicode/utf8"
)

const KindDirectoryServiceAccount = "directory_service_account"

// ValidateDiscoveredAccount preserves privilege evidence for every existing
// account kind. A service identity instead needs an exact native AD binding
// and observed SPNs or an explicit configured rotation binding.
func ValidateDiscoveredAccount(account Account) error {
	if account.Key == "" || account.Name == "" || account.Kind == "" {
		return errors.New("pam discovery: incomplete account")
	}
	if account.Kind != KindDirectoryServiceAccount {
		if len(account.Privileges) == 0 {
			return errors.New("pam discovery: privilege evidence required")
		}
		return nil
	}
	if account.Key != "user:"+strings.ToLower(account.Name) || len(account.Name) > 256 || !utf8.ValidString(account.Name) || account.Details["service_account"] != "true" {
		return errors.New("pam discovery: incomplete service identity")
	}
	for _, r := range account.Name {
		if r < 32 || r == 127 {
			return errors.New("pam discovery: invalid service account name")
		}
	}
	guid, err := hex.DecodeString(account.Details["native_guid"])
	if err != nil || len(guid) != 16 || account.Details["native_guid"] != strings.ToLower(account.Details["native_guid"]) {
		return errors.New("pam discovery: native service GUID required")
	}
	nonzero := false
	for _, value := range guid {
		nonzero = nonzero || value != 0
	}
	if !nonzero {
		return errors.New("pam discovery: zero native service GUID")
	}
	sid := strings.Split(account.Details["native_sid"], "-")
	if len(sid) != 8 || strings.Join(sid[:4], "-") != "S-1-5-21" {
		return errors.New("pam discovery: native domain account SID required")
	}
	for _, value := range sid[4:] {
		n, err := strconv.ParseUint(value, 10, 32)
		if err != nil || strconv.FormatUint(n, 10) != value {
			return errors.New("pam discovery: invalid canonical service SID")
		}
	}
	if dn, err := ldap.ParseDN(account.Details["dn"]); err != nil || len(dn.RDNs) == 0 {
		return errors.New("pam discovery: native service DN required")
	}
	if account.Details["configured_rotation_account"] == "true" {
		return nil
	}
	raw := account.Details["service_principal_names"]
	if len(raw) == 0 || len(raw) > 16384 {
		return errors.New("pam discovery: native service selection evidence required")
	}
	var names []string
	if json.Unmarshal([]byte(raw), &names) != nil || len(names) == 0 || len(names) > 128 {
		return errors.New("pam discovery: bounded service principals required")
	}
	total := 0
	for _, name := range names {
		total += len(name)
		if len(name) == 0 || len(name) > 2048 || total > 8192 || !utf8.ValidString(name) {
			return errors.New("pam discovery: invalid service principal")
		}
		for _, r := range name {
			if r < 32 || r == 127 {
				return errors.New("pam discovery: invalid service principal text")
			}
		}
	}
	return nil
}
