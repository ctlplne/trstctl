// SPDX-License-Identifier: BUSL-1.1
package dynsecret

import (
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"github.com/go-ldap/ldap/v3"
	"sort"
	"strconv"
	"strings"
	"trstctl.com/trstctl/internal/pamdiscovery"
	"unicode/utf8"
)

func adDiscoverySID(raw []byte) (string, error) {
	if len(raw) < 12 || raw[0] != 1 || raw[1] == 0 || raw[1] > 15 || len(raw) != 8+4*int(raw[1]) {
		return "", errors.New("dynsecret AD: invalid native account SID")
	}
	authority := uint64(0)
	for _, value := range raw[2:8] {
		authority = authority<<8 | uint64(value)
	}
	var text strings.Builder
	text.WriteString("S-1-")
	text.WriteString(strconv.FormatUint(authority, 10))
	for i := 0; i < int(raw[1]); i++ {
		text.WriteByte('-')
		text.WriteString(strconv.FormatUint(uint64(binary.LittleEndian.Uint32(raw[8+i*4:])), 10))
	}
	return text.String(), nil
}
func singleADDiscoveryAttribute(entry *ldap.Entry, name string) ([]byte, error) {
	var value []byte
	found := false
	for _, attr := range entry.Attributes {
		if !strings.EqualFold(attr.Name, name) {
			continue
		}
		if found || len(attr.ByteValues) != 1 {
			return nil, errors.New("dynsecret AD: ambiguous native account identity")
		}
		found = true
		value = attr.ByteValues[0]
	}
	if !found {
		return nil, errors.New("dynsecret AD: native account identity unavailable")
	}
	return value, nil
}
func addADDiscoveryIdentity(account *pamdiscovery.Account, entry *ldap.Entry, service bool) error {
	name, err := singleADDiscoveryAttribute(entry, "sAMAccountName")
	if err != nil || len(name) == 0 || len(name) > 256 || !utf8.Valid(name) || string(name) != account.Name {
		return errors.New("dynsecret AD: invalid or ambiguous account name")
	}
	for _, r := range string(name) {
		if r < 32 || r == 127 {
			return errors.New("dynsecret AD: invalid public account name")
		}
	}
	state, err := singleADDiscoveryAttribute(entry, "userAccountControl")
	if err != nil {
		return err
	}
	flags, err := strconv.ParseUint(string(state), 10, 32)
	if err != nil {
		return errors.New("dynsecret AD: account disabled state is unavailable")
	}
	account.Disabled = flags&2 != 0
	guid, err := singleADDiscoveryAttribute(entry, "objectGUID")
	if err != nil || len(guid) != 16 {
		return errors.New("dynsecret AD: native account GUID unavailable")
	}
	sidRaw, err := singleADDiscoveryAttribute(entry, "objectSid")
	if err != nil {
		return err
	}
	sid, err := adDiscoverySID(sidRaw)
	if err != nil {
		return err
	}
	encoded := hex.EncodeToString(guid)
	if prior := account.Details["native_guid"]; prior != "" && (prior != encoded || account.Details["native_sid"] != sid || !sameADDiscoveryDN(account.Details["dn"], entry.DN)) {
		return errors.New("dynsecret AD: duplicate account binding differs")
	}
	account.Details["native_guid"] = encoded
	account.Details["native_sid"] = sid
	if !service {
		return nil
	}
	account.Details["service_account"] = "true"
	account.Kind = pamdiscovery.KindDirectoryServiceAccount
	names := append([]string(nil), entry.GetAttributeValues("servicePrincipalName")...)
	if len(names) > 128 {
		return errors.New("dynsecret AD: service principal count exceeds bound")
	}
	total := 0
	for _, name := range names {
		total += len(name)
		if total > 8192 {
			return errors.New("dynsecret AD: service principal metadata exceeds byte bound")
		}
		if len(name) == 0 || len(name) > 2048 || !utf8.ValidString(name) {
			return errors.New("dynsecret AD: invalid bounded service principal")
		}
		for _, r := range name {
			if r < 32 || r == 127 {
				return errors.New("dynsecret AD: invalid service principal text")
			}
		}
	}
	if len(names) > 0 {
		sort.Strings(names)
		raw, err := json.Marshal(names)
		if err != nil {
			return err
		}
		account.Details["service_principal_names"] = string(raw)
	}
	return nil
}

func sameADDiscoveryDN(left, right string) bool {
	a, err := ldap.ParseDN(left)
	if err != nil {
		return false
	}
	b, err := ldap.ParseDN(right)
	return err == nil && a.EqualFold(b)
}
