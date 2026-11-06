// SPDX-License-Identifier: BUSL-1.1

// Package accessdesktop defines reviewed public desktop routing, never passwords.
package accessdesktop

import (
	"encoding/hex"
	"errors"
	"net"
	"strconv"
	"strings"
)

const TargetRDP = "rdp"
const RecordingScope = "desktop_pixels"

// Binding fixes the upstream server independently of the credential and viewer.
// TLSOnly is explicit for xrdp; false requires network-level authentication.
type Binding struct {
	AccountKind       string         `json:"account_kind,omitempty"`
	Accounts          []BoundAccount `json:"accounts,omitempty"`
	Address           string         `json:"address"`
	CertificateSHA256 string         `json:"certificate_sha256"`
	Domain            string         `json:"domain,omitempty"`
	Width             uint16         `json:"width"`
	Height            uint16         `json:"height"`
	TLSOnly           bool           `json:"tls_only,omitempty"`
}

func (b Binding) Validate() error {
	host, port, err := net.SplitHostPort(b.Address)
	p, e := strconv.ParseUint(port, 10, 16)
	pin, pe := hex.DecodeString(b.CertificateSHA256)
	if err != nil || e != nil || p == 0 || len(host) == 0 || len(host) > 255 || strings.ContainsAny(host, "\x00 \t\r\n/@\\") || pe != nil || len(pin) != 32 || b.Width < 320 || b.Width > 1280 || b.Height < 200 || b.Height > 1024 || len(b.Domain) > 128 || strings.ContainsAny(b.Domain, "\x00\r\n") {
		return errors.New("desktop needs an explicit host:port, certificate SHA-256 pin, bounded domain and 320–1280 by 200–1024 dimensions")
	}
	return b.validateAccounts()
}

// BoundAccount fixes an AD principal's directory reference and RDP logon name.
// These are public identities. The password still comes only from the vault.
type BoundAccount struct {
	Reference string `json:"reference"`
	Username  string `json:"username"`
}

func (b Binding) PermitsAccount(reference, username string) bool {
	if b.AccountKind == "" {
		return true
	}
	if b.AccountKind != "active_directory" {
		return false
	}
	for _, account := range b.Accounts {
		if strings.EqualFold(account.Reference, reference) && account.Username == username {
			return true
		}
	}
	return false
}
func (b Binding) validateAccounts() error {
	if b.AccountKind == "" && len(b.Accounts) == 0 {
		return nil
	}
	if b.AccountKind != "active_directory" || len(b.Accounts) < 1 || len(b.Accounts) > 2 {
		return errors.New("AD desktop requires one or two reviewed account identities")
	}
	for i, account := range b.Accounts {
		if len(account.Reference) == 0 || len(account.Reference) > 4096 || !strings.Contains(account.Reference, "=") || strings.ContainsAny(account.Reference, "\x00\r\n") || len(account.Username) == 0 || len(account.Username) > 128 || strings.TrimSpace(account.Username) != account.Username || strings.ContainsAny(account.Username, "\x00\r\n\t\\/@") {
			return errors.New("AD desktop identity needs an exact bounded account reference and bare logon name")
		}
		for _, previous := range b.Accounts[:i] {
			if strings.EqualFold(previous.Reference, account.Reference) || strings.EqualFold(previous.Username, account.Username) {
				return errors.New("duplicate AD desktop identity")
			}
		}
	}
	return nil
}
