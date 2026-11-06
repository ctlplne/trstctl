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
	Address           string `json:"address"`
	CertificateSHA256 string `json:"certificate_sha256"`
	Domain            string `json:"domain,omitempty"`
	Width             uint16 `json:"width"`
	Height            uint16 `json:"height"`
	TLSOnly           bool   `json:"tls_only,omitempty"`
}

func (b Binding) Validate() error {
	host, port, err := net.SplitHostPort(b.Address)
	p, e := strconv.ParseUint(port, 10, 16)
	pin, pe := hex.DecodeString(b.CertificateSHA256)
	if err != nil || e != nil || p == 0 || len(host) == 0 || len(host) > 255 || strings.ContainsAny(host, "\x00 \t\r\n/@\\") || pe != nil || len(pin) != 32 || b.Width < 320 || b.Width > 1280 || b.Height < 200 || b.Height > 1024 || len(b.Domain) > 128 || strings.ContainsAny(b.Domain, "\x00\r\n") {
		return errors.New("desktop needs an explicit host:port, certificate SHA-256 pin, bounded domain and 320–1280 by 200–1024 dimensions")
	}
	return nil
}
