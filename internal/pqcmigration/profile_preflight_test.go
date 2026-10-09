// SPDX-License-Identifier: BUSL-1.1

package pqcmigration

import (
	"strings"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/profile"
)

func TestPQCReissueProfilePreflightRejectsDisallowedObservedName(t *testing.T) {
	selected := profile.CertificateProfile{
		Name: "u5-internal-eab-30d", Version: 1,
		AllowedKeyAlgorithms: []string{"ECDSA"}, AllowedProtocols: []string{"acme"},
		AllowedDNSSuffixes: []string{"eab.partner-lab.example.com"},
		MaxValidity:        profile.Duration(30 * 24 * time.Hour),
	}
	asset := Asset{ID: "observed-rsa", Kind: "certificate-key", Location: "127.0.0.1:10443"}
	if err := validatePQCReissueProfile(selected, asset, ProtocolACME); err == nil ||
		!strings.Contains(err.Error(), `127.0.0.1`) ||
		!strings.Contains(err.Error(), `u5-internal-eab-30d`) {
		t.Fatalf("preflight error = %v, want exact refused name and selected profile", err)
	}
	asset.Location = "pay.eab.partner-lab.example.com:443"
	if err := validatePQCReissueProfile(selected, asset, ProtocolACME); err != nil {
		t.Fatalf("permitted observed name refused: %v", err)
	}
}
