// SPDX-License-Identifier: BUSL-1.1

package pqcmigration

import (
	"strings"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/profile"
)

func TestPQCReissueProfilePreflightUsesBoundIdentityNameAndHostAlgorithm(t *testing.T) {
	selected := profile.CertificateProfile{
		Name: "u5-internal-eab-30d", Version: 1,
		AllowedKeyAlgorithms: []string{"ML-DSA-65"}, AllowedProtocols: []string{"api"},
		AllowedDNSSuffixes: []string{"eab.partner-lab.example.com"},
		MaxValidity:        profile.Duration(30 * 24 * time.Hour),
	}
	asset := Asset{ID: "observed-rsa", Kind: "certificate-key", Location: "127.0.0.1:10443", CertificateFingerprint: strings.Repeat("a", 64)}
	if err := validatePQCReissueProfile(selected, asset, "apache.partner-lab.example.com", ProtocolHostCSR); err == nil ||
		!strings.Contains(err.Error(), `apache.partner-lab.example.com`) ||
		!strings.Contains(err.Error(), `u5-internal-eab-30d`) {
		t.Fatalf("preflight error = %v, want bound subject refusal and selected profile", err)
	}
	if err := validatePQCReissueProfile(selected, asset, "pay.eab.partner-lab.example.com", ProtocolHostCSR); err != nil {
		t.Fatalf("permitted bound subject refused: %v", err)
	}
}
