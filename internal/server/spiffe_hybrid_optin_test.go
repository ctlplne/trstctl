// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/protocols/spiffe"
)

type spiffeHybridOptInIssuer struct{}

func (spiffeHybridOptInIssuer) IssueAdditionalX509SVID(context.Context, string, time.Time) (spiffe.AdditionalX509SVID, error) {
	return spiffe.AdditionalX509SVID{CertificateDER: []byte("test-certificate"), PrivateKeyPKCS8: []byte("test-key"), Hint: "test-hybrid"}, nil
}

func TestServedSPIFFEHybridRequiresOperatorOptIn(t *testing.T) {
	for _, hybrid := range []bool{false, true} {
		t.Run(map[bool]string{false: "stock_default", true: "explicit_hybrid"}[hybrid], func(t *testing.T) {
			calls := 0
			_ = newOperatingServedHarness(t, config.Protocols{SPIFFE: config.SPIFFEProtocol{
				Enabled: true, TenantID: servedTestTenant, TrustDomain: "served.test",
				SocketPath: filepath.Join(t.TempDir(), "workload.sock"), HybridSVIDs: hybrid,
			}}, func(d *Deps) {
				d.LicensedSPIFFESVIDFactory = func([]byte, crypto.DigestSigner) (spiffe.AdditionalX509SVIDIssuer, error) {
					calls++
					return spiffeHybridOptInIssuer{}, nil
				}
			})
			want := 0
			if hybrid {
				want = 1
			}
			if calls != want {
				t.Fatalf("additional SVID factory calls = %d, want %d", calls, want)
			}
		})
	}
}
