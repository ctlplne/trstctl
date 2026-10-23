// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"os"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/crypto/certinfo"
	"trstctl.com/trstctl/internal/discovery/cloudcert"
	"trstctl.com/trstctl/internal/discovery/ctmonitor"
	"trstctl.com/trstctl/internal/keyposture"
)

func serverKeypostureFixture(t *testing.T, name string) []byte {
	t.Helper()
	data, err := os.ReadFile("../keyposture/testdata/" + name) // #nosec G304 -- a fixed test fixture, named by the test itself (CWE-22)
	if err != nil {
		t.Fatal(err)
	}
	return data
}

// Part 4: a cloud-discovered certificate is rated from the bytes the provider
// returned, so an RSA-1024 certificate is weak and a leaf under one of the
// eight eMudhra intermediates is distrusted, each with its risk raised.
func TestCloudFindingMetadataRatesTheReturnedCertificate(t *testing.T) {
	for _, tc := range []struct {
		fixture, wantKey, wantValue string
		wantRisk                    int
	}{
		{"rsa-1024.pem", keyposture.MetaKeyStrength, "weak", keyposture.RiskWeak},
		{"leaf-under-em-ov-tls-ca-g3c.pem", keyposture.MetaDistrustEntry, "EM OV TLS CA - G3C", keyposture.RiskDistrusted},
	} {
		raw := serverKeypostureFixture(t, tc.fixture)
		info, err := certinfo.Inspect(raw)
		if err != nil {
			t.Fatal(err)
		}
		meta, risk := cloudFindingMetadata(cloudcert.Found{Provider: "aws-acm", ResourceID: "arn:x", Cert: info, Raw: raw})
		if meta[tc.wantKey] != tc.wantValue || risk < tc.wantRisk {
			t.Fatalf("%s: metadata %v risk %d", tc.fixture, meta, risk)
		}
	}
	ordinary := serverKeypostureFixture(t, "ecdsa-p256-ordinary.pem")
	info, err := certinfo.Inspect(ordinary)
	if err != nil {
		t.Fatal(err)
	}
	if meta, _ := cloudFindingMetadata(cloudcert.Found{Provider: "aws-acm", Cert: info, Raw: ordinary}); meta[keyposture.MetaKeyStrength] != nil || meta[keyposture.MetaDistrustEntry] != nil {
		t.Fatalf("an ordinary certificate was rated: %v", meta)
	}
}

func TestCTFindingMetadataCarriesTheMonitorVerdict(t *testing.T) {
	f := ctmonitor.Finding{LogURL: "log-a", Subject: "CN=shop.example.com", NotAfter: time.Now().Add(365 * 24 * time.Hour),
		AuthorityKeyID: "34eaea0cebc90adaf9d0c5e2ed9b78c9879e1b6c",
		Posture:        keyposture.Verdict{DistrustEntry: "EM OV TLS CA - G3C", DistrustHow: "issuer_key_id", DistrustReason: "weak"}}
	meta, risk := ctFindingMetadata(f)
	if meta[keyposture.MetaDistrustEntry] != "EM OV TLS CA - G3C" || meta["authority_key_id"] == "" || risk != keyposture.RiskDistrusted {
		t.Fatalf("CT metadata %v risk %d", meta, risk)
	}
}
