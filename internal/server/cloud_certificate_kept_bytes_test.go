// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"bytes"
	"strings"
	"testing"

	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/crypto/certinfo"
	"trstctl.com/trstctl/internal/discovery/cloudcert"
	"trstctl.com/trstctl/internal/discovery/netscan"
)

// TestKeptCloudCertificateBytesB13L1 pins what a cloud listing keeps: the
// leaf as DER (Azure Key Vault returns the certificate alone) or as the first
// of a PEM chain (ACM, Google Certificate Manager) with the issuers after it,
// bounded as a sweep's are, and nothing for bytes that are not the listed
// certificate.
func TestKeptCloudCertificateBytesB13L1(t *testing.T) {
	f := newScannedRevocationFixture(t)
	listed := certinfo.Info{SHA256Fingerprint: f.leaf.SHA256Fingerprint}
	leafPEM, caPEM := certificatePEM(f.leafDER), certificatePEM(f.caDER)

	leaf, chain := keptCloudCertificateBytes(cloudcert.Found{Raw: f.leafDER, Cert: listed})
	if !bytes.Equal(leaf, f.leafDER) || len(chain.Issuers) != 0 {
		t.Fatalf("a DER listing kept %d bytes and %d issuers; want the leaf alone", len(leaf), len(chain.Issuers))
	}
	leaf, chain = keptCloudCertificateBytes(cloudcert.Found{Raw: []byte(leafPEM + caPEM), Cert: listed})
	if !bytes.Equal(leaf, f.leafDER) || len(chain.Issuers) != 1 || !bytes.Equal(chain.Issuers[0].CertificateDER, f.caDER) ||
		chain.Issuers[0].SHA256 != crypto.SHA256Hex(f.caDER) || chain.LeafFingerprint != strings.ToLower(f.leaf.SHA256Fingerprint) {
		t.Fatalf("a PEM chain kept leaf %d bytes, chain %+v; want the leaf and its issuer", len(leaf), chain)
	}
	leaf, chain = keptCloudCertificateBytes(cloudcert.Found{Raw: []byte(leafPEM + strings.Repeat(caPEM, netscan.MaxKeptIssuers+2)), Cert: listed})
	if !bytes.Equal(leaf, f.leafDER) || len(chain.Issuers) != netscan.MaxKeptIssuers {
		t.Fatalf("a long chain kept %d issuers; want the bound %d", len(chain.Issuers), netscan.MaxKeptIssuers)
	}
	other := newScannedRevocationFixture(t)
	for name, found := range map[string]cloudcert.Found{
		"another certificate's bytes": {Raw: []byte(leafPEM + caPEM), Cert: certinfo.Info{SHA256Fingerprint: other.leaf.SHA256Fingerprint}},
		"the issuer listed first":     {Raw: []byte(caPEM + leafPEM), Cert: listed},
		"not a certificate":           {Raw: []byte("not a certificate"), Cert: listed},
		"text around the chain":       {Raw: []byte("hidden\n" + leafPEM + caPEM), Cert: listed},
		"no bytes":                    {Cert: listed},
	} {
		if leaf, chain := keptCloudCertificateBytes(found); leaf != nil || len(chain.Issuers) != 0 {
			t.Errorf("%s: kept %d bytes and %d issuers", name, len(leaf), len(chain.Issuers))
		}
	}
}
