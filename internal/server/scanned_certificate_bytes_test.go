// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"bytes"
	"testing"

	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/discovery/segmentscan"
)

// A211: the control plane keeps a relay's certificate bytes only when they
// hash to what the relay reported: a leaf that does not keeps nothing, and the
// issuers stop at the first one that does not.
func TestKeptScanBytesFollowTheReportedHashes(t *testing.T) {
	leaf, first, second := []byte("leaf certificate"), []byte("first issuer"), []byte("second issuer")
	finding := segmentscan.Finding{
		Fingerprint: crypto.SHA256Hex(leaf), CertificateDER: leaf,
		ChainCertSHA256: []string{crypto.SHA256Hex(first), crypto.SHA256Hex(second)},
		ChainDER:        [][]byte{first, second},
	}
	der, chain := keptScanBytes(finding)
	if !bytes.Equal(der, leaf) || len(chain.Issuers) != 2 || chain.LeafFingerprint != finding.Fingerprint {
		t.Fatalf("matching bytes kept = %d leaf bytes, %d issuers", len(der), len(chain.Issuers))
	}
	swapped := finding
	swapped.ChainDER = [][]byte{first, []byte("not the second issuer")}
	if _, chain := keptScanBytes(swapped); len(chain.Issuers) != 1 {
		t.Fatalf("an issuer whose bytes do not match its hash was kept: %d issuers", len(chain.Issuers))
	}
	forged := finding
	forged.CertificateDER = []byte("another leaf")
	if der, chain := keptScanBytes(forged); der != nil || len(chain.Issuers) != 0 {
		t.Fatal("bytes that do not hash to the reported fingerprint were kept")
	}
	if der, chain := keptScanBytes(segmentscan.Finding{Fingerprint: finding.Fingerprint}); der != nil || len(chain.Issuers) != 0 {
		t.Fatal("a finding without bytes kept some")
	}
}
