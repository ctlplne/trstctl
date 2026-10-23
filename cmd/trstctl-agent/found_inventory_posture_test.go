// SPDX-License-Identifier: BUSL-1.1

package main

import (
	"encoding/pem"
	"os"
	"testing"

	agentdiscovery "trstctl.com/trstctl/internal/agent/discovery"
	"trstctl.com/trstctl/internal/crypto/certinfo"
	"trstctl.com/trstctl/internal/keyposture"
)

func agentFixture(t *testing.T, name string) []byte {
	t.Helper()
	data, err := os.ReadFile("../../internal/keyposture/testdata/" + name) // #nosec G304 -- a fixed test fixture, named by the test itself (CWE-22)
	if err != nil {
		t.Fatal(err)
	}
	return data
}

// Part 4 Done-when: a host trust store holding emSign ECC Root CA - G3 is a
// finding. The agent rates every certificate it found while the bytes are at
// hand; the verdict travels as metadata and raises the risk.
func TestFoundInventoryFindingsRateTrustStoresAndLeaves(t *testing.T) {
	root := agentFixture(t, "emsign-ecc-root-ca-g3.pem")
	rootInfo, err := certinfo.Inspect(root)
	if err != nil {
		t.Fatal(err)
	}
	got := foundInventoryFindings(agentdiscovery.SourceTrustStore, []agentdiscovery.Found{{Source: agentdiscovery.SourceTrustStore, Location: "/etc/ssl/certs/emSign_ECC_Root_CA_-_G3.pem", Cert: rootInfo, Raw: root}}, 20)
	if len(got) != 1 || got[0].Kind != agentdiscovery.SourceTrustStore || got[0].RiskScore != 95 ||
		got[0].Metadata["distrust_entry"] != "emSign ECC Root CA - G3" || got[0].Metadata["distrust_how"] != "itself" || got[0].Metadata["spki_sha256"] == "" {
		t.Fatalf("trust store holding emSign ECC Root CA - G3: %+v", got)
	}
	leafPEM := agentFixture(t, "leaf-under-em-ov-tls-ca-g3c.pem")
	inter := agentFixture(t, "em-ov-tls-ca-g3c.pem")
	leafInfo, err := certinfo.Inspect(leafPEM)
	if err != nil {
		t.Fatal(err)
	}
	interBlock, _ := pem.Decode(inter)
	got = foundInventoryFindings(agentdiscovery.SourceFilesystem, []agentdiscovery.Found{{Source: agentdiscovery.SourceFilesystem, Location: "/etc/nginx/shop.pem", Cert: leafInfo, Raw: leafPEM, Chain: [][]byte{interBlock.Bytes}}}, 10)
	if len(got) != 1 || got[0].Metadata["distrust_how"] != "chain" || got[0].Metadata["authority_key_id"] == "" || got[0].RiskScore != 95 {
		t.Fatalf("leaf with its chain: %+v", got)
	}
	ordinary := agentFixture(t, "ecdsa-p256-ordinary.pem")
	ordInfo, err := certinfo.Inspect(ordinary)
	if err != nil {
		t.Fatal(err)
	}
	got = foundInventoryFindings(agentdiscovery.SourceFilesystem, []agentdiscovery.Found{{Source: agentdiscovery.SourceFilesystem, Location: "/etc/ssl/api.pem", Cert: ordInfo, Raw: ordinary}}, 10)
	if len(got) != 1 || got[0].RiskScore != 10 || got[0].Metadata["key_strength"] != "" || got[0].Metadata["distrust_entry"] != "" {
		t.Fatalf("an ordinary certificate was rated: %+v", got)
	}
	if got[0].Metadata["rsa_spki"] != "" {
		t.Fatalf("an ECDSA certificate carried an RSA key: %+v", got[0].Metadata)
	}
	// An RSA certificate's public key travels with it for the control plane's
	// blocklists and batch-GCD audit, and hashes to the reported spki_sha256.
	rsaPEM := agentFixture(t, "rsa-1024.pem")
	rsaInfo, err := certinfo.Inspect(rsaPEM)
	if err != nil {
		t.Fatal(err)
	}
	got = foundInventoryFindings(agentdiscovery.SourceFilesystem, []agentdiscovery.Found{{Source: agentdiscovery.SourceFilesystem, Location: "/etc/ssl/legacy.pem", Cert: rsaInfo, Raw: rsaPEM}}, 10)
	if len(got) != 1 {
		t.Fatalf("RSA certificate: %+v", got)
	}
	if _, ok := keyposture.ReportedRSAKey(got[0].Metadata["rsa_spki"], got[0].Metadata["spki_sha256"]); !ok {
		t.Fatalf("the RSA key does not match the reported spki_sha256: %+v", got[0].Metadata)
	}
}
