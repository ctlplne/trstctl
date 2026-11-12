// SPDX-License-Identifier: BUSL-1.1

package main

import (
	"os"
	"path/filepath"
	"testing"

	agentdiscovery "trstctl.com/trstctl/internal/agent/discovery"
)

// X2: keystore passwords come from a file, one per line, and a library's
// post-quantum answer travels with its version and the reason.
func TestHostCryptoInventoryHelpers(t *testing.T) {
	path := filepath.Join(t.TempDir(), "keystore-passwords")
	if err := os.WriteFile(path, []byte("storepass\r\n\nchangeit-too\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	passwords, err := readKeystorePasswords(path)
	if err != nil || len(passwords) != 2 || string(passwords[0]) != "storepass" || string(passwords[1]) != "changeit-too" {
		t.Fatalf("passwords = %q, %v", passwords, err)
	}
	if none, err := readKeystorePasswords(""); err != nil || none != nil {
		t.Fatalf("no password file = %q, %v", none, err)
	}
	if _, err := readKeystorePasswords(filepath.Join(t.TempDir(), "missing")); err == nil {
		t.Fatal("a missing password file was ignored")
	}
	findings := cryptoLibraryInventoryFindings([]agentdiscovery.LibraryFound{
		{Location: "/usr/lib/libcrypto.so.3", Library: "openssl", Version: "3.5.1", PQHybrid: agentdiscovery.PQHybridYes, Basis: "b1"},
		{Location: "/usr/lib/old/libcrypto.so.3", Library: "openssl", Version: "3.0.13", PQHybrid: agentdiscovery.PQHybridNo, Basis: "b2"},
	})
	if len(findings) != 2 || findings[0].Kind != "crypto_library" || findings[0].Metadata["pq_hybrid_x25519mlkem768"] != "yes" ||
		findings[1].Metadata["library_version"] != "3.0.13" || findings[1].RiskScore <= findings[0].RiskScore ||
		findings[0].Provenance != agentdiscovery.SourceCryptoLibrary+":/usr/lib/libcrypto.so.3" {
		t.Fatalf("library findings = %+v", findings)
	}

	// X2-L6: the system crypto policy is one more finding; LEGACY rates
	// above a library that cannot negotiate X25519MLKEM768.
	policies := cryptoLibraryInventoryFindings([]agentdiscovery.LibraryFound{
		{Location: "/etc/crypto-policies/config", Library: agentdiscovery.CryptoPolicyLibrary, Version: "DEFAULT:PQ", PQHybrid: agentdiscovery.PQHybridYes, Basis: "p1"},
		{Location: "/etc/crypto-policies/config", Library: agentdiscovery.CryptoPolicyLibrary, Version: "LEGACY", PQHybrid: agentdiscovery.PQHybridNo, Basis: "p2"},
	})
	if len(policies) != 2 || policies[0].Metadata["library"] != "crypto-policies" || policies[0].Metadata["library_version"] != "DEFAULT:PQ" ||
		policies[0].RiskScore != 10 || policies[1].RiskScore <= findings[1].RiskScore {
		t.Fatalf("policy findings = %+v", policies)
	}
}
