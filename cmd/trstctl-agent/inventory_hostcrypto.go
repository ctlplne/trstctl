// SPDX-License-Identifier: BUSL-1.1

package main

import (
	"bytes"
	"context"
	"flag"
	"fmt"
	"os"
	"strings"

	"trstctl.com/trstctl/internal/agent"
	agentdiscovery "trstctl.com/trstctl/internal/agent/discovery"
	"trstctl.com/trstctl/internal/crypto/secret"
)

// Host crypto inventory (X2): the keystores on this host and the TLS libraries
// and Go programs it runs. Both report metadata only over the agent channel.
var (
	inventoryKeystores = flag.String("inventory-keystores", "",
		"comma-separated Java keystore (JKS, JCEKS, BCFKS) and PKCS#12 files, directories or globs whose key entries the agent inventories: alias, key type and size from each entry's certificate, never key bytes; a JCEKS or BCFKS store's secret keys are counted, never unsealed")
	inventoryKeystorePasswordFile = flag.String("inventory-keystore-password-file", "",
		"file holding keystore passwords, one per line, tried in order before the published default \"changeit\"; a file rather than a flag, because process arguments expose credentials. A JKS or JCEKS lists its entries without one (marked unverified); a PKCS#12 file or BCFKS store it cannot open is reported locked")
	inventoryCryptoLibraries = flag.String("inventory-crypto-libraries", "",
		"comma-separated TLS library files, directories or globs (libssl, libcrypto, libgnutls, NSS's libsoftokn3, libwolfssl; OpenSSL, LibreSSL, BoringSSL, AWS-LC, wolfSSL, GnuTLS and NSS) whose versions the agent reads from the files, with whether each can negotiate X25519MLKEM768; nothing is executed")
	inventoryGoBinaries = flag.String("inventory-go-binaries", "",
		"comma-separated Go program files or globs whose build information the agent reads for the same post-quantum answer")
	inventoryJava = flag.String("inventory-java", "",
		"comma-separated Java installations (a JDK or JRE home), directories or globs holding them, and BouncyCastle jars (bcprov, bctls and their FIPS editions) or the directories that hold them: each installation's version and security providers, each jar's version, with the same post-quantum answer for their TLS; nothing is run")
)

func reportHostCryptoInventory(ctx context.Context, a *agent.Agent, ch agent.ChannelClient) {
	if paths := splitList(*inventoryKeystores); len(paths) > 0 {
		if err := reportKeystoreInventory(ctx, a, ch, paths, strings.TrimSpace(*inventoryKeystorePasswordFile)); err != nil {
			fmt.Fprintln(os.Stderr, "trstctl-agent: keystore inventory report failed:", err)
		}
	}
	libraries, programs, java := splitList(*inventoryCryptoLibraries), splitList(*inventoryGoBinaries), splitList(*inventoryJava)
	if len(libraries)+len(programs)+len(java) > 0 {
		if err := reportCryptoLibraryInventory(ctx, a, ch, libraries, programs, java); err != nil {
			fmt.Fprintln(os.Stderr, "trstctl-agent: crypto library inventory report failed:", err)
		}
	}
}

func reportKeystoreInventory(ctx context.Context, a *agent.Agent, ch agent.ChannelClient, paths []string, passwordFile string) error {
	passwords, err := readKeystorePasswords(passwordFile)
	if err != nil {
		return err
	}
	defer func() {
		for _, p := range passwords {
			secret.Wipe(p)
		}
	}()
	found, err := agentdiscovery.NewKeystoreSource(passwords, paths...).Discover(ctx)
	if err != nil {
		return err
	}
	findings := privateKeyInventoryFindings(found)
	if len(findings) == 0 {
		return nil
	}
	resp, err := a.ReportInventory(ctx, ch, agentdiscovery.SourceKeystore, findings)
	if err != nil {
		return err
	}
	fmt.Printf("trstctl-agent: reported %d keystore inventory findings (run %s, rejected %d)\n", resp.Recorded, resp.RunID, resp.Rejected)
	return nil
}

// readKeystorePasswords reads one password per line; the caller wipes them.
func readKeystorePasswords(path string) ([][]byte, error) {
	if path == "" {
		return nil, nil
	}
	data, err := os.ReadFile(path) // #nosec G304 -- operator-configured keystore password file (CWE-22)
	if err != nil {
		return nil, fmt.Errorf("read keystore password file: %w", err)
	}
	defer secret.Wipe(data)
	var out [][]byte
	for _, line := range bytes.Split(data, []byte("\n")) {
		line = bytes.TrimRight(line, "\r")
		if len(line) > 0 {
			out = append(out, append([]byte(nil), line...))
		}
	}
	return out, nil
}

// cryptoLibrarySource is the library source the agent's flags configure:
// TLS libraries, Go programs, the system crypto policy (X2-L6) and Java
// (X2-L4R).
func cryptoLibrarySource(libraries, programs, java []string) *agentdiscovery.CryptoLibrarySource {
	return agentdiscovery.NewCryptoLibrarySource(libraries, programs).
		WithCryptoPolicy(agentdiscovery.DefaultCryptoPolicyRoot).WithJava(java...)
}

func reportCryptoLibraryInventory(ctx context.Context, a *agent.Agent, ch agent.ChannelClient, libraries, programs, java []string) error {
	found, err := cryptoLibrarySource(libraries, programs, java).Discover(ctx)
	if err != nil {
		return err
	}
	findings := cryptoLibraryInventoryFindings(found)
	if len(findings) == 0 {
		return nil
	}
	resp, err := a.ReportInventory(ctx, ch, agentdiscovery.SourceCryptoLibrary, findings)
	if err != nil {
		return err
	}
	fmt.Printf("trstctl-agent: reported %d crypto library inventory findings (run %s, rejected %d)\n", resp.Recorded, resp.RunID, resp.Rejected)
	return nil
}

// cryptoLibraryInventoryFindings reports each library or program with its
// version and post-quantum answer; a library that cannot negotiate
// X25519MLKEM768 rates higher risk than one whose answer is unknown.
func cryptoLibraryInventoryFindings(found []agentdiscovery.LibraryFound) []agent.InventoryFinding {
	findings := make([]agent.InventoryFinding, 0, len(found))
	for _, f := range found {
		risk := 30
		switch f.PQHybrid {
		case agentdiscovery.PQHybridYes:
			risk = 10
		case agentdiscovery.PQHybridNo:
			risk = 50
		}
		// X2-L6: a LEGACY system policy weakens every library on the host.
		if f.Library == agentdiscovery.CryptoPolicyLibrary && agentdiscovery.CryptoPolicyIsLegacy(f.Version) {
			risk = 70
		}
		meta := map[string]string{
			"library":                  f.Library,
			"library_version":          f.Version,
			"pq_hybrid_x25519mlkem768": f.PQHybrid,
			"pq_basis":                 f.Basis,
		}
		// X2-L4R: a Java installation's security providers, in order.
		if len(f.Providers) > 0 {
			meta["java_security_providers"] = strings.Join(f.Providers, ", ")
		}
		findings = append(findings, agent.InventoryFinding{
			Kind:       "crypto_library",
			Ref:        f.Location,
			Provenance: agentdiscovery.SourceCryptoLibrary + ":" + f.Location,
			RiskScore:  risk,
			Metadata:   meta,
		})
	}
	return findings
}
