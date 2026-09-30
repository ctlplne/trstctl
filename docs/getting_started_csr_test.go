// SPDX-License-Identifier: BUSL-1.1

package docs

import (
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"trstctl.com/trstctl/internal/crypto"
)

func TestGettingStartedOpenSSLCSRPassesIssuanceParser(t *testing.T) {
	if _, err := exec.LookPath("openssl"); err != nil {
		t.Skip("OpenSSL is required to execute the documented first-certificate command")
	}

	lines := strings.Split(read(t, "getting-started.md"), "\n")
	var command []string
	for i, line := range lines {
		if !strings.HasPrefix(line, "openssl req -new -newkey ec ") {
			continue
		}
		for ; i < len(lines); i++ {
			command = append(command, lines[i])
			if !strings.HasSuffix(strings.TrimSpace(lines[i]), "\\") {
				break
			}
		}
		break
	}
	if len(command) == 0 {
		t.Fatal("getting-started.md has no first-certificate OpenSSL CSR command")
	}

	dir := t.TempDir()
	cmd := exec.Command("sh", "-c", "umask 077\n"+strings.Join(command, "\n"))
	cmd.Dir = dir
	if output, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("documented CSR command failed: %v: %s", err, output)
	}

	csr, err := os.ReadFile(filepath.Join(dir, "payments.csr"))
	if err != nil {
		t.Fatal(err)
	}
	_, info, err := crypto.ParsePublicCSRPEM(csr)
	if err != nil {
		t.Fatalf("documented CSR cannot pass the issuance parser: %v", err)
	}
	if info.KeyAlgorithm != "ECDSA" || info.KeyBits != 256 || info.CommonName != "payments.svc" || !slices.Equal(info.DNSNames, []string{"payments.svc"}) {
		t.Fatalf("documented CSR lost its intended key or DNS identity: %+v", info)
	}
	key, err := os.Stat(filepath.Join(dir, "payments.key"))
	if err != nil {
		t.Fatal(err)
	}
	if key.Mode().Perm()&0o077 != 0 {
		t.Fatalf("documented private key is readable outside its owner: %v", key.Mode().Perm())
	}
}
