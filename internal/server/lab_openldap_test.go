// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"context"
	"encoding/hex"
	"encoding/pem"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/crypto/mtls"
)

// labOpenLDAP is a running directory from the pinned OpenLDAP image, serving
// LDAPS for ldap.lab.test with a certificate from the crypto boundary.
type labOpenLDAP struct {
	id, addr, admin, adminPassword, base string
	trustPEM                             []byte
}

// startLabOpenLDAP runs the pinned image for one test, or skips when docker or
// the image is not available.
func startLabOpenLDAP(t *testing.T) labOpenLDAP {
	t.Helper()
	if testing.Short() {
		t.Skip("container acceptance test")
	}
	if _, err := exec.LookPath("docker"); err != nil {
		t.Skipf("docker is required: %v", err)
	}
	if out, err := exec.Command("docker", "image", "inspect", a239OpenLDAPImage).CombinedOutput(); err != nil { // #nosec G204 -- test executes a fixed local tool or fixture it built itself (CWE-78)
		t.Skipf("the pinned image %s is not present locally: %v\n%s", a239OpenLDAPImage, err, out)
	}
	random, err := crypto.RandomBytes(16)
	if err != nil {
		t.Fatal(err)
	}
	lab := labOpenLDAP{admin: "cn=admin,dc=lab,dc=test", adminPassword: hex.EncodeToString(random), base: "dc=lab,dc=test"}
	// The image's bundled CA expired on 2026-01-15, so every certificate it
	// generates fails verification. The directory gets a fresh self-signed
	// certificate for ldap.lab.test from the crypto boundary instead, copied in
	// before it starts.
	tlsDir := t.TempDir()
	serving, err := mtls.LoadOrCreateSelfSignedServerCert(filepath.Join(tlsDir, "state", "ldap.pem"), []string{"ldap.lab.test"}, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	lab.trustPEM = serving.TrustPEM
	state, err := os.ReadFile(filepath.Join(tlsDir, "state", "ldap.pem")) // #nosec G304 -- the test's own temp file (CWE-22)
	if err != nil {
		t.Fatal(err)
	}
	files := map[string][]byte{"ca.crt": serving.TrustPEM, "ldap.crt": serving.TrustPEM}
	for rest := state; ; {
		var block *pem.Block
		if block, rest = pem.Decode(rest); block == nil {
			break
		}
		if block.Type == "PRIVATE KEY" {
			files["ldap.key"] = pem.EncodeToMemory(block)
		}
	}
	if len(files["ldap.key"]) == 0 {
		t.Fatal("the generated TLS state holds no key")
	}
	// The image demands client certificates by default; accounts bind with
	// passwords over server-authenticated TLS.
	created, err := exec.Command("docker", "create", "-p", "127.0.0.1::636", "--hostname", "ldap.lab.test", // #nosec G204 -- test executes a fixed local tool or fixture it built itself (CWE-78)
		"-e", "LDAP_ORGANISATION=trstctl lab", "-e", "LDAP_DOMAIN=lab.test", "-e", "LDAP_ADMIN_PASSWORD="+lab.adminPassword,
		"-e", "LDAP_TLS_VERIFY_CLIENT=never", "-e", "LDAP_TLS_CRT_FILENAME=ldap.crt", "-e", "LDAP_TLS_KEY_FILENAME=ldap.key",
		"-e", "LDAP_TLS_CA_CRT_FILENAME=ca.crt", a239OpenLDAPImage).CombinedOutput()
	if err != nil {
		t.Fatalf("docker create: %v %s", err, created)
	}
	lab.id = strings.TrimSpace(string(created))
	t.Cleanup(func() { _ = exec.Command("docker", "rm", "-f", lab.id).Run() }) // #nosec G204 -- test executes a fixed local tool or fixture it built itself (CWE-78)
	for name, body := range files {
		local := filepath.Join(tlsDir, name)
		if err := os.WriteFile(local, body, 0o644); err != nil { // #nosec G306 -- the container's directory server reads it; the key is a throwaway lab key (CWE-276)
			t.Fatal(err)
		}
		if out, err := exec.Command("docker", "cp", local, lab.id+":/container/service/slapd/assets/certs/"+name).CombinedOutput(); err != nil { // #nosec G204 -- test executes a fixed local tool or fixture it built itself (CWE-78)
			t.Fatalf("copy %s: %v %s", name, err, out)
		}
	}
	if out, err := exec.Command("docker", "start", lab.id).CombinedOutput(); err != nil { // #nosec G204 -- test executes a fixed local tool or fixture it built itself (CWE-78)
		t.Fatalf("docker start: %v %s", err, out)
	}
	mapped, err := exec.Command("docker", "port", lab.id, "636/tcp").Output() // #nosec G204 -- test executes a fixed local tool or fixture it built itself (CWE-78)
	if err != nil {
		t.Fatalf("docker port: %v", err)
	}
	lab.addr = strings.TrimSpace(strings.Split(string(mapped), "\n")[0])
	// The image runs a bootstrap server first; it serves LDAPS with the
	// certificate it was given only once its final server is up.
	a201Await(t, "OpenLDAP serving LDAPS", func() bool {
		out, err := a201Exec(lab.id, "env", "LDAPTLS_CACERT=/container/service/slapd/assets/certs/ca.crt", "ldapsearch", "-x",
			"-H", "ldaps://ldap.lab.test", "-D", lab.admin, "-w", lab.adminPassword, "-b", lab.base, "-s", "base", "-LLL", "dn")
		return err == nil && strings.Contains(out, "dn: "+lab.base)
	})
	return lab
}

// tool runs an OpenLDAP client inside the container against its own plain
// listener.
func (lab labOpenLDAP) tool(name string, args ...string) (string, error) {
	return a201Exec(lab.id, append([]string{name, "-x", "-H", "ldap://localhost"}, args...)...)
}

// seed adds an LDIF document as the administrator.
func (lab labOpenLDAP) seed(t *testing.T, ldif string) {
	t.Helper()
	file := filepath.Join(t.TempDir(), "seed.ldif")
	if err := os.WriteFile(file, []byte(ldif), 0o600); err != nil {
		t.Fatal(err)
	}
	if out, err := exec.Command("docker", "cp", file, lab.id+":/tmp/seed.ldif").CombinedOutput(); err != nil { // #nosec G204 -- test executes a fixed local tool or fixture it built itself (CWE-78)
		t.Fatalf("copy the seed: %v %s", err, out)
	}
	if out, err := lab.tool("ldapadd", "-D", lab.admin, "-w", lab.adminPassword, "-f", "/tmp/seed.ldif"); err != nil {
		t.Fatalf("seed the directory: %v %s", err, out)
	}
}

// contextLDAP bounds a client call to the lab.
func contextLDAP() (context.Context, context.CancelFunc) {
	return context.WithTimeout(context.Background(), 10*time.Second)
}
