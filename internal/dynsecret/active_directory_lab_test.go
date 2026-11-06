// SPDX-License-Identifier: BUSL-1.1
package dynsecret

import (
	"bytes"
	"context"
	"encoding/json"
	"net"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/crypto/mtls"
	"trstctl.com/trstctl/internal/crypto/secret"
)

func TestActiveDirectoryVaultedPasswordNativeA263(t *testing.T) {
	if os.Getenv("TRSTCTL_AD_NATIVE_LAB") != "1" {
		t.Skip("owned Samba AD native lab not requested")
	}
	ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
	defer cancel()
	admin, err := os.ReadFile("/run/ad-admin-password")
	if err != nil {
		t.Fatal(err)
	}
	defer secret.Wipe(admin)
	ca, err := os.ReadFile("/run/ad-ca.pem")
	if err != nil {
		t.Fatal(err)
	}
	const account = "CN=a263-proof,OU=TrstctlA263,DC=a263,DC=test"
	cfg := LDAPConfig{Addr: net.JoinHostPort("ad263", "636"), TLSServerName: "ad263", TLSCAPEM: ca, BindDN: "CN=Administrator,CN=Users,DC=a263,DC=test", BindPassword: admin, UsersDN: "OU=TrstctlA263,DC=a263,DC=test", RoleGroups: map[string]string{"directory/proof": account}}
	if err = json.Unmarshal([]byte(`{"directory_mode":"active_directory"}`), &cfg); err != nil {
		t.Fatal(err)
	}
	tls, e := mtls.DialVerifiedTCP(ctx, cfg.Addr, cfg.TLSServerName, ca)
	if e != nil {
		t.Fatal("native fixture TLS preflight:", e)
	}
	_ = tls.Close()
	backend, err := NewLDAPBackend(cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer backend.Close()
	makeCredential := func(previous string) []byte {
		t.Helper()
		ref, raw, e := backend.CreateCredential(ctx, GenerateRequest{Role: "directory/proof", Static: true, Predecessor: previous})
		if e != nil || ref != account {
			t.Fatalf("native AD password reset: ref=%s error=%v", ref, e)
		}
		return raw
	}
	first := makeCredential("")
	defer secret.Wipe(first)
	if err = backend.VerifyCredential(ctx, first); err != nil {
		t.Fatal("new AD password did not bind:", err)
	}
	second := makeCredential(account)
	defer secret.Wipe(second)
	if err = backend.VerifyCredential(ctx, second); err != nil {
		t.Fatal("second AD password did not bind:", err)
	}
	parse := func(raw []byte) []byte {
		t.Helper()
		var c struct {
			Password secret.JSONBytes `json:"password"`
		}
		if json.Unmarshal(raw, &c) != nil || len(c.Password) == 0 {
			t.Fatal("missing byte-backed credential")
		}
		return c.Password
	}
	current := parse(second)
	defer secret.Wipe(current)
	old := parse(first)
	defer secret.Wipe(old)
	if output, e := adStockTool(ctx, current, "ldapsearch", "-D", account, "-LLL", "-b", account, "-s", "base", "sAMAccountName"); e != nil || !bytes.Contains(bytes.ToLower(output), []byte("a263-proof")) {
		t.Fatalf("stock current password refused: %v", e)
	}
	if output, e := adStockTool(ctx, old, "ldapsearch", "-D", account, "-LLL", "-b", account, "-s", "base", "sAMAccountName"); e == nil || !bytes.Contains(output, []byte("Invalid credentials (49)")) {
		t.Fatalf("stock predecessor was not refused: %v", e)
	}
	counter := func() string {
		t.Helper()
		out, e := adStockTool(ctx, admin, "ldapsearch", "-D", cfg.BindDN, "-LLL", "-b", account, "-s", "base", "badPwdCount")
		if e != nil {
			t.Fatal("native account state read:", e)
		}
		for _, line := range strings.Split(string(out), "\n") {
			if strings.HasPrefix(line, "badPwdCount:") {
				return line
			}
		}
		t.Fatal("directory omitted bad-password counter")
		return ""
	}
	// A password from older history may be refused without increasing badPwdCount.
	// An unrelated invalid password must create one native failed-bind count.
	if output, e := adStockTool(ctx, []byte("Tr5!unrelated-owned-invalid-password"), "ldapsearch", "-D", account, "-LLL", "-b", account, "-s", "base", "sAMAccountName"); e == nil || !bytes.Contains(output, []byte("Invalid credentials (49)")) {
		t.Fatal("unrelated invalid password was not refused")
	}
	before := counter()
	if before != "badPwdCount: 1" {
		t.Fatalf("old password attempt did not reach native AD: %s", before)
	}
	for i := 0; i < 2; i++ {
		if err = backend.VerifyCredential(ctx, first); err == nil {
			t.Fatal("unsafe repeated bind allowed")
		}
	}
	if after := counter(); after != before {
		t.Fatalf("lockout-aware refusal sent more passwords: before=%s after=%s", before, after)
	}
}

// Passwords reach stock tools only through a private inherited read pipe.
func adStockTool(ctx context.Context, password []byte, tool string, args ...string) ([]byte, error) {
	input, output, err := os.Pipe()
	if err != nil {
		return nil, err
	}
	defer func() { _ = input.Close() }()
	if _, err = output.Write(password); err != nil {
		_ = output.Close()
		return nil, err
	}
	_ = output.Close()
	command := exec.CommandContext(ctx, "/usr/bin/"+tool, append([]string{"-x", "-H", "ldaps://ad263:636", "-y", "/proc/self/fd/3"}, args...)...) // #nosec G204 -- fixed stock tools and test-owned public directory arguments; password arrives on an inherited pipe, no shell (CWE-78)
	command.ExtraFiles = []*os.File{input}
	command.Env = []string{"PATH=/usr/bin:/bin", "HOME=/nonexistent", "LDAPTLS_CACERT=/run/ad-ca.pem"}
	return command.CombinedOutput()
}
