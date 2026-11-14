// SPDX-License-Identifier: BUSL-1.1
package dynsecret

import (
	"bytes"
	"context"
	"os"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/crypto/secret"
)

// TestActiveDirectoryAccountSignInCheckNativeA258L1 is A258-L1's proof on a
// stock Samba Active Directory domain controller (the A258-L1 lab: domain
// lockout threshold 3, read with samba-tool). The account's state and
// badPwdCount are read with the domain controller's own ldbsearch, never
// through the code under test. The rotation sets the vaulted password; the
// check reads healthy and the count stays 0. A changed password is tried at
// 0 and 1 failed sign-ins (rejected, the count goes to 2); at 2 neither the
// changed nor the right password is sent, however often, and the account is
// not locked. A stock wrong bind then locks it (the threshold is real), and
// the check reads locked without a sign-in. Unlocked, the right password
// reads healthy and clears the count. A password settings object with
// threshold 2 applied to the account wins over the domain's 3: at 1 failed
// sign-in the check sends nothing. A disabled account reads rejected without a
// sign-in.
func TestActiveDirectoryAccountSignInCheckNativeA258L1(t *testing.T) {
	if os.Getenv("TRSTCTL_AD_LOCKOUT_LAB") != "1" {
		t.Skip("owned Samba AD lockout lab not requested")
	}
	ctx, cancel := context.WithTimeout(t.Context(), 4*time.Minute)
	defer cancel()
	container := os.Getenv("TRSTCTL_AD_LAB_CONTAINER")
	ca, err := os.ReadFile(os.Getenv("TRSTCTL_AD_LAB_CA")) // #nosec G304 G703 -- the lab runner's own CA file (CWE-22)
	if err != nil {
		t.Fatal(err)
	}
	admin, err := os.ReadFile(os.Getenv("TRSTCTL_AD_LAB_ADMIN")) // #nosec G304 G703 -- the lab runner's own protected password file (CWE-22)
	if err != nil {
		t.Fatal(err)
	}
	admin = bytes.TrimSpace(admin)
	defer secret.Wipe(admin)
	const (
		account = "CN=a258-proof,OU=TrstctlA258,DC=a258,DC=test"
		pso     = "CN=a258-strict,CN=Password Settings Container,CN=System,DC=a258,DC=test"
	)
	backend, err := NewLDAPBackend(LDAPConfig{DirectoryMode: "active_directory", Addr: os.Getenv("TRSTCTL_AD_LAB_ADDR"), TLSServerName: "ad258", TLSCAPEM: ca,
		BindDN: "CN=Administrator,CN=Users,DC=a258,DC=test", BindPassword: admin, UsersDN: "OU=TrstctlA258,DC=a258,DC=test",
		RoleGroups: map[string]string{"desktop/proof": account}})
	if err != nil {
		t.Fatal(err)
	}
	defer backend.Close()

	// The domain controller's own tools, inside its container.
	dc := func(args ...string) string {
		t.Helper()
		out, err := exec.CommandContext(ctx, "docker", append([]string{"exec", container}, args...)...).CombinedOutput() // #nosec G204 G702 -- the lab runner's own container and stock Samba tools; no credential arguments (CWE-78)
		if err != nil {
			t.Fatalf("%v: %v %s", args, err, out)
		}
		return string(out)
	}
	attribute := regexp.MustCompile(`(?m)^(badPwdCount|lockoutTime|msDS-User-Account-Control-Computed): (\d+)$`)
	state := func() (bad int, locked bool) {
		t.Helper()
		out := dc("ldbsearch", "-H", "/var/lib/trstctl-ad/private/sam.ldb", "-b", account, "-s", "base", "badPwdCount", "lockoutTime", "msDS-User-Account-Control-Computed")
		for _, m := range attribute.FindAllStringSubmatch(out, -1) {
			n, _ := strconv.Atoi(m[2])
			switch m[1] {
			case "badPwdCount":
				bad = n
			case "lockoutTime":
				locked = locked || n != 0
			case "msDS-User-Account-Control-Computed":
				locked = locked || n&16 != 0
			}
		}
		return bad, locked
	}
	// A stock wrong bind (OpenLDAP's ldapsearch), as someone else's mistyped
	// password; the directory must refuse it as invalid credentials.
	stockWrongBind := func() {
		t.Helper()
		out, err := exec.CommandContext(ctx, "docker", "exec", "-e", "LDAPTLS_CACERT=/run/ad-cert.pem", container, "ldapsearch", "-x", "-H", "ldaps://ad258", "-D", account, "-w", "Tr5!someone-elses-typo", "-b", account, "-s", "base", "sAMAccountName").CombinedOutput() // #nosec G204 G702 -- the lab runner's own container, stock OpenLDAP tool, a deliberately wrong lab password (CWE-78)
		if err == nil || !bytes.Contains(out, []byte("Invalid credentials (49)")) {
			t.Fatalf("the stock wrong bind was not refused as invalid credentials: %v %s", err, out)
		}
	}

	_, vaulted, err := backend.CreateCredential(ctx, GenerateRequest{Role: "desktop/proof", Static: true})
	if err != nil {
		t.Fatal("the rotation's password reset:", err)
	}
	defer secret.Wipe(vaulted)
	changed := a258l1Credential(t, account, []byte("Tr5!changed-"+"behind-the-vault"))
	check := func(credential []byte) string {
		t.Helper()
		return SignInStatusOf(backend.CheckADAccountSignIn(ctx, credential))
	}
	expect := func(step, got, want string, bad int, locked bool) {
		t.Helper()
		gotBad, gotLocked := state()
		if got != want || gotBad != bad || gotLocked != locked {
			t.Fatalf("%s: read %s with badPwdCount %d, locked %v; want %s, %d, %v", step, got, gotBad, gotLocked, want, bad, locked)
		}
		t.Logf("%s: %s (badPwdCount %d, locked %v)", step, got, gotBad, gotLocked)
	}

	if out := dc("samba-tool", "domain", "passwordsettings", "show"); !regexp.MustCompile(`Account lockout threshold \(attempts\): 3`).MatchString(out) {
		t.Fatalf("the lab's domain lockout threshold is not 3:\n%s", out)
	}
	expect("the vaulted password", check(vaulted), SignInHealthy, 0, false)
	expect("a changed password at 0", check(changed), SignInRejected, 1, false)
	expect("a changed password at 1", check(changed), SignInRejected, 2, false)
	for i := 0; i < 5; i++ {
		expect("a changed password one short of lockout", check(changed), SignInLockoutRisk, 2, false)
		expect("the vaulted password one short of lockout", check(vaulted), SignInLockoutRisk, 2, false)
	}

	// The control: one more stock wrong bind locks the account.
	stockWrongBind()
	expect("locked by a stock wrong bind", check(vaulted), SignInLocked, 3, true)

	dc("samba-tool", "user", "unlock", "a258-proof")
	expect("unlocked, the vaulted password", check(vaulted), SignInHealthy, 0, false)

	// A password settings object with threshold 2 wins over the domain's 3.
	dc("samba-tool", "domain", "passwordsettings", "pso", "create", "a258-strict", "1", "--account-lockout-threshold=2", "--account-lockout-duration=30", "--reset-account-lockout-after=30")
	dc("samba-tool", "domain", "passwordsettings", "pso", "apply", "a258-strict", "a258-proof")
	// LDIF folds long lines: a continuation line starts with one space.
	if out := strings.ReplaceAll(dc("ldbsearch", "-H", "/var/lib/trstctl-ad/private/sam.ldb", "-b", account, "-s", "base", "msDS-ResultantPSO"), "\n ", ""); !strings.Contains(strings.ToLower(out), strings.ToLower(pso)) {
		t.Fatalf("the settings object does not apply to the account:\n%s", out)
	}
	stockWrongBind()
	expect("one short of the settings object's threshold", check(vaulted), SignInLockoutRisk, 1, false)
	dc("samba-tool", "user", "unlock", "a258-proof")
	dc("samba-tool", "domain", "passwordsettings", "pso", "delete", "a258-strict")

	// Disabled: classified from its state, nothing sent.
	dc("samba-tool", "user", "disable", "a258-proof")
	expect("a disabled account", check(vaulted), SignInRejected, 0, false)
}
