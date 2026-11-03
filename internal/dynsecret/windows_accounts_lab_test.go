// SPDX-License-Identifier: BUSL-1.1

package dynsecret

import (
	"context"
	"encoding/json"
	"encoding/pem"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/crypto/secret"
)

// A240 Windows local accounts, against the windows-latest runner itself,
// prepared by scripts/ci/a240-windows-accounts-lab.ps1: OpenSSH Server on
// 127.0.0.1:22, administrator trstctl_admin (Administrators; its ECDSA key in
// administrators_authorized_keys), the pair orders_app_a/orders_app_b and the
// single account orders_single, each with the lab's initial password. The
// served rotation around these calls (phases, the approved deadline, the
// single-phase acknowledgement) is the same for unix and windows and is
// proven by the Unix served test; the windows-latest runner has no embedded
// PostgreSQL for the served harness, so this proves the provider itself.
func TestWindowsLocalAccountsLabA240(t *testing.T) {
	authorized, fingerprint, initialFile := os.Getenv("TRSTCTL_A240_WINDOWS_AUTHORIZED_KEYS"), os.Getenv("TRSTCTL_A240_WINDOWS_HOST_KEY"), os.Getenv("TRSTCTL_A240_WINDOWS_INITIAL_PASSWORD_FILE")
	if authorized == "" || fingerprint == "" || initialFile == "" {
		t.Skip("lab test: scripts/ci/a240-windows-accounts-lab.ps1 prepares the windows-latest runner and sets TRSTCTL_A240_WINDOWS_*")
	}
	// The administrator's key is generated here, in memory, and only its
	// public half reaches the runner: administrators_authorized_keys, which
	// sshd reads only while Administrators and SYSTEM alone may write it.
	adminKey, err := crypto.GenerateLockedKey(crypto.ECDSAP256)
	if err != nil {
		t.Fatal(err)
	}
	defer adminKey.Destroy()
	authorizedLine, err := crypto.SSHPublicKeyFromSigner(adminKey)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(authorized, authorizedLine, 0o600); err != nil { // #nosec G703 -- runner-provided lab path (CWE-22)
		t.Fatal(err)
	}
	for _, args := range [][]string{
		{authorized, "/setowner", "Administrators"},
		{authorized, "/inheritance:r", "/grant", "Administrators:F", "/grant", "SYSTEM:F"},
	} {
		if out, err := exec.Command("icacls.exe", args...).CombinedOutput(); err != nil { // #nosec G204,G702 -- fixed Windows tool on the lab's own file (CWE-78)
			t.Fatalf("restrict administrators_authorized_keys: %v %s", err, out)
		}
	}
	der, err := adminKey.PKCS8()
	if err != nil {
		t.Fatal(err)
	}
	defer secret.Wipe(der)
	adminPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
	defer secret.Wipe(adminPEM)
	initial, err := os.ReadFile(initialFile) // #nosec G304,G703 -- runner-provided lab fixture path (CWE-22)
	if err != nil {
		t.Fatal(err)
	}
	initialPassword := []byte(strings.TrimSpace(string(initial)))
	const addr = "127.0.0.1:22"
	target := crypto.SSHAccountTarget{Address: addr, HostKeyFingerprint: fingerprint, Windows: true}
	loginErr := func(account string, password []byte) error {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		return crypto.VerifySSHAccountPassword(ctx, target, account, password)
	}
	logsIn := func(account string, password []byte) bool { return loginErr(account, password) == nil }
	if errA, errS := loginErr("orders_app_a", initialPassword), loginErr("orders_single", initialPassword); errA != nil || errS != nil {
		// The errors name the stage (unreachable, host identity, the SSH
		// authentication answer), never a password.
		t.Fatalf("the lab's initial password does not log in: orders_app_a: %v; orders_single: %v", errA, errS)
	}
	b, err := NewUnixAccountsBackend(UnixAccountsConfig{Address: addr, AdminUser: "trstctl_admin", AdminKey: adminPEM,
		HostKeyFingerprint: fingerprint, Windows: true, RoleAccounts: map[string]string{"single": "orders_single"},
		RotationAccounts: map[string][2]string{"orders": {"orders_app_a", "orders_app_b"}}})
	if err != nil {
		t.Fatal(err)
	}
	defer b.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	type credential struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}
	parse := func(raw []byte) credential {
		t.Helper()
		var c credential
		if err := json.Unmarshal(raw, &c); err != nil || c.Username == "" || c.Password == "" {
			t.Fatalf("the credential: %v", err)
		}
		return c
	}

	// Two two-user cycles: stage the other account, both log in, retire the
	// predecessor, only the successor logs in.
	live := credential{Username: "orders_app_a", Password: string(initialPassword)}
	for cycle, next := range []string{"orders_app_b", "orders_app_a"} {
		ref, raw, err := b.CreateCredential(ctx, GenerateRequest{Role: "orders", Static: true, LeaseID: "a240-windows-" + next, Predecessor: live.Username})
		if err != nil {
			t.Fatalf("cycle %d stage: %v", cycle+1, err)
		}
		successor := parse(raw)
		if ref != next || successor.Username != next {
			t.Fatalf("cycle %d staged %s (%s), want %s", cycle+1, ref, successor.Username, next)
		}
		if err := b.VerifyCredential(ctx, raw); err != nil {
			t.Fatalf("cycle %d verify: %v", cycle+1, err)
		}
		if !logsIn(live.Username, []byte(live.Password)) {
			t.Fatalf("cycle %d: the predecessor must keep working until retirement", cycle+1)
		}
		if err := b.Revoke(ctx, live.Username); err != nil {
			t.Fatalf("cycle %d retire: %v", cycle+1, err)
		}
		if logsIn(live.Username, []byte(live.Password)) || !logsIn(next, []byte(successor.Password)) {
			t.Fatalf("cycle %d: after retirement only the successor may log in", cycle+1)
		}
		live = successor
	}

	// The single account changes in place: the old password stops at once.
	_, raw, err := b.CreateCredential(ctx, GenerateRequest{Role: "single", Static: true, LeaseID: "a240-windows-single"})
	if err != nil {
		t.Fatalf("single: %v", err)
	}
	single := parse(raw)
	if !logsIn("orders_single", []byte(single.Password)) || logsIn("orders_single", initialPassword) {
		t.Fatal("an in-place change must leave only the new password working")
	}
	if err := b.Revoke(ctx, "trstctl_admin"); err == nil {
		t.Fatal("an account the provider does not rotate was accepted")
	}
	t.Logf("A240_WINDOWS_OK two two-user cycles and an in-place change on %s", addr)
}
