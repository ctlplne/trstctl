// SPDX-License-Identifier: BUSL-1.1

package crypto_test

import (
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/pamsignin"
)

// TestWindowsSignInScriptRunsNativelyA274 runs the Windows sign-in report's
// PowerShell (as bypass detection runs it over OpenSSH) on this Windows host
// for the current user, and reads its framed output: the script's syntax and
// framing on a real Windows PowerShell. windows-latest runs it.
func TestWindowsSignInScriptRunsNativelyA274(t *testing.T) {
	user := os.Getenv("USERNAME")
	if user == "" {
		t.Skip("no USERNAME on this host")
	}
	command, err := crypto.SSHSignInScript(true, []string{user}, time.Now().Add(-7*24*time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	encoded, ok := strings.CutPrefix(command, "powershell.exe -NoLogo -NoProfile -NonInteractive -EncodedCommand ")
	if !ok {
		t.Fatalf("the command: %s", command)
	}
	out, err := exec.Command("powershell.exe", "-NoLogo", "-NoProfile", "-NonInteractive", "-EncodedCommand", encoded).CombinedOutput() // #nosec G204 G702 -- the fixed report script this test proves, run on the test host (CWE-78)
	if err != nil {
		t.Fatalf("the report failed: %v\n%s", err, out)
	}
	signIns, err := pamsignin.ParseWindowsReport(out, []string{user}, time.Time{})
	if err != nil {
		t.Fatalf("the report did not frame: %v\n%s", err, out)
	}
	t.Logf("%d logons of %s read from the Security log", len(signIns), user)
}
