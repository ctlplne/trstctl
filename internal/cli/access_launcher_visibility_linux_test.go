// SPDX-License-Identifier: BUSL-1.1

//go:build linux

package cli

import (
	"bytes"
	"os"
	"os/exec"
	"strings"
	"testing"
)

func TestAccessLauncherProtectsParentEnvironment(t *testing.T) {
	const marker = "caller-credential-visibility-fixture"
	if os.Getenv("TRSTCTL_VISIBILITY_HELPER") == "1" {
		before := exec.Command("sh", "-c", "cat /proc/$PPID/environ")
		before.Env = []string{"PATH=/usr/bin:/bin"}
		visible, err := before.CombinedOutput()
		if err != nil || !bytes.Contains(visible, []byte(marker)) {
			t.Fatalf("baseline parent environment read: marker visible=%t err=%v", bytes.Contains(visible, []byte(marker)), err)
		}
		protected, err := protectLauncherProcess()
		if err != nil || !protected {
			t.Fatalf("protect launcher: protected=%t err=%v", protected, err)
		}
		child := exec.Command("sh", "-c", "cat /proc/$PPID/environ")
		child.Env = []string{"PATH=/usr/bin:/bin"}
		output, err := child.CombinedOutput()
		if bytes.Contains(output, []byte(marker)) {
			t.Fatal("child read the caller credential from its parent environment")
		}
		if err == nil {
			t.Fatal("child unexpectedly read its parent environment")
		}
		return
	}
	self := exec.Command(os.Args[0], "-test.run=^TestAccessLauncherProtectsParentEnvironment$")
	self.Env = append(os.Environ(), "TRSTCTL_VISIBILITY_HELPER=1", "TRSTCTL_TOKEN="+marker)
	output, err := self.CombinedOutput()
	if err != nil {
		t.Fatalf("launcher helper: %v: %s", err, strings.TrimSpace(string(output)))
	}
}
