// SPDX-License-Identifier: BUSL-1.1

package rdp

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/crypto/secret"
)

func TestNativeDesktopServed(t *testing.T) {
	helper := os.Getenv("TRSTCTL_RDP_HELPER")
	if helper == "" {
		if os.Getenv("TRSTCTL_REQUIRE_RDP_LAB") == "1" {
			t.Fatal("native RDP lab required")
		}
		t.Skip("native Linux RDP lab not requested")
	}
	password, err := os.ReadFile("/run/rdp-password")
	if err != nil {
		t.Fatal(err)
	}
	defer secret.Wipe(password)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	target := Target{Address: "127.0.0.1:3389", Username: "desktop-proof", CertificateSHA256: os.Getenv("TRSTCTL_RDP_PIN"), Width: 800, Height: 600, TLSOnly: true}
	s, err := Start(ctx, helper, target, password)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = s.Close() }()
	proofPath := fmt.Sprintf("/home/desktop-proof/rdp-proof-%d", time.Now().UnixNano())
	defer func() {
		if e := os.Remove(proofPath); e != nil && !os.IsNotExist(e) {
			t.Error(e)
		}
	}()
	frames := 0
	deadline := time.After(20 * time.Second)
	done := make(chan error, 1)
	go func() {
		for {
			p, e := s.ReadPacket()
			if e != nil {
				select {
				case done <- e:
				default:
				}
				return
			}
			if p.Kind == 2 && p.Width == 800 && p.Height == 600 && len(p.Pixels) == 800*600*4 {
				frames++
				if frames == 3 {
					done <- nil
				}
			}
		}
	}()
	select {
	case err = <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-deadline:
		t.Fatal("no bounded desktop frames")
	}
	proc := fmt.Sprintf("/proc/%d", s.pid)
	b, e := os.ReadFile(proc + "/cmdline") // #nosec G304 -- exact child PID created by this test, fixed proc metadata file (CWE-22)
	if e != nil || bytes.Contains(b, password) {
		t.Fatal("credential present in process arguments or arguments unreadable")
	}
	// PR_SET_DUMPABLE=0 deliberately denies /proc/environ to the parent's
	// unprivileged container root. Require that protection when access is denied;
	// if a privileged test runner can read it, still require credential absence.
	b, e = os.ReadFile(proc + "/environ") // #nosec G304 -- exact child PID created by this test, fixed proc metadata file (CWE-22)
	if e != nil && !os.IsPermission(e) {
		t.Fatal(e)
	}
	if e == nil && bytes.Contains(b, password) {
		t.Fatal("credential present in native environment")
	}
	status, e := os.ReadFile(proc + "/status") // #nosec G304 -- exact child PID created by this test, fixed proc metadata file (CWE-22)
	if e != nil {
		t.Fatal(e)
	}
	locked := false
	for _, line := range strings.Split(string(status), "\n") {
		if strings.HasPrefix(line, "VmLck:") {
			parts := strings.Fields(line)
			n, _ := strconv.Atoi(parts[1])
			locked = n > 0
		}
	}
	if !locked {
		t.Fatal("native credential process is not memory locked")
	}
	// The lab startwm runs xterm. Type a command through the upstream desktop,
	// then independently read the target's file rather than trusting a Ready packet.
	time.Sleep(time.Second)
	for _, c := range []byte("printf desktop-input-proven > " + proofPath) {
		if err = s.Input(4, 0, uint16(c), 0); err != nil {
			select {
			case cause := <-done:
				t.Fatalf("input failed: %v; native: %v", err, cause)
			default:
				t.Fatal(err)
			}
		}
		if err = s.Input(4, 0x8000, uint16(c), 0); err != nil {
			t.Fatal(err)
		}
	}
	if err = s.Input(3, 0, 0x1c, 0); err != nil {
		t.Fatal(err)
	}
	if err = s.Input(3, 0x8000, 0x1c, 0); err != nil {
		t.Fatal(err)
	}
	until := time.Now().Add(5 * time.Second)
	for time.Now().Before(until) {
		b, e := os.ReadFile(proofPath) // #nosec G304 -- test-owned unique filename beneath fixed lab account home (CWE-22)
		if e == nil && string(b) == "desktop-input-proven" {
			return
		}
		time.Sleep(100 * time.Millisecond)
	}
	t.Fatal("RDP input did not execute the desktop task")
}
