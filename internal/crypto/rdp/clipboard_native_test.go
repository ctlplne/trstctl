// SPDX-License-Identifier: BUSL-1.1
package rdp

import (
	"context"
	"errors"
	"fmt"
	"os"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/crypto/secret"
)

// TestNativeDesktopClipboardPolicyA269 drives the native helper against the
// lab's xrdp: with both directions allowed the operator's text reaches the
// session's clipboard and the session's text comes back; with none, the
// operator's text is refused and the session's text never leaves.
func TestNativeDesktopClipboardPolicyA269(t *testing.T) {
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
	run := func(allow bool) {
		ctx, cancel := context.WithTimeout(context.Background(), 40*time.Second)
		defer cancel()
		target := Target{Address: "127.0.0.1:3389", Username: "desktop-proof", CertificateSHA256: os.Getenv("TRSTCTL_RDP_PIN"), Width: 800, Height: 600,
			TLSOnly: true, ClipboardToTarget: allow, ClipboardFromTarget: allow}
		s, err := Start(ctx, helper, target, password)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = s.Close() }()
		frames, texts, failed := make(chan struct{}, 1), make(chan string, 4), make(chan error, 1)
		go func() {
			n := 0
			for {
				p, e := s.ReadPacket()
				if e != nil {
					failed <- e
					return
				}
				if p.Kind == 2 {
					if n++; n == 3 {
						frames <- struct{}{}
					}
				}
				if p.Kind == 4 {
					texts <- string(p.Text)
				}
			}
		}()
		select {
		case <-frames:
		case e := <-failed:
			t.Fatalf("the helper ended before the desktop rendered (clipboard allowed: %v): %v", allow, e)
		case <-ctx.Done():
			t.Fatal("no desktop frames")
		}
		time.Sleep(time.Second)
		nonce := time.Now().UnixNano()
		toTarget := fmt.Sprintf("to-target-%d", nonce)
		fromTarget := fmt.Sprintf("from-target-%d", nonce)
		proof := fmt.Sprintf("/home/desktop-proof/clipboard-%d", nonce)
		defer func() { _ = os.Remove(proof) }()
		err = s.Clipboard([]byte(toTarget))
		if !allow {
			if !errors.Is(err, ErrClipboardRefused) {
				t.Fatal("the operator's clipboard reached the helper without a policy", err)
			}
		} else if err != nil {
			t.Fatal(err)
		}
		typed := fmt.Sprintf("xclip -o -selection clipboard > %s; printf %s | xclip -i -selection clipboard", proof, fromTarget)
		for _, c := range []byte(typed) {
			if err = s.Input(4, 0, uint16(c), 0); err != nil {
				t.Fatal(err)
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
		if allow {
			until := time.Now().Add(10 * time.Second)
			for {
				b, e := os.ReadFile(proof) // #nosec G304 -- test-owned unique filename beneath fixed lab account home (CWE-22)
				if e == nil && string(b) == toTarget {
					break
				}
				if time.Now().After(until) {
					t.Fatalf("the operator's clipboard did not reach the session (%q, %v)", b, e)
				}
				time.Sleep(100 * time.Millisecond)
			}
			// xrdp reattaches the same X session, whose clipboard may still
			// hold the earlier run's text: wait for this run's own.
			wait := time.After(10 * time.Second)
			for {
				select {
				case got := <-texts:
					if got == fromTarget {
						return
					}
				case <-wait:
					t.Fatal("the session's clipboard never came back")
				}
			}
		}
		select {
		case got := <-texts:
			t.Fatalf("the session's clipboard left without a policy: %q", got)
		case <-time.After(4 * time.Second):
		}
		if b, e := os.ReadFile(proof); e == nil && string(b) == toTarget { // #nosec G304 -- test-owned unique filename (CWE-22)
			t.Fatal("the operator's clipboard reached the session without a policy")
		}
	}
	run(false)
	run(true)
}
