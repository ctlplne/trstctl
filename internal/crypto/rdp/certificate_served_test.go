// SPDX-License-Identifier: BUSL-1.1

package rdp

import (
	"context"
	"os"
	"strings"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/crypto/secret"
)

func TestNativeDesktopRejectsForeignCertificate(t *testing.T) {
	helper := os.Getenv("TRSTCTL_RDP_HELPER")
	if helper == "" {
		if os.Getenv("TRSTCTL_REQUIRE_RDP_LAB") == "1" {
			t.Fatal("native RDP lab required")
		}
		t.Skip("native RDP lab not requested")
	}
	password, e := os.ReadFile("/run/rdp-password")
	if e != nil {
		t.Fatal(e)
	}
	defer secret.Wipe(password)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	s, e := Start(ctx, helper, Target{Address: "127.0.0.1:3389", Username: "desktop-proof", CertificateSHA256: strings.Repeat("00", 32), Width: 800, Height: 600, TLSOnly: true}, password)
	if e != nil {
		t.Fatal(e)
	}
	defer func() { _ = s.Close() }()
	if _, e = s.ReadPacket(); e == nil {
		t.Fatal("foreign pinned certificate accepted")
	}
}

func TestNativeDesktopNLAHasNoTLSFallback(t *testing.T) {
	helper := os.Getenv("TRSTCTL_RDP_HELPER")
	if helper == "" {
		if os.Getenv("TRSTCTL_REQUIRE_RDP_LAB") == "1" {
			t.Fatal("native RDP lab required")
		}
		t.Skip("native RDP lab not requested")
	}
	password, e := os.ReadFile("/run/rdp-password")
	if e != nil {
		t.Fatal(e)
	}
	defer secret.Wipe(password)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	// This lab server only supports TLS, not NLA. The default must refuse it.
	s, e := Start(ctx, helper, Target{Address: "127.0.0.1:3389", Username: "desktop-proof", CertificateSHA256: os.Getenv("TRSTCTL_RDP_PIN"), Width: 800, Height: 600}, password)
	if e != nil {
		t.Fatal(e)
	}
	defer func() { _ = s.Close() }()
	if _, e = s.ReadPacket(); e == nil {
		t.Fatal("NLA silently fell back to TLS-only sign-in")
	}
}
