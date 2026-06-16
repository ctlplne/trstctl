package sshprobe_test

import (
	"context"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/crypto/sshprobe"
	"trstctl.com/trstctl/internal/crypto/sshtestserver"
)

// Probe captures the server's host key and is non-invasive: it never attempts
// authentication.
func TestProbeCapturesHostKeyNonInvasively(t *testing.T) {
	srv, err := sshtestserver.Start()
	if err != nil {
		t.Fatal(err)
	}
	defer srv.Close()

	res, err := sshprobe.Probe(context.Background(), srv.Addr())
	if err != nil {
		t.Fatalf("probe: %v", err)
	}
	if res.HostKeyType != "ssh-ed25519" {
		t.Errorf("host key type = %q, want ssh-ed25519", res.HostKeyType)
	}
	if res.FingerprintSHA256 != srv.FingerprintSHA256() {
		t.Errorf("fingerprint = %s, want %s", res.FingerprintSHA256, srv.FingerprintSHA256())
	}

	time.Sleep(50 * time.Millisecond)
	if srv.AuthAttempted() {
		t.Error("probe was not non-invasive: it attempted authentication")
	}
}

// A probe to a closed port fails within the timeout.
func TestProbeUnreachable(t *testing.T) {
	_, err := sshprobe.Probe(context.Background(), "127.0.0.1:1", sshprobe.WithTimeout(500*time.Millisecond))
	if err == nil {
		t.Error("expected an error probing a closed port")
	}
}
