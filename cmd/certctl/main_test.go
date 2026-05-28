package main

import (
	"bytes"
	"context"
	"io"
	"strings"
	"testing"
	"time"
)

// TestRun_VersionFlag encodes the acceptance criterion that the binary reports
// its version and exits cleanly (no error) for both --version and -version.
func TestRun_VersionFlag(t *testing.T) {
	for _, arg := range []string{"--version", "-version"} {
		var stdout, stderr bytes.Buffer
		if err := run(context.Background(), []string{arg}, &stdout, &stderr); err != nil {
			t.Fatalf("run(%q) returned error: %v", arg, err)
		}
		out := stdout.String()
		if !strings.Contains(out, "certctl") {
			t.Errorf("run(%q) printed %q to stdout, want it to contain %q", arg, out, "certctl")
		}
		if strings.TrimSpace(out) == "" {
			t.Errorf("run(%q) printed nothing to stdout", arg)
		}
	}
}

// TestRun_CleanShutdownOnContextCancel encodes "boots and shuts down cleanly":
// the control plane blocks until its context is cancelled (as it would be on
// SIGINT/SIGTERM) and then returns nil.
func TestRun_CleanShutdownOnContextCancel(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- run(ctx, nil, io.Discard, io.Discard) }()

	// Give run a moment to boot, then request shutdown.
	time.Sleep(50 * time.Millisecond)
	cancel()

	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("clean shutdown returned error: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("run did not return within 2s of context cancellation")
	}
}

// TestRun_UnknownFlagIsError ensures bad input fails loudly rather than booting.
func TestRun_UnknownFlagIsError(t *testing.T) {
	var stdout, stderr bytes.Buffer
	if err := run(context.Background(), []string{"--no-such-flag"}, &stdout, &stderr); err == nil {
		t.Fatal("run with an unknown flag returned nil, want an error")
	}
}

// TestRun_HelpExitsCleanly ensures -h/--help is treated as a clean exit, not an
// error (flag.ErrHelp must not propagate as a failure).
func TestRun_HelpExitsCleanly(t *testing.T) {
	for _, arg := range []string{"-h", "--help"} {
		var stdout, stderr bytes.Buffer
		if err := run(context.Background(), []string{arg}, &stdout, &stderr); err != nil {
			t.Errorf("run(%q) returned error %v, want clean exit", arg, err)
		}
	}
}
