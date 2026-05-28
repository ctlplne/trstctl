package buildinfo

import (
	"runtime"
	"strings"
	"testing"
)

// The linker-injected vars are empty under `go test`, so these tests exercise
// the fallback paths and the formatting contract that the --version flag relies
// on. They must never panic or return empty strings.

func TestAccessorsNeverEmpty(t *testing.T) {
	if got := Version(); got == "" {
		t.Error("Version() returned empty string; a fallback is required")
	}
	if got := Commit(); got == "" {
		t.Error("Commit() returned empty string; a fallback is required")
	}
	if got := Date(); got == "" {
		t.Error("Date() returned empty string; a fallback is required")
	}
}

func TestStringContainsVersionAndPlatform(t *testing.T) {
	s := String("certctl")
	for _, want := range []string{
		"certctl",
		Version(),
		runtime.GOOS,
		runtime.GOARCH,
		runtime.Version(),
	} {
		if !strings.Contains(s, want) {
			t.Errorf("String(%q) = %q, want it to contain %q", "certctl", s, want)
		}
	}
}

func TestStringUsesProvidedBinaryName(t *testing.T) {
	for _, name := range []string{"certctl", "certctl-signer", "certctl-agent"} {
		if !strings.HasPrefix(String(name), name+" ") {
			t.Errorf("String(%q) should begin with %q followed by a space, got %q", name, name, String(name))
		}
	}
}
