package dist_test

import (
	"strings"
	"testing"

	"trstctl.com/trstctl/internal/dist"
)

// Known SHA-256 vectors (FIPS 180-4 / RFC 6234).
const (
	sumEmpty = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
	sumABC   = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
)

// TestChecksumsKnownVectorsAndFormat is the "SHA-256 published" acceptance at
// the tooling layer: the manifest carries the correct SHA-256 of each artifact,
// in the standard `sha256sum` format (`<hex><two spaces><name>`), one per line,
// sorted by name so the output is deterministic.
func TestChecksumsKnownVectorsAndFormat(t *testing.T) {
	got := dist.Checksums(map[string][]byte{
		"trstctl-agent.exe": []byte("abc"),
		"SHA256SUMS.txt":    {},
	})
	// Sorted by name: "SHA256SUMS.txt" < "trstctl-agent.exe" (uppercase sorts first).
	want := sumEmpty + "  SHA256SUMS.txt\n" + sumABC + "  trstctl-agent.exe\n"
	if got != want {
		t.Errorf("Checksums =\n%q\nwant\n%q", got, want)
	}
}

// TestChecksumsLineShape: every line is 64 hex chars, two spaces, then the name
// (the exact shape `sha256sum -c` consumes).
func TestChecksumsLineShape(t *testing.T) {
	out := dist.Checksums(map[string][]byte{"a.msi": []byte("payload")})
	line := strings.TrimRight(out, "\n")
	if len(line) < 66 || line[64:66] != "  " {
		t.Fatalf("line not in sha256sum format: %q", line)
	}
	if name := line[66:]; name != "a.msi" {
		t.Errorf("name field = %q, want a.msi", name)
	}
}

// TestChecksumsEmpty: no files yields an empty manifest.
func TestChecksumsEmpty(t *testing.T) {
	if out := dist.Checksums(nil); out != "" {
		t.Errorf("Checksums(nil) = %q, want empty", out)
	}
}
