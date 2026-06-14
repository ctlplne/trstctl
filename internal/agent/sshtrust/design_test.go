package sshtrust

import (
	"os"
	"strings"
	"testing"
)

// TestDesignDocReality is the S13.2 design gate: the reviewed design doc must
// exist and cover the additive-first rule, validated reload with rollback, the
// enumerated lockout-failure modes, and the break-glass recovery path.
func TestDesignDocReality(t *testing.T) {
	b, err := os.ReadFile("../../../docs/design/ssh-trust-rewrite.md")
	if err != nil {
		t.Fatalf("S13.2 design doc missing: %v", err)
	}
	doc := string(b)
	for _, section := range []string{
		"Additive-first",
		"Validate before reload",
		"automatic rollback",
		"Lockout failure modes",
		"Break-glass recovery",
		"sshd -t",
		"Atomic writes",
	} {
		if !strings.Contains(doc, section) {
			t.Errorf("design doc does not cover %q", section)
		}
	}
	for _, id := range []string{"L1", "L2", "L3", "L4", "L5"} {
		if !strings.Contains(doc, id) {
			t.Errorf("design doc missing enumerated lockout mode %s", id)
		}
	}
}
