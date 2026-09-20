// SPDX-License-Identifier: BUSL-1.1

package agentstack_test

import (
	"bytes"
	"errors"
	"strings"
	"testing"

	"trstctl.com/trstctl/internal/agentid/agentstack"
)

// aliasResolver is a small Resolver: it resolves a handful of aliases to
// canonical tool ids and reports every OTHER id as unknown. It lets the tests
// exercise the fail-closed "unknown declared tool is excess" rule.
type aliasResolver struct{ alias map[string]string }

func newAliasResolver() *aliasResolver {
	return &aliasResolver{alias: map[string]string{
		"fs.read":         "tool:fs.read",
		"filesystem.read": "tool:fs.read", // alias -> same canonical id
		"fs.write":        "tool:fs.write",
		"net.http":        "tool:net.http",
		"db.query":        "tool:db.query",
	}}
}

func (r *aliasResolver) ResolveTool(raw string) (string, bool) {
	key := strings.ToLower(strings.TrimSpace(raw))
	if c, ok := r.alias[key]; ok {
		return c, true
	}
	return key, false // unknown/unresolved
}

// TestToolManifest_ExceedsRegisteredRefused asserts a declared manifest that
// exceeds the registered tool set is refused and names the excess, while a
// subset/equal manifest is accepted (AGID-claim-12 / INV-A3, acceptance #3).
func TestToolManifest_ExceedsRegisteredRefused(t *testing.T) {
	registered := agentstack.NewRegisteredToolSet("fs.read", "net.http", "db.query")

	// Subset is accepted.
	if v := agentstack.Compare(agentstack.NewToolManifest("fs.read"), registered, nil); !v.Accepted {
		t.Errorf("subset manifest was refused: %+v", v)
	}
	// Equal is accepted.
	if v := agentstack.Compare(agentstack.NewToolManifest("fs.read", "net.http", "db.query"), registered, nil); !v.Accepted {
		t.Errorf("equal manifest was refused: %+v", v)
	}
	// The empty manifest is accepted.
	if v := agentstack.Compare(agentstack.NewToolManifest(), registered, nil); !v.Accepted {
		t.Errorf("empty manifest was refused: %+v", v)
	}

	// Exceeding is refused, and the excess is named.
	v := agentstack.Compare(agentstack.NewToolManifest("fs.read", "shell.exec"), registered, nil)
	if v.Accepted {
		t.Fatal("manifest with an extra tool was accepted; want refused (AGID-claim-12)")
	}
	if len(v.Excess) != 1 || v.Excess[0] != "shell.exec" {
		t.Fatalf("excess = %v, want exactly [shell.exec]", v.Excess)
	}
	if !strings.Contains(v.Reason, "shell.exec") {
		t.Errorf("refusal reason does not name the excess capability: %q", v.Reason)
	}

	// The error-returning variant wraps the sentinel and names the excess.
	_, err := agentstack.CompareOrError(agentstack.NewToolManifest("fs.read", "shell.exec"), registered, nil)
	if err == nil {
		t.Fatal("CompareOrError accepted an exceeding manifest; want error")
	}
	if !errors.Is(err, agentstack.ErrManifestExceedsRegistered) {
		t.Errorf("error %v is not ErrManifestExceedsRegistered", err)
	}
	if !strings.Contains(err.Error(), "shell.exec") {
		t.Errorf("error does not name the excess: %v", err)
	}
}

// TestToolManifest_AdversarialComparison is the adversarial table: registered ⊇
// declared accepts; any extra tool refuses and names it; an unknown/unresolved
// declared tool is treated as excess (fail-closed) even though by raw string it
// might look registered.
func TestToolManifest_AdversarialComparison(t *testing.T) {
	resolver := newAliasResolver()
	registered := agentstack.NewRegisteredToolSet("fs.read", "net.http", "db.query")

	cases := []struct {
		name       string
		declared   []string
		resolver   agentstack.Resolver
		accept     bool
		wantExcess []string
	}{
		{
			name:     "subset accepts (no resolver)",
			declared: []string{"fs.read", "net.http"},
			accept:   true,
		},
		{
			name:     "equal accepts (no resolver)",
			declared: []string{"db.query", "fs.read", "net.http"},
			accept:   true,
		},
		{
			name:       "one extra refuses and names it",
			declared:   []string{"fs.read", "shell.exec"},
			accept:     false,
			wantExcess: []string{"shell.exec"},
		},
		{
			name:       "several extras all named",
			declared:   []string{"shell.exec", "kms.sign", "fs.read"},
			accept:     false,
			wantExcess: []string{"kms.sign", "shell.exec"},
		},
		{
			name:     "case/whitespace-different subset still accepts (normalized)",
			declared: []string{"  FS.Read ", "NET.HTTP"},
			accept:   true,
		},
		{
			name:     "duplicate declared tool does not create phantom excess",
			declared: []string{"fs.read", "fs.read", "net.http"},
			accept:   true,
		},
		{
			name:     "alias subset accepts under resolver",
			declared: []string{"filesystem.read"}, // alias of fs.read
			resolver: resolver,
			accept:   true,
		},
		{
			name:       "unknown declared tool is excess under resolver (fail-closed)",
			declared:   []string{"fs.read", "totally.unknown"},
			resolver:   resolver,
			accept:     false,
			wantExcess: []string{"totally.unknown"},
		},
		{
			name:       "unknown tool treated as excess even though not in registered by name",
			declared:   []string{"made.up.tool"},
			resolver:   resolver,
			accept:     false,
			wantExcess: []string{"made.up.tool"},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			reg := registered
			v := agentstack.Compare(agentstack.NewToolManifest(tc.declared...), reg, tc.resolver)
			if v.Accepted != tc.accept {
				t.Fatalf("Accepted = %v, want %v (verdict %+v)", v.Accepted, tc.accept, v)
			}
			if tc.accept {
				if len(v.Excess) != 0 {
					t.Errorf("accepted verdict still reported excess %v", v.Excess)
				}
				return
			}
			if len(v.Excess) != len(tc.wantExcess) {
				t.Fatalf("excess = %v, want %v", v.Excess, tc.wantExcess)
			}
			for i := range tc.wantExcess {
				if v.Excess[i] != tc.wantExcess[i] {
					t.Fatalf("excess = %v, want %v", v.Excess, tc.wantExcess)
				}
				if !strings.Contains(v.Reason, tc.wantExcess[i]) {
					t.Errorf("reason %q does not name excess %q", v.Reason, tc.wantExcess[i])
				}
			}
		})
	}
}

// TestToolManifest_DigestStableAndSensitive confirms the tool-manifest digest is
// order/duplicate-independent (stable) yet flips on any add/remove (sensitive),
// and that the empty manifest has a well-defined, distinct digest.
func TestToolManifest_DigestStableAndSensitive(t *testing.T) {
	a := agentstack.NewToolManifest("net.http", "fs.read", "fs.read").Digest()
	b := agentstack.NewToolManifest("fs.read", "net.http").Digest()
	if !bytes.Equal(a, b) {
		t.Error("tool-manifest digest is not order/duplicate independent")
	}
	if len(a) != 32 {
		t.Errorf("tool-manifest digest = %d bytes, want 32", len(a))
	}

	added := agentstack.NewToolManifest("fs.read", "net.http", "db.query").Digest()
	if bytes.Equal(added, b) {
		t.Error("adding a tool did not flip the tool-manifest digest")
	}
	removed := agentstack.NewToolManifest("fs.read").Digest()
	if bytes.Equal(removed, b) {
		t.Error("removing a tool did not flip the tool-manifest digest")
	}

	empty := agentstack.NewToolManifest().Digest()
	if len(empty) != 32 {
		t.Errorf("empty manifest digest = %d bytes, want 32", len(empty))
	}
	if bytes.Equal(empty, b) {
		t.Error("empty manifest digest collided with a non-empty manifest")
	}
}
