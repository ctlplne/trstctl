// SPDX-License-Identifier: BUSL-1.1

package plugincensus

import (
	"bytes"
	"strings"
	"testing"
)

func TestNormalizeIsDeterministicAndBounded(t *testing.T) {
	t.Parallel()
	digestA := "sha256:" + strings.Repeat("a", 64)
	digestB := "sha256:" + strings.Repeat("b", 64)
	input := []Entry{
		{Name: "z-plugin", Digest: digestA, Publisher: digestB, ExecutionContext: ExecutionContextNetworkRelayWASM, Grants: []Grant{
			{Capability: "net.dial", Constraints: []string{"z.example:443", "a.example:443"}},
			{Capability: "fs.read", Constraints: []string{"/etc/relay"}},
		}},
		{Name: "a-plugin", Digest: digestB, Publisher: digestA, ExecutionContext: ExecutionContextNetworkRelayWASM, Grants: []Grant{}},
	}

	got, err := Normalize(input)
	if err != nil {
		t.Fatalf("normalize: %v", err)
	}
	if got[0].Name != "a-plugin" || got[1].Grants[0].Capability != "fs.read" {
		t.Fatalf("normalization did not sort plugins and grants: %#v", got)
	}
	if got[1].Grants[1].Constraints[0] != "a.example:443" {
		t.Fatalf("normalization did not sort constraints: %#v", got[1].Grants[1].Constraints)
	}
	input[0].Grants[0].Constraints[0] = "mutated-after-copy"
	if got[1].Grants[1].Constraints[1] != "z.example:443" {
		t.Fatal("normalized census aliases caller-owned constraint memory")
	}

	statement := Statement{TenantID: "tenant-a", AgentCommonName: "relay-a", Plugins: got, IssuedAtUnix: 42}
	first, err := statement.Canonical()
	if err != nil {
		t.Fatalf("canonical: %v", err)
	}
	second, err := statement.Canonical()
	if err != nil || !bytes.Equal(first, second) {
		t.Fatalf("canonical statement is not deterministic: err=%v", err)
	}
	for _, forbidden := range []string{"private_key", "credential", "module_bytes"} {
		if bytes.Contains(bytes.ToLower(first), []byte(forbidden)) {
			t.Fatalf("canonical metadata contains forbidden byte-bearing field %q", forbidden)
		}
	}
}

func TestNormalizeRefusesAmbiguousOrOversizedCensus(t *testing.T) {
	t.Parallel()
	digest := "sha256:" + strings.Repeat("c", 64)
	valid := Entry{Name: "plugin-a", Digest: digest, Publisher: digest, ExecutionContext: ExecutionContextNetworkRelayWASM, Grants: []Grant{}}

	tests := []struct {
		name    string
		entries []Entry
	}{
		{"duplicate plugin", []Entry{valid, valid}},
		{"unknown capability", []Entry{{Name: valid.Name, Digest: digest, Publisher: digest, ExecutionContext: ExecutionContextNetworkRelayWASM, Grants: []Grant{{Capability: "process.exec", Constraints: []string{}}}}}},
		{"duplicate constraint", []Entry{{Name: valid.Name, Digest: digest, Publisher: digest, ExecutionContext: ExecutionContextNetworkRelayWASM, Grants: []Grant{{Capability: "net.dial", Constraints: []string{"example:443", "example:443"}}}}}},
		{"oversized constraint", []Entry{{Name: valid.Name, Digest: digest, Publisher: digest, ExecutionContext: ExecutionContextNetworkRelayWASM, Grants: []Grant{{Capability: "net.dial", Constraints: []string{strings.Repeat("x", maxMetadataBytes+1)}}}}}},
		{"too many plugins", func() []Entry {
			entries := make([]Entry, MaxPlugins+1)
			for i := range entries {
				entries[i] = valid
				entries[i].Name = "plugin-" + strings.Repeat("a", i/26) + string(rune('a'+i%26))
			}
			return entries
		}()},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if _, err := Normalize(tc.entries); err == nil {
				t.Fatal("Normalize accepted ambiguous or oversized metadata")
			}
		})
	}
}

func TestStatementValidateRequiresWireOrder(t *testing.T) {
	t.Parallel()
	digest := "sha256:" + strings.Repeat("d", 64)
	statement := Statement{
		TenantID: "tenant-a", AgentCommonName: "relay-a", IssuedAtUnix: 42,
		Plugins: []Entry{
			{Name: "z-plugin", Digest: digest, Publisher: digest, ExecutionContext: ExecutionContextNetworkRelayWASM, Grants: []Grant{}},
			{Name: "a-plugin", Digest: digest, Publisher: digest, ExecutionContext: ExecutionContextNetworkRelayWASM, Grants: []Grant{}},
		},
	}
	if err := statement.Validate(); err == nil || !strings.Contains(err.Error(), "not normalized") {
		t.Fatalf("Validate error = %v, want non-normalized refusal", err)
	}
}
