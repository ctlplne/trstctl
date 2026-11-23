// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"context"
	"strings"
	"testing"

	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/crypto"
)

// A module signature authenticates its code, not the names or tenants for which
// its CA may sign. Startup must refuse a CA plugin without an operator-owned
// tenant binding and a durable signer-held issuing authority.
func TestCR073UnboundWASMCAFailsClosedAtStartup(t *testing.T) {
	pubDER, sign, err := crypto.GenerateEd25519KeyPair()
	if err != nil {
		t.Fatal(err)
	}
	workdir, grant := pluginGrantDir(t)
	dir := writePluginDir(t, "reference-ca", caWASMFor(workdir), sign)
	pm, err := NewPluginManager(context.Background(), PluginConfig{
		CADir: dir, TrustedKeyPEMs: [][]byte{crypto.MarshalPublicKeyPEM(pubDER)}, CAGrant: grant,
	}, nil)
	if pm != nil {
		t.Cleanup(func() { _ = pm.Close(context.Background()) })
	}
	if err == nil || !strings.Contains(err.Error(), "tenant") || !strings.Contains(err.Error(), "signer") {
		t.Fatalf("unbound CA plugin startup = %v, want a tenant and signer custody refusal", err)
	}
}

func TestCR073PluginCANamespacesCannotOverlapAcrossTenants(t *testing.T) {
	err := validatePluginCABindings(map[string]config.PluginCABinding{
		"tenant-a-ca": {TenantID: "tenant-a", AuthorityID: "ca-a", DNSSuffixes: []string{"example.test"}},
		"tenant-b-ca": {TenantID: "tenant-b", AuthorityID: "ca-b", DNSSuffixes: []string{"payments.example.test"}},
	})
	if err == nil || !strings.Contains(err.Error(), "overlap") {
		t.Fatalf("overlapping tenant CA namespaces = %v, want refusal", err)
	}
	for _, invalid := range []string{".", "test", "*.example.test", "example.test.", "Example.Test"} {
		if err := validatePluginCABinding(config.PluginCABinding{TenantID: "tenant-a", AuthorityID: "ca-a", DNSSuffixes: []string{invalid}}); err == nil {
			t.Errorf("invalid DNS namespace %q was admitted", invalid)
		}
	}
}
