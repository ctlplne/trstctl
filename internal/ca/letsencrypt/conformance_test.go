// SPDX-License-Identifier: BUSL-1.1

package letsencrypt_test

import (
	"context"
	"testing"

	"trstctl.com/trstctl/internal/ca/catemplate"
	"trstctl.com/trstctl/internal/ca/letsencrypt/acmefake"
)

// TestLetsEncryptPassesCAConformance proves the shared CA-plugin conformance
// suite (extracted in S4.6) validates the real first plugin: the Let's Encrypt
// plugin (S4.3), driven against an in-process fake ACME CA, passes it.
func TestLetsEncryptPassesCAConformance(t *testing.T) {
	srv, err := acmefake.NewServer()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(srv.Close)

	p := newRemoteAccountPlugin(t, "lets-encrypt", srv.DirectoryURL())

	report := catemplate.Conformance(context.Background(), p)
	if !report.OK() {
		t.Fatalf("Let's Encrypt plugin failed CA conformance: %+v", report.Checks)
	}
}
