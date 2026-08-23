// SPDX-License-Identifier: MPL-2.0

package server

import (
	"testing"

	"trstctl.com/trstctl/internal/signing"
)

func TestSignerModeReportsTheOpenedTopology(t *testing.T) {
	tests := []struct {
		name     string
		server   *Server
		expected string
	}{
		{name: "unattached", server: &Server{signerTopology: "external"}, expected: "none"},
		{name: "external", server: &Server{signer: signing.StaticProvider{}, signerTopology: "external"}, expected: "external"},
		{name: "child", server: &Server{signer: signing.StaticProvider{}, signerTopology: "child"}, expected: "child"},
		{name: "direct build compatibility", server: &Server{signer: signing.StaticProvider{}}, expected: "child"},
		{name: "unknown claim fails closed", server: &Server{signer: signing.StaticProvider{}, signerTopology: "sidecar-ish"}, expected: "none"},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if actual := test.server.signerMode(); actual != test.expected {
				t.Fatalf("signerMode() = %q, want %q", actual, test.expected)
			}
		})
	}
}
