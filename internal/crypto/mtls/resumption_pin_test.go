// SPDX-License-Identifier: BUSL-1.1

package mtls

import (
	"crypto/tls"
	"crypto/x509"
	"testing"
)

// A resumed TLS session skips VerifyPeerCertificate, so a pin enforced only
// there would stop applying the moment a session ticket resumes — a ticket
// could outlive a pin rotation (CWE-295). Pinned configs must therefore
// disable server session tickets and carry the pin in VerifyConnection, which
// runs on every connection including resumed ones. Guard for the G123 fix:
// drop either field assignment and this fails.
func TestPinnedConfigsEnforcePinOnResumedSessions(t *testing.T) {
	pin := Pin{}

	srv := serverTLSConfigPinned(tls.Certificate{}, x509.NewCertPool(), &pin)
	if !srv.SessionTicketsDisabled {
		t.Error("pinned server config leaves session tickets enabled; a resumed session would skip the client-pin check")
	}
	if srv.VerifyConnection == nil {
		t.Error("pinned server config has no VerifyConnection; the pin is not enforced on resumed sessions")
	}

	cli := clientTLSConfig(nil, x509.NewCertPool(), "signer", &pin)
	if cli.VerifyConnection == nil {
		t.Error("pinned client config has no VerifyConnection; the pin is not enforced on resumed sessions")
	}
	if cli.ClientSessionCache != nil {
		t.Error("pinned client config sets a session cache; pinned clients must not resume")
	}

	// The unpinned variants must stay untouched: no pin, no resumption change.
	if srvPlain := serverTLSConfig(tls.Certificate{}, x509.NewCertPool()); srvPlain.VerifyConnection != nil {
		t.Error("unpinned server config unexpectedly grew a VerifyConnection")
	}

	// And the connection-level check must actually enforce the pin: an empty
	// peer chain (what a hostile resumption path would present) is refused.
	if err := srv.VerifyConnection(tls.ConnectionState{}); err == nil {
		t.Error("VerifyConnection accepted a connection with no peer certificate")
	}
}
