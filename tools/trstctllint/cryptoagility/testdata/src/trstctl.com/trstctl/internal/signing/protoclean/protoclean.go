// SPDX-License-Identifier: MPL-2.0

package protoclean

type SignerServiceServer interface{}

type ServiceRegistrar interface{}

// Generated gRPC registration is transport wiring, not a runtime crypto-suite
// registry. This mirrors internal/signing/proto and must stay allowed.
func RegisterSignerServiceServer(s ServiceRegistrar, srv SignerServiceServer) {
	_, _ = s, srv
}
