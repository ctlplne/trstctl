//go:build trstctl_conformance

// SPDX-License-Identifier: BUSL-1.1

package pluginhost

import "context"

// Load executes unverified bytes under a grant for author-side sandbox tests.
// It exists only in explicitly tagged conformance builds and package tests.
// Production callers must use LoadVerified or LoadVerifiedWithProvenance.
func (h *Host) Load(ctx context.Context, wasm []byte, grant Grant) (*Plugin, error) {
	return h.instantiateUnverified(ctx, wasm, grant)
}

// Conformance tests exports and execution under an empty capability grant.
// It executes unverified code; passing does not establish publisher trust.
func (h *Host) Conformance(ctx context.Context, wasm []byte) Report {
	return h.conformance(ctx, wasm)
}

// ConformanceUnderGrant tests compatibility under the supplied grant. Run it
// only against disposable resources: guest start and run functions execute.
func (h *Host) ConformanceUnderGrant(ctx context.Context, wasm []byte, grant Grant) Report {
	return h.conformanceUnderGrant(ctx, wasm, grant)
}
