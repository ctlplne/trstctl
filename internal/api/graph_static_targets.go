// SPDX-License-Identifier: BUSL-1.1

package api

import "trstctl.com/trstctl/internal/graph"

// StaticPAMTargetSource is the optional part of a PAMService that names the
// PAM targets the deployment configures statically (G1-L5): they are not in
// the store, so the graph learns them, and the provider each signs in
// through, from here.
type StaticPAMTargetSource interface {
	StaticPAMTargets(tenantID string) []graph.PAMTargetRef
}

// graphOptions adds to opts what the graph cannot read from the store.
func (a *API) graphOptions(tenantID string, opts graph.BuildOptions) graph.BuildOptions {
	if source, ok := a.pam.(StaticPAMTargetSource); ok {
		opts.PAMTargets = source.StaticPAMTargets(tenantID)
	}
	return opts
}
