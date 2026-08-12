// SPDX-License-Identifier: MPL-2.0

package transport

import "trstctl.com/trstctl/internal/plugincensus"

// SignedPluginCensus normalizes and signs one current relay-runtime view. The
// tenant and common name come from the agent's own identity; the server rebuilds
// them from the independently authenticated peer certificate.
func SignedPluginCensus(id StatementSigner, tenantID, commonName string,
	plugins []plugincensus.Entry, issuedAtUnix int64) (*plugincensus.Report, error) {
	normalized, err := plugincensus.Normalize(plugins)
	if err != nil {
		return nil, err
	}
	statement := plugincensus.Statement{
		TenantID: tenantID, AgentCommonName: commonName,
		Plugins: normalized, IssuedAtUnix: issuedAtUnix,
	}
	canonical, err := statement.Canonical()
	if err != nil {
		return nil, err
	}
	signature, err := id.SignStatement(canonical)
	if err != nil {
		return nil, err
	}
	return &plugincensus.Report{Plugins: normalized, IssuedAtUnix: issuedAtUnix, Signature: signature}, nil
}
