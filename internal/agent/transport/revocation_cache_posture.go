// SPDX-License-Identifier: BUSL-1.1

package transport

import "trstctl.com/trstctl/internal/revcacheposture"

// SignedRevocationCachePosture signs the relay's current metadata-only cache
// view with the same key behind its mTLS certificate. The server reconstructs
// tenant and common name from that authenticated certificate before verifying.
func SignedRevocationCachePosture(id StatementSigner, tenantID, commonName string,
	entries []revcacheposture.Entry, issuedAtUnix int64) (*revcacheposture.Report, error) {
	normalized, err := revcacheposture.Normalize(entries)
	if err != nil {
		return nil, err
	}
	statement := revcacheposture.Statement{
		TenantID: tenantID, AgentCommonName: commonName,
		Entries: normalized, IssuedAtUnix: issuedAtUnix,
	}
	canonical, err := statement.Canonical()
	if err != nil {
		return nil, err
	}
	signature, err := id.SignStatement(canonical)
	if err != nil {
		return nil, err
	}
	return &revcacheposture.Report{Entries: normalized, IssuedAtUnix: issuedAtUnix, Signature: signature}, nil
}
