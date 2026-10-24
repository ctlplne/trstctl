// SPDX-License-Identifier: BUSL-1.1

package transport

import "trstctl.com/trstctl/internal/sshkrlreceipt"

// SignedSSHKRLReceipt signs this host's account of the OpenSSH KRL its sshd
// enforces (A109) with the same key behind its mTLS certificate. The server
// reconstructs tenant and common name from that authenticated certificate
// before verifying.
func SignedSSHKRLReceipt(id StatementSigner, tenantID, commonName string,
	receipt sshkrlreceipt.Receipt, issuedAtUnix int64) (*sshkrlreceipt.Report, error) {
	statement := sshkrlreceipt.Statement{
		TenantID: tenantID, AgentCommonName: commonName,
		Receipt: receipt, IssuedAtUnix: issuedAtUnix,
	}
	canonical, err := statement.Canonical()
	if err != nil {
		return nil, err
	}
	signature, err := id.SignStatement(canonical)
	if err != nil {
		return nil, err
	}
	return &sshkrlreceipt.Report{Receipt: receipt, IssuedAtUnix: issuedAtUnix, Signature: signature}, nil
}
