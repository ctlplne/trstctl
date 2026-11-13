// SPDX-License-Identifier: BUSL-1.1

package managedkeystate

import "trstctl.com/trstctl/internal/crypto"

// OperationStamp is the digest a cloud provider adapter stamps on the key a
// managed-key operation creates (A168-L4): SHA-256, in hex, over the
// operation's kind ("generate" or "rotate"), its durable operation id, the
// key a rotation replaces (empty for a generate) and the algorithm. AWS KMS
// carries it whole in the key's trstctl-managed-key-operation tag; GCP Cloud
// KMS and Azure Key Vault carry its first OperationFingerprintLen characters
// in the key's name. One function, so the adapters that stamp a key and the
// reconciliation that names its operation can never disagree.
func OperationStamp(kind, operationID, source, algorithm string) string {
	return crypto.SHA256Hex([]byte(kind + "\x00" + operationID + "\x00" + source + "\x00" + algorithm))
}

// OperationFingerprintLen is how much of the stamp a provider key name keeps
// (Cloud KMS limits a key id to 63 characters).
const OperationFingerprintLen = 48

// OperationFingerprint is the stamp's prefix every provider carries.
func OperationFingerprint(kind, operationID, source, algorithm string) string {
	return OperationStamp(kind, operationID, source, algorithm)[:OperationFingerprintLen]
}
