// SPDX-License-Identifier: BUSL-1.1

// Package cloudkms names the cloud key-service discovery source (X4): the keys
// a cloud account's key management service holds, read with each key's type,
// size and automatic-rotation status. Key material never leaves the service.
package cloudkms

const (
	// SourceKind is the discovery source that reads cloud KMS keys.
	SourceKind = "cloud_kms_key"
	// FindingKind is one cloud KMS key.
	FindingKind = "cloud_kms_key"
	// ProviderAWSKMS reads AWS Key Management Service keys.
	ProviderAWSKMS = "aws-kms"
)
