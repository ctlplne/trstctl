// SPDX-License-Identifier: BUSL-1.1

// Package cloudkeys names the cloud access-key discovery source (M3): the
// long-lived keys a cloud account's users authenticate with, read with each
// key's age and last use so a key nobody has used in 90 days stands out.
package cloudkeys

const (
	// SourceKind is the discovery source that reads cloud access keys.
	SourceKind = "cloud_access_key"
	// FindingKind is one cloud access key.
	FindingKind = "cloud_access_key"
	// ProviderAWSIAM reads IAM user access keys.
	ProviderAWSIAM = "aws-iam"
	// ProviderGCPIAM reads user-managed service-account keys (M3-L1).
	ProviderGCPIAM = "gcp-iam"
)
