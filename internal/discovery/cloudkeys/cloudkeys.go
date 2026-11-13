// SPDX-License-Identifier: BUSL-1.1

// Package cloudkeys names the cloud access-key discovery source (M3): the
// long-lived keys a cloud account's users authenticate with, read with each
// key's age and last use so a key nobody has used in 90 days stands out.
package cloudkeys

import (
	"errors"
	"net/url"
	"strings"
)

const (
	// SourceKind is the discovery source that reads cloud access keys.
	SourceKind = "cloud_access_key"
	// FindingKind is one cloud access key.
	FindingKind = "cloud_access_key"
	// ProviderAWSIAM reads IAM user access keys.
	ProviderAWSIAM = "aws-iam"
	// ProviderGCPIAM reads user-managed service-account keys (M3-L1).
	ProviderGCPIAM = "gcp-iam"
	// ProviderAzureEntra reads app-registration client secrets (M3-L2).
	ProviderAzureEntra = "azure-entra"
)

// DefaultAWSIAMEndpoint is IAM's global endpoint.
const DefaultAWSIAMEndpoint = "https://iam.amazonaws.com"

// AWSIAMEndpoint is an aws-iam connection's endpoint (IAM's global one when
// none is set) and the host its findings name in their provenance.
func AWSIAMEndpoint(endpoint string) (string, string, error) {
	endpoint = strings.TrimSpace(endpoint)
	if endpoint == "" {
		endpoint = DefaultAWSIAMEndpoint
	}
	u, err := url.Parse(endpoint)
	if err != nil || u.Host == "" {
		return "", "", errors.New("aws-iam endpoint is not a URL")
	}
	return endpoint, u.Host, nil
}
