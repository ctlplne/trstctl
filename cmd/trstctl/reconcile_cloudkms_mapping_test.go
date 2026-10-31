// SPDX-License-Identifier: BUSL-1.1

package main

import (
	"testing"

	"trstctl.com/trstctl/internal/config"
)

// A168: an awskms source block becomes one AWS KMS source per authority id
// with its region, files, scope and egress carried over, and a managed_keys
// block one managed-key authority.
func TestReconcileCloudKMSSourcesFromConfig(t *testing.T) {
	kms := &config.ReconcileAuthoritySource{Kind: config.ReconcileSourceKindAWSKMS, // #nosec G101 -- credential file paths only, no credential value (CWE-798)
		Region: " us-east-1 ", Address: " https://kms.vpce.internal ",
		AccessKeyIDFile: "/run/aws/access", SecretAccessKeyFile: "/run/aws/secret", SessionTokenFile: "/run/aws/session",
		AllCustomerKeys: true, MaxObjects: 500, PrivateEndpointCIDRs: []string{"10.30.0.0/16"}}
	managed := &config.ReconcileAuthoritySource{Kind: config.ReconcileSourceKindManagedKeys, Provider: " aws-kms "}
	c := config.Reconcile{Schedules: []config.ReconcileSchedule{
		{TenantID: "t1", Authorities: []config.ReconcileAuthority{{AuthorityID: "aws-kms-prod", Source: kms}, {AuthorityID: "managed-keys-aws", Source: managed}}},
		{TenantID: "t2", Authorities: []config.ReconcileAuthority{{AuthorityID: "aws-kms-prod", Source: kms}, {AuthorityID: "managed-keys-aws", Source: managed}}},
	}}
	sources := reconcileAWSKMSSourcesFromConfig(c)
	if len(sources) != 1 {
		t.Fatalf("awskms sources = %+v, want one for aws-kms-prod", sources)
	}
	if s := sources[0]; s.AuthorityID != "aws-kms-prod" || s.Region != "us-east-1" || s.Address != "https://kms.vpce.internal" ||
		s.AccessKeyIDFile != "/run/aws/access" || s.SecretAccessKeyFile != "/run/aws/secret" || s.SessionTokenFile != "/run/aws/session" ||
		!s.AllCustomerKeys || s.MaxObjects != 500 || len(s.PrivateEndpointCIDRs) != 1 {
		t.Fatalf("awskms source = %+v", s)
	}
	authorities := reconcileManagedKeyAuthoritiesFromConfig(c)
	if len(authorities) != 1 || authorities[0].AuthorityID != "managed-keys-aws" || authorities[0].Provider != "aws-kms" {
		t.Fatalf("managed-key authorities = %+v", authorities)
	}
}
