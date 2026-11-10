// SPDX-License-Identifier: BUSL-1.1

package reconcile

import (
	"context"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"trstctl.com/trstctl/internal/reconcile/awskmstest"
	"trstctl.com/trstctl/internal/reconcile/canon"
	"trstctl.com/trstctl/internal/reconcile/canon/reducers"
)

const (
	a168AccessKey = "AKIAA168KMS"
	a168SecretKey = "a168-kms-secret" // #nosec G101 -- fabricated fixture credential (CWE-798)
)

func a168CredentialFiles(t *testing.T, secretKey string) (string, string) {
	t.Helper()
	dir := t.TempDir()
	access, secret := filepath.Join(dir, "access"), filepath.Join(dir, "secret")
	if err := os.WriteFile(access, []byte(a168AccessKey+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(secret, []byte(secretKey+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	return access, secret
}

func a168Tagged() map[string]string { return map[string]string{awsKMSManagedTag: "op"} }

// A168: the cloud-kms reducer has a source. It asserts the keys trstctl tagged
// as its own in one account and region, read-only and signed, with the KMS
// state mapped onto the canonical vocabulary; it never asserts an AWS-managed
// key, and only asserts untagged customer keys when asked to.
func TestAWSKMSSourceAssertsTheAccountsTrstctlKeys(t *testing.T) {
	stand := awskmstest.New("us-east-1", a168AccessKey, a168SecretKey, 2)
	t.Cleanup(stand.Close)
	stand.Put(
		awskmstest.Key{ID: "k1-active", Spec: "ECC_NIST_P256", State: "Enabled", Tags: a168Tagged()},
		awskmstest.Key{ID: "k2-disabled", Spec: "RSA_3072", State: "Disabled", Tags: a168Tagged()},
		awskmstest.Key{ID: "k3-deleting", Spec: "ECC_NIST_P384", State: "PendingDeletion", Tags: a168Tagged()},
		awskmstest.Key{ID: "k4-untagged", Spec: "SYMMETRIC_DEFAULT", State: "Enabled", Rotation: true},
		awskmstest.Key{ID: "k5-aws", Spec: "SYMMETRIC_DEFAULT", State: "Enabled", Manager: "AWS", Tags: a168Tagged()},
	)
	access, secret := a168CredentialFiles(t, a168SecretKey)
	newSource := func(all bool) *awsKMSSource {
		t.Helper()
		src, err := newAWSKMSSource(AWSKMSSourceConfig{AuthorityID: "aws-kms-lab", Region: "us-east-1", Address: stand.URL(),
			AccessKeyIDFile: access, SecretAccessKeyFile: secret, AllCustomerKeys: all,
			AllowInsecureLoopback: true, HTTPClient: stand.Client()})
		if err != nil {
			t.Fatal(err)
		}
		return src
	}
	snap, err := newSource(false).CloudKMSSnapshot(context.Background(), "tenant-a", nil)
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]reducers.CloudKMSKey{}
	for _, key := range snap.Keys {
		got[key.KeyID] = key
	}
	if len(got) != 3 || got["k1-active"].Status != canon.StatusActive || got["k2-disabled"].Status != canon.StatusDisabled ||
		got["k3-deleting"].Status != canon.StatusPendingDeletion || !strings.HasSuffix(got["k1-active"].NativeID, ":key/k1-active") ||
		!got["k1-active"].CreatedAt.IsZero() {
		t.Fatalf("managed-only snapshot = %+v", snap.Keys)
	}
	if stand.Calls("ListKeys") != 3 {
		t.Fatalf("ListKeys pages = %d, want 3 for five keys at two per page", stand.Calls("ListKeys"))
	}
	all, err := newSource(true).CloudKMSSnapshot(context.Background(), "tenant-a", nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(all.Keys) != 4 {
		t.Fatalf("all customer keys = %+v, want four (never the AWS-managed key)", all.Keys)
	}
	for _, key := range all.Keys {
		if key.KeyID == "k4-untagged" && !key.RotationEnabled {
			t.Fatalf("the symmetric key's rotation standing was not read: %+v", key)
		}
	}
	if stand.Mutations() != 0 || stand.Refused() != 0 {
		t.Fatalf("mutations %d, refused signatures %d", stand.Mutations(), stand.Refused())
	}
}

// A168-L2: in an account several tenants share, a tenant's round asserts its
// own keys and the keys created before the tenant tag existed, never a key
// tagged as another tenant's, whether or not every customer key is asserted.
func TestAWSKMSSourceLeavesAnotherTenantsKeysOutA168L2(t *testing.T) {
	stand := awskmstest.New("us-east-1", a168AccessKey, a168SecretKey, 100)
	t.Cleanup(stand.Close)
	tenantTagged := func(tenant string) map[string]string {
		return map[string]string{awsKMSManagedTag: "op-" + tenant, awsKMSTenantTag: tenant}
	}
	stand.Put(
		awskmstest.Key{ID: "a-own", Spec: "ECC_NIST_P256", State: "Enabled", Tags: tenantTagged("tenant-a")},
		awskmstest.Key{ID: "b-other", Spec: "ECC_NIST_P256", State: "Enabled", Tags: tenantTagged("tenant-b")},
		awskmstest.Key{ID: "legacy", Spec: "ECC_NIST_P256", State: "Enabled", Tags: a168Tagged()},
		awskmstest.Key{ID: "untagged", Spec: "SYMMETRIC_DEFAULT", State: "Enabled"},
	)
	access, secret := a168CredentialFiles(t, a168SecretKey)
	for _, all := range []bool{false, true} {
		src, err := newAWSKMSSource(AWSKMSSourceConfig{AuthorityID: "aws-kms-shared", Region: "us-east-1", Address: stand.URL(),
			AccessKeyIDFile: access, SecretAccessKeyFile: secret, AllCustomerKeys: all,
			AllowInsecureLoopback: true, HTTPClient: stand.Client()})
		if err != nil {
			t.Fatal(err)
		}
		for tenant, want := range map[string][]string{
			"tenant-a": {"a-own", "legacy"},
			"tenant-b": {"b-other", "legacy"},
		} {
			if all {
				want = append(want, "untagged")
			}
			snap, err := src.CloudKMSSnapshot(context.Background(), tenant, nil)
			if err != nil {
				t.Fatal(err)
			}
			var got []string
			for _, key := range snap.Keys {
				got = append(got, key.KeyID)
			}
			slices.Sort(want)
			if !slices.Equal(got, want) {
				t.Fatalf("all=%v: %s's round asserts %v, want %v", all, tenant, got, want)
			}
		}
	}
	if stand.Mutations() != 0 || stand.Refused() != 0 {
		t.Fatalf("mutations %d, refused signatures %d", stand.Mutations(), stand.Refused())
	}
}

func TestAWSKMSSourceFailsClosed(t *testing.T) {
	stand := awskmstest.New("us-east-1", a168AccessKey, a168SecretKey, 100)
	t.Cleanup(stand.Close)
	stand.Put(awskmstest.Key{ID: "k1", Spec: "ECC_NIST_P256", State: "Enabled", Tags: a168Tagged()},
		awskmstest.Key{ID: "k2", Spec: "ECC_NIST_P256", State: "Enabled", Tags: a168Tagged()})
	access, wrongSecret := a168CredentialFiles(t, "wrong")
	src, err := newAWSKMSSource(AWSKMSSourceConfig{AuthorityID: "aws-kms-lab", Region: "us-east-1", Address: stand.URL(),
		AccessKeyIDFile: access, SecretAccessKeyFile: wrongSecret, AllowInsecureLoopback: true, HTTPClient: stand.Client()})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := src.CloudKMSSnapshot(context.Background(), "tenant-a", nil); err == nil || strings.Contains(err.Error(), "wrong") {
		t.Fatalf("a wrong secret = %v; want a status-only failure", err)
	}
	access, secret := a168CredentialFiles(t, a168SecretKey)
	bounded, err := newAWSKMSSource(AWSKMSSourceConfig{AuthorityID: "aws-kms-lab", Region: "us-east-1", Address: stand.URL(),
		AccessKeyIDFile: access, SecretAccessKeyFile: secret, MaxObjects: 1, AllowInsecureLoopback: true, HTTPClient: stand.Client()})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := bounded.CloudKMSSnapshot(context.Background(), "tenant-a", nil); err == nil || !strings.Contains(err.Error(), "max_objects") {
		t.Fatalf("an account over max_objects = %v; want the observation refused rather than partial", err)
	}
	for name, cfg := range map[string]AWSKMSSourceConfig{
		"no region":       {AuthorityID: "a", AccessKeyIDFile: access, SecretAccessKeyFile: secret},
		"no secret file":  {AuthorityID: "a", Region: "us-east-1", AccessKeyIDFile: access},
		"plain http":      {AuthorityID: "a", Region: "us-east-1", Address: "http://kms.example", AccessKeyIDFile: access, SecretAccessKeyFile: secret},
		"no authority id": {Region: "us-east-1", AccessKeyIDFile: access, SecretAccessKeyFile: secret},
	} {
		if _, err := newAWSKMSSource(cfg); err == nil {
			t.Errorf("%s: configuration accepted", name)
		}
	}
}
