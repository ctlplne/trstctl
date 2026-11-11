// SPDX-License-Identifier: BUSL-1.1

package reconcile

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"trstctl.com/trstctl/internal/reconcile/canon"
	"trstctl.com/trstctl/internal/reconcile/canon/reducers"
	"trstctl.com/trstctl/internal/reconcile/cloudkmstest"
)

const (
	a168l1Ring  = "projects/a168l1/locations/us-east1/keyRings/trstctl"
	a168l1Token = "stand-in-kms-token" // #nosec G101 -- a stand-in fixture value, not a credential (CWE-798)
)

func a168l1TokenFile(t *testing.T, token string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "token")
	if err := os.WriteFile(path, []byte(token+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func a168l1Keys(snap reducers.CloudKMSSnapshot) map[string]reducers.CloudKMSKey {
	out := map[string]reducers.CloudKMSKey{}
	for _, key := range snap.Keys {
		out[key.KeyID] = key
	}
	return out
}

// A168-L1: a Cloud KMS key ring is a cloud-kms source. It asserts each version
// of the keys trstctl created (by their ID prefix) under the version's resource
// name, with the algorithm spelled as trstctl's record spells it and the state
// mapped onto the canonical vocabulary; a destroyed version is gone, a key
// labelled as another tenant's is never asserted, and every customer key is
// asserted only when asked. Lists are followed across their pages, and a
// refused token is an error, never an empty account.
func TestGCPKMSSourceAssertsTheRingsTrstctlKeysA168L1(t *testing.T) {
	stand := cloudkmstest.NewGCP(a168l1Ring, a168l1Token)
	t.Cleanup(stand.Close)
	stand.Put(cloudkmstest.GCPKey{ID: "trstctl-g-aaa", Labels: map[string]string{"trstctl-tenant": "tenant-a"},
		Versions: []cloudkmstest.GCPVersion{{Number: 1, State: "ENABLED", Algorithm: "EC_SIGN_P256_SHA256"}}})
	stand.Put(cloudkmstest.GCPKey{ID: "trstctl-r-bbb", Versions: []cloudkmstest.GCPVersion{
		{Number: 1, State: "DISABLED", Algorithm: "RSA_SIGN_PKCS1_3072_SHA256"},
		{Number: 2, State: "DESTROY_SCHEDULED", Algorithm: "RSA_SIGN_PKCS1_3072_SHA256"},
		{Number: 3, State: "DESTROYED", Algorithm: "RSA_SIGN_PKCS1_3072_SHA256"}}})
	stand.Put(cloudkmstest.GCPKey{ID: "trstctl-g-other", Labels: map[string]string{"trstctl-tenant": "tenant-b"},
		Versions: []cloudkmstest.GCPVersion{{Number: 1, State: "ENABLED", Algorithm: "EC_SIGN_P384_SHA384"}}})
	stand.Put(cloudkmstest.GCPKey{ID: "payments-key", RotationPeriod: "7776000s",
		Versions: []cloudkmstest.GCPVersion{{Number: 1, State: "ENABLED", Algorithm: "GOOGLE_SYMMETRIC_ENCRYPTION"}}})
	tokenFile := a168l1TokenFile(t, a168l1Token)
	source := func(all bool, token string) *gcpKMSSource {
		t.Helper()
		src, err := newGCPKMSSource(GCPKMSSourceConfig{AuthorityID: "gcp-kms-lab", KeyRing: a168l1Ring, Address: stand.URL(),
			TokenFile: token, AllCustomerKeys: all, AllowInsecureLoopback: true})
		if err != nil {
			t.Fatal(err)
		}
		return src
	}
	snap, err := source(false, tokenFile).CloudKMSSnapshot(context.Background(), "tenant-a", nil)
	if err != nil {
		t.Fatal(err)
	}
	got := a168l1Keys(snap)
	own, disabled, deleting := stand.VersionName("trstctl-g-aaa", 1), stand.VersionName("trstctl-r-bbb", 1), stand.VersionName("trstctl-r-bbb", 2)
	if len(got) != 3 || got[own].Status != canon.StatusActive || got[own].AlgorithmSpec != "ECDSA-P256" ||
		got[disabled].Status != canon.StatusDisabled || got[disabled].AlgorithmSpec != "RSA-3072" ||
		got[deleting].Status != canon.StatusPendingDeletion {
		t.Fatalf("tenant-a's snapshot = %+v; want its own key, the unlabelled trstctl key's live versions, never tenant-b's", snap.Keys)
	}
	if _, ok := got[stand.VersionName("trstctl-r-bbb", 3)]; ok {
		t.Fatal("a destroyed version was asserted")
	}
	all, err := source(true, tokenFile).CloudKMSSnapshot(context.Background(), "tenant-a", nil)
	if err != nil {
		t.Fatal(err)
	}
	if every := a168l1Keys(all); len(every) != 4 || !every[stand.VersionName("payments-key", 1)].RotationEnabled {
		t.Fatalf("every customer key = %+v; want the customer key too, with its rotation schedule", all.Keys)
	}
	if _, err := source(false, a168l1TokenFile(t, "not-the-token")).CloudKMSSnapshot(context.Background(), "tenant-a", nil); err == nil {
		t.Fatal("a refused token produced a snapshot")
	}
	for _, ring := range []string{"", "projects/a/keyRings/r", "projects/a/locations/l/keyRings/../x"} {
		if _, err := newGCPKMSSource(GCPKMSSourceConfig{AuthorityID: "gcp", KeyRing: ring, TokenFile: tokenFile}); err == nil {
			t.Fatalf("key ring %q was accepted", ring)
		}
	}
}

// A168-L1: a Key Vault vault is a cloud-kms source. It asserts each version of
// the keys trstctl created (by their name prefix) as keys/{name}/{version}, with
// the algorithm read from the version's key and a deleted key awaiting purge as
// pending deletion; a key tagged as another tenant's is never asserted; a
// nextLink that leaves the vault is refused.
func TestAzureKVKeySourceAssertsTheVaultsTrstctlKeysA168L1(t *testing.T) {
	stand := cloudkmstest.NewAzure(a168l1Token)
	t.Cleanup(stand.Close)
	stand.Put(cloudkmstest.AzureKey{Name: "trstctl-generate-aaa", Tags: map[string]string{"trstctl-tenant": "tenant-a"},
		Versions: []cloudkmstest.AzureVersion{{ID: "v1", Enabled: true, Crv: "P-256"}}})
	stand.Put(cloudkmstest.AzureKey{Name: "trstctl-rotate-bbb", Versions: []cloudkmstest.AzureVersion{{ID: "v2", Enabled: false, RSABits: 3072}}})
	stand.Put(cloudkmstest.AzureKey{Name: "trstctl-generate-ccc", Deleted: true, Versions: []cloudkmstest.AzureVersion{{ID: "v3", Enabled: true, Crv: "P-384"}}})
	stand.Put(cloudkmstest.AzureKey{Name: "trstctl-generate-other", Tags: map[string]string{"trstctl-tenant": "tenant-b"},
		Versions: []cloudkmstest.AzureVersion{{ID: "v4", Enabled: true, Crv: "P-256"}}})
	stand.Put(cloudkmstest.AzureKey{Name: "payments", Versions: []cloudkmstest.AzureVersion{{ID: "v5", Enabled: true, RSABits: 2048}}})
	tokenFile := a168l1TokenFile(t, a168l1Token)
	source := func(all bool) *azureKVKeySource {
		t.Helper()
		src, err := newAzureKVKeySource(AzureKVKeySourceConfig{AuthorityID: "azure-kv-lab", VaultURL: stand.URL(), TokenFile: tokenFile,
			AllCustomerKeys: all, AllowInsecureLoopback: true})
		if err != nil {
			t.Fatal(err)
		}
		return src
	}
	snap, err := source(false).CloudKMSSnapshot(context.Background(), "tenant-a", nil)
	if err != nil {
		t.Fatal(err)
	}
	got := a168l1Keys(snap)
	if len(got) != 3 || got["keys/trstctl-generate-aaa/v1"].Status != canon.StatusActive || got["keys/trstctl-generate-aaa/v1"].AlgorithmSpec != "ECDSA-P256" ||
		got["keys/trstctl-rotate-bbb/v2"].Status != canon.StatusDisabled || got["keys/trstctl-rotate-bbb/v2"].AlgorithmSpec != "RSA-3072" ||
		got["keys/trstctl-generate-ccc/v3"].Status != canon.StatusPendingDeletion || got["keys/trstctl-generate-ccc/v3"].AlgorithmSpec != "ECDSA-P384" {
		t.Fatalf("tenant-a's snapshot = %+v", snap.Keys)
	}
	if all, err := source(true).CloudKMSSnapshot(context.Background(), "tenant-a", nil); err != nil || len(all.Keys) != 4 {
		t.Fatalf("every customer key = %+v %v; want four (never tenant-b's)", all.Keys, err)
	}
	stand.SetForeignNextLink("https://elsewhere.example")
	if _, err := source(false).CloudKMSSnapshot(context.Background(), "tenant-a", nil); err == nil || !strings.Contains(err.Error(), "nextLink") {
		t.Fatalf("a nextLink to another host = %v; want refused", err)
	}
}

// A168-L1: the managed-key authority asserts a GCP key by its version's
// resource name and an Azure key relative to its vault, the identities the
// sources assert, and refuses a provider it does not serve.
func TestManagedKeyAuthorityServesGCPAndAzureA168L1(t *testing.T) {
	for provider, want := range map[string]struct{ in, out string }{
		"gcp-kms":         {a168l1Ring + "/cryptoKeys/trstctl-g-aaa/cryptoKeyVersions/1", a168l1Ring + "/cryptoKeys/trstctl-g-aaa/cryptoKeyVersions/1"},
		"azure-key-vault": {"https://lab.vault.azure.net/keys/trstctl-generate-aaa/v1", "keys/trstctl-generate-aaa/v1"},
		"aws-kms":         {"arn:aws:kms:us-east-1:111122223333:key/k1", "k1"},
	} {
		src, err := newStoreManagedKeySource(nil, ManagedKeyAuthorityConfig{AuthorityID: "managed-" + provider, Provider: provider})
		if err != nil {
			t.Fatalf("%s: %v", provider, err)
		}
		if got := src.keyID(want.in); got != want.out {
			t.Fatalf("%s key id %q -> %q; want %q", provider, want.in, got, want.out)
		}
	}
	if _, err := newStoreManagedKeySource(nil, ManagedKeyAuthorityConfig{AuthorityID: "managed-oci", Provider: "oci-vault"}); err == nil {
		t.Fatal("an unserved provider was accepted")
	}
}
