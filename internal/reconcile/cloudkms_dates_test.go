// SPDX-License-Identifier: BUSL-1.1

package reconcile

import (
	"context"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/reconcile/cloudkmstest"
)

// A168-L3: with key_dates_since set, the GCP and Azure sources assert a key
// version's own creation date and, once destruction or purge is scheduled,
// that date — to the second — for versions created at or after it; older
// versions, and every version when it is unset, carry no dates.
func TestCloudKMSSourcesAssertProviderDatesSinceA168L3(t *testing.T) {
	since := time.Date(2026, 11, 13, 0, 0, 0, 0, time.UTC)
	created := time.Date(2026, 11, 13, 8, 0, 1, 500_000_000, time.UTC)
	gcp := cloudkmstest.NewGCP(a168l1Ring, a168l1Token)
	t.Cleanup(gcp.Close)
	gcp.Put(cloudkmstest.GCPKey{ID: "trstctl-g-new", Versions: []cloudkmstest.GCPVersion{
		{Number: 1, State: "ENABLED", Algorithm: "EC_SIGN_P256_SHA256", Created: created},
		{Number: 2, State: "DESTROY_SCHEDULED", Algorithm: "EC_SIGN_P256_SHA256", Created: created, Destroys: created.Add(24 * time.Hour)},
		{Number: 3, State: "ENABLED", Algorithm: "EC_SIGN_P256_SHA256", Created: time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC)}}})
	tokenFile := a168l1TokenFile(t, a168l1Token)
	gcpSnap := func(since time.Time) map[string]time.Time {
		t.Helper()
		src, err := newGCPKMSSource(GCPKMSSourceConfig{AuthorityID: "gcp-dates", KeyRing: a168l1Ring, Address: gcp.URL(),
			TokenFile: tokenFile, AllowInsecureLoopback: true, KeyDatesSince: since})
		if err != nil {
			t.Fatal(err)
		}
		snap, err := src.CloudKMSSnapshot(context.Background(), "tenant-a", nil)
		if err != nil {
			t.Fatal(err)
		}
		out := map[string]time.Time{}
		for _, key := range snap.Keys {
			out[key.KeyID+"|created"], out[key.KeyID+"|deleted"] = key.CreatedAt, key.DeletedAt
		}
		return out
	}
	second := time.Date(2026, 11, 13, 8, 0, 1, 0, time.UTC)
	got := gcpSnap(since)
	v1, v2, v3 := gcp.VersionName("trstctl-g-new", 1), gcp.VersionName("trstctl-g-new", 2), gcp.VersionName("trstctl-g-new", 3)
	if !got[v1+"|created"].Equal(second) || !got[v1+"|deleted"].IsZero() || !got[v2+"|deleted"].Equal(second.Add(24*time.Hour)) ||
		!got[v3+"|created"].IsZero() {
		t.Fatalf("GCP dates since %s = %v", since, got)
	}
	for k, v := range gcpSnap(time.Time{}) {
		if !v.IsZero() {
			t.Fatalf("GCP asserted %s = %s with key_dates_since unset", k, v)
		}
	}

	azure := cloudkmstest.NewAzure(a168l1Token)
	t.Cleanup(azure.Close)
	azure.Put(cloudkmstest.AzureKey{Name: "trstctl-generate-new", Versions: []cloudkmstest.AzureVersion{{ID: "v1", Enabled: true, Crv: "P-256", Created: created}}})
	azure.Put(cloudkmstest.AzureKey{Name: "trstctl-generate-gone", Deleted: true, PurgeAt: created.Add(90 * 24 * time.Hour),
		Versions: []cloudkmstest.AzureVersion{{ID: "v2", Enabled: true, Crv: "P-256", Created: created}}})
	azure.Put(cloudkmstest.AzureKey{Name: "trstctl-generate-old", Versions: []cloudkmstest.AzureVersion{{ID: "v3", Enabled: true, Crv: "P-256",
		Created: time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC)}}})
	src, err := newAzureKVKeySource(AzureKVKeySourceConfig{AuthorityID: "azure-dates", VaultURL: azure.URL(), TokenFile: tokenFile,
		AllowInsecureLoopback: true, KeyDatesSince: since})
	if err != nil {
		t.Fatal(err)
	}
	snap, err := src.CloudKMSSnapshot(context.Background(), "tenant-a", nil)
	if err != nil {
		t.Fatal(err)
	}
	keys := a168l1Keys(snap)
	if k := keys["keys/trstctl-generate-new/v1"]; !k.CreatedAt.Equal(second) || !k.DeletedAt.IsZero() {
		t.Fatalf("Azure active key dates = %+v", k)
	}
	if k := keys["keys/trstctl-generate-gone/v2"]; !k.CreatedAt.Equal(second) || !k.DeletedAt.Equal(time.Unix(created.Add(90*24*time.Hour).Unix(), 0).UTC()) {
		t.Fatalf("Azure deleted key dates = %+v", k)
	}
	if k := keys["keys/trstctl-generate-old/v3"]; !k.CreatedAt.IsZero() {
		t.Fatalf("an older Azure key carried dates: %+v", k)
	}

	// The shared rule: whole seconds, nothing for an older key or with no
	// moment set.
	if c, d := cloudKMSKeyDates(since, created, created.Add(time.Hour)); !c.Equal(second) || !d.Equal(second.Add(time.Hour)) {
		t.Fatalf("dates = %s %s", c, d)
	}
	if c, d := cloudKMSKeyDates(since, since.Add(-time.Second), time.Time{}); !c.IsZero() || !d.IsZero() {
		t.Fatal("a key created before the moment carried dates")
	}
	if c, _ := cloudKMSKeyDates(time.Time{}, created, time.Time{}); !c.IsZero() {
		t.Fatal("dates were asserted with no moment set")
	}
}
