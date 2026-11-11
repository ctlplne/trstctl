// SPDX-License-Identifier: BUSL-1.1

package secretsync

import (
	"context"
	"errors"
	"slices"
	"strings"
	"testing"

	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/secretsync/ssmtest"
)

func newParameterStoreA202L1(t *testing.T, stand *ssmtest.Server, prefix string) *AWSParameterStorePusher {
	t.Helper()
	pusher, err := NewAWSParameterStorePusher(AWSParameterStoreConfig{
		Endpoint: stand.URL, HTTPClient: stand.Client(), Region: "us-east-1",
		AccessKeyID: "stand-in-ssm-key-id", SecretAccessKey: []byte("stand-in-ssm-secret"), PathPrefix: prefix, // #nosec G101 -- a stand-in fixture value, not a credential (CWE-798)
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pusher.Close)
	return pusher
}

// A202-L1: the Parameter Store target reads what it holds — the decrypted
// value's digest, a listing by path across pages, a delete — and settles a
// lost delivery by comparing the parameter with the command's value, so a
// value changed outside trstctl reads as drift.
func TestParameterStoreReadsItsParametersBackA202L1(t *testing.T) {
	ctx := context.Background()
	stand := ssmtest.New()
	t.Cleanup(stand.Close)
	pusher := newParameterStoreA202L1(t, stand, "apps")
	target := NewAWSParamStoreTarget(pusher)
	if !target.CanReconcile() {
		t.Fatal("the Parameter Store target does not claim receiver reconcile")
	}
	scoped, ok := target.Scoped()
	if !ok || !ScopedReadsBack(scoped) || ScopedFlatKeys(scoped) {
		t.Fatal("the Parameter Store target is not a scoped, read-back, path-keyed destination")
	}

	for _, kv := range [][2]string{{"orders/db", "db-one"}, {"orders/cache", "cache-one"}, {"orders/queue/token", "queue-one"}, {"billing/db", "billing-one"}} {
		if err := pusher.Push(ctx, kv[0], []byte(kv[1])); err != nil {
			t.Fatal(err)
		}
	}
	stand.Set("/elsewhere/orders/db", "not-under-this-target")

	exists, digest, err := scoped.ReadDigest(ctx, "orders/db")
	if err != nil || !exists || digest != crypto.SHA256Hex([]byte("db-one")) {
		t.Fatalf("ReadDigest = %v %q %v, want the decrypted value's SHA-256", exists, digest, err)
	}
	if exists, digest, err := scoped.ReadDigest(ctx, "orders/missing"); err != nil || exists || digest != "" {
		t.Fatalf("ReadDigest of a missing parameter = %v %q %v", exists, digest, err)
	}

	stand.SetPageSize(2)
	keys, err := scoped.ListKeys(ctx, "orders", 0)
	if err != nil || !slices.Equal(keys, []string{"orders/cache", "orders/db", "orders/queue/token"}) {
		t.Fatalf("ListKeys(orders) = %v %v, want the three keys across pages", keys, err)
	}
	all, err := scoped.ListKeys(ctx, "", 0)
	if err != nil || len(all) != 4 || slices.Contains(all, "elsewhere/orders/db") {
		t.Fatalf("ListKeys of the whole target = %v %v", all, err)
	}
	if _, err := scoped.ListKeys(ctx, "orders", 2); !errors.Is(err, ErrScopedListLimit) {
		t.Fatalf("ListKeys over the limit = %v, want ErrScopedListLimit", err)
	}

	if state, err := target.ReconcileOperation(ctx, "op-1", "orders/db", []byte("db-one")); err != nil || state != ReceiverStateMatches {
		t.Fatalf("reconcile of the delivered value = %q %v, want matches", state, err)
	}
	stand.Set("/apps/orders/db", "changed-outside-trstctl")
	if state, err := target.ReconcileOperation(ctx, "op-1", "orders/db", []byte("db-one")); err != nil || state != ReceiverStateDiffers {
		t.Fatalf("reconcile after drift = %q %v, want differs", state, err)
	}
	if state, err := target.ReconcileOperation(ctx, "op-2", "orders/missing", []byte("x")); err != nil || state != ReceiverStateDiffers {
		t.Fatalf("reconcile of a missing parameter = %q %v, want differs", state, err)
	}

	if err := scoped.Delete(ctx, "orders/cache"); err != nil {
		t.Fatal(err)
	}
	if _, ok := stand.Value("/apps/orders/cache"); ok {
		t.Fatal("Delete left the parameter")
	}
	if err := scoped.Delete(ctx, "orders/cache"); err != nil {
		t.Fatalf("deleting a parameter already gone = %v, want nil", err)
	}
	for _, call := range stand.Calls() {
		if !slices.Contains([]string{"PutParameter", "GetParameter", "GetParametersByPath", "DeleteParameter"}, call) {
			t.Fatalf("unexpected SSM action %q", call)
		}
	}
}

// A202-L1: the names a scoped sync may write are names SSM accepts.
func TestParameterStoreValidKeyA202L1(t *testing.T) {
	for _, c := range []struct {
		prefix, key string
		want        string
	}{
		{"apps", "orders/db", ""},
		{"", "orders/db", ""},
		{"", "aws/orders", "aws or ssm"},
		{"", "SSM-config", "aws or ssm"},
		{"apps", "aws/orders", ""},
		{"apps", "orders//db", "empty path segment"},
		{"apps", "orders db", "letters, digits"},
		{"apps", "", "needs a key"},
		{"apps", strings.Repeat("a/", 15) + "b", "levels deep"},
		{"apps", strings.Repeat("x", 1100), "at most 1011"},
	} {
		err := ParameterStoreValidKey(c.prefix, c.key)
		if c.want == "" && err != nil || c.want != "" && (err == nil || !strings.Contains(err.Error(), c.want)) {
			t.Errorf("ParameterStoreValidKey(%q, %q) = %v, want %q", c.prefix, c.key, err, c.want)
		}
	}
}
