// SPDX-License-Identifier: BUSL-1.1

package dynsecret

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/crypto"
)

// testPrincipalSuffix is a test lease's principal suffix: 16 lowercase hex
// digits derived from the lease ID, standing in for the control plane's keyed
// suffix (KeyedPrincipalSuffix), which only the deployment key can compute.
func testPrincipalSuffix(leaseID string) string {
	return crypto.SHA256Hex([]byte("test principal suffix\x00" + leaseID))[:keyedPrincipalSuffixDigits]
}

// testPrincipalDigest is a fixed-key stand-in for the deployment key's
// DerivedDigest.
func testPrincipalDigest(label, material []byte) ([]byte, error) {
	return crypto.HMACSHA256(append([]byte("test key\x00"), label...), material), nil
}

// CR-220: a lease's principal suffix is keyed and bound to tenant, registration
// epoch, provider and lease, so no caller can compute or choose another lease's.
func TestKeyedPrincipalSuffixBindsTenantEpochProviderAndLease(t *testing.T) {
	base, err := KeyedPrincipalSuffix(testPrincipalDigest, "tenant-a", "epoch-1", "pg", "lease-1")
	if err != nil {
		t.Fatal(err)
	}
	if !validKeyedPrincipalSuffix(base) {
		t.Fatalf("suffix %q is not 16 lowercase hex digits", base)
	}
	again, err := KeyedPrincipalSuffix(testPrincipalDigest, "tenant-a", "epoch-1", "pg", "lease-1")
	if err != nil || again != base {
		t.Fatalf("a retry of the same lease derived %q, want %q (%v)", again, base, err)
	}
	for name, args := range map[string][4]string{
		"another tenant":                 {"tenant-b", "epoch-1", "pg", "lease-1"},
		"a re-registered tenant (epoch)": {"tenant-a", "epoch-2", "pg", "lease-1"},
		"another provider":               {"tenant-a", "epoch-1", "pg2", "lease-1"},
		"another lease":                  {"tenant-a", "epoch-1", "pg", "lease-2"},
		// Length prefixes keep field boundaries: these concatenate alike.
		"shifted boundary": {"tenant-ae", "poch-1", "pg", "lease-1"},
	} {
		got, err := KeyedPrincipalSuffix(testPrincipalDigest, args[0], args[1], args[2], args[3])
		if err != nil {
			t.Fatal(err)
		}
		if got == base {
			t.Errorf("%s derived the same suffix %q", name, got)
		}
	}
	if _, err := KeyedPrincipalSuffix(nil, "tenant-a", "epoch-1", "pg", "lease-1"); err == nil {
		t.Error("a missing deployment key derived a suffix")
	}
	for _, missing := range [][4]string{{"", "e", "p", "l"}, {"t", "", "p", "l"}, {"t", "e", "", "l"}, {"t", "e", "p", ""}} {
		if _, err := KeyedPrincipalSuffix(testPrincipalDigest, missing[0], missing[1], missing[2], missing[3]); err == nil {
			t.Errorf("KeyedPrincipalSuffix accepted %q", missing)
		}
	}
	failing := func([]byte, []byte) ([]byte, error) { return nil, errors.New("key unavailable") }
	if _, err := KeyedPrincipalSuffix(failing, "tenant-a", "epoch-1", "pg", "lease-1"); err == nil {
		t.Error("a failing derivation produced a suffix")
	}
}

// CR-220: the name builder refuses a lease without the keyed suffix (the old
// unkeyed lease digest is gone from every backend path), uses the suffix it is
// given, and shortens it - never below ten digits - before it would cut the
// configured prefix, which the revoke gate matches whole.
func TestLeaseNamesUseTheKeyedSuffixAndKeepThePrefixWhole(t *testing.T) {
	if _, err := scopedNameForRequest("trstctl", GenerateRequest{Role: "reader", LeaseID: "lease-1"}, 63, "_"); err == nil {
		t.Fatal("a lease without the keyed suffix was named")
	}
	for _, bad := range []string{"0123456789", "0123456789ABCDEF", "0123456789abcdeg", strings.Repeat("a", 17)} {
		if _, err := scopedNameForRequest("trstctl", GenerateRequest{Role: "reader", LeaseID: "lease-1", PrincipalSuffix: bad}, 63, "_"); err == nil {
			t.Errorf("suffix %q was accepted", bad)
		}
	}
	suffix := "0123456789abcdef"
	name, err := scopedNameForRequest("trstctl", GenerateRequest{Role: "reader", LeaseID: "lease-1", PrincipalSuffix: suffix}, 63, "_")
	if err != nil || name != "trstctl_reader_"+suffix {
		t.Fatalf("name = %q (%v), want trstctl_reader_%s", name, err, suffix)
	}
	// MySQL's 32-character budget with a 16-character prefix: the full keyed
	// suffix would cut the prefix, so the suffix gives up digits instead.
	name, err = scopedNameForRequest("trstctl_app_prod", GenerateRequest{Role: "reader", LeaseID: "lease-1", PrincipalSuffix: suffix}, 32, "_")
	if err != nil || len(name) > 32 || !strings.HasPrefix(name, "trstctl_app_prod_") || !issuedPrincipalName("trstctl_app_prod", name) {
		t.Fatalf("long-prefix name = %q (%v): prefix cut, over budget, or refused by the gate", name, err)
	}
	if tail := name[strings.LastIndexByte(name, '_')+1:]; len(tail) < legacyPrincipalSuffixDigits || !strings.HasPrefix(suffix, tail) {
		t.Fatalf("long-prefix suffix = %q, want a 10-16 digit prefix of %q", tail, suffix)
	}
	// A prefix too long even for ten digits keeps today's behavior (the prefix
	// is cut; FF-DYN-NAME-BUDGET owns that case), with ten keyed digits.
	name, err = scopedNameForRequest(strings.Repeat("p", 30), GenerateRequest{Role: "r", LeaseID: "l", PrincipalSuffix: suffix}, 32, "_")
	if err != nil || len(name) > 32 || !strings.HasSuffix(name, "_"+suffix[:legacyPrincipalSuffixDigits]) {
		t.Fatalf("over-long prefix name = %q (%v)", name, err)
	}
	// No lease: a random suffix, as before.
	name, err = scopedNameForRequest("trstctl", GenerateRequest{Role: "reader"}, 63, "_")
	if err != nil || !issuedPrincipalName("trstctl", name) {
		t.Fatalf("random name = %q (%v)", name, err)
	}
}

// CR-220: revocation still accepts every name ever issued - the earlier
// releases' ten-digit lease digest and the keyed suffix, shortened or not -
// and still refuses names trstctl did not issue.
func TestRevokeGateAcceptsLegacyAndKeyedNamesOnly(t *testing.T) {
	for _, ok := range []string{
		"trstctl_reader_0123456789",       // earlier releases
		"trstctl_reader_0123456789abcdef", // keyed
		"trstctl_reader_0123456789abc",    // keyed, shortened for a long prefix
		"TRSTCTL_READER_0123456789ABCDEF", // upper-cased by the target
		"trstctl_0123456789abcdef",        // role cut away entirely
	} {
		if !issuedPrincipalName("trstctl", ok) {
			t.Errorf("gate refused issued name %q", ok)
		}
	}
	for _, refused := range []string{
		"trstctl_admin",
		"trstctl_reader_012345678",         // 9 digits
		"trstctl_reader_0123456789abcdef0", // 17 digits
		"trstctl_reader_0123456789abcdeg",  // not hex
		"other_reader_0123456789abcdef",    // another prefix
		"trstctlx_reader_0123456789abcdef", // prefix only by string prefix
		"trstctl_reader",                   // no suffix
		"orders_app",
	} {
		if issuedPrincipalName("trstctl", refused) {
			t.Errorf("gate accepted %q", refused)
		}
	}
	if !issuedPrincipalNameWith("trstctl", "trstctl-reader-0123456789abcdef", '-') || issuedPrincipalNameWith("trstctl", "trstctl-reader-0123456789abcdef0", '-') {
		t.Error("the hyphen gate does not follow the same suffix rule")
	}
}

// The AWS decoy backend keeps finding the decoys earlier releases named: its
// legacy helper reproduces the old name exactly.
func TestLegacyDecoyNamesAreUnchanged(t *testing.T) {
	got, err := LegacyLeasePrincipalName("trstctl-honey", "honeytoken", "lease-decoy-1", 64, "_")
	if err != nil {
		t.Fatal(err)
	}
	if want := "trstctl_honey_honeytoken_" + crypto.SHA256Hex([]byte("lease-decoy-1"))[:legacyPrincipalSuffixDigits]; got != want {
		t.Fatalf("legacy decoy name = %q, want %q", got, want)
	}
	if _, err := LegacyLeasePrincipalName("trstctl-honey", "honeytoken", " ", 64, "_"); err == nil {
		t.Fatal("a legacy name was derived without a lease")
	}
}

// The library engine and the conformance helper name with a suffix too.
func TestEngineAndConformancePassAPrincipalSuffix(t *testing.T) {
	var seen []GenerateRequest
	p := recordingSuffixProvider{seen: &seen}
	if err := Conform(p); err != nil {
		t.Fatal(err)
	}
	for _, req := range seen {
		if req.LeaseID == "" || !validKeyedPrincipalSuffix(req.PrincipalSuffix) {
			t.Fatalf("conformance request %+v carries no keyed-shape suffix", req)
		}
	}
	if seen[0].PrincipalSuffix == seen[1].PrincipalSuffix {
		t.Fatal("conformance's two leases share one suffix")
	}

	seen = nil
	engine, err := New(Config{TenantID: "tenant-a", Providers: []Provider{p}, Queue: NewMemoryQueue()})
	if err != nil {
		t.Fatal(err)
	}
	for _, key := range []string{"engine-issue-1", "engine-issue-2"} {
		if _, _, err := engine.Issue(context.Background(), p.Name(), "reader", time.Minute, key); err != nil {
			t.Fatal(err)
		}
	}
	if len(seen) != 2 {
		t.Fatalf("the engine sent %d requests, want 2", len(seen))
	}
	for _, req := range seen {
		if req.LeaseID == "" || !validKeyedPrincipalSuffix(req.PrincipalSuffix) {
			t.Fatalf("engine request %+v carries no keyed-shape suffix", req)
		}
	}
	if seen[0].PrincipalSuffix == seen[1].PrincipalSuffix {
		t.Fatal("the engine's two leases share one suffix")
	}
	// The suffix is not the caller's to choose: another engine of the same
	// tenant (another process embedding the library against the same server)
	// issuing under the same Idempotency-Key names a different principal.
	other, err := New(Config{TenantID: "tenant-a", Providers: []Provider{p}, Queue: NewMemoryQueue()})
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := other.Issue(context.Background(), p.Name(), "reader", time.Minute, "engine-issue-1"); err != nil {
		t.Fatal(err)
	}
	if len(seen) != 3 || seen[2].PrincipalSuffix == seen[0].PrincipalSuffix {
		t.Fatalf("two engines issuing under one Idempotency-Key named suffixes %q and %q", seen[0].PrincipalSuffix, seen[len(seen)-1].PrincipalSuffix)
	}
}

type recordingSuffixProvider struct{ seen *[]GenerateRequest }

func (recordingSuffixProvider) Name() string { return "recording" }
func (p recordingSuffixProvider) Generate(_ context.Context, req GenerateRequest) (Credential, error) {
	*p.seen = append(*p.seen, req)
	return Credential{BackendRef: "ref-" + req.LeaseID, Secret: bytes.Repeat([]byte{1}, 4)}, nil
}
func (recordingSuffixProvider) Revoke(context.Context, string) error { return nil }
