// SPDX-License-Identifier: MPL-2.0

package discovery

import "testing"

func TestFindingIDIsStableAndBindsTheWholeNaturalKeyAUD96(t *testing.T) {
	const (
		tenant      = "11111111-1111-4111-8111-111111111111"
		run         = "22222222-2222-4222-8222-222222222222"
		kind        = "x509_certificate"
		ref         = "shadow.example.test:443"
		fingerprint = "sha256:abc"
	)
	want := FindingID(tenant, run, kind, ref, fingerprint)
	if got := FindingID(tenant, run, kind, ref, fingerprint); got != want {
		t.Fatalf("same natural key produced %q then %q", want, got)
	}
	variants := []string{
		FindingID("33333333-3333-4333-8333-333333333333", run, kind, ref, fingerprint),
		FindingID(tenant, "44444444-4444-4444-8444-444444444444", kind, ref, fingerprint),
		FindingID(tenant, run, "ssh_key", ref, fingerprint),
		FindingID(tenant, run, kind, "other.example.test:443", fingerprint),
		FindingID(tenant, run, kind, ref, "sha256:def"),
	}
	for i, got := range variants {
		if got == want {
			t.Errorf("natural-key variant %d reused %q", i, want)
		}
	}
}

func TestFindingIdentityBindsTheSourceObservationAndIgnoresTheRun(t *testing.T) {
	const (
		tenant      = "11111111-1111-4111-8111-111111111111"
		source      = "55555555-5555-4555-8555-555555555555"
		kind        = "x509_certificate"
		ref         = "shadow.example.test:443"
		fingerprint = "sha256:abc"
	)
	want := FindingIdentity(tenant, source, kind, ref, fingerprint)
	if got := FindingIdentity(tenant, source, kind, ref, fingerprint); got != want {
		t.Fatalf("same observation produced %q then %q", want, got)
	}
	if got := FindingID(tenant, "22222222-2222-4222-8222-222222222222", kind, ref, fingerprint); got == want {
		t.Fatalf("source-scoped identity collided with the legacy run-scoped payload ID %q", got)
	}
	variants := []string{
		FindingIdentity("33333333-3333-4333-8333-333333333333", source, kind, ref, fingerprint),
		FindingIdentity(tenant, "66666666-6666-4666-8666-666666666666", kind, ref, fingerprint),
		FindingIdentity(tenant, source, "ssh_key", ref, fingerprint),
		FindingIdentity(tenant, source, kind, "other.example.test:443", fingerprint),
		FindingIdentity(tenant, source, kind, ref, "sha256:def"),
	}
	for i, got := range variants {
		if got == want {
			t.Errorf("observation variant %d reused %q", i, want)
		}
	}
}
