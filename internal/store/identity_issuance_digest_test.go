// SPDX-License-Identifier: BUSL-1.1

package store

import (
	"encoding/json"
	"testing"
	"time"
)

// A245-L5: the identity digest an issuance approval binds moves with what the
// identity puts into the certificate and with nothing else.
func TestIdentityIssuanceDigestMovesOnlyWithWhatTheCertificateCarriesA245L5(t *testing.T) {
	notAfter := time.Date(2031, 1, 2, 3, 4, 5, 6000, time.UTC)
	issuer := "11111111-2222-3333-4444-555555555555"
	base := Identity{
		ID: "identity-1", Kind: KindX509Certificate, Name: "orders.example.test", OwnerID: "owner-1",
		IssuerID: &issuer, NotAfter: &notAfter,
		Attributes: json.RawMessage(`{"subject_key_algorithm":"ECDSA-P256","endpoint_preview_sha256":"aa","dns_names":["orders.example.test"],"port":8443,
			"deployment_target_id":"t-1","connector":"f5","target":"lb","deployment_target":"lb","deployment_connector":"f5","deployment_route":"agent",
			"issuing_authority_source":"private","issuing_authority_id":"ca-1","issuing_authority_name":"Orders CA",
			"renewal_paused":{"t-1":{"reason":"rolled back"}}}`),
	}
	want, err := IdentityIssuanceDigest(base)
	if err != nil {
		t.Fatal(err)
	}
	if len(want) != 64 || !isLowerHexSHA256(want) {
		t.Fatalf("digest %q is not a lower-case hex SHA-256", want)
	}
	with := func(edit func(*Identity)) string {
		t.Helper()
		changed := base
		edit(&changed)
		got, err := IdentityIssuanceDigest(changed)
		if err != nil {
			t.Fatal(err)
		}
		return got
	}

	// The same content however it is spelled reads the same digest.
	if got := with(func(i *Identity) {
		i.Attributes = json.RawMessage(`{"renewal_paused":{"t-1":{"reason":"rolled back"}},"port":8443,"dns_names":["orders.example.test"],
			"endpoint_preview_sha256":"aa","subject_key_algorithm":"ECDSA-P256","deployment_target_id":"t-1","connector":"f5","target":"lb",
			"deployment_target":"lb","deployment_connector":"f5","deployment_route":"agent","issuing_authority_source":"private",
			"issuing_authority_id":"ca-1","issuing_authority_name":"Orders CA"}`)
		at := notAfter.In(time.FixedZone("IST", 5*3600+1800))
		i.NotAfter = &at
	}); got != want {
		t.Fatal("reordered attributes or another time zone changed the digest")
	}

	// What the identity puts into the certificate moves it.
	for name, edit := range map[string]func(*Identity){
		"name":     func(i *Identity) { i.Name = "billing.example.test" },
		"kind":     func(i *Identity) { i.Kind = "x509" },
		"issuer":   func(i *Identity) { i.IssuerID = nil },
		"validity": func(i *Identity) { later := notAfter.Add(time.Microsecond); i.NotAfter = &later },
		"subject key": func(i *Identity) {
			i.Attributes = replaceAttribute(t, base.Attributes, "subject_key_algorithm", "ML-DSA-65")
		},
		"reviewed preview": func(i *Identity) {
			i.Attributes = replaceAttribute(t, base.Attributes, "endpoint_preview_sha256", "bb")
		},
		"subject names": func(i *Identity) {
			i.Attributes = replaceAttribute(t, base.Attributes, "dns_names", []string{"*.example.test"})
		},
		"requester CSR": func(i *Identity) {
			i.Attributes = replaceAttribute(t, base.Attributes, "subject_csr_pem", "-----BEGIN CERTIFICATE REQUEST-----")
		},
		"a number's value":  func(i *Identity) { i.Attributes = replaceAttribute(t, base.Attributes, "port", 8444) },
		"erased attributes": func(i *Identity) { i.Attributes = json.RawMessage(`{}`) },
	} {
		if with(edit) == want {
			t.Errorf("changing the %s left the digest unchanged", name)
		}
	}

	// The owner, the renewal pause and what the destination and issuer
	// bindings cover on their own do not.
	for name, edit := range map[string]func(*Identity){
		"owner":  func(i *Identity) { i.OwnerID = "owner-2" },
		"status": func(i *Identity) { i.Status = "issued" },
		"renewal pause": func(i *Identity) {
			i.Attributes = replaceAttribute(t, base.Attributes, "renewal_paused", map[string]any{})
		},
		"target": func(i *Identity) { i.Attributes = replaceAttribute(t, base.Attributes, "deployment_target_id", "t-2") },
		"route": func(i *Identity) {
			i.Attributes = replaceAttribute(t, base.Attributes, "deployment_route", "control_plane")
		},
		"issuer source": func(i *Identity) {
			i.Attributes = replaceAttribute(t, base.Attributes, "issuing_authority_source", "external")
		},
		"issuer name": func(i *Identity) {
			i.Attributes = replaceAttribute(t, base.Attributes, "issuing_authority_name", "Renamed CA")
		},
	} {
		if with(edit) != want {
			t.Errorf("changing the %s moved the digest", name)
		}
	}

	if _, err := IdentityIssuanceDigest(Identity{Attributes: json.RawMessage(`[1]`)}); err == nil {
		t.Fatal("attributes that are not an object were digested")
	}
	if a, err1 := IdentityIssuanceDigest(Identity{Name: "n"}); err1 != nil {
		t.Fatal(err1)
	} else if b, err2 := IdentityIssuanceDigest(Identity{Name: "n", Attributes: json.RawMessage(`null`)}); err2 != nil || a != b {
		t.Fatalf("absent and null attributes read differently (%v)", err2)
	}
}

func replaceAttribute(t *testing.T, raw json.RawMessage, key string, value any) json.RawMessage {
	t.Helper()
	var attrs map[string]any
	if err := json.Unmarshal(raw, &attrs); err != nil {
		t.Fatal(err)
	}
	attrs[key] = value
	out, err := json.Marshal(attrs)
	if err != nil {
		t.Fatal(err)
	}
	return out
}

// A245-L5: the identity digest travels in the approval's evidence refs, parses
// back out of them, and a digest that is not lower-case hex SHA-256 is refused.
func TestIssuanceBindingCarriesTheIdentityDigestThroughItsEvidenceA245L5(t *testing.T) {
	digest := "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	binding := OperationApprovalIssuanceBinding{RequestedTTLSeconds: 3600, EffectiveTTLSeconds: 3600,
		IssuerSource: PlatformIssuerSource, IssuerID: PlatformIssuerID, IdentityDigest: digest}
	refs, err := binding.EvidenceRefs()
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := operationApprovalIssuanceBindingFromEvidence(refs)
	if err != nil || parsed == nil || parsed.IdentityDigest != digest || !parsed.BindsDestinationOrIssuer() {
		t.Fatalf("parsed binding = (%+v, %v)", parsed, err)
	}
	if _, err := operationApprovalIssuanceBindingFromEvidence(append(refs, "issuance-identity-sha256:"+digest)); err == nil {
		t.Fatal("a repeated identity digest was accepted")
	}
	for _, bad := range []string{"0123", digest[:63] + "G", "0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF"} {
		binding.IdentityDigest = bad
		if _, err := binding.EvidenceRefs(); err == nil {
			t.Fatalf("identity digest %q was accepted", bad)
		}
	}
	if !sameOperationApprovalIssuanceBinding(parsed, &OperationApprovalIssuanceBinding{RequestedTTLSeconds: 3600, EffectiveTTLSeconds: 3600}) {
		t.Fatal("an event's decoded binding, which never carries the identity digest, did not match the evidence's")
	}
}
