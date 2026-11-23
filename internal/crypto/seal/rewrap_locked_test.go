// SPDX-License-Identifier: BUSL-1.1
package seal

import (
	"bytes"
	"errors"
	"testing"
)

func TestAuthenticatedRewrapPairAcceptsOnlyDEKOnlyTransformation(t *testing.T) {
	source, err := NewLocalKEK(bytes.Repeat([]byte{0x41}, 32))
	if err != nil {
		t.Fatal(err)
	}
	defer source.Destroy()
	destination, err := NewLocalKEK(bytes.Repeat([]byte{0x42}, 32))
	if err != nil {
		t.Fatal(err)
	}
	defer destination.Destroy()
	aad := []byte("tenant/name")
	domain := []byte("tenant-domain/1")
	before, err := Seal(source, []byte("secret-value"), aad)
	if err != nil {
		t.Fatal(err)
	}
	after, err := RewrapDomain(source, destination, before, domain)
	if err != nil {
		t.Fatal(err)
	}
	equal, err := AuthenticatedRewrapPair(source, before, nil, destination, after, domain, aad)
	if err != nil || !equal {
		t.Fatalf("authenticated DEK-only rewrap equal=%t err=%v", equal, err)
	}
	fresh, err := SealDomain(destination, []byte("secret-value"), aad, domain)
	if err != nil {
		t.Fatal(err)
	}
	if equal, err := AuthenticatedRewrapPair(source, before, nil, destination, fresh, domain, aad); err != nil || equal {
		t.Fatalf("fresh re-encryption equal=%t err=%v, want false", equal, err)
	}
	if equal, err := AuthenticatedRewrapPair(source, before, nil, destination, after, domain, []byte("wrong-name")); !errors.Is(err, ErrDecrypt) || equal {
		t.Fatalf("wrong AAD equal=%t err=%v, want decrypt refusal", equal, err)
	}
	if equal, err := AuthenticatedRewrapPair(destination, before, nil, destination, after, domain, aad); !errors.Is(err, ErrDecrypt) || equal {
		t.Fatalf("wrong source wrapper equal=%t err=%v, want decrypt refusal", equal, err)
	}
	if equal, err := AuthenticatedRewrapPair(source, before, nil, destination, after, []byte("wrong-domain"), aad); !errors.Is(err, ErrDomain) || equal {
		t.Fatalf("wrong domain equal=%t err=%v, want domain refusal", equal, err)
	}
}
