package signing

import (
	"testing"

	"trstctl.com/trstctl/internal/crypto"
	signerpb "trstctl.com/trstctl/internal/signing/proto"
)

func TestAlgorithmConversionRoundTrip(t *testing.T) {
	for _, alg := range []crypto.Algorithm{
		crypto.RSA2048, crypto.RSA3072, crypto.RSA4096,
		crypto.ECDSAP256, crypto.ECDSAP384, crypto.ECDSAP521,
	} {
		p := algorithmToProto(alg)
		got, err := algorithmFromProto(p)
		if err != nil || got != alg {
			t.Errorf("round-trip %v -> %v -> %v (err %v)", alg, p, got, err)
		}
	}
	if _, err := algorithmFromProto(signerpb.Algorithm_ALGORITHM_UNSPECIFIED); err == nil {
		t.Error("unspecified algorithm should error")
	}
}

func TestHashConversion(t *testing.T) {
	cases := []struct {
		p signerpb.Hash
		h crypto.Hash
		n int
	}{
		{signerpb.Hash_HASH_SHA256, crypto.SHA256, 32},
		{signerpb.Hash_HASH_SHA384, crypto.SHA384, 48},
		{signerpb.Hash_HASH_SHA512, crypto.SHA512, 64},
	}
	for _, c := range cases {
		h, n, err := hashFromProto(c.p)
		if err != nil || h != c.h || n != c.n {
			t.Errorf("hashFromProto(%v) = %v,%d,%v", c.p, h, n, err)
		}
		if hashToProto(c.h) != c.p {
			t.Errorf("hashToProto(%v) != %v", c.h, c.p)
		}
	}
	if _, _, err := hashFromProto(signerpb.Hash_HASH_UNSPECIFIED); err == nil {
		t.Error("unspecified hash should error")
	}
}

func TestPaddingConversion(t *testing.T) {
	if paddingFromProto(signerpb.RSAPadding_RSA_PADDING_PSS) != crypto.RSAPSS {
		t.Error("PSS")
	}
	if paddingFromProto(signerpb.RSAPadding_RSA_PADDING_PKCS1V15) != crypto.RSAPKCS1v15 {
		t.Error("PKCS1v15")
	}
	if paddingFromProto(signerpb.RSAPadding_RSA_PADDING_UNSPECIFIED) != crypto.RSAPKCS1v15 {
		t.Error("unspecified should default to PKCS1v15")
	}
	if paddingToProto(crypto.RSAPSS) != signerpb.RSAPadding_RSA_PADDING_PSS {
		t.Error("to PSS")
	}
	if paddingToProto(crypto.RSAPKCS1v15) != signerpb.RSAPadding_RSA_PADDING_PKCS1V15 {
		t.Error("to PKCS1v15")
	}
}

func TestValidateSignRequest(t *testing.T) {
	good := &signerpb.SignRequest{
		Handle: &signerpb.KeyHandle{Id: "x"},
		Digest: make([]byte, 32),
		Hash:   signerpb.Hash_HASH_SHA256,
	}
	if err := validateSignRequest(good); err != nil {
		t.Errorf("valid request rejected: %v", err)
	}

	bad := []*signerpb.SignRequest{
		nil,
		{},
		{Handle: &signerpb.KeyHandle{Id: ""}, Digest: make([]byte, 32), Hash: signerpb.Hash_HASH_SHA256},
		{Handle: &signerpb.KeyHandle{Id: "x"}, Hash: signerpb.Hash_HASH_SHA256},                                // no digest
		{Handle: &signerpb.KeyHandle{Id: "x"}, Digest: make([]byte, 99), Hash: signerpb.Hash_HASH_SHA256},      // too long
		{Handle: &signerpb.KeyHandle{Id: "x"}, Digest: make([]byte, 16), Hash: signerpb.Hash_HASH_SHA256},      // wrong length
		{Handle: &signerpb.KeyHandle{Id: "x"}, Digest: make([]byte, 32), Hash: signerpb.Hash_HASH_UNSPECIFIED}, // bad hash
	}
	for i, r := range bad {
		if err := validateSignRequest(r); err == nil {
			t.Errorf("bad request %d was accepted", i)
		}
	}
}
