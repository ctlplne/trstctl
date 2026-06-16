package tsa

import (
	"context"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/crypto"
)

func TestTSANewValidation(t *testing.T) {
	if _, err := New(Config{}); err == nil {
		t.Error("empty TenantID accepted")
	}
	if _, err := New(Config{TenantID: "t1"}); err == nil {
		t.Error("missing TSA cert/signer accepted")
	}
}

func TestTSAEmptyImprintAndWrongRoot(t *testing.T) {
	a, _ := newTSA(t, nil)
	if _, err := a.Timestamp(context.Background(), nil); err == nil {
		t.Error("empty message imprint accepted")
	}
	hash := crypto.SHA256Sum([]byte("data"))
	tok, err := a.Timestamp(context.Background(), hash)
	if err != nil {
		t.Fatal(err)
	}
	other, _ := crypto.GenerateLockedKey(crypto.ECDSAP256)
	defer other.Destroy()
	otherRoot, _ := crypto.SelfSignedCACert(other, "Other Root", time.Hour)
	if err := Verify(tok, hash, otherRoot); err == nil {
		t.Error("token verified against an untrusted root")
	}
}
