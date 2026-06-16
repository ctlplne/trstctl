package awsiid

import (
	"context"
	"testing"

	"trstctl.com/trstctl/internal/attest"
	"trstctl.com/trstctl/internal/crypto"
)

func TestAWSIIDConformsAndExtracts(t *testing.T) {
	doc := []byte(`{"instanceId":"i-0abc123","accountId":"111122223333","region":"us-east-1","instanceType":"m5.large","imageId":"ami-1"}`)
	good, root, err := crypto.SignCMS(doc)
	if err != nil {
		t.Fatal(err)
	}
	// A forged document signed by a different (untrusted) key.
	forged, _, err := crypto.SignCMS(doc)
	if err != nil {
		t.Fatal(err)
	}
	a := &Attestor{Roots: [][]byte{root}}
	if err := attest.Conform(a, good, forged); err != nil {
		t.Fatalf("Conform: %v", err)
	}
	att, err := a.Attest(context.Background(), good)
	if err != nil {
		t.Fatal(err)
	}
	if att.Subject != "i-0abc123" {
		t.Errorf("subject = %q", att.Subject)
	}
	found := false
	for _, s := range att.Selectors {
		if s == "aws:account:111122223333" {
			found = true
		}
	}
	if !found {
		t.Errorf("account selector missing: %v", att.Selectors)
	}
}

func TestAWSIIDAccountAllowlist(t *testing.T) {
	doc := []byte(`{"instanceId":"i-1","accountId":"999","region":"eu-west-1"}`)
	good, root, _ := crypto.SignCMS(doc)
	a := &Attestor{Roots: [][]byte{root}, AllowedAccounts: map[string]bool{"111": true}}
	if _, err := a.Attest(context.Background(), good); err == nil {
		t.Error("attested an account that is not on the allowlist")
	}
}
