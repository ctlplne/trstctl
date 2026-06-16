package azureimds

import (
	"context"
	"testing"

	"trstctl.com/trstctl/internal/attest"
	"trstctl.com/trstctl/internal/crypto"
)

func TestAzureIMDSConformsAndExtracts(t *testing.T) {
	doc := []byte(`{"vmId":"d3f1-aaaa","subscriptionId":"sub-123","resourceGroupName":"rg1","location":"eastus","name":"vm1"}`)
	good, root, err := crypto.SignCMS(doc)
	if err != nil {
		t.Fatal(err)
	}
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
	if att.Subject != "d3f1-aaaa" {
		t.Errorf("subject = %q", att.Subject)
	}
}

func TestAzureSubscriptionAllowlist(t *testing.T) {
	doc := []byte(`{"vmId":"v1","subscriptionId":"other","location":"eu"}`)
	good, root, _ := crypto.SignCMS(doc)
	a := &Attestor{Roots: [][]byte{root}, AllowedSubscriptions: map[string]bool{"sub-123": true}}
	if _, err := a.Attest(context.Background(), good); err == nil {
		t.Error("attested a subscription not on the allowlist")
	}
}
