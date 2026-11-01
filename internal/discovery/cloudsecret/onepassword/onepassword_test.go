// SPDX-License-Identifier: BUSL-1.1

package onepassword_test

import (
	"context"
	"strings"
	"testing"

	"trstctl.com/trstctl/internal/discovery/cloudcert"
	"trstctl.com/trstctl/internal/discovery/cloudsecret"
	"trstctl.com/trstctl/internal/discovery/cloudsecret/onepassword"
	"trstctl.com/trstctl/internal/discovery/cloudsecret/secretstoretest"
)

func TestOnePasswordItemsMetadataAndFieldInspection(t *testing.T) {
	stripe := "sk" + "_live_" + strings.Repeat("A173op", 5)[:28]
	stand := secretstoretest.NewOnePassword("op-a173", []secretstoretest.OnePasswordItem{
		{Vault: "Payments", Title: "Stripe live", Fields: map[string]string{"credential": stripe, "username": "payments-bot"}},
		{Vault: "Payments", Title: "Notes", Category: "SECURE_NOTE", Fields: map[string]string{"notesPlain": "rotate quarterly"}},
		{Vault: "Infra", Title: "Bastion", Fields: map[string]string{"password": "correct horse battery staple"}},
	})
	t.Cleanup(stand.Close)
	e, err := onepassword.New(onepassword.Config{BaseURL: stand.URL(), HTTPClient: stand.Client(), Vaults: []string{"Payments"}, Token: cloudcert.StaticToken("op-a173")})
	if err != nil {
		t.Fatal(err)
	}
	found, err := e.Enumerate(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(found) != 2 {
		t.Fatalf("metadata-only = %+v", found)
	}
	for _, call := range stand.Seen() {
		if strings.Count(call, "/items/") > 0 {
			t.Fatalf("a metadata-only run read item details: %s", call)
		}
	}
	e, err = onepassword.New(onepassword.Config{BaseURL: stand.URL(), HTTPClient: stand.Client(), Token: cloudcert.StaticToken("op-a173"), InspectContent: true})
	if err != nil {
		t.Fatal(err)
	}
	found, err = e.Enumerate(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	var creds []cloudsecret.Credential
	for _, f := range found {
		if f.Kind == cloudsecret.FindingKindAPIKey {
			creds = append(creds, *f.Credential)
			if f.Location != "Payments" || f.SecretName != "Stripe live" {
				t.Fatalf("credential finding = %+v", f)
			}
		}
	}
	if len(creds) != 1 || creds[0].Rule != "stripe_secret_key" || creds[0].Field != "credential" || len(found) != 4 {
		t.Fatalf("inspected = %+v (%d findings)", creds, len(found))
	}
	if _, err := onepassword.New(onepassword.Config{Token: cloudcert.StaticToken("x")}); err == nil {
		t.Fatal("a source with no Connect endpoint was accepted")
	}
	e, _ = onepassword.New(onepassword.Config{BaseURL: stand.URL(), HTTPClient: stand.Client(), Vaults: []string{"Missing"}, Token: cloudcert.StaticToken("op-a173")})
	if _, err := e.Enumerate(context.Background()); err == nil || !strings.Contains(err.Error(), "not visible") {
		t.Fatalf("missing vault = %v", err)
	}
}
