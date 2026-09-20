// SPDX-License-Identifier: BUSL-1.1

package sourcecatalog

import (
	"strings"
	"testing"
)

func TestCatalogIsCompleteAndTyped(t *testing.T) {
	catalog := All()
	if err := Validate(catalog); err != nil {
		t.Fatalf("validate source capability catalog: %v", err)
	}
	if len(catalog.Items) != 17 {
		t.Fatalf("catalog source kinds=%d, want 17 served OpenAPI kinds", len(catalog.Items))
	}
	for _, kind := range []string{"network", "ssh", "adcs", "cloud_certificate", "cloud_secret", "secret_store"} {
		item, ok := Find(kind)
		if !ok || item.SetupSurface != SetupSourceWizard || len(item.Configuration) == 0 {
			t.Errorf("primary source %q has no typed source-wizard contract", kind)
		}
	}
}

func TestBrokenCatalogOracleFailsForExpectedReasons(t *testing.T) {
	t.Run("missing typed payload", func(t *testing.T) {
		broken := All()
		broken.Items[0].Configuration = nil
		if err := Validate(broken); err == nil {
			t.Fatal("negative oracle: a source with no typed configuration passed")
		}
	})

	t.Run("missing recover stage", func(t *testing.T) {
		broken := All()
		broken.Items[0].ConsoleStages = []string{"configure", "preview", "execute", "observe", "prove"}
		if err := Validate(broken); err == nil {
			t.Fatal("negative oracle: a source with no recovery path passed")
		}
	})

	t.Run("secret value field", func(t *testing.T) {
		broken := All()
		broken.Items[0].Configuration = append(broken.Items[0].Configuration,
			Field{Path: "client_secret", Label: "Client secret", Type: "string", Description: "unsafe inline secret"})
		if err := Validate(broken); err == nil {
			t.Fatal("negative oracle: an inline secret-looking field passed")
		}
	})
}

func TestValidateConfigRejectsEmptyAndUnknownProvider(t *testing.T) {
	if err := ValidateConfig("cloud_certificate", []byte(`{}`)); err == nil {
		t.Fatal("empty cloud certificate config passed")
	}
	if err := ValidateConfig("cloud_secret", []byte(`{"providers":[{"provider":"made-up"}]}`)); err == nil {
		t.Fatal("unknown cloud secret provider passed")
	}
	if err := ValidateConfig("cloud_secret", []byte(`{"providers":[{"provider":"aws-secrets-manager","region":"us-east-1"}]}`)); err != nil {
		t.Fatalf("catalog-advertised provider rejected: %v", err)
	}
}

func TestCloudSecretCapabilityMakesValueAccessAnExplicitOptIn(t *testing.T) {
	capability, ok := Find("cloud_secret")
	if !ok {
		t.Fatal("cloud_secret capability missing")
	}
	found := false
	for _, field := range capability.Configuration {
		if field.Path == "providers[].inspect_content" {
			found = true
			if field.Required || !field.Advanced {
				t.Fatalf("inspect_content must be optional and advanced: %+v", field)
			}
		}
	}
	if !found || !strings.Contains(capability.DataHandling, "Optional content inspection") {
		t.Fatalf("cloud-secret value boundary is not explicit: %+v", capability)
	}
}
