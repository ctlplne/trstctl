package terraformprovider

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"strings"
	"testing"

	"github.com/hashicorp/terraform-plugin-framework/providerserver"
	"github.com/hashicorp/terraform-plugin-go/tfprotov6"
	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
)

func TestTerraformApplyCreatesProfileCertificateAndSecret(t *testing.T) {
	if os.Getenv("TRSTCTL_RUN_TERRAFORM_ACC") != "1" {
		t.Skip("set TRSTCTL_RUN_TERRAFORM_ACC=1 with terraform on PATH to run the real terraform apply acceptance test")
	}
	if path := os.Getenv("TRSTCTL_TERRAFORM_PATH"); path != "" {
		t.Setenv("TF_ACC_TERRAFORM_PATH", path)
	}
	if _, err := exec.LookPath(terraformCommand()); err != nil {
		t.Fatalf("terraform CLI is required for acceptance test: %v", err)
	}
	t.Setenv("TF_ACC", "1")

	srv := terraformAcceptanceServer(t)
	t.Cleanup(srv.Close)

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: map[string]func() (tfprotov6.ProviderServer, error){
			"trstctl": providerserver.NewProtocol6WithError(NewWithHTTPClient("test", srv.Client())()),
		},
		Steps: []resource.TestStep{
			{
				Config: terraformAcceptanceConfig(srv.URL),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr("trstctl_profile.web", "name", "web"),
					resource.TestCheckResourceAttr("trstctl_profile.web", "version", "1"),
					resource.TestCheckResourceAttr("trstctl_pki_certificate.leaf", "serial", "01"),
					resource.TestCheckResourceAttrSet("trstctl_pki_certificate.leaf", "certificate_pem"),
					resource.TestCheckResourceAttrSet("trstctl_pki_certificate.leaf", "private_key_pem"),
					resource.TestCheckResourceAttr("trstctl_secret.db", "name", "apps/api/password"),
					resource.TestCheckResourceAttr("trstctl_secret.db", "version", "1"),
				),
			},
		},
	})
}

func terraformCommand() string {
	if path := os.Getenv("TRSTCTL_TERRAFORM_PATH"); path != "" {
		return path
	}
	return "terraform"
}

func terraformAcceptanceConfig(endpoint string) string {
	return fmt.Sprintf(`
provider "trstctl" {
  endpoint = %[1]q
  token    = "tok-test"
  tenant   = "tenant-a"
}

resource "trstctl_profile" "web" {
  name = "web"
  spec_json = jsonencode({
    allowed_key_algorithms = ["ECDSA-P256"]
    max_validity           = "1h"
  })
}

resource "trstctl_pki_certificate" "leaf" {
  common_name = "svc.example.test"
  ttl_seconds = 600
}

resource "trstctl_secret" "db" {
  name  = "apps/api/password"
  value = "initial-fixture-value"
}
`, endpoint)
}

func terraformAcceptanceServer(t *testing.T) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer tok-test" {
			t.Errorf("Authorization header = %q", r.Header.Get("Authorization"))
		}
		if r.Header.Get("X-Tenant-ID") != "tenant-a" {
			t.Errorf("X-Tenant-ID header = %q", r.Header.Get("X-Tenant-ID"))
		}
		if r.Method != http.MethodGet && r.Header.Get("Idempotency-Key") == "" {
			t.Errorf("%s %s missing Idempotency-Key", r.Method, r.URL.Path)
		}
		w.Header().Set("Content-Type", "application/json")
		switch r.Method + " " + r.URL.Path {
		case "POST /api/v1/profiles":
			_, _ = w.Write([]byte(`{"id":"prof-1","name":"web","version":1,"active":true,"created_by":"terraform","spec":{"allowed_key_algorithms":["ECDSA-P256"],"max_validity":"1h"}}`))
		case "GET /api/v1/profiles/web/versions/1":
			_, _ = w.Write([]byte(`{"id":"prof-1","name":"web","version":1,"active":true,"created_by":"terraform","spec":{"allowed_key_algorithms":["ECDSA-P256"],"max_validity":"1h"}}`))
		case "POST /api/v1/secrets/pki":
			_, _ = w.Write([]byte(`{"serial":"01","common_name":"svc.example.test","certificate":"-----BEGIN CERTIFICATE-----\nfixture\n-----END CERTIFICATE-----\n","private_key":"-----BEGIN PRIVATE KEY-----\nfixture\n-----END PRIVATE KEY-----\n"}`))
		case "POST /api/v1/secrets/store":
			_, _ = w.Write([]byte(`{"name":"apps/api/password","version":1,"created_at":"2026-06-26T01:00:00Z","updated_at":"2026-06-26T01:00:00Z"}`))
		case "GET /api/v1/secrets/store/apps/api/password":
			_, _ = w.Write([]byte(`{"name":"apps/api/password","value":"initial-fixture-value","version":1}`))
		case "DELETE /api/v1/secrets/store/apps/api/password":
			w.WriteHeader(http.StatusNoContent)
		default:
			http.Error(w, "unexpected "+strings.TrimSpace(r.Method+" "+r.URL.Path), http.StatusNotFound)
		}
	}))
}
