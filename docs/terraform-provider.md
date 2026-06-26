# Terraform provider

`terraform-provider-trstctl` lets Terraform drive the same served trstctl API that
the CLI and SDKs use. It is useful for the parts of non-human identity management
that belong in infrastructure-as-code: creating certificate profiles, issuing
short-lived PKI credentials for automation, and managing application secrets.

The provider is generated from the served OpenAPI contract where possible: the
route constants for profiles, PKI secret issuance, and secret-store CRUD come from
`clients/sdk/openapi.json`, and tests fail if those operation ids drift.

## Build or install

Build the provider with the normal release target:

```bash
make build
```

For local Terraform development, place the binary where Terraform's development
override can find it:

```bash
mkdir -p ~/.terraform.d/plugins/registry.terraform.io/trstctl/trstctl/0.1.0/darwin_arm64
cp bin/terraform-provider-trstctl \
  ~/.terraform.d/plugins/registry.terraform.io/trstctl/trstctl/0.1.0/darwin_arm64/
```

Use the matching OS/architecture directory for Linux CI runners.

## Provider configuration

The provider uses the same connection contract as `trstctl-cli`:

| Terraform field | Environment fallback | Sent as |
| --- | --- | --- |
| `endpoint` | `TRSTCTL_SERVER` | Base URL, for example `https://trstctl.example.com` |
| `token` | `TRSTCTL_TOKEN` | `Authorization: Bearer <token>` |
| `tenant` | `TRSTCTL_TENANT` | `X-Tenant-ID` for header/dev auth |

Bearer API tokens carry their own tenant in normal production use, so `tenant` is
usually only needed in local/dev header-auth environments.

```hcl
terraform {
  required_providers {
    trstctl = {
      source  = "trstctl/trstctl"
      version = "0.1.0"
    }
  }
}

provider "trstctl" {
  endpoint = var.trstctl_endpoint
  token    = var.trstctl_token
}
```

Every Terraform mutation sends an `Idempotency-Key`. If you do not set one, the
provider derives a stable seed from the resource identity and operation. That means
a retry returns the original trstctl result instead of creating a duplicate remote
object.

## Certificate profiles

`trstctl_profile` calls `POST /api/v1/profiles`. Profiles are versioned facts: an
update creates a new active version instead of rewriting the old one.

```hcl
resource "trstctl_profile" "web_server" {
  name = "web-server"

  spec_json = jsonencode({
    allowed_key_algorithms = ["ECDSA-P256"]
    allowed_ekus           = ["serverAuth"]
    max_validity           = "24h"
  })
}
```

Destroying the Terraform resource removes only the Terraform state binding. trstctl
keeps the profile version in its event-sourced history so audit replay remains
complete.

## Short-lived PKI certificates

`trstctl_pki_certificate` calls `POST /api/v1/secrets/pki`. The response contains
the issued leaf certificate and its matching private key.

```hcl
resource "trstctl_pki_certificate" "deploy_hook" {
  common_name   = "deploy-hook.internal.example"
  ttl_seconds   = 900
  reissue_nonce = var.release_id
}

output "deploy_hook_certificate" {
  value = trstctl_pki_certificate.deploy_hook.certificate_pem
}

output "deploy_hook_private_key" {
  value     = trstctl_pki_certificate.deploy_hook.private_key_pem
  sensitive = true
}
```

Terraform stores resource attributes in state. The provider marks
`private_key_pem` as sensitive, but the bytes still exist in the state backend. Use
an encrypted remote backend with tight access controls, and prefer short TTLs.

Destroying this resource does not revoke the certificate. Revocation is a lifecycle
or incident-response action in trstctl, not a delete of the issued artifact.

## Application secrets

`trstctl_secret` manages `/api/v1/secrets/store`. Create writes version 1, update
rotates to the next version, read explicitly reveals the current value, and destroy
purges the stored secret.

```hcl
resource "trstctl_secret" "database_password" {
  name  = "apps/payments/database_password"
  value = var.database_password
}
```

The secret value is sealed at rest inside trstctl, but Terraform state still holds
the configured value. Treat the Terraform state backend as a secret store: encrypt
it, restrict readers, and avoid logging plans that show sensitive values.

## Acceptance test

The provider has a real Terraform apply acceptance test. It runs against a local
fake trstctl HTTP server that enforces the same routes, headers, and idempotency
contract as the served API:

```bash
TRSTCTL_RUN_TERRAFORM_ACC=1 \
TRSTCTL_TERRAFORM_PATH=/path/to/terraform \
go test ./... -run TestTerraformApplyCreatesProfileCertificateAndSecret -count=1 -v
```

That test creates a profile, issues a PKI certificate, creates and reads a secret,
then lets Terraform destroy the managed secret.
