# Terraform provider

`terraform-provider-trstctl` lets Terraform drive the same served trstctl API that
the CLI and SDKs use. It is useful for the parts of non-human identity management
that belong in infrastructure-as-code: creating certificate profiles, issuing
short-lived PKI credentials for automation, and managing application secrets.

The provider is generated from the served OpenAPI contract where possible: the
route constants for profiles, PKI secret issuance, and secret-store CRUD come from
`clients/sdk/openapi.json`, and tests fail if those operation ids drift.

## Build or install

Every release tag publishes the provider in the exact Terraform Registry
release layout as GitHub Release assets: one
`terraform-provider-trstctl_<version>_<os>_<arch>.zip` per platform
(linux/darwin amd64+arm64, windows amd64), the
`terraform-provider-trstctl_<version>_manifest.json` protocol manifest, and a
GPG-signed `terraform-provider-trstctl_<version>_SHA256SUMS` — the shape the
Registry ingests directly, produced by
`scripts/release/terraform-registry-assets.sh` and covered by SLSA provenance
(`terraform-provider-trstctl.intoto.jsonl`). A real `terraform apply`
acceptance test runs in CI on every push (`TRSTCTL_RUN_TERRAFORM_ACC=1`
against a pinned terraform binary), so the plan/apply/read/delete loop is
exercised, not claimed. Registry publication requires the
`terraform-registry-signing` environment to carry the signing key
(`TERRAFORM_GPG_PRIVATE_KEY`); until the `trstctl` Registry namespace is
registered with that key's public half, install from the Release assets or
build locally.

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

## GitOps, Pulumi, and GitLab CI

The distribution includes ready-to-copy IaC examples under `deploy/iac/`:

- `deploy/iac/gitops/base/` is a Kustomize base containing a Terraform
  ConfigMap and apply Job. The Terraform config provisions a `trstctl_profile`,
  a `trstctl_pki_certificate`, and a `trstctl_secret`.
- `deploy/iac/gitops/argocd/application.yaml` points ArgoCD at that base.
- `deploy/iac/gitops/flux/kustomization.yaml` points Flux at the same base.
- `deploy/iac/pulumi/trstctl-resources/` is a Pulumi TypeScript dynamic-provider
  example that provisions the same profile, PKI certificate, and secret through
  the served REST API.
- `deploy/iac/gitlab/trstctl-iac.gitlab-ci.yml` provides GitLab CI plan/apply
  jobs for the Terraform base.

All examples read `TRSTCTL_ENDPOINT` and `TRSTCTL_TOKEN` from the cluster or CI
environment. The IaC acceptance test parses those assets and replays both the
GitOps Terraform declaration and the Pulumi resource plan against a fake trstctl
API, proving they hit `/api/v1/profiles`, `/api/v1/secrets/pki`, and
`/api/v1/secrets/store` with auth and idempotency headers:

```bash
go test ./deploy/iac -run TestGitOpsAndPulumiExamplesProvisionTrstctlResources -count=1 -v
```

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
