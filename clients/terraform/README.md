# trstctl Terraform provider

`terraform-provider-trstctl` is its own Go module (`trstctl.com/terraform-provider`),
licensed MPL-2.0 like the rest of the `clients/` tree. The module path sits outside
`trstctl.com/trstctl`, so the compiler refuses any import of the control plane's
`internal/` packages: the provider talks to trstctl only over the served REST API.

- Build: `make build` produces `bin/terraform-provider-trstctl`; release archives come
  from `scripts/release/terraform-registry-assets.sh`.
- Test: `make sdk-test`, or `cd clients/terraform && go test ./...`.
- Routes: `internal/terraformprovider/openapi_routes.gen.go` is generated from
  `clients/sdk/openapi.json` by `go run ./scripts/gen-terraform-provider-routes`.
- Documentation: `docs/terraform-provider.md`.
