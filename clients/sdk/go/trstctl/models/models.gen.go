//go:build ignore

// This file is intentionally excluded from the build (`//go:build ignore`).
//
// oapi-codegen can generate a complete Go models file for EVERY component schema
// in the OpenAPI contract, but its output imports github.com/oapi-codegen/runtime
// (for openapi_types.UUID/Date wrappers). Pulling that in would violate this
// SDK's stdlib-only supply-chain guarantee (see go.mod) for a credential client.
//
// The supported Go surface is therefore the hand-written, dependency-free
// transport and curated structs in the parent package (client.go, resources.go,
// iterator.go) — they decode the same wire shapes the generator would emit.
//
// If you specifically need the full generated model set, run the blessed config
// and accept the extra dependency in a CONSUMER module of your own:
//
//	go run github.com/oapi-codegen/oapi-codegen/v2/cmd/oapi-codegen@v2.7.1 \
//	  -config clients/sdk/go/oapi-codegen.yaml clients/sdk/openapi.json
//
// then remove this build tag in your fork. We keep this placeholder (rather than
// the generated output) so `go build ./...` of the SDK stays stdlib-only and
// always green offline.
package trstctlmodels
