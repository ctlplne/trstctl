package docs

import (
	"strings"
	"testing"
)

func TestFrontendOpenAPIContractGenerationBoundary(t *testing.T) {
	generator := read(t, "../web/scripts/gen-api-types.mjs")
	for _, want := range []string{
		"internal/api/testdata/openapi.golden.json",
		"src/lib/api-types.gen.ts",
		"contract drift",
		"process.exit(1)",
		"matches the served OpenAPI contract",
	} {
		if !strings.Contains(generator, want) {
			t.Errorf("gen-api-types.mjs must keep the served OpenAPI drift gate; missing %q", want)
		}
	}

	packageJSON := read(t, "../web/package.json")
	for _, want := range []string{
		`"gen:api": "node scripts/gen-api-types.mjs"`,
		`"build": "npm run gen:api -- --check && tsc -p tsconfig.build.json && vite build"`,
	} {
		if !strings.Contains(packageJSON, want) {
			t.Errorf("web/package.json must run the OpenAPI type check before build; missing %q", want)
		}
	}

	ci := read(t, "../.github/workflows/ci.yml")
	for _, want := range []string{
		"Contract check (FE types vs served OpenAPI)",
		"npm run gen:api -- --check",
		"npm run build",
	} {
		if !strings.Contains(ci, want) {
			t.Errorf("ci.yml must keep the frontend/OpenAPI contract gate; missing %q", want)
		}
	}

	apiClient := read(t, "../web/src/lib/api.ts")
	apiClientLower := strings.ToLower(apiClient)
	for _, want := range []string{
		"from \"./api-types.gen\"",
		"generated",
		"served openapi contract",
	} {
		if !strings.Contains(apiClientLower, want) {
			t.Errorf("web API client must consume generated served-contract types; missing %q", want)
		}
	}

	generatedTypes := read(t, "../web/src/lib/api-types.gen.ts")
	for _, want := range []string{
		"Code generated from the served OpenAPI contract",
		"web/scripts/gen-api-types.mjs",
		"TestOpenAPIGolden",
	} {
		if !strings.Contains(generatedTypes, want) {
			t.Errorf("generated FE types must keep their source-of-truth banner; missing %q", want)
		}
	}

	contractTests := read(t, "../internal/api/contract_drift_test.go")
	for _, want := range []string{
		"TestGeneratedFETypesMatchServedContract",
		"TestContractDriftDetectsInjectedMismatch",
		"regenerate web/src/lib/api-types.gen.ts",
	} {
		if !strings.Contains(contractTests, want) {
			t.Errorf("Go contract tests must pin generated frontend types; missing %q", want)
		}
	}
}
