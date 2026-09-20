// SPDX-License-Identifier: BUSL-1.1

package docs

import "testing"

// TestSupply005TypeScriptSDKGeneratorLockfileSCAIsRequired locks SUPPLY-005:
// the TypeScript SDK generator lockfile must be part of npm SCA, and the gate
// must prove a known HIGH/CRITICAL advisory in that lockfile fails closed. ELI5:
// generated SDK code is only trustworthy if the generator dependency tree is
// scanned, not merely pinned.
func TestSupply005TypeScriptSDKGeneratorLockfileSCAIsRequired(t *testing.T) {
	mk := read(t, "../Makefile")
	requireAllContained(t, "SUPPLY-005", "Makefile", mk,
		"npm dependency tree SCA (web + TypeScript SDK generator + Pulumi IaC)",
		"bash scripts/ci/npm-audit-dependency-surfaces.sh",
	)

	checker := read(t, "../scripts/ci/npm-audit-dependency-surfaces.sh")
	requireAllContained(t, "SUPPLY-005", "scripts/ci/npm-audit-dependency-surfaces.sh", checker,
		"clients/sdk/typescript",
		"TypeScript SDK generator dependency tree",
		"--package-lock-only",
		"--audit-level=high",
		"--include=dev",
		"web build and runtime dependency tree",
		"build-and-production",
	)

	selftest := read(t, "../scripts/ci/npm-audit-dependency-surfaces_selftest.sh")
	requireAllContained(t, "SUPPLY-005", "scripts/ci/npm-audit-dependency-surfaces_selftest.sh", selftest,
		"minimist\":\"0.0.8",
		"rejects critical minimist advisory in TypeScript SDK generator lockfile",
		"TRSTCTL_TS_SDK_NPM_PREFIX",
	)

	ci := read(t, "../.github/workflows/ci.yml")
	requireAllContained(t, "SUPPLY-005", "ci.yml", ci,
		"npm dependency tree SCA (web + TypeScript SDK + Pulumi IaC)",
		"bash scripts/ci/npm-audit-dependency-surfaces_selftest.sh",
		"bash scripts/ci/npm-audit-dependency-surfaces.sh",
	)

	dependabot := read(t, "../.github/dependabot.yml")
	requireAllContained(t, "SUPPLY-005", "dependabot.yml", dependabot,
		`directory: "/clients/sdk/typescript"`,
		`prefix: "deps(sdk-ts)"`,
	)

	supplyDocs := read(t, "supply-chain.md")
	requireAllContained(t, "SUPPLY-005", "docs/supply-chain.md", supplyDocs,
		"clients/sdk/typescript/package-lock.json",
		"scripts/ci/npm-audit-dependency-surfaces.sh",
		"minimist@0.0.8",
	)

	supplyReadme := read(t, "../deploy/supply-chain/README.md")
	requireAllContained(t, "SUPPLY-005", "deploy/supply-chain/README.md", supplyReadme,
		"npm (TypeScript SDK generator)",
		"clients/sdk/typescript/package-lock.json",
		"scripts/ci/npm-audit-dependency-surfaces.sh",
	)
}
