// SPDX-License-Identifier: BUSL-1.1

package main

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

// configSubsystemEntry names the declarations a migrated subsystem owns.
type configSubsystemEntry struct {
	types []string
	funcs []string
}

// configSubsystemFiles is the ENGHEALTH-003 table. internal/config already keeps
// per-subsystem configuration in its own sibling file (code_signing.go,
// connectors.go, external_ca.go, notifications_incident.go,
// secret_integrations.go); this table records the subsystems that have been
// migrated off config.go onto that same seam.
//
// config.go stays the top-level Config struct, Default/Parse/Load, the env-binding
// dispatcher, and the Validate aggregator. The env-binding dispatcher in
// particular MUST NOT be split out: deploy/deploycheck_test.go (OPS-008),
// deploy/docker/dist_test.go and deploy/helm/helm_test.go derive the binary's real
// TRSTCTL_* env contract by parsing config.go for set{String,Bool,BoolPtr,Int,CSV}
// calls, so moving an apply*Env function would silently shrink what those gates
// check. Only a subsystem's TYPES and its DEDICATED validators move.
//
// Adding a row is how the split proceeds: move the declarations to the sibling,
// then list them here so they cannot drift back into config.go.
func configSubsystemFiles() map[string]configSubsystemEntry {
	return map[string]configSubsystemEntry{
		"managed_keys.go": {
			types: []string{
				"ManagedKeys",
				"ManagedKeysAWSKMS",
				"ManagedKeysAzureKV",
				"ManagedKeysGCPKMS",
				"ManagedKeysPKCS11HSM",
				"ManagedKeysTPM2",
			},
			funcs: []string{
				"validateManagedKeys",
				"validateManagedKeyPrivateCIDRs",
				"validateManagedKeyEndpoint",
			},
		},
	}
}

// TestConfigPackageSubsystemsStaySplit is the ENGHEALTH-003 guardrail: once a
// subsystem's configuration has been moved to its own file in internal/config, it
// must stay there. The check is structural rather than a line-count ratchet — it
// asserts the sibling exists, that config.go does not re-declare the subsystem's
// types or validators, and that the sibling still declares them (so a stale table
// row fails too).
func TestConfigPackageSubsystemsStaySplit(t *testing.T) {
	root := moduleRoot(t)
	dir := filepath.Join(root, "internal", "config")
	configTypes, configFuncs := configDeclNames(t, filepath.Join(dir, "config.go"))
	var findings []string
	for file, entry := range configSubsystemFiles() {
		path := filepath.Join(dir, file)
		if _, err := os.Stat(path); err != nil {
			findings = append(findings, fmt.Sprintf("internal/config/%s is missing; the subsystem it owns has not been split out of config.go", file))
			continue
		}
		siblingTypes, siblingFuncs := configDeclNames(t, path)
		for _, name := range entry.types {
			if configTypes[name] {
				findings = append(findings, fmt.Sprintf("type %s is declared in internal/config/config.go; it belongs in internal/config/%s", name, file))
			}
			if !siblingTypes[name] {
				findings = append(findings, fmt.Sprintf("internal/config/%s no longer declares type %s; the ENGHEALTH-003 table is stale", file, name))
			}
		}
		for _, name := range entry.funcs {
			if configFuncs[name] {
				findings = append(findings, fmt.Sprintf("func %s is declared in internal/config/config.go; it belongs in internal/config/%s", name, file))
			}
			if !siblingFuncs[name] {
				findings = append(findings, fmt.Sprintf("internal/config/%s no longer declares func %s; the ENGHEALTH-003 table is stale", file, name))
			}
		}
	}
	if len(findings) > 0 {
		sort.Strings(findings)
		t.Fatalf("ENGHEALTH-003: internal/config subsystem split regressed:\n%s", strings.Join(findings, "\n"))
	}
}

// configDeclNames returns the top-level type names and the non-method function
// names declared in one Go file.
func configDeclNames(t *testing.T, path string) (map[string]bool, map[string]bool) {
	t.Helper()
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, path, nil, 0)
	if err != nil {
		t.Fatalf("parse %s: %v", path, err)
	}
	types := map[string]bool{}
	funcs := map[string]bool{}
	for _, decl := range file.Decls {
		switch d := decl.(type) {
		case *ast.GenDecl:
			for _, spec := range d.Specs {
				if ts, ok := spec.(*ast.TypeSpec); ok {
					types[ts.Name.Name] = true
				}
			}
		case *ast.FuncDecl:
			if d.Recv == nil {
				funcs[d.Name.Name] = true
			}
		}
	}
	return types, funcs
}
