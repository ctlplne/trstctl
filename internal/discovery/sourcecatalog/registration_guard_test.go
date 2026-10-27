// SPDX-License-Identifier: BUSL-1.1

package sourcecatalog

import (
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"path/filepath"
	"strings"
	"testing"
)

// Every production source registration must be reviewed as either tenant-authored
// or product-owned. A new call site fails by file and function until its name
// authority and public admission path are classified here.
func TestEveryDiscoverySourceRegistrationHasOwnerClassification(t *testing.T) {
	t.Parallel()
	root := filepath.Clean(filepath.Join("..", "..", ".."))
	expected := map[string]string{
		"internal/api/discovery.go:createDiscoverySource":                             "tenant-authored generic declaration",
		"internal/api/ct_monitoring.go:updateCTMonitoring":                            "tenant-authored CT declaration",
		"internal/api/secrets_scanning.go:ingestThirdPartySecretScan":                 "product-owned third-party secret scan",
		"internal/api/secrets_scanning.go:receiveSecretRepoWebhook":                   "product-owned repository secret scan",
		"internal/orchestrator/discovery.go:RecordAgentInventory":                     "product-owned authenticated agent inventory",
		"internal/orchestrator/discovery.go:RecordSecretScan":                         "product-owned local secret scan",
		"internal/orchestrator/weak_key_audit.go:RecordWeakKeyAudit":                  "product-owned inventory weak-key audit",
		"internal/orchestrator/endpoint_chain_finding.go:RecordEndpointChainMismatch": "product-owned endpoint issuer-chain verification",
		"internal/orchestrator/exposure_probe.go:QueueExposureProbe":                  "product-owned NHI exposure reachability probe",
		"internal/orchestrator/remediation_rotate.go:RecordRotationUnverified":        "product-owned credential-rotate replacement verification",
		"internal/orchestrator/profile_posture.go:recordProfileRSAFloorFinding":       "product-owned certificate profile posture",
		"internal/orchestrator/external_observation.go:recordObservationFinding":      "product-owned external observation intake",
	}
	found := make(map[string]bool)
	for _, tree := range []string{"internal", "cmd", "ee", "deploy", "plugins", "clients"} {
		err := filepath.WalkDir(filepath.Join(root, tree), func(path string, entry fs.DirEntry, walkErr error) error {
			if walkErr != nil {
				return walkErr
			}
			if entry.IsDir() || !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
				return nil
			}
			parsed, err := parser.ParseFile(token.NewFileSet(), path, nil, parser.SkipObjectResolution)
			if err != nil {
				return err
			}
			rel, err := filepath.Rel(root, path)
			if err != nil {
				return err
			}
			for _, declaration := range parsed.Decls {
				fn, ok := declaration.(*ast.FuncDecl)
				if !ok || fn.Body == nil {
					continue
				}
				ast.Inspect(fn.Body, func(node ast.Node) bool {
					call, ok := node.(*ast.CallExpr)
					if !ok {
						return true
					}
					selector, ok := call.Fun.(*ast.SelectorExpr)
					if ok && selector.Sel.Name == "UpsertDiscoverySource" {
						found[filepath.ToSlash(rel)+":"+fn.Name.Name] = true
					}
					return true
				})
			}
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
	}
	for callsite := range found {
		if _, classified := expected[callsite]; !classified {
			t.Errorf("unclassified discovery-source registration %s", callsite)
		}
	}
	for callsite, owner := range expected {
		if !found[callsite] {
			t.Errorf("stale discovery-source registration classification %s (%s)", callsite, owner)
		}
	}
}

func TestEveryProductSourceNamespaceIsRegistered(t *testing.T) {
	t.Parallel()
	want := map[string]string{
		AgentSourcePrefix:               "authenticated agent inventory",
		SecretScanSourcePrefix:          "product secret scan",
		SecretRepositorySourcePrefix:    "repository secret scan",
		ThirdPartySecretSourcePrefix:    "third-party secret scan",
		WeakKeyAuditSourcePrefix:        "inventory weak-key audit",
		EndpointChainSourcePrefix:       "endpoint issuer-chain verification",
		ExposureProbeSourcePrefix:       "NHI exposure reachability probe",
		RemediationRotationSourcePrefix: "credential-rotate replacement verification",
		ProfilePostureSourcePrefix:      "certificate profile posture",
		ExternalObserverSourcePrefix:    "external observation intake",
	}
	seen := make(map[string]bool)
	for _, namespace := range ReservedNamespaces() {
		if owner, ok := want[namespace.Prefix]; !ok || owner != namespace.Producer {
			t.Errorf("unclassified product source namespace %q (%s)", namespace.Prefix, namespace.Producer)
		}
		if seen[namespace.Prefix] {
			t.Errorf("duplicate product source namespace %q", namespace.Prefix)
		}
		seen[namespace.Prefix] = true
	}
	for prefix := range want {
		if !seen[prefix] {
			t.Errorf("missing product source namespace %q", prefix)
		}
	}
}
