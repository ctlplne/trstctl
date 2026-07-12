// SPDX-License-Identifier: MPL-2.0

package main

import (
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

func TestKubernetesPostureRuntimeSourceBindsBothFocusedAndFullGroupModes(t *testing.T) {
	repo, err := filepath.Abs(filepath.Join("..", ".."))
	if err != nil {
		t.Fatal(err)
	}
	entries := []Entry{
		{
			ID: "k8s_posture_routes.certificate_signing_requests", CardID: "WIRE-K8SDESC-101", Capability: "k8s_posture_routes",
			Dependencies: []string{"trstctl.com/trstctl/internal/api"},
			Assembly:     AssemblyProof{File: "internal/server/run.go", Function: "buildRunDeps", Binding: "returned-field", Field: "APIOptions", Calls: []string{"kubernetesCSRPostureFromConfig"}},
			Runtime: RuntimeProof{
				Package: "./internal/server", Test: "TestDODKubernetesPostureRoutesProductionAssembly",
				File: "internal/server/dod_kubernetes_posture_runtime_test.go", Mode: "assembled-handler", Method: "GET",
				Path: "/api/v1/kubernetes/certificate-signing-requests", SubstrateID: "kubernetes_kind_posture_v1",
			},
		},
		{
			ID: "k8s_posture_routes.trust_bundles", CardID: "WIRE-K8SDESC-102", Capability: "k8s_posture_routes",
			Dependencies: []string{"trstctl.com/trstctl/internal/api"},
			Assembly:     AssemblyProof{File: "internal/server/run.go", Function: "buildRunDeps", Binding: "returned-field", Field: "APIOptions", Calls: []string{"kubernetesTrustBundlePostureFromConfig"}},
			Runtime: RuntimeProof{
				Package: "./internal/server", Test: "TestDODKubernetesPostureRoutesProductionAssembly",
				File: "internal/server/dod_kubernetes_posture_runtime_test.go", Mode: "assembled-handler", Method: "GET",
				Path: "/api/v1/kubernetes/trust-bundles", SubstrateID: "kubernetes_kind_posture_v1",
			},
		},
	}
	substrates := map[string]Substrate{
		"kubernetes_kind_posture_v1": {
			Kind: "vendor-emulator", Verifier: "interop", Execution: "command",
			Command: []string{"tools/dodcensus/substrates/kubernetes_kind.py"}, IdentityFiles: []string{"tools/dodcensus/substrates/kubernetes_kind.py"},
			Identity:     "trstctl-kubernetes-kind-posture-v1@sha256:31e8a8f7addbf82bbeaff47fff0034bf34512423ec47eba5d6766817d1638202",
			ContractFile: "tools/dodcensus/contracts/kubernetes-kind-posture-v1.json", ContractSHA256: "sha256:c5d80931e5fecd381d082a6672511d65e18c0352c514702f1586e08c58dd0e5f",
		},
	}
	profile := BuildProfile{CGOEnabled: "0", GOOS: "linux", GOARCH: "amd64"}
	for _, entry := range entries {
		if evidence := inspectAssembly(repo, entry, profile); !evidence.OK {
			t.Errorf("%s assembly closure: %s; required=%v found=%v", entry.ID, evidence.Detail, evidence.Required, evidence.Found)
		}
		if evidence := inspectRuntimeBindingForGroup(repo, entry, substrates, entries, profile); !evidence.OK {
			t.Errorf("%s runtime closure: %s; required=%v found=%v", entry.ID, evidence.Detail, evidence.Required, evidence.Found)
		}
	}
}

func TestKubernetesPostureManifestClosesExplicitAssemblyAndRealKindRuntime(t *testing.T) {
	repo, err := filepath.Abs(filepath.Join("..", ".."))
	if err != nil {
		t.Fatal(err)
	}
	manifest, err := loadManifest(filepath.Join(repo, "tools", "dodcensus", "manifest.json"))
	if err != nil {
		t.Fatal(err)
	}
	profile := manifest.BuildProfiles[manifest.DefaultBuildProfile]
	expected := map[string]struct {
		cardID string
		call   string
		path   string
	}{
		"k8s_posture_routes.certificate_signing_requests": {
			cardID: "WIRE-K8SDESC-101", call: "kubernetesCSRPostureFromConfig",
			path: "/api/v1/kubernetes/certificate-signing-requests",
		},
		"k8s_posture_routes.trust_bundles": {
			cardID: "WIRE-K8SDESC-102", call: "kubernetesTrustBundlePostureFromConfig",
			path: "/api/v1/kubernetes/trust-bundles",
		},
	}
	found := map[string]bool{}
	actualGroup := make([]Entry, 0, len(expected))
	for _, entry := range manifest.Entries {
		want, ok := expected[entry.ID]
		if !ok {
			continue
		}
		found[entry.ID] = true
		actualGroup = append(actualGroup, entry)
		if entry.CardID != want.cardID || entry.Capability != "k8s_posture_routes" || entry.Enforcement != enforcementRequired {
			t.Errorf("%s card/capability/enforcement=%q/%q/%q, want %s/k8s_posture_routes/required",
				entry.ID, entry.CardID, entry.Capability, entry.Enforcement, want.cardID)
		}
		if entry.Inventory == nil || *entry.Inventory {
			t.Errorf("%s inventory=%v, want explicit false residual", entry.ID, entry.Inventory)
		}
		if !slices.Equal(entry.Dependencies, []string{"trstctl.com/trstctl/internal/api"}) {
			t.Errorf("%s dependencies=%v, want exact served API implementation package", entry.ID, entry.Dependencies)
		}
		if entry.Assembly.File != "internal/server/run.go" || entry.Assembly.Function != "buildRunDeps" ||
			entry.Assembly.Binding != "returned-field" || entry.Assembly.Field != "APIOptions" ||
			!slices.Equal(entry.Assembly.Calls, []string{want.call}) {
			t.Errorf("%s assembly=%+v, want buildRunDeps returned APIOptions calling %s", entry.ID, entry.Assembly, want.call)
		}
		if entry.Runtime.Package != "./internal/server" || entry.Runtime.Test != "TestDODKubernetesPostureRoutesProductionAssembly" ||
			entry.Runtime.File != "internal/server/dod_kubernetes_posture_runtime_test.go" ||
			entry.Runtime.Mode != "assembled-handler" || entry.Runtime.Method != "GET" ||
			entry.Runtime.Path != want.path || entry.Runtime.SubstrateID != "kubernetes_kind_posture_v1" {
			t.Errorf("%s runtime=%+v, want exact real-kind reconcile/mTLS/readback proof", entry.ID, entry.Runtime)
		}
		if evidence := inspectAssembly(repo, entry, profile); !evidence.OK {
			t.Errorf("%s assembly closure: %s; required=%v found=%v", entry.ID, evidence.Detail, evidence.Required, evidence.Found)
		}
	}
	for id := range expected {
		if !found[id] {
			t.Errorf("manifest is missing %s", id)
		}
	}
	for _, entry := range actualGroup {
		if evidence := inspectRuntimeBindingForGroup(repo, entry, manifest.Substrates, actualGroup, profile); !evidence.OK {
			t.Errorf("%s focused/full-group runtime closure: %s; required=%v found=%v", entry.ID, evidence.Detail, evidence.Required, evidence.Found)
		}
	}

	substrate, ok := manifest.Substrates["kubernetes_kind_posture_v1"]
	if !ok {
		t.Fatal("manifest is missing kubernetes_kind_posture_v1")
	}
	if substrate.Kind != "vendor-emulator" || substrate.Verifier != "interop" || substrate.Execution != "command" ||
		!slices.Equal(substrate.Command, []string{"tools/dodcensus/substrates/kubernetes_kind.py"}) ||
		!slices.Equal(substrate.IdentityFiles, []string{"tools/dodcensus/substrates/kubernetes_kind.py"}) ||
		!strings.HasPrefix(substrate.Identity, "trstctl-kubernetes-kind-posture-v1@sha256:") ||
		substrate.ContractFile != "tools/dodcensus/contracts/kubernetes-kind-posture-v1.json" || substrate.ContractSHA256 == "" {
		t.Fatalf("substrate=%+v, want digest-pinned real-kind command and independent posture contract", substrate)
	}
}
