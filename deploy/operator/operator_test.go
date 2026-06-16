package operator

import (
	"os"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

func TestCRDIsValid(t *testing.T) {
	var crd struct {
		APIVersion string `yaml:"apiVersion"`
		Kind       string `yaml:"kind"`
		Spec       struct {
			Group string `yaml:"group"`
			Names struct {
				Kind   string `yaml:"kind"`
				Plural string `yaml:"plural"`
			} `yaml:"names"`
			Versions []struct {
				Name    string `yaml:"name"`
				Served  bool   `yaml:"served"`
				Storage bool   `yaml:"storage"`
			} `yaml:"versions"`
		} `yaml:"spec"`
	}
	b, err := os.ReadFile("crd.yaml")
	if err != nil {
		t.Fatal(err)
	}
	if err := yaml.Unmarshal(b, &crd); err != nil {
		t.Fatalf("crd.yaml is not valid YAML: %v", err)
	}
	if crd.Kind != "CustomResourceDefinition" {
		t.Errorf("kind = %q", crd.Kind)
	}
	if crd.Spec.Group != "trstctl.com" || crd.Spec.Names.Kind != "TrstctlControlPlane" {
		t.Errorf("CRD group/kind = %q/%q", crd.Spec.Group, crd.Spec.Names.Kind)
	}
	if len(crd.Spec.Versions) == 0 || !crd.Spec.Versions[0].Served || !crd.Spec.Versions[0].Storage {
		t.Error("CRD has no served+stored version")
	}
}

// TestOperatorDocIsHonestAndCodeBound pins OPS-004: the package doc.go must not
// over-claim a built, kind-tested operator controller while no such controller or
// image exists. It is code-bound in BOTH directions:
//   - while there is no cmd/trstctl-operator (the controller binary), doc.go must
//     disclose the operator as PLANNED/not-yet-shipped and must NOT claim the
//     controller image is built or integration-tested on CI/kind (the original
//     over-claim);
//   - if a future change adds the controller binary, the stale "planned/not shipped"
//     wording must be retired (caught here so the doc cannot lie the other way).
//
// This is the package-doc counterpart to docs/docs_test.go
// TestKubernetesControlPlaneDeploymentIsReal, which guards the product docs.
func TestOperatorDocIsHonestAndCodeBound(t *testing.T) {
	doc, err := os.ReadFile("doc.go")
	if err != nil {
		t.Fatalf("read doc.go: %v", err)
	}
	src := string(doc)
	low := strings.ToLower(src)

	// Reality anchor: the controller binary the operator would build into an image.
	_, statErr := os.Stat("../../cmd/trstctl-operator")
	controllerExists := statErr == nil

	if controllerExists {
		// The operator is now real: the not-yet-shipped disclosure would be a stale
		// under-claim and must be gone.
		if strings.Contains(low, "planned, not yet shipped") || strings.Contains(low, "not yet shipped") {
			t.Error("cmd/trstctl-operator now exists, but doc.go still calls the operator not-yet-shipped — update the disclosure (OPS-004)")
		}
		return
	}

	// Not shipped: doc.go must say so, cite S15.1, and carry NO over-claim that the
	// controller image is built / integration-tested on CI (kind).
	if !strings.Contains(low, "planned") || !strings.Contains(src, "S15.1") {
		t.Error("doc.go must disclose the operator as PLANNED (S15.1) while no controller binary exists (OPS-004)")
	}
	overClaims := []string{
		"controller image is built and integration-tested",
		"built and integration-tested on ci",
		"built+kind-tested",
		"kind-tested",
		"the operator is built and tested",
	}
	for _, oc := range overClaims {
		if strings.Contains(low, oc) {
			t.Errorf("doc.go over-claims a built/tested operator (%q) while there is no cmd/trstctl-operator and no image build (OPS-004/OPS-002)", oc)
		}
	}
	// It must point at the manifests-only reality (not advertise a deployable
	// controller).
	if !strings.Contains(low, "manifest") {
		t.Error("doc.go should state the package ships only manifests (CRD + RBAC + Deployment) + structural validation, not a deployable controller (OPS-004)")
	}
}

// TestOperatorManifestHasRBACAndIsolatedDeployment (OPS-008 behavioural): instead
// of grepping operator.yaml for "kind: ServiceAccount", "runAsNonRoot: true", etc.
// (which pass even if those tokens sit in comments or the wrong object), this parses
// every document into a Kubernetes object and asserts the BUNDLE composition by KIND,
// that the ClusterRole/Binding wire to the same ServiceAccount, that the API group is
// trstctl.com, and that the Deployment's container is actually hardened (parsed
// securityContext, not substring).
func TestOperatorManifestHasRBACAndIsolatedDeployment(t *testing.T) {
	b, err := os.ReadFile("operator.yaml")
	if err != nil {
		t.Fatal(err)
	}
	dec := yaml.NewDecoder(strings.NewReader(string(b)))
	byKind := map[string][]map[string]any{}
	for {
		var doc map[string]any
		if err := dec.Decode(&doc); err != nil {
			break
		}
		if len(doc) == 0 {
			continue
		}
		kind, _ := doc["kind"].(string)
		if kind == "" {
			t.Errorf("operator.yaml has a document with no kind: %v", doc)
			continue
		}
		byKind[kind] = append(byKind[kind], doc)
	}

	// The bundle must carry the four RBAC+workload objects, parsed by kind.
	for _, want := range []string{"ServiceAccount", "ClusterRole", "ClusterRoleBinding", "Deployment"} {
		if len(byKind[want]) == 0 {
			t.Errorf("operator.yaml has no %s (need SA + ClusterRole + Binding + Deployment)", want)
		}
	}
	if len(byKind) == 0 {
		t.Fatal("operator.yaml decoded into no Kubernetes objects")
	}

	// The ClusterRoleBinding must bind the ClusterRole to the ServiceAccount the bundle
	// declares — a real wiring check, not a token search. (A binding that references a
	// different SA name would leave the controller without permissions.)
	if len(byKind["ServiceAccount"]) > 0 && len(byKind["ClusterRoleBinding"]) > 0 {
		saName, _ := nestedString(byKind["ServiceAccount"][0], "metadata", "name")
		crb := byKind["ClusterRoleBinding"][0]
		subjects := asAnyMaps(crb["subjects"])
		boundSA := false
		for _, s := range subjects {
			if k, _ := s["kind"].(string); k == "ServiceAccount" {
				if n, _ := s["name"].(string); n == saName && saName != "" {
					boundSA = true
				}
			}
		}
		if !boundSA {
			t.Errorf("operator.yaml ClusterRoleBinding does not bind to the bundle's ServiceAccount %q", saName)
		}
		// The ClusterRole must manage the trstctl.com API group (the operator's CRD).
		if len(byKind["ClusterRole"]) > 0 {
			if !clusterRoleCoversGroup(byKind["ClusterRole"][0], "trstctl.com") {
				t.Error("operator.yaml ClusterRole does not grant rules on the trstctl.com API group (its CRD)")
			}
		}
	}

	// The Deployment's container must be hardened — parsed securityContext fields, not
	// a substring of "runAsNonRoot: true" anywhere in the file.
	if len(byKind["Deployment"]) > 0 {
		dep := byKind["Deployment"][0]
		spec, _ := dep["spec"].(map[string]any)
		tmpl, _ := spec["template"].(map[string]any)
		pod, _ := tmpl["spec"].(map[string]any)
		cs := asAnyMaps(pod["containers"])
		if len(cs) == 0 {
			t.Fatal("operator.yaml Deployment has no containers")
		}
		sc, _ := cs[0]["securityContext"].(map[string]any)
		if sc == nil {
			t.Error("operator.yaml Deployment container has no securityContext")
		} else {
			if ro, _ := sc["readOnlyRootFilesystem"].(bool); !ro {
				t.Error("operator.yaml Deployment container is not readOnlyRootFilesystem: true")
			}
			// runAsNonRoot may be set at pod or container scope.
			podSC, _ := pod["securityContext"].(map[string]any)
			nonRoot := boolField(sc, "runAsNonRoot") || boolField(podSC, "runAsNonRoot")
			if !nonRoot {
				t.Error("operator.yaml Deployment does not set runAsNonRoot: true (pod or container scope)")
			}
		}
	}
}

func nestedString(m map[string]any, keys ...string) (string, bool) {
	cur := m
	for i, k := range keys {
		if i == len(keys)-1 {
			s, ok := cur[k].(string)
			return s, ok
		}
		next, ok := cur[k].(map[string]any)
		if !ok {
			return "", false
		}
		cur = next
	}
	return "", false
}

func asAnyMaps(v any) []map[string]any {
	raw, _ := v.([]any)
	out := make([]map[string]any, 0, len(raw))
	for _, e := range raw {
		if m, ok := e.(map[string]any); ok {
			out = append(out, m)
		}
	}
	return out
}

func boolField(m map[string]any, key string) bool {
	if m == nil {
		return false
	}
	b, _ := m[key].(bool)
	return b
}

// clusterRoleCoversGroup reports whether any rule in a ClusterRole grants the given
// API group.
func clusterRoleCoversGroup(cr map[string]any, group string) bool {
	rules, _ := cr["rules"].([]any)
	for _, r := range rules {
		rule, _ := r.(map[string]any)
		groups, _ := rule["apiGroups"].([]any)
		for _, g := range groups {
			if s, _ := g.(string); s == group {
				return true
			}
		}
	}
	return false
}
