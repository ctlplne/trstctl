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
	if crd.Spec.Group != "trustctl.io" || crd.Spec.Names.Kind != "TrustctlControlPlane" {
		t.Errorf("CRD group/kind = %q/%q", crd.Spec.Group, crd.Spec.Names.Kind)
	}
	if len(crd.Spec.Versions) == 0 || !crd.Spec.Versions[0].Served || !crd.Spec.Versions[0].Storage {
		t.Error("CRD has no served+stored version")
	}
}

func TestOperatorManifestHasRBACAndIsolatedDeployment(t *testing.T) {
	b, err := os.ReadFile("operator.yaml")
	if err != nil {
		t.Fatal(err)
	}
	// Each YAML document must parse.
	dec := yaml.NewDecoder(strings.NewReader(string(b)))
	docs := 0
	for {
		var doc any
		if err := dec.Decode(&doc); err != nil {
			break
		}
		docs++
	}
	if docs < 4 {
		t.Errorf("operator.yaml has %d documents, want >=4 (SA, ClusterRole, Binding, Deployment)", docs)
	}
	body := string(b)
	for _, want := range []string{"kind: ServiceAccount", "kind: ClusterRole", "kind: ClusterRoleBinding", "kind: Deployment", "trustctl.io", "runAsNonRoot: true", "readOnlyRootFilesystem: true"} {
		if !strings.Contains(body, want) {
			t.Errorf("operator.yaml missing %q", want)
		}
	}
}
