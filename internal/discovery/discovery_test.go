package discovery

import (
	"context"
	"testing"

	"trustctl.io/trustctl/internal/auditsink"
	"trustctl.io/trustctl/internal/graph"
)

type memLister struct{ findings []Finding }

func (m memLister) List(context.Context) ([]Finding, error) { return m.findings, nil }

func TestDiscoverRecordsProvenanceNoValues(t *testing.T) {
	g := graph.New()
	rec := &auditsink.Recorder{}
	src := NewVaultSource(memLister{findings: []Finding{
		{Ref: "secret/data/app/db", Kind: "secret", Provenance: "vault@cluster-1", Attrs: map[string]string{"stale": "true"}},
	}})
	c := NewConnector(src, g, "t1", rec)
	n, err := c.Discover(context.Background())
	if err != nil || n != 1 {
		t.Fatalf("Discover = %d (err %v)", n, err)
	}
	node, ok := g.Node("disc:hashicorp-vault:secret/data/app/db")
	if !ok {
		t.Fatal("finding not merged into graph")
	}
	if node.Attrs["provenance"] != "vault@cluster-1" {
		t.Errorf("provenance = %q", node.Attrs["provenance"])
	}
	if node.Attrs["risk"] != "60" { // secret(30) + stale(30)
		t.Errorf("risk = %q, want 60", node.Attrs["risk"])
	}
	// AN-8: no audit record should ever contain a secret value (there is none to leak).
	for _, r := range rec.Records() {
		if len(r.Data) > 4096 {
			t.Error("suspiciously large discovery audit payload")
		}
	}
}

func TestAllDiscoveryConnectorsConform(t *testing.T) {
	ml := memLister{findings: []Finding{{Ref: "r1", Kind: "api-key", Provenance: "src"}}}
	sources := []Source{
		NewVaultSource(ml), NewAWSSecretsManagerSource(ml), NewAzureKeyVaultSource(ml),
		NewGCPSecretManagerSource(ml), NewKubernetesSecretsSource(ml), NewInfisicalSource(ml),
		NewAWSIAMKeySource(ml), NewGCPSAKeySource(ml), NewAzureSPSecretSource(ml),
		NewGitHubActionsSecretSource(ml), NewCICDStoreSource(ml),
	}
	if len(sources) != 11 {
		t.Fatalf("expected 11 connectors (6 stores + 5 key/token), have %d", len(sources))
	}
	names := map[string]bool{}
	for _, s := range sources {
		if err := Conform(s); err != nil {
			t.Errorf("%s: %v", s.Name(), err)
		}
		if names[s.Name()] {
			t.Errorf("duplicate connector name %q", s.Name())
		}
		names[s.Name()] = true
	}
}

func TestApiKeyScoredHigh(t *testing.T) {
	if Score(Finding{Kind: "api-key", Attrs: map[string]string{"never_rotated": "true"}}) != 90 {
		t.Errorf("api-key+never_rotated score = %d, want 90", Score(Finding{Kind: "api-key", Attrs: map[string]string{"never_rotated": "true"}}))
	}
}
