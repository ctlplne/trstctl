// Package discovery provides read-only discovery of credentials that already live
// elsewhere (S20.1 secret stores / F35, S20.2 API keys & tokens / F36): a
// connector template plus read-only connectors that enumerate a source and merge
// findings into the inventory/graph with provenance — never mutating the source
// and never persisting secret VALUES (a Finding carries only an identifier and
// metadata, AN-8). Tenant-scoped (AN-1); findings are risk-scored (F19) and graphed
// (F21). This is the on-ramp: see everything in trustctl before moving anything.
package discovery

import (
	"context"
	"fmt"

	"trustctl.io/trustctl/internal/auditsink"
	"trustctl.io/trustctl/internal/graph"
)

// Finding is a discovered credential reference — never its value (AN-8).
type Finding struct {
	Ref        string // identifier only: ARN / name / path
	Kind       string // "secret" | "api-key" | "token"
	Provenance string // source system + location
	Attrs      map[string]string
}

// Source is a read-only credential source. Enumerate must never mutate the source.
type Source interface {
	Name() string
	Enumerate(ctx context.Context) ([]Finding, error)
}

// Connector merges a source's findings into the graph with provenance.
type Connector struct {
	source   Source
	graph    *graph.Graph
	tenantID string
	audit    auditsink.Auditor
}

// NewConnector constructs a discovery Connector.
func NewConnector(source Source, g *graph.Graph, tenantID string, audit auditsink.Auditor) *Connector {
	if audit == nil {
		audit = auditsink.Nop{}
	}
	return &Connector{source: source, graph: g, tenantID: tenantID, audit: audit}
}

// Discover enumerates the source (read-only) and records each finding in the graph
// with provenance and a risk score. No secret value is ever recorded or logged.
func (c *Connector) Discover(ctx context.Context) (int, error) {
	findings, err := c.source.Enumerate(ctx)
	if err != nil {
		return 0, fmt.Errorf("discovery: %s enumerate: %w", c.source.Name(), err)
	}
	for _, f := range findings {
		attrs := map[string]string{"tenant_id": c.tenantID, "provenance": f.Provenance, "kind": f.Kind, "risk": fmt.Sprint(Score(f))}
		for k, v := range f.Attrs {
			attrs[k] = v
		}
		c.graph.AddNode(graph.Node{ID: "disc:" + c.source.Name() + ":" + f.Ref, Kind: graph.KindCredential, Name: f.Ref, Attrs: attrs})
		_ = c.audit.Audit(ctx, "discovery.found", c.tenantID,
			[]byte(fmt.Sprintf(`{"source":%q,"ref":%q,"kind":%q,"provenance":%q}`, c.source.Name(), f.Ref, f.Kind, f.Provenance)))
	}
	return len(findings), nil
}

// Score is a simple risk score (F19): API keys/tokens rank above stored secrets,
// nudged up when metadata marks them old or unrotated.
func Score(f Finding) int {
	score := 10
	switch f.Kind {
	case "api-key":
		score = 60
	case "token":
		score = 50
	case "secret":
		score = 30
	}
	if f.Attrs["stale"] == "true" || f.Attrs["never_rotated"] == "true" {
		score += 30
	}
	if score > 100 {
		score = 100
	}
	return score
}

// Conform asserts a source enumerates and that every finding carries an identifier
// and provenance (and, structurally, no value). Every connector must pass it.
func Conform(source Source) error {
	if source == nil || source.Name() == "" {
		return fmt.Errorf("discovery: source has no name")
	}
	fs, err := source.Enumerate(context.Background())
	if err != nil {
		return fmt.Errorf("discovery: %s enumerate: %w", source.Name(), err)
	}
	if len(fs) == 0 {
		return fmt.Errorf("discovery: %s enumerated nothing", source.Name())
	}
	for _, f := range fs {
		if f.Ref == "" || f.Provenance == "" {
			return fmt.Errorf("discovery: %s finding missing ref/provenance", source.Name())
		}
	}
	return nil
}

// Lister is the read-only API seam a connector drives (the live client in prod, an
// in-memory double in tests).
type Lister interface {
	List(ctx context.Context) ([]Finding, error)
}

type genericSource struct {
	name   string
	lister Lister
}

func (g genericSource) Name() string                                     { return g.name }
func (g genericSource) Enumerate(ctx context.Context) ([]Finding, error) { return g.lister.List(ctx) }

// Secret-store connectors (S20.1).
func NewVaultSource(l Lister) Source             { return genericSource{"hashicorp-vault", l} }
func NewAWSSecretsManagerSource(l Lister) Source { return genericSource{"aws-secrets-manager", l} }
func NewAzureKeyVaultSource(l Lister) Source     { return genericSource{"azure-key-vault", l} }
func NewGCPSecretManagerSource(l Lister) Source  { return genericSource{"gcp-secret-manager", l} }
func NewKubernetesSecretsSource(l Lister) Source { return genericSource{"kubernetes-secrets", l} }
func NewInfisicalSource(l Lister) Source         { return genericSource{"infisical", l} }

// API key / token sources (S20.2).
func NewAWSIAMKeySource(l Lister) Source           { return genericSource{"aws-iam-keys", l} }
func NewGCPSAKeySource(l Lister) Source            { return genericSource{"gcp-sa-keys", l} }
func NewAzureSPSecretSource(l Lister) Source       { return genericSource{"azure-sp-secrets", l} }
func NewGitHubActionsSecretSource(l Lister) Source { return genericSource{"github-actions-secrets", l} }
func NewCICDStoreSource(l Lister) Source           { return genericSource{"cicd-store", l} }
