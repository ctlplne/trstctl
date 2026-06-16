// Package broker is the AI-agent / non-human-identity broker (S11.10, F61): a
// first-class surface for issuing and governing the identities of autonomous AI
// agents and MCP tools. Each identity is short-lived and attested (built over
// ephemeral issuance + the attestation pipeline), policy-scoped (gated by the
// S10.1 policy engine on every issuance), and fully audited (AN-2). An agent's
// blast radius is queryable in the credential graph, and revocation is one action.
package broker

import (
	"context"
	"fmt"
	"strings"
	"time"

	"trstctl.com/trstctl/internal/auditsink"
	"trstctl.com/trstctl/internal/ephemeral"
	"trstctl.com/trstctl/internal/graph"
	"trstctl.com/trstctl/internal/policy"
)

// PolicyGate is the policy decision seam (S10.1). policy.Engine satisfies it.
type PolicyGate interface {
	Evaluate(ctx context.Context, in policy.Input) (policy.Decision, error)
}

// Compile-time proof that the S10.1 engine is a valid gate for the broker.
var _ PolicyGate = (*policy.Engine)(nil)

// Revoker marks an issued credential revoked (KRL/CRL/status). It is a seam so the
// broker is testable without the revocation subsystem.
type Revoker interface {
	Revoke(ctx context.Context, tenantID, credentialID string) error
}

// Config configures a Broker.
type Config struct {
	TenantID string
	Issuer   *ephemeral.Issuer // attested, short-TTL issuance (S11.9)
	Policy   PolicyGate        // S10.1 gate; required
	Graph    *graph.Graph      // shared with the ephemeral verifier so edges connect
	Audit    auditsink.Auditor
	Revoker  Revoker
}

// Broker issues and governs AI-agent / NHI identities.
type Broker struct {
	cfg Config
}

// New validates configuration and constructs a Broker.
func New(cfg Config) (*Broker, error) {
	if cfg.TenantID == "" {
		return nil, fmt.Errorf("broker: TenantID required (AN-1)")
	}
	if cfg.Issuer == nil {
		return nil, fmt.Errorf("broker: Issuer required")
	}
	if cfg.Policy == nil {
		return nil, fmt.Errorf("broker: Policy gate required (S10.1)")
	}
	if cfg.Graph == nil {
		cfg.Graph = graph.New()
	}
	if cfg.Audit == nil {
		cfg.Audit = auditsink.Nop{}
	}
	return &Broker{cfg: cfg}, nil
}

// IssueRequest requests an agent identity.
type IssueRequest struct {
	AgentID        string
	Method         string // attestation method
	Payload        []byte // attestation proof
	PublicKeyDER   []byte
	Scopes         []string
	IdempotencyKey string
}

// AgentIdentity is an issued, attested, policy-scoped agent identity.
type AgentIdentity struct {
	AgentID      string
	NodeID       string
	Subject      string
	CredentialID string
	CertDER      []byte
	Scopes       []string
	NotAfter     time.Time
}

func agentNodeID(id string) string { return "agent:" + id }

// Issue gates the request through policy (S10.1), mints an attested short-TTL
// credential (S11.9), records the agent and its credential in the graph, and
// audits the action. A policy-denied request mints nothing.
func (b *Broker) Issue(ctx context.Context, req IssueRequest) (AgentIdentity, error) {
	if req.AgentID == "" {
		return AgentIdentity{}, fmt.Errorf("broker: AgentID required")
	}
	in := policy.Input{
		Action:   policy.ActionIssue,
		TenantID: b.cfg.TenantID,
		Subject:  req.AgentID,
		Attrs: map[string]any{
			"agent_id":           req.AgentID,
			"scopes":             req.Scopes,
			"attestation_method": req.Method,
		},
	}
	dec, err := b.cfg.Policy.Evaluate(ctx, in)
	if err != nil {
		return AgentIdentity{}, fmt.Errorf("broker: policy: %w", err)
	}
	if !dec.Allow {
		_ = auditsink.Emit(ctx, b.cfg.Audit, nil, "agent.identity.refused", b.cfg.TenantID,
			[]byte(fmt.Sprintf(`{"agent_id":%q,"reason":%q}`, req.AgentID, dec.Reason)))
		return AgentIdentity{}, fmt.Errorf("broker: policy denied agent %q: %s", req.AgentID, dec.Reason)
	}
	res, err := b.cfg.Issuer.Issue(ctx, ephemeral.Request{
		Method: req.Method, Payload: req.Payload, PublicKeyDER: req.PublicKeyDER, IdempotencyKey: req.IdempotencyKey,
	})
	if err != nil {
		return AgentIdentity{}, err
	}
	nodeID := agentNodeID(req.AgentID)
	b.cfg.Graph.AddNode(graph.Node{
		ID: nodeID, Kind: graph.KindWorkload, Name: req.AgentID,
		Attrs: map[string]string{"tenant_id": b.cfg.TenantID, "kind": "ai-agent", "scopes": strings.Join(req.Scopes, ",")},
	})
	b.cfg.Graph.AddNode(graph.Node{
		ID: res.CredentialID, Kind: graph.KindCredential, Name: res.Subject,
		Attrs: map[string]string{"tenant_id": b.cfg.TenantID},
	})
	b.cfg.Graph.AddEdge(graph.Edge{From: nodeID, To: res.CredentialID, Type: graph.EdgeOwns})
	_ = auditsink.Emit(ctx, b.cfg.Audit, nil, "agent.identity.issued", b.cfg.TenantID,
		[]byte(fmt.Sprintf(`{"agent_id":%q,"credential_id":%q,"subject":%q}`, req.AgentID, res.CredentialID, res.Subject)))
	return AgentIdentity{
		AgentID: req.AgentID, NodeID: nodeID, Subject: res.Subject,
		CredentialID: res.CredentialID, CertDER: res.CertDER, Scopes: req.Scopes, NotAfter: res.NotAfter,
	}, nil
}

// Revoke revokes every credential the agent owns in one action and audits it.
func (b *Broker) Revoke(ctx context.Context, agentID string) error {
	nodeID := agentNodeID(agentID)
	if _, ok := b.cfg.Graph.Node(nodeID); !ok {
		return fmt.Errorf("broker: unknown agent %q", agentID)
	}
	creds := b.cfg.Graph.Neighbors(nodeID, graph.EdgeOwns)
	for _, c := range creds {
		if b.cfg.Revoker != nil {
			if err := b.cfg.Revoker.Revoke(ctx, b.cfg.TenantID, c.ID); err != nil {
				return fmt.Errorf("broker: revoke %s: %w", c.ID, err)
			}
		}
		n, _ := b.cfg.Graph.Node(c.ID)
		if n.Attrs == nil {
			n.Attrs = map[string]string{}
		}
		n.Attrs["revoked"] = "true"
		b.cfg.Graph.AddNode(n)
	}
	return b.cfg.Audit.Audit(ctx, "agent.identity.revoked", b.cfg.TenantID,
		[]byte(fmt.Sprintf(`{"agent_id":%q,"credentials":%d}`, agentID, len(creds))))
}

// BlastRadius returns everything reachable from the agent in the credential graph
// — its credentials and the attestations they exhibit — so an operator can see an
// agent's exposure before acting.
func (b *Broker) BlastRadius(agentID string) []graph.Node {
	return b.cfg.Graph.Reachable(agentNodeID(agentID))
}
