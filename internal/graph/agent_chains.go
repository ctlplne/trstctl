// SPDX-License-Identifier: BUSL-1.1

package graph

import (
	"context"
	"strconv"
	"strings"
	"time"
)

// AGID chain-bound credentials in the access graph (Q4-L4). A chain-bound
// credential is issued to the leaf of a signed delegation chain: a principal
// delegated to an agent, which may have delegated on to another, each hop
// narrowing what it passes on. The AGID store keeps the chains; the graph
// reads them through AgentChainSource so it never reads that store itself.

// agidChainBoundKind is a chain-bound credential's credential_kind attribute.
const agidChainBoundKind = "agid_chain_bound"

// MaxAgentChains bounds how many chain-bound credentials one graph build
// reads; a cut is named on the chain-bound credentials it leaves out.
const MaxAgentChains = 10000

// AgentChainSource lists a tenant's AGID chain-bound credentials with their
// delegation chains. more is true when the list stopped at limit.
type AgentChainSource interface {
	AgentChains(ctx context.Context, tenantID string, limit int) (chains []AgentChain, more bool, err error)
}

// AgentChain is one chain-bound credential and the delegation chain it was
// issued under, root first.
type AgentChain struct {
	CredentialID string
	// SubjectID is the leaf delegate the credential was issued to.
	SubjectID string
	NotBefore time.Time
	NotAfter  time.Time
	// Revoked is true once a revocation directive covers the credential.
	Revoked bool
	// ChainBroken is true when the chain could not be read root to leaf; the
	// credential is listed with no delegation links then.
	ChainBroken bool
	Links       []AgentDelegationLink
	// What the leaf record passes on: tools ("fs.read" is the tool fs for
	// read), resources, and the scopes that act on those resources.
	Tools     []string
	Resources []AgentChainResource
	Scopes    []string
}

// AgentDelegationLink is one signed delegation record: the delegator handed
// authority to the delegate for the record's validity window.
type AgentDelegationLink struct {
	DelegatorID string
	DelegateID  string
	NotBefore   time.Time
	NotAfter    time.Time
}

// AgentChainResource is a resource a chain's leaf record names.
type AgentChainResource struct {
	Kind  string
	Value string
}

func liveAt(now, notBefore, notAfter time.Time) bool {
	return !now.Before(notBefore) && (notAfter.IsZero() || now.Before(notAfter))
}

// addAgentChains draws each chain-bound credential: the live delegation
// records as DELEGATED edges between principals, the credential HELD by its
// leaf delegate, and, while it and every record of its chain are live and it
// is not revoked, an access grant to each tool and resource its leaf record
// passes on.
func addAgentChains(g *Graph, chains []AgentChain, more bool, principals principalIndex, now time.Time) {
	for _, c := range chains {
		id := credentialID("agid", c.CredentialID)
		attrs := map[string]string{"credential_kind": agidChainBoundKind, "subject": c.SubjectID,
			"not_after": c.NotAfter.UTC().Format(time.RFC3339), "chain_records": strconv.Itoa(len(c.Links))}
		if c.Revoked {
			attrs["revoked"] = "true"
		}
		if c.ChainBroken {
			attrs["chain_broken"] = "true"
		}
		if more {
			attrs["list_cut_at"] = strconv.Itoa(MaxAgentChains)
		}
		g.AddNode(Node{ID: id, Kind: KindCredential, Name: "chain-bound credential for " + c.SubjectID, Attrs: attrs})
		live := !c.Revoked && !c.ChainBroken && liveAt(now, c.NotBefore, c.NotAfter)
		for _, link := range c.Links {
			if !liveAt(now, link.NotBefore, link.NotAfter) {
				live = false
				continue
			}
			from, to := principals.node(g, link.DelegatorID), principals.node(g, link.DelegateID)
			if from != to {
				g.AddEdge(Edge{From: from, To: to, Type: EdgeDelegated, Source: "agent delegation record", Confidence: confidenceAuthority})
			}
		}
		g.AddEdge(Edge{From: principals.node(g, c.SubjectID), To: id, Type: EdgeHolds, Source: "agent chain-bound issuance", Confidence: confidenceAuthority})
		if !live {
			continue
		}
		for _, tool := range c.Tools {
			resource, action := agentScopeResource(g, "tool:"+strings.TrimPrefix(tool, "tool:"))
			grant := Edge{From: id, To: resource, Type: EdgeGrantsAccess, Source: "agent delegation tool", Confidence: confidenceAuthority}
			if action != "" {
				grant.Actions = []string{action}
			}
			g.AddEdge(grant)
		}
		for _, r := range c.Resources {
			resource := resourceID("agent-resource:" + r.Kind + ":" + r.Value)
			if _, ok := g.Node(resource); !ok {
				g.AddNode(Node{ID: resource, Kind: KindResource, Name: r.Kind + ":" + r.Value, Attrs: map[string]string{
					"resource_kind": "agent_delegation_resource", "selector_kind": r.Kind}})
			}
			g.AddEdge(Edge{From: id, To: resource, Type: EdgeGrantsAccess, Source: "agent delegation resource",
				Confidence: confidenceAuthority, Actions: c.Scopes})
		}
	}
}
