// SPDX-License-Identifier: BUSL-1.1

package graph

import (
	"context"
	"strings"
	"time"

	"trstctl.com/trstctl/internal/store"
)

// The access side of the graph (G1, step 1): the people, roles and AI agents
// in trstctl's own records, the credentials they hold, what those credentials
// reach and who approved them. Every source is read in tenant-scoped keyset
// pages. A link is "authoritative" when the record names both ends exactly.
//
//   - tenant members        → person nodes, HAS_ROLE → role nodes
//   - agent-broker issuance → ai-agent nodes, HOLDS → their certificates; the
//     requester DELEGATED → the agent; a live certificate GRANTS_ACCESS → the
//     tools its scopes name
//   - API tokens, machine
//     sessions              → credentials HOLDS'd by their subject, GRANTS_ACCESS → the trstctl API
//   - PAM sessions          → credentials HOLDS'd by the requester and the attested
//     workload, GRANTS_ACCESS → the database or host, APPROVED by each approver
//   - dynamic-secret leases → credentials GRANTS_ACCESS → the provider's backend
//   - issuance requests     → APPROVED from the decider to the issued identity
//
// A subject that is neither a member nor an AI agent becomes a workload node
// "principal:<subject>", so a token or session is never left without a holder.

const (
	trstctlAPIResource  = "res:trstctl-api"
	confidenceAuthority = "authoritative"
)

// principalIndex resolves an authenticated subject to its graph node.
type principalIndex map[string]string

func (p principalIndex) node(g *Graph, subject string) string {
	if id, ok := p[subject]; ok {
		return id
	}
	id := "principal:" + subject
	g.AddNode(Node{ID: id, Kind: KindWorkload, Name: subject, Attrs: map[string]string{
		"principal": subject, "resolved_as": "not a tenant member or AI agent",
	}})
	p[subject] = id
	return id
}

func addAccessSources(ctx context.Context, st *store.Store, tenantID string, g *Graph, certs []store.Certificate, now time.Time) error {
	principals := principalIndex{}
	if err := addPeopleAndRoles(ctx, st, tenantID, g, principals); err != nil {
		return err
	}
	addAIAgents(g, certs, principals, now)
	for _, add := range []func(context.Context, *store.Store, string, *Graph, principalIndex, time.Time) error{
		addAPITokens, addMachineSessions, addPAMAccess, addDynamicSecretLeases, addIssuanceApprovals,
	} {
		if err := add(ctx, st, tenantID, g, principals, now); err != nil {
			return err
		}
	}
	return nil
}

func addPeopleAndRoles(ctx context.Context, st *store.Store, tenantID string, g *Graph, principals principalIndex) error {
	for after := ""; ; {
		page, err := st.ListTenantMembersPage(ctx, tenantID, after, true, pageSize)
		if err != nil {
			return err
		}
		for _, m := range page {
			id := "person:" + m.Subject
			g.AddNode(Node{ID: id, Kind: KindPerson, Name: firstNonEmpty(m.DisplayName, m.Subject), Attrs: map[string]string{
				"subject": m.Subject, "status": m.Status, "source": m.Source,
			}})
			principals[m.Subject] = id
			if m.OffboardedAt != nil {
				continue
			}
			for _, role := range m.Roles {
				g.AddNode(Node{ID: "role:" + role, Kind: KindRole, Name: role})
				g.AddEdge(Edge{From: id, To: "role:" + role, Type: EdgeHasRole, Source: "tenant membership", Confidence: confidenceAuthority})
			}
		}
		if len(page) < pageSize {
			return nil
		}
		after = page[len(page)-1].Subject
	}
}

// addAIAgents names the agent behind every broker-issued certificate. The
// broker records the agent ID and the attested subject it verified, so either
// one presented later as an authenticated subject resolves to the same agent.
// Every agent is registered before any edge is drawn, so a requester that is
// itself an agent resolves to that agent. The principal who asked for the
// identity DELEGATED to the agent (Q4), and a live credential reaches the
// resources its scopes name.
func addAIAgents(g *Graph, certs []store.Certificate, principals principalIndex, now time.Time) {
	for _, c := range certs {
		issuance := c.BrokerIssuance
		if issuance == nil || issuance.AgentID == "" {
			continue
		}
		id := "aiagent:" + issuance.AgentID
		if _, ok := g.Node(id); !ok {
			g.AddNode(Node{ID: id, Kind: KindAIAgent, Name: issuance.AgentID, Attrs: map[string]string{
				"agent_id": issuance.AgentID, "subject": issuance.Subject,
				"attestation_method": issuance.Method, "owner_id": issuance.OwnerID,
			}})
		}
		for _, subject := range []string{issuance.AgentID, issuance.Subject} {
			if _, taken := principals[subject]; subject != "" && !taken {
				principals[subject] = id
			}
		}
	}
	for _, c := range certs {
		issuance := c.BrokerIssuance
		if issuance == nil || issuance.AgentID == "" {
			continue
		}
		id, cert := "aiagent:"+issuance.AgentID, credentialID("cert", c.ID)
		g.AddEdge(Edge{From: id, To: cert, Type: EdgeHolds, Source: "agent broker issuance", Confidence: confidenceAuthority})
		if issuance.RequestedBy != "" {
			if from := principals.node(g, issuance.RequestedBy); from != id {
				g.AddEdge(Edge{From: from, To: id, Type: EdgeDelegated, Source: "agent broker issuance requester", Confidence: confidenceAuthority})
			}
		}
		if c.Status != "active" || (c.NotAfter != nil && !c.NotAfter.After(now)) {
			continue
		}
		for _, scope := range issuance.Scopes {
			resource := agentScopeResource(g, scope)
			g.AddEdge(Edge{From: cert, To: resource, Type: EdgeGrantsAccess, Source: "agent broker scope", Confidence: confidenceAuthority})
		}
	}
}

// agentScopeResource is the resource a broker scope names: "tool:inventory.read"
// reaches the tool "tool:inventory" (the action stays an attribute of the
// scope). A scope without an action names itself.
func agentScopeResource(g *Graph, scope string) string {
	target := scope
	if dot := strings.LastIndexByte(scope, '.'); dot > strings.IndexByte(scope, ':') && dot > 0 {
		target = scope[:dot]
	}
	id := resourceID("agent-scope:" + target)
	if _, ok := g.Node(id); !ok {
		g.AddNode(Node{ID: id, Kind: KindResource, Name: target, Attrs: map[string]string{"resource_kind": "agent_scope"}})
	}
	return id
}

func ensureTrstctlAPI(g *Graph) {
	if _, ok := g.Node(trstctlAPIResource); !ok {
		g.AddNode(Node{ID: trstctlAPIResource, Kind: KindResource, Name: "trstctl API", Attrs: map[string]string{"resource_kind": "trstctl_api"}})
	}
}

func addAPITokens(ctx context.Context, st *store.Store, tenantID string, g *Graph, principals principalIndex, now time.Time) error {
	for after := store.ZeroUUID; ; {
		page, err := st.ListAPITokensPage(ctx, tenantID, after, "", false, pageSize)
		if err != nil {
			return err
		}
		for _, t := range page {
			if t.RevokedAt != nil || (t.ExpiresAt != nil && !t.ExpiresAt.After(now)) {
				continue
			}
			id := credentialID("token", t.ID)
			attrs := map[string]string{"credential_kind": "api_token", "subject": t.Subject, "scopes": strings.Join(t.Scopes, " ")}
			if t.ExpiresAt != nil {
				attrs["expires_at"] = t.ExpiresAt.UTC().Format(time.RFC3339)
			}
			g.AddNode(Node{ID: id, Kind: KindCredential, Name: "API token for " + t.Subject, Attrs: attrs})
			g.AddEdge(Edge{From: principals.node(g, t.Subject), To: id, Type: EdgeHolds, Source: "API token subject", Confidence: confidenceAuthority})
			ensureTrstctlAPI(g)
			g.AddEdge(Edge{From: id, To: trstctlAPIResource, Type: EdgeGrantsAccess, Source: "API token scopes", Confidence: confidenceAuthority})
		}
		if len(page) < pageSize {
			return nil
		}
		after = page[len(page)-1].ID
	}
}

func addMachineSessions(ctx context.Context, st *store.Store, tenantID string, g *Graph, principals principalIndex, now time.Time) error {
	for after := ""; ; {
		page, err := st.ListMachineSessionsAfter(ctx, tenantID, after, pageSize)
		if err != nil {
			return err
		}
		for _, m := range page {
			if m.Status != store.MachineSessionStatusActive || m.RevokedAt != nil || !m.ExpiresAt.After(now) {
				continue
			}
			id := credentialID("msession", m.ID)
			g.AddNode(Node{ID: id, Kind: KindCredential, Name: "machine session for " + m.Principal, Attrs: map[string]string{
				"credential_kind": "machine_session", "subject": m.Principal, "method": m.Method,
				"scopes": strings.Join(m.Scopes, " "), "expires_at": m.ExpiresAt.UTC().Format(time.RFC3339),
			}})
			g.AddEdge(Edge{From: principals.node(g, m.Principal), To: id, Type: EdgeHolds, Source: "machine session principal", Confidence: confidenceAuthority})
			ensureTrstctlAPI(g)
			g.AddEdge(Edge{From: id, To: trstctlAPIResource, Type: EdgeGrantsAccess, Source: "machine session scopes", Confidence: confidenceAuthority})
		}
		if len(page) < pageSize {
			return nil
		}
		after = page[len(page)-1].ID
	}
}

func pamTargetResourceID(targetType, targetID string) string {
	return resourceID("pam:" + targetType + ":" + targetID)
}

// addPAMAccess links each live PAM session to the database or host it grants,
// the principal who requested it, the workload it was attested to and the
// people who approved its activation.
func addPAMAccess(ctx context.Context, st *store.Store, tenantID string, g *Graph, principals principalIndex, now time.Time) error {
	targets, err := st.ListPAMTargets(ctx, tenantID)
	if err != nil {
		return err
	}
	for _, t := range targets {
		id := pamTargetResourceID(t.TargetType, t.ID)
		g.AddNode(Node{ID: id, Kind: KindResource, Name: t.ID, Attrs: map[string]string{
			"resource_kind": "pam_target", "target_type": t.TargetType, "host": t.Host,
			"provider_id": t.ProviderID, "enabled": boolString(t.Enabled),
		}})
		if t.TargetType == "postgres" && t.ProviderID != "" {
			ensureDynamicSecretBackend(g, t.ProviderID)
			g.AddEdge(Edge{From: id, To: resourceID("dynamic-secret:" + t.ProviderID), Type: EdgeConnectsTo, Source: "PAM target provider reference", Confidence: confidenceAuthority})
		}
	}
	for after := ""; ; {
		page, err := st.ListLivePAMSessionAccessPage(ctx, tenantID, now, after, pageSize)
		if err != nil {
			return err
		}
		var approvalIDs []string
		for _, s := range page {
			if s.ApprovalRequestID != "" {
				approvalIDs = append(approvalIDs, s.ApprovalRequestID)
			}
		}
		approvers, err := st.OperationApprovalApprovers(ctx, tenantID, approvalIDs)
		if err != nil {
			return err
		}
		for _, s := range page {
			addPAMSession(g, principals, s, approvers[s.ApprovalRequestID])
		}
		if len(page) < pageSize {
			return nil
		}
		after = page[len(page)-1].ID
	}
}

func addPAMSession(g *Graph, principals principalIndex, s store.PAMSessionAccess, approvers []string) {
	id := credentialID("pam", s.ID)
	g.AddNode(Node{ID: id, Kind: KindCredential, Name: s.Role + "@" + s.TargetID, Attrs: map[string]string{
		"credential_kind": "pam_session", "target_type": s.TargetType, "role": s.Role, "status": s.Status,
		"expires_at": s.ExpiresAt.UTC().Format(time.RFC3339), "approval_recorded": boolString(s.ApprovalRequestID != ""),
	}})
	target := pamTargetResourceID(s.TargetType, s.TargetID)
	if _, ok := g.Node(target); !ok {
		// A target from static configuration has no registered row; the session
		// still names it exactly.
		g.AddNode(Node{ID: target, Kind: KindResource, Name: s.TargetID, Attrs: map[string]string{
			"resource_kind": "pam_target", "target_type": s.TargetType,
		}})
	}
	g.AddEdge(Edge{From: id, To: target, Type: EdgeGrantsAccess, Source: "PAM session grant", Confidence: confidenceAuthority})
	if s.RequestedBy != "" {
		g.AddEdge(Edge{From: principals.node(g, s.RequestedBy), To: id, Type: EdgeHolds, Source: "PAM session requester", Confidence: confidenceAuthority})
	}
	if s.Subject != "" && s.Subject != s.RequestedBy {
		g.AddEdge(Edge{From: principals.node(g, s.Subject), To: id, Type: EdgeHolds, Source: "PAM session attested workload", Confidence: confidenceAuthority})
	}
	for _, approver := range approvers {
		g.AddEdge(Edge{From: principals.node(g, approver), To: id, Type: EdgeApproved, Source: "PAM approval decision", Confidence: confidenceAuthority})
	}
}

func ensureDynamicSecretBackend(g *Graph, provider string) {
	id := resourceID("dynamic-secret:" + provider)
	if _, ok := g.Node(id); !ok {
		g.AddNode(Node{ID: id, Kind: KindResource, Name: provider, Attrs: map[string]string{"resource_kind": "dynamic_secret_backend", "provider": provider}})
	}
}

// addDynamicSecretLeases adds each active lease and the backend it reaches. A
// lease does not record who requested it (only a non-reversible binding
// digest), so it carries holder_recorded=false rather than a guessed holder.
func addDynamicSecretLeases(ctx context.Context, st *store.Store, tenantID string, g *Graph, _ principalIndex, now time.Time) error {
	for after := ""; ; {
		page, err := st.ListDynamicSecretLeasesPage(ctx, tenantID, "", store.DynamicSecretLeaseActive, after, pageSize)
		if err != nil {
			return err
		}
		for _, l := range page {
			if !l.ExpiresAt.After(now) {
				continue
			}
			id := credentialID("lease", l.ID)
			g.AddNode(Node{ID: id, Kind: KindCredential, Name: l.Role + "@" + l.Provider, Attrs: map[string]string{
				"credential_kind": "dynamic_secret_lease", "provider": l.Provider, "role": l.Role,
				"expires_at": l.ExpiresAt.UTC().Format(time.RFC3339), "holder_recorded": "false",
			}})
			ensureDynamicSecretBackend(g, l.Provider)
			g.AddEdge(Edge{From: id, To: resourceID("dynamic-secret:" + l.Provider), Type: EdgeGrantsAccess, Source: "dynamic-secret lease", Confidence: confidenceAuthority})
		}
		if len(page) < pageSize {
			return nil
		}
		after = page[len(page)-1].ID
	}
}

// addIssuanceApprovals links the person who approved an issuance request to
// the identity it issued.
func addIssuanceApprovals(ctx context.Context, st *store.Store, tenantID string, g *Graph, principals principalIndex, _ time.Time) error {
	for after := ""; ; {
		page, err := st.ListIssuanceRequestsAfter(ctx, tenantID, "issued", after, pageSize)
		if err != nil {
			return err
		}
		for _, r := range page {
			identity := credentialID("id", r.IdentityID)
			if _, ok := g.Node(identity); !ok || r.DecidedBy == "" {
				continue
			}
			g.AddEdge(Edge{From: principals.node(g, r.DecidedBy), To: identity, Type: EdgeApproved, Source: "issuance request decision", Confidence: confidenceAuthority})
		}
		if len(page) < pageSize {
			return nil
		}
		after = page[len(page)-1].ID
	}
}

func boolString(v bool) string {
	if v {
		return "true"
	}
	return "false"
}
