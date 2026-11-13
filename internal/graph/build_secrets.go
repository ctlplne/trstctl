// SPDX-License-Identifier: BUSL-1.1

package graph

import (
	"context"
	"slices"
	"strconv"
	"strings"
	"time"

	"trstctl.com/trstctl/internal/authz"
	"trstctl.com/trstctl/internal/store"
)

// The secret store in the access graph (G1-L4). Who may read a stored secret
// is permission resolution: a principal holding secrets:read — through a
// built-in or custom role, an API token's scopes or a machine session's —
// reads every secret outside a restricted environment, and a restricted
// environment only when it is also a project member granted that
// environment. The graph draws that at the scope it is decided: one node per
// secrets-project environment and one for the store's names in no project,
// each CONTAINS the secrets in it, and each reader CAN_READ the scopes it may.
// A restricted environment's names are never listed (a denied read answers
// as no such secret, so names are not an existence oracle); its readers are.

// maxGraphSecrets bounds the secret names one graph lists; past it the root
// says it was cut short.
const maxGraphSecrets = 10000

// maxGraphSecretProjects bounds the projects one graph reads.
const maxGraphSecretProjects = 500

// secretStoreRoot is the scope of every secret name in no project.
const secretStoreRoot = "res:secret-store"

// secretReaders is what the graph reads about the secret store.
type secretReaders struct {
	// readerRoles are the role names whose permissions include secrets:read.
	readerRoles map[string]bool
	// environments are the secrets-project environments.
	environments []store.SecretProjectEnvironment
	// members are each project's members.
	members map[string][]store.SecretProjectMember
	// secrets are the names outside restricted environments.
	secrets   []store.Secret
	truncated bool
	// readers are the live credentials holding secrets:read, by graph node id,
	// with the subject each acts for.
	readers []secretReaderCredential
}

type secretReaderCredential struct {
	id, subject string
}

// readsSecrets reports whether a permission list grants secrets:read.
func readsSecrets(perms []string) bool {
	role := authz.Role{}
	for _, p := range perms {
		role.Permissions = append(role.Permissions, authz.Permission(p))
	}
	return role.Allows(authz.SecretsRead)
}

func loadSecretReaders(ctx context.Context, st *store.Store, tenantID string, now time.Time) (secretReaders, error) {
	in := secretReaders{readerRoles: map[string]bool{}, members: map[string][]store.SecretProjectMember{}}
	for name, role := range authz.BuiltinRoles() {
		if role.Allows(authz.SecretsRead) {
			in.readerRoles[name] = true
		}
	}
	custom, err := st.ListTenantCustomRoles(ctx, tenantID)
	if err != nil {
		return in, err
	}
	for _, role := range custom {
		if readsSecrets(role.Permissions) {
			in.readerRoles[role.Name] = true
		}
	}
	projects, err := st.ListSecretProjects(ctx, tenantID, maxGraphSecretProjects)
	if err != nil {
		return in, err
	}
	var hidden []string
	for _, p := range projects {
		_, envs, members, err := st.GetSecretProject(ctx, tenantID, p.Slug)
		if err != nil {
			return in, err
		}
		in.environments = append(in.environments, envs...)
		in.members[p.Slug] = members
		for _, e := range envs {
			if e.Restricted {
				hidden = append(hidden, e.Project+"/"+e.Slug+"/")
			}
		}
	}
	for after := ""; ; {
		page, err := st.ListSecretNamesAfter(ctx, tenantID, after, hidden, pageSize)
		if err != nil {
			return in, err
		}
		for _, s := range page {
			if len(in.secrets) == maxGraphSecrets {
				in.truncated = true
				break
			}
			in.secrets = append(in.secrets, s)
		}
		if in.truncated || len(page) < pageSize {
			break
		}
		after = page[len(page)-1].Name
	}
	for after := store.ZeroUUID; ; {
		page, err := st.ListAPITokensPage(ctx, tenantID, after, "", false, pageSize)
		if err != nil {
			return in, err
		}
		for _, t := range page {
			if t.RevokedAt == nil && (t.ExpiresAt == nil || t.ExpiresAt.After(now)) && readsSecrets(t.Scopes) {
				in.readers = append(in.readers, secretReaderCredential{id: credentialID("token", t.ID), subject: t.Subject})
			}
		}
		if len(page) < pageSize {
			break
		}
		after = page[len(page)-1].ID
	}
	for after := ""; ; {
		page, err := st.ListMachineSessionsAfter(ctx, tenantID, after, pageSize)
		if err != nil {
			return in, err
		}
		for _, m := range page {
			if m.Status == store.MachineSessionStatusActive && m.RevokedAt == nil && m.ExpiresAt.After(now) && readsSecrets(m.Scopes) {
				in.readers = append(in.readers, secretReaderCredential{id: credentialID("msession", m.ID), subject: m.Principal})
			}
		}
		if len(page) < pageSize {
			break
		}
		after = page[len(page)-1].ID
	}
	return in, nil
}

// secretScopeID is the node of one secrets-project environment.
func secretScopeID(project, environment string) string {
	return resourceID("secret-scope:" + project + "/" + environment)
}

// addSecretScopes draws the secret store's scopes, the secrets in the open
// ones and who may read each scope. A role draws its edges only when someone
// holds it (its node is already in the graph).
func addSecretScopes(g *Graph, principals principalIndex, in secretReaders) {
	var open []string
	restricted := map[string][]string{} // project → its restricted environments
	scopes := map[string]bool{}
	for _, e := range in.environments {
		id := secretScopeID(e.Project, e.Slug)
		attrs := map[string]string{"resource_kind": "secret_scope", "project": e.Project, "environment": e.Slug, "restricted": "false"}
		if e.Restricted {
			attrs["restricted"] = "true"
			attrs["secrets"] = "not listed: a restricted environment's names are shown only through the secrets API to its members"
			restricted[e.Project] = append(restricted[e.Project], e.Slug)
		} else {
			open = append(open, id)
		}
		g.AddNode(Node{ID: id, Kind: KindResource, Name: e.Project + "/" + e.Slug, Attrs: attrs})
		scopes[id] = true
	}
	for _, s := range in.secrets {
		scope := secretStoreRoot
		if parts := strings.SplitN(s.Name, "/", 3); len(parts) == 3 && scopes[secretScopeID(parts[0], parts[1])] {
			scope = secretScopeID(parts[0], parts[1])
		} else if !scopes[secretStoreRoot] {
			// The store's root appears once a name sits in no project.
			root := map[string]string{"resource_kind": "secret_scope", "scope": "names in no project", "secrets": "listed"}
			if in.truncated {
				root["secrets"] = "cut short at the graph's bound"
			}
			g.AddNode(Node{ID: secretStoreRoot, Kind: KindResource, Name: "secret store", Attrs: root})
			scopes[secretStoreRoot] = true
			open = append(open, secretStoreRoot)
		}
		id := credentialID("secret", s.Name)
		g.AddNode(Node{ID: id, Kind: KindCredential, Name: s.Name, Attrs: map[string]string{
			"credential_kind": "stored_secret", "version": strconv.Itoa(s.Version), "owner_id": s.OwnerID,
		}})
		g.AddEdge(Edge{From: scope, To: id, Type: EdgeContains, Source: "secret name", Confidence: confidenceAuthority})
	}
	if in.truncated && !scopes[secretStoreRoot] {
		g.AddNode(Node{ID: secretStoreRoot, Kind: KindResource, Name: "secret store", Attrs: map[string]string{
			"resource_kind": "secret_scope", "scope": "names in no project", "secrets": "cut short at the graph's bound"}})
		scopes[secretStoreRoot] = true
		open = append(open, secretStoreRoot)
	}
	// Open scopes: every role someone holds that grants secrets:read, and
	// every live token or machine session that does.
	var readerRoles []string
	for role := range in.readerRoles {
		if _, held := g.Node("role:" + role); held {
			readerRoles = append(readerRoles, role)
		}
	}
	slices.Sort(readerRoles)
	for _, role := range readerRoles {
		for _, scope := range open {
			g.AddEdge(Edge{From: "role:" + role, To: scope, Type: EdgeCanRead, Source: "role permissions (secrets:read)", Confidence: confidenceAuthority})
		}
	}
	for _, c := range in.readers {
		if _, ok := g.Node(c.id); !ok {
			continue
		}
		for _, scope := range open {
			g.AddEdge(Edge{From: c.id, To: scope, Type: EdgeCanRead, Source: "credential scopes (secrets:read)", Confidence: confidenceAuthority})
		}
	}
	// Restricted environments: a member granted the environment who also
	// holds secrets:read — through a role (a person) or a live credential
	// acting for the member's subject.
	readersBySubject := map[string][]string{}
	for _, c := range in.readers {
		readersBySubject[c.subject] = append(readersBySubject[c.subject], c.id)
	}
	projects := make([]string, 0, len(restricted))
	for project := range restricted {
		projects = append(projects, project)
	}
	slices.Sort(projects)
	for _, project := range projects {
		for _, m := range in.members[project] {
			for _, env := range restricted[project] {
				if len(m.Environments) > 0 && !slices.Contains(m.Environments, env) {
					continue
				}
				scope := secretScopeID(project, env)
				if personReads(g, principals, m.Subject, in.readerRoles) {
					g.AddEdge(Edge{From: principals[m.Subject], To: scope, Type: EdgeCanRead,
						Source: "project membership (" + m.Role + ") and role permissions (secrets:read)", Confidence: confidenceAuthority})
				}
				for _, id := range readersBySubject[m.Subject] {
					if _, ok := g.Node(id); ok {
						g.AddEdge(Edge{From: id, To: scope, Type: EdgeCanRead,
							Source: "project membership (" + m.Role + ") and credential scopes (secrets:read)", Confidence: confidenceAuthority})
					}
				}
			}
		}
	}
}

// personReads reports whether subject is a person holding a role that grants
// secrets:read.
func personReads(g *Graph, principals principalIndex, subject string, readerRoles map[string]bool) bool {
	id, ok := principals[subject]
	if !ok || !strings.HasPrefix(id, "person:") {
		return false
	}
	for _, e := range g.edges {
		if e.From == id && e.Type == EdgeHasRole && readerRoles[strings.TrimPrefix(e.To, "role:")] {
			return true
		}
	}
	return false
}
