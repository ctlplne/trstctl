// SPDX-License-Identifier: BUSL-1.1

package graph

import (
	"testing"

	"trstctl.com/trstctl/internal/store"
)

// G1-L4: the secret store joins the access graph at the scope reads are
// decided. A role someone holds that grants secrets:read, and a live token
// whose scopes do, CAN_READ the store's root and every open environment; a
// restricted environment is read only by a member granted it who also holds
// secrets:read (by a role, or a token acting for the member); its names are
// never listed, while each open scope CONTAINS its secrets. A role nobody
// holds draws nothing, and a member without secrets:read reads nothing.
func TestSecretScopesShowWhoMayReadG1L4(t *testing.T) {
	g := New()
	principals := principalIndex{}
	person := func(subject string, roles ...string) {
		id := "person:" + subject
		g.AddNode(Node{ID: id, Kind: KindPerson, Name: subject})
		principals[subject] = id
		for _, r := range roles {
			g.AddNode(Node{ID: "role:" + r, Kind: KindRole, Name: r})
			g.AddEdge(Edge{From: id, To: "role:" + r, Type: EdgeHasRole})
		}
	}
	person("ana", "operator")       // reads by role
	person("ben", "viewer")         // no secrets:read
	person("cy", "viewer", "vault") // reads by a custom role
	person("dee", "viewer")         // a member without secrets:read
	g.AddNode(Node{ID: "token:t1", Kind: KindCredential})
	g.AddNode(Node{ID: "token:t2", Kind: KindCredential})
	in := secretReaders{
		readerRoles: map[string]bool{"operator": true, "admin": true, "vault": true},
		environments: []store.SecretProjectEnvironment{
			{Project: "orders", Slug: "dev"}, {Project: "orders", Slug: "prod", Restricted: true},
		},
		members: map[string][]store.SecretProjectMember{"orders": {
			{Project: "orders", Subject: "ana", Role: "admin", Environments: []string{"prod"}},
			{Project: "orders", Subject: "cy", Role: "viewer", Environments: []string{"dev"}},
			{Project: "orders", Subject: "dee", Role: "admin"},
			{Project: "orders", Subject: "ci-bot", Role: "developer"},
		}},
		secrets: []store.Secret{{Name: "orders/dev/db/password", Version: 3}, {Name: "legacy-api-key", Version: 1}},
		readers: []secretReaderCredential{{id: "token:t1", subject: "ci-bot"}, {id: "token:t2", subject: "someone-else"}},
	}
	addSecretScopes(g, principals, in)

	dev, prod := secretScopeID("orders", "dev"), secretScopeID("orders", "prod")
	has := func(from, to string, typ EdgeType) bool {
		for _, e := range g.edges {
			if e.From == from && e.To == to && e.Type == typ {
				return true
			}
		}
		return false
	}
	want := [][3]string{
		{secretStoreRoot, credentialID("secret", "legacy-api-key"), string(EdgeContains)},
		{dev, credentialID("secret", "orders/dev/db/password"), string(EdgeContains)},
		{"role:operator", secretStoreRoot, string(EdgeCanRead)},
		{"role:operator", dev, string(EdgeCanRead)},
		{"role:vault", dev, string(EdgeCanRead)},
		{"token:t1", dev, string(EdgeCanRead)},
		{"token:t2", secretStoreRoot, string(EdgeCanRead)},
		{"person:ana", prod, string(EdgeCanRead)}, // member granted prod, operator role
		{"token:t1", prod, string(EdgeCanRead)},   // ci-bot is a member of every environment
	}
	for _, w := range want {
		if !has(w[0], w[1], EdgeType(w[2])) {
			t.Fatalf("missing %s -%s-> %s", w[0], w[2], w[1])
		}
	}
	notWant := [][3]string{
		{"role:operator", prod, string(EdgeCanRead)}, // a role alone never reads a restricted environment
		{"role:viewer", dev, string(EdgeCanRead)},
		{"role:admin", dev, string(EdgeCanRead)},  // nobody holds admin here
		{"person:cy", prod, string(EdgeCanRead)},  // granted dev only
		{"person:dee", prod, string(EdgeCanRead)}, // a member without secrets:read
		{"token:t2", prod, string(EdgeCanRead)},   // its subject is no member
	}
	for _, w := range notWant {
		if has(w[0], w[1], EdgeType(w[2])) {
			t.Fatalf("unexpected %s -%s-> %s", w[0], w[2], w[1])
		}
	}
	n, ok := g.Node(prod)
	if !ok || n.Attrs["restricted"] != "true" {
		t.Fatalf("restricted scope = %+v", n)
	}
	for _, e := range g.edges {
		if e.From == prod && e.Type == EdgeContains {
			t.Fatalf("a restricted environment listed %s", e.To)
		}
	}
}
