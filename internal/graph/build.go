package graph

import (
	"context"
	"strconv"

	"trstctl.com/trstctl/internal/store"
)

// pageSize bounds each keyset page when reading the paginated inventory tables.
const pageSize = 500

// Build constructs the credential graph for a tenant from its inventory. The
// mapping (F21):
//
//   - owners            → workload nodes      (the principals that hold credentials)
//   - issuers           → issuer nodes        (CAs and other authorities)
//   - identities/certs/
//     SSH keys          → credential nodes
//   - deployment targets
//     and locations     → resource nodes      (where credentials live or grant access)
//
// Edges are oriented for blast-radius analysis (impact flows From→To):
// issuer──ISSUED──▶credential, workload──OWNS──▶credential,
// credential──DEPLOYED_TO──▶resource, and credential──GRANTS_ACCESS──▶resource
// for standing SSH access. Certificate issuance is linked best-effort by issuer
// name; identities carry a real issuer foreign key.
//
// Every read is tenant-scoped through the store (AN-1); the graph never spans
// tenants.
func Build(ctx context.Context, st *store.Store, tenantID string) (*Graph, error) {
	g := New()

	owners, err := st.ListOwners(ctx, tenantID)
	if err != nil {
		return nil, err
	}
	for _, o := range owners {
		g.AddNode(Node{
			ID:    workloadID(o.ID),
			Kind:  KindWorkload,
			Name:  o.Name,
			Attrs: map[string]string{"owner_kind": string(o.Kind)},
		})
	}

	issuers, err := st.ListIssuers(ctx, tenantID)
	if err != nil {
		return nil, err
	}
	issuerByName := make(map[string]string, len(issuers)) // issuer name → node ID
	for _, is := range issuers {
		nid := issuerID(is.ID)
		g.AddNode(Node{
			ID:    nid,
			Kind:  KindIssuer,
			Name:  is.Name,
			Attrs: map[string]string{"issuer_kind": string(is.Kind)},
		})
		issuerByName[is.Name] = nid
	}

	// Deployment targets first, so their richer attributes win over the bare
	// resource nodes synthesized from credential locations below.
	targets, err := st.ListDeploymentTargets(ctx, tenantID)
	if err != nil {
		return nil, err
	}
	for _, t := range targets {
		g.AddNode(Node{
			ID:    resourceID(t.Name),
			Kind:  KindResource,
			Name:  t.Name,
			Attrs: map[string]string{"target_type": t.Type, "target_id": t.ID},
		})
	}

	// Identities carry real owner and issuer foreign keys.
	idents, err := st.ListIdentities(ctx, tenantID)
	if err != nil {
		return nil, err
	}
	for _, it := range idents {
		nid := credentialID("id", it.ID)
		g.AddNode(Node{
			ID:    nid,
			Kind:  KindCredential,
			Name:  it.Name,
			Attrs: map[string]string{"credential_kind": string(it.Kind), "status": it.Status},
		})
		if it.OwnerID != "" {
			g.AddEdge(Edge{From: workloadID(it.OwnerID), To: nid, Type: EdgeOwns})
		}
		if it.IssuerID != nil {
			g.AddEdge(Edge{From: issuerID(*it.IssuerID), To: nid, Type: EdgeIssued})
		}
	}

	certs, err := allCertificates(ctx, st, tenantID)
	if err != nil {
		return nil, err
	}
	for _, c := range certs {
		nid := credentialID("cert", c.ID)
		g.AddNode(Node{
			ID:    nid,
			Kind:  KindCredential,
			Name:  c.Subject,
			Attrs: map[string]string{"fingerprint": c.Fingerprint, "status": c.Status, "serial": c.Serial},
		})
		if c.OwnerID != nil {
			g.AddEdge(Edge{From: workloadID(*c.OwnerID), To: nid, Type: EdgeOwns})
		}
		if c.DeploymentLocation != "" {
			ensureResource(g, c.DeploymentLocation)
			g.AddEdge(Edge{From: nid, To: resourceID(c.DeploymentLocation), Type: EdgeDeployedTo})
		}
		if isID, ok := issuerByName[c.Issuer]; ok {
			g.AddEdge(Edge{From: isID, To: nid, Type: EdgeIssued})
		}
	}

	keys, err := allSSHKeys(ctx, st, tenantID)
	if err != nil {
		return nil, err
	}
	for _, k := range keys {
		nid := credentialID("ssh", k.ID)
		name := k.Comment
		if name == "" {
			name = k.Fingerprint
		}
		g.AddNode(Node{
			ID:   nid,
			Kind: KindCredential,
			Name: name,
			Attrs: map[string]string{
				"key_type":        k.KeyType,
				"fingerprint":     k.Fingerprint,
				"source":          k.Source,
				"standing_access": strconv.FormatBool(k.StandingAccess),
				"orphaned":        strconv.FormatBool(k.Orphaned),
			},
		})
		if k.Location != "" {
			ensureResource(g, k.Location)
			edge := EdgeDeployedTo
			if k.StandingAccess {
				edge = EdgeGrantsAccess
			}
			g.AddEdge(Edge{From: nid, To: resourceID(k.Location), Type: edge})
		}
	}

	// Cryptographic assets from the CBOM (F52): each observed crypto usage is a
	// node, linked to the resource that exhibits it.
	assets, err := st.ListCryptoAssets(ctx, tenantID)
	if err != nil {
		return nil, err
	}
	for _, a := range assets {
		nid := "crypto:" + a.ID
		name := firstNonEmpty(a.Algorithm, a.Protocol, a.Cipher)
		g.AddNode(Node{
			ID:   nid,
			Kind: KindCryptoAsset,
			Name: name,
			Attrs: map[string]string{
				"asset_kind":         a.Kind,
				"location":           a.Location,
				"algorithm":          a.Algorithm,
				"protocol":           a.Protocol,
				"cipher":             a.Cipher,
				"strength":           a.Strength,
				"quantum_vulnerable": strconv.FormatBool(a.QuantumVulnerable),
				"out_of_policy":      strconv.FormatBool(a.OutOfPolicy),
			},
		})
		if a.Location != "" {
			ensureResource(g, a.Location)
			g.AddEdge(Edge{From: resourceID(a.Location), To: nid, Type: EdgeExhibits})
		}
	}

	return g, nil
}

// firstNonEmpty returns the first non-empty string, or "".
func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if v != "" {
			return v
		}
	}
	return ""
}

func workloadID(id string) string           { return "wl:" + id }
func issuerID(id string) string             { return "iss:" + id }
func resourceID(loc string) string          { return "res:" + loc }
func credentialID(prefix, id string) string { return prefix + ":" + id }

// ensureResource adds a resource node for a credential location only if one is
// not already present (so a deployment target's richer node is not clobbered).
func ensureResource(g *Graph, loc string) {
	id := resourceID(loc)
	if _, ok := g.Node(id); !ok {
		g.AddNode(Node{ID: id, Kind: KindResource, Name: loc})
	}
}

// allCertificates reads every certificate for the tenant by paging the keyset.
func allCertificates(ctx context.Context, st *store.Store, tenantID string) ([]store.Certificate, error) {
	var out []store.Certificate
	after := store.ZeroUUID
	for {
		page, err := st.ListCertificatesPage(ctx, tenantID, after, nil, pageSize, nil)
		if err != nil {
			return nil, err
		}
		out = append(out, page...)
		if len(page) < pageSize {
			return out, nil
		}
		after = page[len(page)-1].ID
	}
}

// allSSHKeys reads every SSH key for the tenant by paging the keyset.
func allSSHKeys(ctx context.Context, st *store.Store, tenantID string) ([]store.SSHKey, error) {
	var out []store.SSHKey
	after := store.ZeroUUID
	for {
		page, err := st.ListSSHKeysPage(ctx, tenantID, after, pageSize)
		if err != nil {
			return nil, err
		}
		out = append(out, page...)
		if len(page) < pageSize {
			return out, nil
		}
		after = page[len(page)-1].ID
	}
}
