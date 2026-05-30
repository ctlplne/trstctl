package risk

import (
	"context"
	"sort"
	"strings"
	"time"

	"certctl.io/certctl/internal/graph"
	"certctl.io/certctl/internal/store"
)

// pageSize bounds each keyset page when reading the certificate inventory.
const pageSize = 500

// CredentialRisk is one scored credential, ready to sort, filter, and serve.
type CredentialRisk struct {
	CredentialID string         `json:"credential_id"`
	Subject      string         `json:"subject"`
	Kind         string         `json:"kind"`
	Privilege    PrivilegeClass `json:"privilege"`
	Sensitivity  Sensitivity    `json:"sensitivity"`
	Exposure     int            `json:"exposure"`
	OwnerActive  bool           `json:"owner_active"`
	ExpiresAt    time.Time      `json:"expires_at"`
	Score        float64        `json:"score"`
	Components   Components     `json:"components"`
}

// ScoreInventory builds the tenant's credential graph (F21) and scores every
// certificate in the inventory, returning them ranked by score descending. Reads
// are tenant-scoped through the store (AN-1).
func ScoreInventory(ctx context.Context, st *store.Store, tenantID string) ([]CredentialRisk, error) {
	g, err := graph.Build(ctx, st, tenantID)
	if err != nil {
		return nil, err
	}
	now := time.Now()

	var out []CredentialRisk
	after := store.ZeroUUID
	for {
		page, err := st.ListCertificatesPage(ctx, tenantID, after, pageSize, nil)
		if err != nil {
			return nil, err
		}
		for _, c := range page {
			out = append(out, scoreCertificate(g, c, now))
		}
		if len(page) < pageSize {
			break
		}
		after = page[len(page)-1].ID
	}

	SortByScore(out)
	return out, nil
}

// scoreCertificate derives a certificate's signals (exposure from the graph, the
// rest from the inventory row) and scores it.
func scoreCertificate(g *graph.Graph, c store.Certificate, now time.Time) CredentialRisk {
	exposure := credentialExposure(g, "cert:"+c.ID)
	priv := inferPrivilege(c, exposure)
	sens := inferSensitivity(c)
	ownerActive := c.OwnerID != nil && *c.OwnerID != ""

	sc := Compute(Signals{
		Now:         now,
		NotBefore:   deref(c.NotBefore),
		NotAfter:    deref(c.NotAfter),
		Exposure:    exposure,
		Privilege:   priv,
		LastRotated: deref(c.RenewedAt),
		OwnerActive: ownerActive,
		Sensitivity: sens,
	})
	return CredentialRisk{
		CredentialID: c.ID, Subject: c.Subject, Kind: "certificate",
		Privilege: priv, Sensitivity: sens, Exposure: exposure,
		OwnerActive: ownerActive, ExpiresAt: deref(c.NotAfter),
		Score: sc.Total, Components: sc.Components,
	}
}

// credentialExposure counts the resources reachable from a credential node in
// the graph — its deployment-and-access footprint.
func credentialExposure(g *graph.Graph, nodeID string) int {
	return len(g.BlastRadius(nodeID).ByKind[graph.KindResource])
}

// inferPrivilege derives a privilege class: a wildcard certificate or one that
// reaches many resources grants the most; a broadly-scoped one is standard.
func inferPrivilege(c store.Certificate, exposure int) PrivilegeClass {
	switch {
	case isWildcard(c) || exposure >= 8:
		return PrivilegeHigh
	case len(c.SANs) > 3 || exposure >= 2:
		return PrivilegeStandard
	default:
		return PrivilegeLow
	}
}

// inferSensitivity infers sensitivity from a certificate's names: a wildcard
// covers a whole namespace (high); several names is medium.
func inferSensitivity(c store.Certificate) Sensitivity {
	switch {
	case isWildcard(c):
		return SensitivityHigh
	case len(c.SANs) > 1:
		return SensitivityMedium
	default:
		return SensitivityLow
	}
}

func isWildcard(c store.Certificate) bool {
	if strings.Contains(c.Subject, "*.") {
		return true
	}
	for _, s := range c.SANs {
		if strings.HasPrefix(s, "*.") {
			return true
		}
	}
	return false
}

func deref(t *time.Time) time.Time {
	if t == nil {
		return time.Time{}
	}
	return *t
}

// SortByScore orders credentials by score descending, ties broken by id.
func SortByScore(rs []CredentialRisk) {
	sort.Slice(rs, func(i, j int) bool {
		if rs[i].Score != rs[j].Score {
			return rs[i].Score > rs[j].Score
		}
		return rs[i].CredentialID < rs[j].CredentialID
	})
}

// SortByExpiry orders credentials by soonest expiry first; credentials with no
// expiry sort last.
func SortByExpiry(rs []CredentialRisk) {
	sort.Slice(rs, func(i, j int) bool {
		ei, ej := rs[i].ExpiresAt, rs[j].ExpiresAt
		if ei.IsZero() != ej.IsZero() {
			return !ei.IsZero()
		}
		if !ei.Equal(ej) {
			return ei.Before(ej)
		}
		return rs[i].CredentialID < rs[j].CredentialID
	})
}

// Filter narrows a scored list.
type Filter struct {
	MinScore     float64
	MinPrivilege *PrivilegeClass
	OwnerActive  *bool
}

// Apply returns the credentials matching the filter, preserving order.
func (f Filter) Apply(rs []CredentialRisk) []CredentialRisk {
	out := make([]CredentialRisk, 0, len(rs))
	for _, r := range rs {
		if r.Score < f.MinScore {
			continue
		}
		if f.MinPrivilege != nil && r.Privilege < *f.MinPrivilege {
			continue
		}
		if f.OwnerActive != nil && r.OwnerActive != *f.OwnerActive {
			continue
		}
		out = append(out, r)
	}
	return out
}
