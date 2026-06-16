package risk

import (
	"testing"
	"time"

	"trstctl.com/trstctl/internal/graph"
	"trstctl.com/trstctl/internal/store"
)

func tptr(t time.Time) *time.Time { return &t }
func sptr(s string) *string       { return &s }

// exposureGraph: cert c1 is deployed to three resources; cert c2 to none.
func exposureGraph() *graph.Graph {
	g := graph.New()
	g.AddNode(graph.Node{ID: "cert:c1", Kind: graph.KindCredential})
	for _, r := range []string{"res:a", "res:b", "res:c"} {
		g.AddNode(graph.Node{ID: r, Kind: graph.KindResource})
		g.AddEdge(graph.Edge{From: "cert:c1", To: r, Type: graph.EdgeDeployedTo})
	}
	g.AddNode(graph.Node{ID: "cert:c2", Kind: graph.KindCredential})
	return g
}

func TestCredentialExposureCountsResources(t *testing.T) {
	g := exposureGraph()
	if got := credentialExposure(g, "cert:c1"); got != 3 {
		t.Errorf("exposure(c1) = %d, want 3", got)
	}
	if got := credentialExposure(g, "cert:c2"); got != 0 {
		t.Errorf("exposure(c2) = %d, want 0", got)
	}
}

func TestInferPrivilege(t *testing.T) {
	wild := store.Certificate{Subject: "CN=*.example.com"}
	if got := inferPrivilege(wild, 0); got != PrivilegeHigh {
		t.Errorf("wildcard privilege = %v, want High", got)
	}
	if got := inferPrivilege(store.Certificate{Subject: "CN=svc"}, 9); got != PrivilegeHigh {
		t.Errorf("high-exposure privilege = %v, want High", got)
	}
	broad := store.Certificate{Subject: "CN=svc", SANs: []string{"a", "b", "c", "d"}}
	if got := inferPrivilege(broad, 0); got != PrivilegeStandard {
		t.Errorf("many-SAN privilege = %v, want Standard", got)
	}
	if got := inferPrivilege(store.Certificate{Subject: "CN=svc"}, 0); got != PrivilegeLow {
		t.Errorf("plain privilege = %v, want Low", got)
	}
}

func TestInferSensitivity(t *testing.T) {
	if got := inferSensitivity(store.Certificate{SANs: []string{"*.example.com"}}); got != SensitivityHigh {
		t.Errorf("wildcard sensitivity = %v, want High", got)
	}
	if got := inferSensitivity(store.Certificate{SANs: []string{"a", "b"}}); got != SensitivityMedium {
		t.Errorf("multi-name sensitivity = %v, want Medium", got)
	}
	if got := inferSensitivity(store.Certificate{SANs: []string{"a"}}); got != SensitivityLow {
		t.Errorf("single-name sensitivity = %v, want Low", got)
	}
}

// A certificate reaching resources in the graph scores higher than an otherwise
// identical one reaching none — exposure flows from the F21 graph.
func TestScoreCertificateUsesGraphExposure(t *testing.T) {
	g := exposureGraph()
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	mk := func(id string) store.Certificate {
		return store.Certificate{
			ID: id, Subject: "CN=svc", OwnerID: sptr("owner-1"),
			NotBefore: tptr(now.Add(-100 * time.Hour)), NotAfter: tptr(now.Add(900 * time.Hour)),
			RenewedAt: tptr(now.Add(-24 * time.Hour)),
		}
	}
	exposed := scoreCertificate(g, mk("c1"), now)
	isolated := scoreCertificate(g, mk("c2"), now)

	if exposed.Exposure != 3 || isolated.Exposure != 0 {
		t.Fatalf("exposure: c1=%d c2=%d, want 3/0", exposed.Exposure, isolated.Exposure)
	}
	if !(exposed.Score > isolated.Score) {
		t.Errorf("exposed score %.2f should exceed isolated %.2f", exposed.Score, isolated.Score)
	}
	if exposed.Kind != "certificate" {
		t.Errorf("kind = %q", exposed.Kind)
	}
}

func TestSortByScoreDescending(t *testing.T) {
	rs := []CredentialRisk{{CredentialID: "a", Score: 10}, {CredentialID: "b", Score: 90}, {CredentialID: "c", Score: 50}}
	SortByScore(rs)
	if rs[0].CredentialID != "b" || rs[1].CredentialID != "c" || rs[2].CredentialID != "a" {
		t.Errorf("sort by score = %v", []string{rs[0].CredentialID, rs[1].CredentialID, rs[2].CredentialID})
	}
}

func TestSortByExpirySoonestFirst(t *testing.T) {
	now := time.Now()
	rs := []CredentialRisk{
		{CredentialID: "late", ExpiresAt: now.Add(100 * time.Hour)},
		{CredentialID: "none"},
		{CredentialID: "soon", ExpiresAt: now.Add(1 * time.Hour)},
	}
	SortByExpiry(rs)
	if rs[0].CredentialID != "soon" || rs[1].CredentialID != "late" || rs[2].CredentialID != "none" {
		t.Errorf("sort by expiry = %v", []string{rs[0].CredentialID, rs[1].CredentialID, rs[2].CredentialID})
	}
}

func TestFilterApply(t *testing.T) {
	high := PrivilegeHigh
	active := true
	rs := []CredentialRisk{
		{CredentialID: "a", Score: 80, Privilege: PrivilegeHigh, OwnerActive: false},
		{CredentialID: "b", Score: 40, Privilege: PrivilegeLow, OwnerActive: true},
		{CredentialID: "c", Score: 90, Privilege: PrivilegeCritical, OwnerActive: true},
	}
	if got := (Filter{MinScore: 50}).Apply(rs); len(got) != 2 {
		t.Errorf("min-score filter kept %d, want 2", len(got))
	}
	if got := (Filter{MinPrivilege: &high}).Apply(rs); len(got) != 2 {
		t.Errorf("min-privilege filter kept %d, want 2 (High, Critical)", len(got))
	}
	if got := (Filter{OwnerActive: &active}).Apply(rs); len(got) != 2 {
		t.Errorf("owner-active filter kept %d, want 2", len(got))
	}
}
