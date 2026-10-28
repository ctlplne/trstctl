// SPDX-License-Identifier: BUSL-1.1

package reconcile_test

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/crypto/mtls"
	"trstctl.com/trstctl/internal/reconcile"
	"trstctl.com/trstctl/internal/reconcile/canon"
)

// ejbcaDouble is EJBCA's REST v2 certificate search over mutual TLS. It
// filters by the criteria the source sends (status, issued before, expiring
// after, CA name), answers the count-only mode, pages in expiry order and
// encodes base64Cert in two layers, as EJBCA 9.6.3 Community does.
type ejbcaDouble struct {
	t        *testing.T
	mu       sync.Mutex
	certs    []ejbcaDoubleCert
	requests []ejbcaDoubleRequest
	// dropOnPage leaves one certificate out of that page: a ledger that moved
	// between the count and the read.
	dropOnPage int
	httpStatus int
}

type ejbcaDoubleCert struct {
	der          []byte
	caName       string
	status       int
	reason       int
	listedSerial string
	// oneLayer sends base64 DER; EJBCA 9.6 sends base64 of the base64 text.
	oneLayer bool
}

type ejbcaDoubleRequest struct {
	Pagination struct {
		PageSize    int `json:"page_size"`
		CurrentPage int `json:"current_page"`
	} `json:"pagination"`
	Sort *struct {
		Property  string `json:"property"`
		Operation string `json:"operation"`
	} `json:"sort"`
	Criteria []struct {
		Property  string `json:"property"`
		Value     string `json:"value"`
		Operation string `json:"operation"`
	} `json:"criteria"`
}

func (d *ejbcaDouble) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost || r.URL.Path != "/ejbca/ejbca-rest-api/v2/certificate/search" {
		http.NotFound(w, r)
		return
	}
	var req ejbcaDoubleRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	d.requests = append(d.requests, req)
	if d.httpStatus != 0 {
		w.WriteHeader(d.httpStatus)
		_ = json.NewEncoder(w).Encode(map[string]any{"error_code": d.httpStatus, "error_message": "refused by the double"})
		return
	}
	statuses, cas := map[int]bool{}, map[string]bool{}
	var issuedBefore, expiresAfter time.Time
	for _, c := range req.Criteria {
		switch c.Property {
		case "STATUS":
			statuses[map[string]int{"CERT_ACTIVE": 20, "CERT_REVOKED": 40}[c.Value]] = true
		case "CA":
			cas[c.Value] = true
		case "ISSUED_DATE":
			issuedBefore, _ = time.Parse(time.RFC3339, c.Value)
		case "EXPIRE_DATE":
			expiresAfter, _ = time.Parse(time.RFC3339, c.Value)
		}
	}
	type match struct {
		cert  ejbcaDoubleCert
		facts crypto.CertificateFacts
	}
	var matches []match
	for _, cert := range d.certs {
		facts, err := crypto.CertificateFactsFromDER(cert.der)
		if err != nil {
			d.t.Errorf("double certificate: %v", err)
			continue
		}
		if !statuses[cert.status] || (len(cas) > 0 && !cas[cert.caName]) ||
			(!issuedBefore.IsZero() && !facts.NotBefore.Before(issuedBefore)) || (!expiresAfter.IsZero() && !facts.NotAfter.After(expiresAfter)) {
			continue
		}
		matches = append(matches, match{cert: cert, facts: facts})
	}
	sort.SliceStable(matches, func(i, j int) bool { return matches[i].facts.NotAfter.Before(matches[j].facts.NotAfter) })
	type listed struct {
		Fingerprint      string `json:"fingerprint"`
		SerialNumber     string `json:"serialNumber"`
		Status           int    `json:"status"`
		RevocationReason int    `json:"revocationReason"`
		Base64Cert       string `json:"base64Cert"`
	}
	out := []listed{}
	total := len(matches)
	if page := req.Pagination.CurrentPage; page > 0 {
		start := (page - 1) * req.Pagination.PageSize
		for i := start; i < start+req.Pagination.PageSize && i < len(matches); i++ {
			if page == d.dropOnPage && i == start {
				continue
			}
			m := matches[i]
			serial := strings.ToUpper(m.facts.SerialHex)
			if m.cert.listedSerial != "" {
				serial = m.cert.listedSerial
			}
			encoded := base64.StdEncoding.EncodeToString(m.cert.der)
			if !m.cert.oneLayer {
				encoded = base64.StdEncoding.EncodeToString([]byte(encoded))
			}
			out = append(out, listed{Fingerprint: crypto.SHA256Hex(m.cert.der)[:40], SerialNumber: serial, Status: m.cert.status,
				RevocationReason: m.cert.reason, Base64Cert: encoded})
		}
		total = len(out)
	}
	_ = json.NewEncoder(w).Encode(map[string]any{"certificates": out,
		"pagination_summary": map[string]int{"page_size": req.Pagination.PageSize, "current_page": req.Pagination.CurrentPage, "total_certs": total}})
}

// ejbcaLab is a CA in the source's jurisdiction, another CA outside it, and
// the double serving their certificates over mutual TLS.
type ejbcaLab struct {
	double   *ejbcaDouble
	address  string
	material *mtls.SignerPeerMaterial
	caFile   string
	leaves   map[string][]byte
}

func newEJBCALab(t *testing.T) *ejbcaLab {
	t.Helper()
	newCA := func(cn string) (*crypto.LockedSigner, []byte) {
		key, err := crypto.GenerateLockedKey(crypto.ECDSAP256)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(key.Destroy)
		der, err := crypto.SelfSignedCACert(key, cn, 24*time.Hour)
		if err != nil {
			t.Fatal(err)
		}
		return key, der
	}
	leaf := func(caKey *crypto.LockedSigner, caDER []byte, name string) []byte {
		hostKey, err := crypto.GenerateHostSubjectKey(name, []string{name})
		if err != nil {
			t.Fatal(err)
		}
		der, err := crypto.SignLeafFromCSR(caDER, caKey, hostKey.CSRDER, time.Hour)
		if err != nil {
			t.Fatal(err)
		}
		return der
	}
	labKey, labDER := newCA("EJBCA Lab Issuing CA")
	otherKey, otherDER := newCA("EJBCA Other CA")
	lab := &ejbcaLab{leaves: map[string][]byte{
		"active":  leaf(labKey, labDER, "active.ejbca.lab.test"),
		"revoked": leaf(labKey, labDER, "revoked.ejbca.lab.test"),
		"hold":    leaf(labKey, labDER, "hold.ejbca.lab.test"),
		"other":   leaf(otherKey, otherDER, "other.ejbca.lab.test"),
	}}
	lab.double = &ejbcaDouble{t: t, certs: []ejbcaDoubleCert{
		{der: lab.leaves["active"], caName: "LabCA", status: 20, reason: -1},
		{der: lab.leaves["revoked"], caName: "LabCA", status: 40, reason: 1},
		// On hold: EJBCA keeps it in the revoked status group with reason 6.
		{der: lab.leaves["hold"], caName: "LabCA", status: 40, reason: 6, oneLayer: true},
		{der: lab.leaves["other"], caName: "OtherCA", status: 20, reason: -1},
	}}
	dir := t.TempDir()
	lab.caFile = filepath.Join(dir, "issuers.pem")
	if err := os.WriteFile(lab.caFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: labDER}), 0o600); err != nil {
		t.Fatal(err)
	}
	material, err := mtls.GenerateSignerPeerMaterial(dir, "ejbca.lab.test", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	lab.material = material
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	tlsLn, err := mtls.MutualTLSServerListenerFromFiles(ln, material.Signer.CertFile, material.Signer.KeyFile, material.Signer.PeerCAFile)
	if err != nil {
		t.Fatal(err)
	}
	srv := &http.Server{Handler: lab.double, ReadHeaderTimeout: 5 * time.Second}
	go func() { _ = srv.Serve(tlsLn) }()
	t.Cleanup(func() { _ = srv.Close() })
	lab.address = "https://" + ln.Addr().String()
	return lab
}

func (lab *ejbcaLab) config(id string) reconcile.EJBCASourceConfig {
	return reconcile.EJBCASourceConfig{
		AuthorityID: id, Address: lab.address, ServerName: "ejbca.lab.test",
		CAFile: lab.material.ControlPlane.PeerCAFile, ClientCertFile: lab.material.ControlPlane.CertFile,
		ClientKeyFile: lab.material.ControlPlane.KeyFile, IssuerCertificatesFile: lab.caFile,
		PageSize: 2, AllowLoopback: true,
	}
}

func observeEJBCA(t *testing.T, cfg reconcile.EJBCASourceConfig) (canon.Set, error) {
	t.Helper()
	rt, err := reconcile.NewRuntime(reconcile.RuntimeConfig{EJBCASources: []reconcile.EJBCASourceConfig{cfg}})
	if err != nil {
		t.Fatalf("NewRuntime: %v", err)
	}
	obs, err := rt.Reducers.Observe(context.Background(), cfg.AuthorityID, "11111111-1111-1111-1111-111111111111")
	return obs.Set, err
}

// A218: the EJBCA source reads the named CA's ledger over mutual TLS with the
// v2 search frozen at the observation (active or revoked, issued before it,
// expiring after it), counts first, pages in expiry order, and asserts each
// certificate's identity from its DER and its standing; another CA's
// certificate stays outside the jurisdiction.
func TestEJBCASourceObservesTheNamedCAsLedger(t *testing.T) {
	lab := newEJBCALab(t)
	set, err := observeEJBCA(t, lab.config("ejbca-lab"))
	if err != nil {
		t.Fatalf("observe: %v", err)
	}
	statuses := map[string]string{}
	for _, rec := range set.Records {
		if rec.RecordType != canon.RecordTypeX509Certificate || rec.Provenance.AuthorityID != "ejbca-lab" {
			t.Fatalf("record %+v", rec)
		}
		statuses[rec.Provenance.NativeID] = rec.Status
	}
	want := map[string]string{
		crypto.SHA256Hex(lab.leaves["active"])[:40]:  canon.StatusActive,
		crypto.SHA256Hex(lab.leaves["revoked"])[:40]: canon.StatusRevoked,
		crypto.SHA256Hex(lab.leaves["hold"])[:40]:    canon.StatusRevoked,
	}
	if len(statuses) != len(want) {
		t.Fatalf("observed %v, want the lab CA's three certificates and not the other CA's", statuses)
	}
	for id, status := range want {
		if statuses[id] != status {
			t.Fatalf("certificate %s = %q, want %q (observed %v)", id, statuses[id], status, statuses)
		}
	}
	lab.double.mu.Lock()
	defer lab.double.mu.Unlock()
	if len(lab.double.requests) != 4 || lab.double.requests[0].Pagination.CurrentPage != -1 {
		t.Fatalf("requests = %+v; want the count, then pages 1, 2 and the empty page 3", lab.double.requests)
	}
	properties := map[string]bool{}
	for _, c := range lab.double.requests[0].Criteria {
		properties[c.Property+"="+c.Value] = true
		if c.Property == "ISSUED_DATE" && c.Operation != "BEFORE" || c.Property == "EXPIRE_DATE" && c.Operation != "AFTER" {
			t.Fatalf("criterion %+v", c)
		}
	}
	if !properties["STATUS=CERT_ACTIVE"] || !properties["STATUS=CERT_REVOKED"] {
		t.Fatalf("criteria = %+v; want active and revoked certificates", lab.double.requests[0].Criteria)
	}
	if page := lab.double.requests[1]; page.Sort == nil || page.Sort.Property != "EXPIRE_DATE" || page.Sort.Operation != "ASC" {
		t.Fatalf("page request = %+v; want expiry order", page)
	}
}

// CA names narrow the search on EJBCA's side.
func TestEJBCASourceSendsTheConfiguredCANames(t *testing.T) {
	lab := newEJBCALab(t)
	cfg := lab.config("ejbca-lab")
	cfg.CANames = []string{"LabCA"}
	set, err := observeEJBCA(t, cfg)
	if err != nil || len(set.Records) != 3 {
		t.Fatalf("observe = %d records, %v", len(set.Records), err)
	}
	lab.double.mu.Lock()
	defer lab.double.mu.Unlock()
	for _, c := range lab.double.requests[0].Criteria {
		if c.Property == "CA" && c.Value == "LabCA" {
			return
		}
	}
	t.Fatalf("criteria = %+v; want CA=LabCA", lab.double.requests[0].Criteria)
}

// A ledger that moved between the count and the pages, one larger than
// max_objects, a serial EJBCA lists differently from the certificate, a
// protocol that is off, and a client certificate EJBCA does not trust each
// fail the observation rather than report part of the ledger.
func TestEJBCASourceFailsClosed(t *testing.T) {
	for _, tc := range []struct {
		name  string
		setup func(lab *ejbcaLab, cfg *reconcile.EJBCASourceConfig)
		want  string
	}{
		{"ledger moved", func(lab *ejbcaLab, _ *reconcile.EJBCASourceConfig) { lab.double.dropOnPage = 1 }, "ledger changed"},
		{"too large", func(_ *ejbcaLab, cfg *reconcile.EJBCASourceConfig) { cfg.MaxCertificates = 2 }, "exceed max_objects"},
		{"serial mismatch", func(lab *ejbcaLab, _ *reconcile.EJBCASourceConfig) { lab.double.certs[0].listedSerial = "0BAD" }, "lists serial"},
		{"v2 search off", func(lab *ejbcaLab, _ *reconcile.EJBCASourceConfig) { lab.double.httpStatus = http.StatusNotFound }, "REST Certificate Management V2"},
		{"refused", func(lab *ejbcaLab, _ *reconcile.EJBCASourceConfig) { lab.double.httpStatus = http.StatusForbidden }, "refused by the double"},
		{"untrusted client", func(_ *ejbcaLab, cfg *reconcile.EJBCASourceConfig) {
			other, err := mtls.GenerateSignerPeerMaterial(t.TempDir(), "ejbca.lab.test", time.Hour)
			if err != nil {
				t.Fatal(err)
			}
			cfg.ClientCertFile, cfg.ClientKeyFile = other.ControlPlane.CertFile, other.ControlPlane.KeyFile
		}, "search"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			lab := newEJBCALab(t)
			cfg := lab.config("ejbca-lab")
			tc.setup(lab, &cfg)
			if _, err := observeEJBCA(t, cfg); err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("observe = %v; want an error naming %q", err, tc.want)
			}
		})
	}
}

// An ejbca, stepca or inventory authority never replaces a store-backed one.
func TestCALedgerAuthoritiesCannotReplaceTheStoreBackedOnes(t *testing.T) {
	for _, cfg := range []reconcile.RuntimeConfig{
		{EJBCASources: []reconcile.EJBCASourceConfig{{AuthorityID: "trstctl-self", Address: "https://ejbca.lab.test", CAFile: "ca", ClientCertFile: "c", ClientKeyFile: "k", IssuerCertificatesFile: "i"}}},
		{StepCASources: []reconcile.StepCASourceConfig{{AuthorityID: "trstctl-ca", DSNFile: "d", IssuerCertificatesFile: "i"}}},
		{InventoryAuthorities: []reconcile.InventoryAuthorityConfig{{AuthorityID: "trstctl-self", IssuerCertificatesFile: "i"}}},
	} {
		if _, err := reconcile.NewRuntime(cfg); err == nil || !strings.Contains(err.Error(), "reserved") {
			t.Fatalf("NewRuntime(%+v) = %v; want the store-backed id refused", cfg, err)
		}
	}
}
