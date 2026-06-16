package projections_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"trstctl.com/trstctl/internal/cbom"
	"trstctl.com/trstctl/internal/cbom/hostsource"
	"trstctl.com/trstctl/internal/cbom/tlssource"
	"trstctl.com/trstctl/internal/graph"
)

// TestCBOMScanPopulatesInventoryAndGraph is the S6.8 acceptance over embedded
// PostgreSQL: a scan inventories cryptographic usage on a fixture environment,
// flags a weak / quantum-vulnerable asset, and the results populate the CBOM and
// the credential graph. Scanning is read-only and bounded.
func TestCBOMScanPopulatesInventoryAndGraph(t *testing.T) {
	s := newStore(t)
	ctx := context.Background()

	// A real TLS endpoint (presents a certificate over a real handshake).
	tlsSrv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer tlsSrv.Close()
	addr := strings.TrimPrefix(tlsSrv.URL, "https://")

	// A host config that enables a weak protocol and a weak cipher.
	dir := t.TempDir()
	conf := filepath.Join(dir, "nginx.conf")
	if err := os.WriteFile(conf, []byte("ssl_protocols TLSv1 TLSv1.2;\nssl_ciphers DES-CBC3-SHA:ECDHE-RSA-AES128-GCM-SHA256;\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	scanner := cbom.NewScanner(cbom.NewStoreSink(s, tenantA), cbom.WithWorkers(2))
	defer scanner.Close()
	rep := scanner.Scan(ctx, []cbom.Source{
		tlssource.New([]string{addr}),
		hostsource.New(conf),
	})

	if rep.Findings < 3 {
		t.Fatalf("report = %+v, want several findings", rep)
	}
	if rep.QuantumVulnerable < 1 {
		t.Errorf("scan did not flag any quantum-vulnerable asset: %+v", rep)
	}
	if rep.OutOfPolicy < 1 {
		t.Errorf("scan did not flag any out-of-policy asset (TLSv1.0 / 3DES): %+v", rep)
	}

	// The CBOM is populated, with the weak/quantum flags persisted.
	assets, err := s.ListCryptoAssets(ctx, tenantA)
	if err != nil {
		t.Fatal(err)
	}
	if len(assets) < 3 {
		t.Fatalf("crypto_assets = %d, want >= 3", len(assets))
	}
	var sawQuantum, sawWeakProtocol bool
	for _, a := range assets {
		if a.QuantumVulnerable {
			sawQuantum = true
		}
		if a.Protocol == "TLSv1.0" && a.OutOfPolicy {
			sawWeakProtocol = true
		}
	}
	if !sawQuantum {
		t.Error("no quantum-vulnerable asset persisted to the CBOM")
	}
	if !sawWeakProtocol {
		t.Error("the weak TLSv1.0 protocol was not persisted/flagged")
	}

	// Folded into the credential graph as crypto-asset nodes.
	g, err := graph.Build(ctx, s, tenantA)
	if err != nil {
		t.Fatal(err)
	}
	cryptoNodes, quantumNode := 0, false
	for _, n := range g.Nodes() {
		if n.Kind != graph.KindCryptoAsset {
			continue
		}
		cryptoNodes++
		if n.Attrs["quantum_vulnerable"] == "true" {
			quantumNode = true
		}
	}
	if cryptoNodes < 3 {
		t.Errorf("graph has %d crypto-asset nodes, want >= 3", cryptoNodes)
	}
	if !quantumNode {
		t.Error("graph has no quantum-vulnerable crypto-asset node")
	}
}
