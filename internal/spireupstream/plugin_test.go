// SPDX-License-Identifier: BUSL-1.1

package spireupstream

import (
	"bytes"
	"context"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"google.golang.org/grpc"

	upstreamauthorityv1 "github.com/spiffe/spire-plugin-sdk/proto/spire/plugin/server/upstreamauthority/v1"
	configv1 "github.com/spiffe/spire-plugin-sdk/proto/spire/service/common/config/v1"

	"trstctl.com/trstctl/internal/crypto"
)

func TestPluginMintX509CAAndSubscribeCallsServedTrstctlPath(t *testing.T) {
	rootKey, err := crypto.GenerateLockedKey(crypto.ECDSAP256)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(rootKey.Destroy)
	root, err := crypto.SelfSignedHierarchyCA(rootKey, crypto.HierarchyCAProfile{
		CommonName: "trstctl SPIRE root",
		MaxPathLen: 1,
		TTL:        24 * time.Hour,
	})
	if err != nil {
		t.Fatal(err)
	}
	childKey, err := crypto.GenerateLockedKey(crypto.ECDSAP256)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(childKey.Destroy)
	child, err := crypto.SignIntermediateHierarchyCA(root.CertificateDER, rootKey, childKey.Public(), crypto.HierarchyCAProfile{
		CommonName: "SPIRE Server CA",
		MaxPathLen: 0,
		TTL:        time.Hour,
	})
	if err != nil {
		t.Fatal(err)
	}

	tokenFile := writeTempToken(t, []byte("plugin-token\n"))
	var seenCSRPEM string
	var seenTTL float64
	var seenAuth string
	var seenIdem string
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != "/api/v1/ca/authorities/root-1/intermediates/csr" {
			t.Fatalf("unexpected trstctl request %s %s", r.Method, r.URL.Path)
		}
		seenAuth = r.Header.Get("Authorization")
		seenIdem = r.Header.Get("Idempotency-Key")
		var body struct {
			CSRPem string         `json:"csr_pem"`
			Spec   map[string]any `json:"spec"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			t.Fatalf("decode plugin request: %v", err)
		}
		seenCSRPEM = body.CSRPem
		seenTTL, _ = body.Spec["ttl_seconds"].(float64)
		chain := append([]byte{}, child.CertificatePEM...)
		chain = append(chain, root.CertificatePEM...)
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"certificate_pem": string(chain),
			"serial":          "01",
			"not_after":       time.Now().Add(time.Hour).UTC().Format(time.RFC3339),
		})
	}))
	t.Cleanup(srv.Close)
	caBundleFile := t.TempDir() + "/trstctl-ca.pem"
	if err := os.WriteFile(caBundleFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: srv.Certificate().Raw}), 0o600); err != nil {
		t.Fatal(err)
	}

	p := New()
	_, err = p.Configure(context.Background(), &configv1.ConfigureRequest{HclConfiguration: `
endpoint = "` + srv.URL + `"
ca_bundle_file = "` + caBundleFile + `"
ca_authority_id = "root-1"
token_file = "` + tokenFile + `"
common_name = "SPIRE Server CA"
ttl_seconds = 900
max_path_len = 0
permitted_dns_domains = ["example.org"]
`})
	if err != nil {
		t.Fatalf("configure plugin: %v", err)
	}

	csrKey, err := crypto.GenerateLockedKey(crypto.ECDSAP256)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(csrKey.Destroy)
	csrDER, err := crypto.CreateCertificateRequest(crypto.CertificateRequestTemplate{CommonName: "SPIRE Server CA"}, csrKey)
	if err != nil {
		t.Fatalf("create CSR: %v", err)
	}
	stream := &mintStream{ctx: context.Background()}
	if err := p.MintX509CAAndSubscribe(&upstreamauthorityv1.MintX509CARequest{
		Csr:          csrDER,
		PreferredTtl: 1800,
	}, stream); err != nil {
		t.Fatalf("MintX509CAAndSubscribe: %v", err)
	}

	if seenAuth != "Bearer plugin-token" {
		t.Fatalf("Authorization = %q, want bearer token from token_file", seenAuth)
	}
	if !strings.HasPrefix(seenIdem, "spire-upstream-root-1-") {
		t.Fatalf("Idempotency-Key = %q, want stable SPIRE upstream prefix", seenIdem)
	}
	if block, _ := pem.Decode([]byte(seenCSRPEM)); block == nil || block.Type != "CERTIFICATE REQUEST" {
		t.Fatalf("plugin did not forward the SPIRE CSR as PEM: %q", firstLine(seenCSRPEM))
	}
	if seenTTL != 1800 {
		t.Fatalf("ttl_seconds = %v, want preferred_ttl override 1800", seenTTL)
	}
	if len(stream.responses) != 1 {
		t.Fatalf("responses = %d, want exactly one initial bundle response", len(stream.responses))
	}
	resp := stream.responses[0]
	if got := len(resp.GetX509CaChain()); got != 1 {
		t.Fatalf("x509_ca_chain length = %d, want signed SPIRE CA only", got)
	}
	if got := len(resp.GetUpstreamX509Roots()); got != 1 {
		t.Fatalf("upstream_x509_roots length = %d, want trstctl root", got)
	}
	if !bytes.Equal(resp.GetX509CaChain()[0].GetAsn1(), child.CertificateDER) {
		t.Fatal("x509_ca_chain[0] is not the signed SPIRE intermediate returned by trstctl")
	}
	if !bytes.Equal(resp.GetUpstreamX509Roots()[0].GetAsn1(), root.CertificateDER) {
		t.Fatal("upstream_x509_roots[0] is not the trstctl root returned by trstctl")
	}
}

type mintStream struct {
	grpc.ServerStream
	ctx       context.Context
	responses []*upstreamauthorityv1.MintX509CAResponse
}

func (s *mintStream) Context() context.Context {
	if s.ctx != nil {
		return s.ctx
	}
	return context.Background()
}

func (s *mintStream) Send(resp *upstreamauthorityv1.MintX509CAResponse) error {
	s.responses = append(s.responses, resp)
	return nil
}

func writeTempToken(t *testing.T, token []byte) string {
	t.Helper()
	path := t.TempDir() + "/token"
	if err := os.WriteFile(path, token, 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func firstLine(s string) string {
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		return s[:i]
	}
	return s
}
