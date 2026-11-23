// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"bytes"
	"context"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/metadata"

	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/protocols/spiffe/workloadpb"
)

const li6AttackerTenant = "66666666-6666-4666-8666-666666666666"

func TestCR042TenantSPIFFECAIsDistinctStableAndRefusesMissingPublicState(t *testing.T) {
	h := newOperatingServedHarness(t, config.Protocols{SPIFFE: config.SPIFFEProtocol{
		Enabled: true, TenantID: servedTestTenant, TrustDomain: "served.test",
	}})
	client := h.srv.signer.Client()
	ctx := context.Background()
	firstKey, firstCert, err := h.srv.provisionTenantSPIFFECA(ctx, client, servedTestTenant)
	if err != nil {
		t.Fatal(err)
	}
	secondKey, secondCert, err := h.srv.provisionTenantSPIFFECA(ctx, client, servedTestTenant)
	if err != nil || !bytes.Equal(firstCert, secondCert) || !bytes.Equal(firstKey.Public().DER, secondKey.Public().DER) {
		t.Fatalf("tenant SPIFFE CA changed across a repeated provision: %v", err)
	}
	foreignKey, foreignCert, err := h.srv.provisionTenantSPIFFECA(ctx, client, li6AttackerTenant)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(firstCert, foreignCert) || bytes.Equal(firstKey.Public().DER, foreignKey.Public().DER) {
		t.Fatal("two tenants share one Workload API CA")
	}
	certFile := h.caFile + ".spiffe-" + servedTestTenant
	if err := os.Remove(certFile); err != nil {
		t.Fatal(err)
	}
	if _, _, err := h.srv.provisionTenantSPIFFECA(ctx, client, servedTestTenant); err == nil {
		t.Fatal("a signer key without its persisted public CA certificate silently replaced the trust anchor")
	}
}

// The victim's served Workload API hands out the same trust bundle a relying
// party uses. A second tenant must not mint the victim workload's URI under it.
func TestCR042NeighbourTenantCannotMintVictimSPIFFEIdentity(t *testing.T) {
	ctx := context.Background()
	socketDir, err := os.MkdirTemp("", "trstctl-li6-spiffe-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(socketDir) })
	// macOS exposes /var as a symlink to /private/var; the production socket
	// guard correctly refuses a symlink ancestor, so use the canonical path.
	socketDir, err = filepath.EvalSymlinks(socketDir)
	if err != nil {
		t.Fatal(err)
	}
	socket := filepath.Join(socketDir, "s.sock")
	h := newOperatingServedHarness(t, config.Protocols{
		SPIFFE: config.SPIFFEProtocol{
			Enabled: true, TenantID: servedTestTenant, TrustDomain: "served.test", SocketPath: socket, ServeLocalWorkloads: true,
		},
	})
	if got := h.srv.SPIFFESocket(); got != socket || !protoContains(h.srv.ServedProtocols(), "spiffe") {
		t.Fatalf("SPIFFE mount not ready: socket=%q protocols=%v", got, h.srv.ServedProtocols())
	}
	victimTenant := servedTestTenant
	registerServedTenantID(t, h, li6AttackerTenant, "LI-6 attacker tenant")
	const workloadID = "spiffe://served.test/workload"

	// Tenant B's workload receives its SVID and trust bundle from the served socket.
	sctx, scancel := context.WithCancel(ctx)
	done := make(chan struct{})
	go func() { defer close(done); h.srv.RunSPIFFE(sctx) }()
	t.Cleanup(func() { scancel(); <-done })
	waitForSocket(t, socket, 5*time.Second)
	conn, err := grpc.NewClient("unix://"+socket, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	fetchCtx, fcancel := context.WithTimeout(metadata.NewOutgoingContext(ctx, metadata.Pairs(spiffeSecurityHeader())), 10*time.Second)
	defer fcancel()
	stream, err := workloadpb.NewSpiffeWorkloadAPIClient(conn).FetchX509SVID(fetchCtx, &workloadpb.X509SVIDRequest{})
	if err != nil {
		t.Fatalf("FetchX509SVID: %v", err)
	}
	svidResp, err := stream.Recv()
	if err != nil || len(svidResp.GetSvids()) == 0 {
		t.Fatalf("recv SVID: %v", err)
	}
	legit := svidResp.GetSvids()[0]
	if legit.GetSpiffeId() != workloadID {
		t.Fatalf("served SVID ID = %q", legit.GetSpiffeId())
	}
	bundle := legit.GetBundle()

	// Tenant A: ordinary identity issuance with its own CSR naming tenant B's
	// workload ID.
	tok := seedScopedToken(t, h.store, li6AttackerTenant,
		"owners:read", "owners:write", "identities:read", "identities:write", "certs:read", "certs:issue")
	code, body := secretsReq(t, h, http.MethodPost, "/api/v1/owners", tok, map[string]any{
		"kind": "workload", "name": "li6-attacker", "email": "attacker@example.test",
	})
	if code != http.StatusCreated {
		t.Fatalf("create owner = %d %s", code, body)
	}
	var owner struct {
		ID string `json:"id"`
	}
	if err := json.Unmarshal(body, &owner); err != nil {
		t.Fatal(err)
	}
	code, body = secretsReq(t, h, http.MethodPost, "/api/v1/identities", tok, map[string]any{
		"owner_id": owner.ID, "kind": "x509", "name": "attacker-workload.example.test",
	})
	if code != http.StatusCreated {
		t.Fatalf("create identity = %d %s", code, body)
	}
	var ident struct {
		ID string `json:"id"`
	}
	if err := json.Unmarshal(body, &ident); err != nil {
		t.Fatal(err)
	}
	key, err := crypto.GenerateLockedKey(crypto.ECDSAP256)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(key.Destroy)
	csrDER, err := crypto.CreateCertificateRequest(crypto.CertificateRequestTemplate{
		CommonName: "attacker-workload.example.test", URIs: []string{workloadID},
	}, key)
	if err != nil {
		t.Fatal(err)
	}
	code, body = secretsReq(t, h, http.MethodPost, "/api/v1/identities/"+ident.ID+"/transitions", tok, map[string]any{
		"to": "issued", "reason": "li6", "subject_csr_pem": string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csrDER})),
	})
	if code != http.StatusOK {
		t.Fatalf("issue = %d %s", code, body)
	}
	if err := h.srv.Drain(ctx); err != nil {
		t.Fatalf("drain: %v", err)
	}
	certs, err := h.store.ListCertificatesPage(ctx, li6AttackerTenant, "00000000-0000-0000-0000-000000000000", nil, 50, nil)
	if err != nil {
		t.Fatal(err)
	}
	var leaf []byte
	for _, c := range certs {
		if id := certificateSPIFFEID(c.CertificateDER); id == workloadID {
			leaf = c.CertificateDER
		}
	}
	if leaf == nil {
		t.Logf("no certificate carrying %s was issued to tenant %s (property holds); certs=%d", workloadID, li6AttackerTenant, len(certs))
		return
	}
	keyPKCS8, err := key.PKCS8()
	if err != nil {
		t.Fatal(err)
	}
	check, err := crypto.VerifyX509SVID(leaf, bundle, keyPKCS8, time.Now())
	if err != nil {
		t.Logf("tenant B's bundle rejects tenant A's certificate (property holds): %v", err)
		return
	}
	t.Errorf("tenant %s holds a certificate that tenant %s's served SPIFFE trust bundle verifies as %s "+
		"(the SPIFFE ID tenant %s's Workload API hands its workload): %+v",
		li6AttackerTenant, victimTenant, check.SPIFFEID, victimTenant, check)
}
