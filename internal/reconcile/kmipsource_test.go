// SPDX-License-Identifier: BUSL-1.1

package reconcile_test

import (
	"context"
	"errors"
	"net"
	"strings"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/crypto/mtls"
	"trstctl.com/trstctl/internal/reconcile"
	"trstctl.com/trstctl/internal/reconcile/canon"
	"trstctl.com/trstctl/internal/reconcile/canon/reducers"
	"trstctl.com/trstctl/internal/reconcile/canon/reducers/kmip/kmiptest"
)

// startKMIPDouble serves the KMIP double behind a TLS 1.3 mutual-auth listener
// on loopback and returns its address and the client's TLS material.
func startKMIPDouble(t *testing.T, srv *kmiptest.Server) (string, *mtls.SignerPeerMaterial) {
	t.Helper()
	material, err := mtls.GenerateSignerPeerMaterial(t.TempDir(), "kmip.lab.test", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	tlsLn, err := mtls.MutualTLSServerListenerFromFiles(ln, material.Signer.CertFile, material.Signer.KeyFile, material.Signer.PeerCAFile)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = tlsLn.Close() })
	go func() {
		for {
			conn, err := tlsLn.Accept()
			if err != nil {
				return
			}
			go srv.Serve(conn)
		}
	}()
	return ln.Addr().String(), material
}

// A124: a configured KMIP authority is observed through the production
// runtime registry over mutual TLS: keys and certificates land on the shared
// canonical vocabulary, a template is skipped, no key value is requested, and
// the unconfigured "kmip" placeholder still fails closed.
func TestRuntime_KMIPAuthorityObservesConfiguredServer(t *testing.T) {
	key, err := crypto.GenerateLockedKey(crypto.ECDSAP256)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(key.Destroy)
	certDER, err := crypto.SelfSignedCACert(key, "KMIP Lab CA", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	created := time.Date(2026, 4, 1, 0, 0, 0, 0, time.UTC)
	srv := kmiptest.New()
	srv.Add("aes-1", kmiptest.Object{ObjectType: kmiptest.ObjectTypeSymmetricKey, Algorithm: kmiptest.AlgorithmAES, Length: 256, State: kmiptest.StateActive, Initial: created})
	srv.Add("aes-2", kmiptest.Object{ObjectType: kmiptest.ObjectTypeSymmetricKey, Algorithm: kmiptest.AlgorithmAES, Length: 128, State: kmiptest.StatePreActive, Initial: created})
	srv.Add("ca-1", kmiptest.Object{ObjectType: kmiptest.ObjectTypeCertificate, Algorithm: kmiptest.AlgorithmECDSA, Length: 256, State: kmiptest.StateActive, Initial: created, CertificateDER: certDER})
	srv.Add("tmpl-1", kmiptest.Object{ObjectType: kmiptest.ObjectTypeTemplate, State: kmiptest.StateActive})
	addr, material := startKMIPDouble(t, srv)

	rt, err := reconcile.NewRuntime(reconcile.RuntimeConfig{KMIPSources: []reconcile.KMIPSourceConfig{{
		AuthorityID: "kmip-lab", Address: addr, ServerName: "kmip.lab.test",
		CAFile: material.ControlPlane.PeerCAFile, ClientCertFile: material.ControlPlane.CertFile, ClientKeyFile: material.ControlPlane.KeyFile,
		AllowLoopback: true,
	}}})
	if err != nil {
		t.Fatalf("NewRuntime: %v", err)
	}
	const tenant = "11111111-1111-1111-1111-111111111111"
	obs, err := rt.Reducers.Observe(context.Background(), "kmip-lab", tenant)
	if err != nil {
		t.Fatalf("observe kmip-lab: %v", err)
	}
	if obs.AuthorityID != "kmip-lab" || obs.Denied != 0 || !strings.HasPrefix(obs.Watermark.Position, "kmip:kmip-lab@") {
		t.Fatalf("observation header: %+v", obs)
	}
	byType := map[string]int{}
	byStatus := map[string]int{}
	for _, rec := range obs.Set.Records {
		byType[rec.RecordType]++
		byStatus[rec.Status]++
	}
	if byType[canon.RecordTypeKey] != 2 || byType[canon.RecordTypeX509Certificate] != 1 || len(obs.Set.Records) != 3 {
		t.Fatalf("record types = %v (want 2 keys and 1 certificate; the template skipped)", byType)
	}
	// The reducer maps Pre-Active to "pending", which the canon vocabulary
	// does not carry, so it reduces to unknown (recorded as a lead).
	if byStatus[canon.StatusActive] != 2 || byStatus[canon.StatusUnknown] != 1 {
		t.Fatalf("statuses = %v", byStatus)
	}
	if srv.KeyValueReads() != 0 || len(srv.Errors()) != 0 {
		t.Fatalf("key value reads %d, refused requests %v", srv.KeyValueReads(), srv.Errors())
	}
	if _, err := rt.Reducers.Observe(context.Background(), "kmip", tenant); !errors.Is(err, reducers.ErrMissingSource) {
		t.Fatalf("unconfigured kmip authority must fail closed, got %v", err)
	}
}

// A server certificate for another name, a client the server does not trust
// and a source missing its TLS material each fail before any inventory.
func TestRuntime_KMIPAuthorityFailsClosed(t *testing.T) {
	srv := kmiptest.New()
	srv.Add("aes-1", kmiptest.Object{ObjectType: kmiptest.ObjectTypeSymmetricKey, State: kmiptest.StateActive})
	addr, material := startKMIPDouble(t, srv)
	other, err := mtls.GenerateSignerPeerMaterial(t.TempDir(), "kmip.lab.test", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	observe := func(cfg reconcile.KMIPSourceConfig) error {
		t.Helper()
		cfg.AuthorityID, cfg.Address, cfg.AllowLoopback = "kmip-lab", addr, true
		rt, err := reconcile.NewRuntime(reconcile.RuntimeConfig{KMIPSources: []reconcile.KMIPSourceConfig{cfg}})
		if err != nil {
			return err
		}
		_, err = rt.Reducers.Observe(context.Background(), "kmip-lab", "11111111-1111-1111-1111-111111111111")
		return err
	}
	if err := observe(reconcile.KMIPSourceConfig{ServerName: "other.lab.test", CAFile: material.ControlPlane.PeerCAFile,
		ClientCertFile: material.ControlPlane.CertFile, ClientKeyFile: material.ControlPlane.KeyFile}); err == nil {
		t.Fatal("a server certificate for another name was accepted")
	}
	if err := observe(reconcile.KMIPSourceConfig{ServerName: "kmip.lab.test", CAFile: material.ControlPlane.PeerCAFile,
		ClientCertFile: other.ControlPlane.CertFile, ClientKeyFile: other.ControlPlane.KeyFile}); err == nil {
		t.Fatal("a client certificate the server does not trust was observed")
	}
	if err := observe(reconcile.KMIPSourceConfig{ServerName: "kmip.lab.test", CAFile: material.ControlPlane.PeerCAFile}); err == nil {
		t.Fatal("a source without its client certificate was accepted")
	}
	if err := observe(reconcile.KMIPSourceConfig{ServerName: "kmip.lab.test", CAFile: material.ControlPlane.PeerCAFile,
		ClientCertFile: material.ControlPlane.CertFile, ClientKeyFile: material.ControlPlane.KeyFile, MaxObjects: -1}); err == nil {
		t.Fatal("a negative object cap was accepted")
	}
}
