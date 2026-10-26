// SPDX-License-Identifier: BUSL-1.1

package a10_test

import (
	"bytes"
	"context"
	"encoding/pem"
	"errors"
	"slices"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/connector"
	"trstctl.com/trstctl/internal/connector/a10"
	"trstctl.com/trstctl/internal/connector/a10/a10test"
	"trstctl.com/trstctl/internal/crypto"
)

const a10TargetID = "9c1d5e6f-7a8b-4c0d-8f3c-9a712d4e4b8a"

func signA10CSR(t *testing.T, csrPEM []byte) []byte {
	t.Helper()
	block, _ := pem.Decode(csrPEM)
	if block == nil || block.Type != "CERTIFICATE REQUEST" {
		t.Fatalf("the A10 returned no PEM CSR: %q", csrPEM)
	}
	ca, err := crypto.GenerateLockedKey(crypto.ECDSAP256)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(ca.Destroy)
	caDER, err := crypto.SelfSignedCACert(ca, "A10 Appliance Test CA", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	leafDER, err := crypto.SignLeafFromCSR(caDER, ca, block.Bytes, time.Hour)
	if err != nil {
		t.Fatalf("sign the A10 CSR: %v", err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: leafDER})
}

// A122: the A10 generates the key and CSR itself; the signed certificate is
// uploaded under its fingerprint name and bound to the template with that key,
// readback sees it serving, and a rollback to an earlier appliance-generated
// predecessor re-binds the template to that certificate and its own key
// without reading it. A predecessor key whose object is gone is refused.
func TestA10GeneratesTheKeyOnTheApplianceAndRollsBackToItsOwnKey(t *testing.T) {
	srv := a10test.New("admin", "s3cret")
	defer srv.Close()
	c := a10.New(srv.URL(), "admin", []byte("s3cret"))
	t.Cleanup(c.Close)
	ops := connector.NewHTTPOps(srv.Client())
	ctx := context.Background()

	install := func(jobID int64) (connector.ApplianceKey, string) {
		t.Helper()
		req := connector.ApplianceKeyRequest{
			ObjectName: connector.ApplianceKeyObjectName(a10TargetID, jobID),
			CommonName: "vip.example.test", DNSNames: []string{"vip.example.test", "api.example.test"},
		}
		key, _, err := connector.RunApplianceKey(ctx, c, ops, req)
		if err != nil {
			t.Fatalf("generate the key on the A10: %v", err)
		}
		if !srv.DeviceKey(req.ObjectName + ".key") {
			t.Fatalf("the A10 holds no key %s.key", req.ObjectName)
		}
		block, _ := pem.Decode(key.CSRPEM)
		info, err := crypto.InspectCSR(block.Bytes)
		if err != nil || info.CommonName != "vip.example.test" || !slices.Equal(info.DNSNames, req.DNSNames) {
			t.Fatalf("CSR names = %+v %v", info, err)
		}
		again, _, err := connector.RunApplianceKey(ctx, c, ops, req)
		if err != nil || !bytes.Equal(again.CSRPEM, key.CSRPEM) {
			t.Fatalf("a second request for the same object = %v, want the same CSR", err)
		}
		certPEM := signA10CSR(t, key.CSRPEM)
		fp := connector.CertificateFingerprint(certPEM)
		if _, err := connector.RunApplianceInstall(ctx, c, ops, connector.Deployment{Target: a10Template, CertPEM: certPEM, Fingerprint: fp}, key); err != nil {
			t.Fatalf("install against the A10 key: %v", err)
		}
		return key, fp
	}
	first, firstFP := install(41)
	second, secondFP := install(42)
	binding, ok := srv.Binding(a10Template)
	if !ok || binding.CertFile != connector.DeployedObjectName(a10Template, secondFP)+".crt" || binding.KeyFile != second.ObjectName+".key" {
		t.Fatalf("template binding = %+v %v", binding, ok)
	}
	if got, err := connector.RunReadback(ctx, c, ops, a10Template); err != nil || connector.ClassifyReadback(got, secondFP) != connector.ReadbackServing {
		t.Fatalf("readback = %+v %v, want the second certificate serving", got, err)
	}
	if _, err := connector.RunRollback(ctx, c, ops, connector.Rollback{
		Target: a10Template, PredecessorFingerprint: firstFP, PredecessorKeyObject: first.ObjectName,
	}); err != nil {
		t.Fatalf("roll back to the first appliance key: %v", err)
	}
	binding, _ = srv.Binding(a10Template)
	if binding.CertFile != connector.DeployedObjectName(a10Template, firstFP)+".crt" || binding.KeyFile != first.ObjectName+".key" {
		t.Fatalf("template after the rollback = %+v, want the first certificate and its key", binding)
	}
	if srv.DeviceKeyReads() != 0 {
		t.Fatalf("the connector read an appliance key %d times", srv.DeviceKeyReads())
	}
	srv.RemoveCSR(second.ObjectName + ".csr")
	if _, err := connector.RunRollback(ctx, c, ops, connector.Rollback{
		Target: a10Template, PredecessorFingerprint: secondFP, PredecessorKeyObject: second.ObjectName,
	}); !errors.Is(err, connector.ErrNoPredecessorInstalled) {
		t.Fatalf("rollback to an appliance key whose object is gone = %v, want ErrNoPredecessorInstalled", err)
	}
}

// A certificate for any other key is refused by the A10, and an appliance-key
// install that carries a private key is refused before any call.
func TestA10ApplianceKeyInstallRefusesAMismatchedCertificate(t *testing.T) {
	srv := a10test.New("admin", "s3cret")
	defer srv.Close()
	c := a10.New(srv.URL(), "admin", []byte("s3cret"))
	t.Cleanup(c.Close)
	ops := connector.NewHTTPOps(srv.Client())
	ctx := context.Background()
	key, _, err := connector.RunApplianceKey(ctx, c, ops, connector.ApplianceKeyRequest{
		ObjectName: connector.ApplianceKeyObjectName(a10TargetID, 43), CommonName: "vip.example.test",
		DNSNames: []string{"vip.example.test"},
	})
	if err != nil {
		t.Fatal(err)
	}
	other, err := crypto.GenerateHostSubjectKey("vip.example.test", []string{"vip.example.test"})
	if err != nil {
		t.Fatal(err)
	}
	defer other.Destroy()
	foreign := signA10CSR(t, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: other.CSRDER}))
	dep := connector.Deployment{Target: a10Template, CertPEM: foreign, Fingerprint: connector.CertificateFingerprint(foreign)}
	if _, err := connector.RunApplianceInstall(ctx, c, ops, dep, key); err == nil {
		t.Fatal("a certificate for another key was bound with the A10 key")
	}
	if _, bound := srv.Binding(a10Template); bound {
		t.Fatal("the refused install changed the template")
	}
	dep.KeyPEM = []byte("-----BEGIN PRIVATE KEY-----")
	if _, err := connector.RunApplianceInstall(ctx, c, ops, dep, key); err == nil {
		t.Fatal("an appliance-key install carrying a private key was accepted")
	}
}
