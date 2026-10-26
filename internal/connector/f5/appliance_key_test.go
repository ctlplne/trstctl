// SPDX-License-Identifier: BUSL-1.1

package f5_test

import (
	"bytes"
	"context"
	"encoding/pem"
	"slices"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/connector"
	"trstctl.com/trstctl/internal/connector/f5"
	"trstctl.com/trstctl/internal/connector/f5/f5test"
	"trstctl.com/trstctl/internal/crypto"
)

const f5TargetID = "5e6f7a8b-9c0d-4f3c-9a71-2d4e4b8a9c1d"

// signF5CSR is the control plane's half in these tests: a CA signs the CSR
// the BIG-IP returned.
func signF5CSR(t *testing.T, csrPEM []byte) []byte {
	t.Helper()
	block, _ := pem.Decode(csrPEM)
	if block == nil || block.Type != "CERTIFICATE REQUEST" {
		t.Fatalf("the BIG-IP returned no PEM CSR: %q", csrPEM)
	}
	ca, err := crypto.GenerateLockedKey(crypto.ECDSAP256)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(ca.Destroy)
	caDER, err := crypto.SelfSignedCACert(ca, "F5 Appliance Test CA", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	leafDER, err := crypto.SignLeafFromCSR(caDER, ca, block.Bytes, time.Hour)
	if err != nil {
		t.Fatalf("sign the BIG-IP CSR: %v", err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: leafDER})
}

// A122: the BIG-IP generates the key and CSR itself; the signed certificate
// is installed under its fingerprint name and bound with that key, readback
// sees it serving, and a rollback to an earlier appliance-generated
// predecessor re-binds the profile to that certificate and its own key.
func TestF5GeneratesTheKeyOnTheBigIPAndRollsBackToItsOwnKey(t *testing.T) {
	srv := f5test.New(user, pass)
	defer srv.Close()
	c := f5.New(srv.URL(), profile, f5.WithBasicAuthBytes(user, []byte(pass)))
	ops := connector.NewHTTPOps(srv.Client())
	ctx := context.Background()

	install := func(jobID int64) (connector.ApplianceKey, string) {
		t.Helper()
		req := connector.ApplianceKeyRequest{
			ObjectName: connector.ApplianceKeyObjectName(f5TargetID, jobID),
			CommonName: "app.example.test", DNSNames: []string{"app.example.test", "www.example.test"},
		}
		key, _, err := connector.RunApplianceKey(ctx, c, ops, req)
		if err != nil {
			t.Fatalf("generate the key on the BIG-IP: %v", err)
		}
		if !srv.DeviceKey(req.ObjectName + ".key") {
			t.Fatalf("the BIG-IP holds no key %s.key", req.ObjectName)
		}
		block, _ := pem.Decode(key.CSRPEM)
		info, err := crypto.InspectCSR(block.Bytes)
		if err != nil || info.CommonName != "app.example.test" || !slices.Equal(info.DNSNames, req.DNSNames) {
			t.Fatalf("CSR names = %+v %v", info, err)
		}
		again, _, err := connector.RunApplianceKey(ctx, c, ops, req)
		if err != nil || !bytes.Equal(again.CSRPEM, key.CSRPEM) {
			t.Fatalf("a second request for the same object = %v, want the same CSR", err)
		}
		certPEM := signF5CSR(t, key.CSRPEM)
		fp := connector.CertificateFingerprint(certPEM)
		if _, err := connector.RunApplianceInstall(ctx, c, ops, connector.Deployment{Target: profile, CertPEM: certPEM, Fingerprint: fp}, key); err != nil {
			t.Fatalf("install against the BIG-IP key: %v", err)
		}
		return key, fp
	}
	first, firstFP := install(41)
	_, secondFP := install(42)
	chain, ok := srv.Profile(profile)
	if !ok || chain.Cert != connector.DeployedObjectName(profile, secondFP)+".crt" ||
		chain.Key != connector.ApplianceKeyObjectName(f5TargetID, 42)+".key" {
		t.Fatalf("profile chain = %+v %v", chain, ok)
	}
	if got, err := connector.RunReadback(ctx, c, ops, profile); err != nil || connector.ClassifyReadback(got, secondFP) != connector.ReadbackServing {
		t.Fatalf("readback = %+v %v, want the second certificate serving", got, err)
	}
	if _, err := connector.RunRollback(ctx, c, ops, connector.Rollback{
		Target: profile, PredecessorFingerprint: firstFP, PredecessorKeyObject: first.ObjectName,
	}); err != nil {
		t.Fatalf("roll back to the first appliance key: %v", err)
	}
	chain, _ = srv.Profile(profile)
	if chain.Cert != connector.DeployedObjectName(profile, firstFP)+".crt" || chain.Key != first.ObjectName+".key" {
		t.Fatalf("profile after the rollback = %+v, want the first certificate and its key", chain)
	}
}

// A certificate for any other key is refused by the BIG-IP, and an
// appliance-key install that carries a private key is refused before any call.
func TestF5ApplianceKeyInstallRefusesAMismatchedCertificate(t *testing.T) {
	srv := f5test.New(user, pass)
	defer srv.Close()
	c := f5.New(srv.URL(), profile, f5.WithBasicAuthBytes(user, []byte(pass)))
	ops := connector.NewHTTPOps(srv.Client())
	ctx := context.Background()
	key, _, err := connector.RunApplianceKey(ctx, c, ops, connector.ApplianceKeyRequest{
		ObjectName: connector.ApplianceKeyObjectName(f5TargetID, 43), CommonName: "app.example.test",
		DNSNames: []string{"app.example.test"},
	})
	if err != nil {
		t.Fatal(err)
	}
	other, err := crypto.GenerateHostSubjectKey("app.example.test", []string{"app.example.test"})
	if err != nil {
		t.Fatal(err)
	}
	defer other.Destroy()
	foreign := signF5CSR(t, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: other.CSRDER}))
	dep := connector.Deployment{Target: profile, CertPEM: foreign, Fingerprint: connector.CertificateFingerprint(foreign)}
	if _, err := connector.RunApplianceInstall(ctx, c, ops, dep, key); err == nil {
		t.Fatal("a certificate for another key was bound with the BIG-IP key")
	}
	if _, bound := srv.Profile(profile); bound {
		t.Fatal("the refused install changed the profile")
	}
	dep.KeyPEM = []byte("-----BEGIN PRIVATE KEY-----")
	if _, err := connector.RunApplianceInstall(ctx, c, ops, dep, key); err == nil {
		t.Fatal("an appliance-key install carrying a private key was accepted")
	}
}
