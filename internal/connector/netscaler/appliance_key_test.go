// SPDX-License-Identifier: BUSL-1.1

package netscaler_test

import (
	"bytes"
	"context"
	"encoding/pem"
	"errors"
	"slices"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/connector"
	"trstctl.com/trstctl/internal/connector/netscaler"
	"trstctl.com/trstctl/internal/connector/netscaler/netscalertest"
	"trstctl.com/trstctl/internal/crypto"
)

// nsTargetID is the destination the appliance keys in these tests belong to.
const nsTargetID = "0f3c9a71-2d4e-4b8a-9c1d-5e6f7a8b9c0d"

// signApplianceCSR is the control plane's half in these tests: a CA signs the
// CSR the appliance returned.
func signApplianceCSR(t *testing.T, csrPEM []byte) []byte {
	t.Helper()
	block, _ := pem.Decode(csrPEM)
	if block == nil || block.Type != "CERTIFICATE REQUEST" {
		t.Fatalf("the appliance returned no PEM CSR: %q", csrPEM)
	}
	ca, err := crypto.GenerateLockedKey(crypto.ECDSAP256)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(ca.Destroy)
	caDER, err := crypto.SelfSignedCACert(ca, "Appliance Test CA", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	leafDER, err := crypto.SignLeafFromCSR(caDER, ca, block.Bytes, time.Hour)
	if err != nil {
		t.Fatalf("sign the appliance CSR: %v", err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: leafDER})
}

// A122: the NetScaler generates the key itself, returns only a CSR, and the
// signed certificate is installed against that key. The key never leaves the
// appliance, a second request for the same object returns the same CSR, and
// the certkey reads back as serving the certificate.
func TestNetScalerGeneratesTheKeyOnTheApplianceAndInstallsAgainstIt(t *testing.T) {
	srv := netscalertest.New(user, pass)
	defer srv.Close()
	c := netscaler.New(srv.URL(), user, []byte(pass))
	ops := connector.NewHTTPOps(srv.Client())
	ctx := context.Background()

	req := connector.ApplianceKeyRequest{
		ObjectName: connector.ApplianceKeyObjectName(nsTargetID, 41),
		CommonName: "vip.example.test", DNSNames: []string{"vip.example.test", "www.example.test"},
	}
	key, _, err := connector.RunApplianceKey(ctx, c, ops, req)
	if err != nil {
		t.Fatalf("generate the key on the appliance: %v", err)
	}
	if key.ObjectName != req.ObjectName || !srv.DeviceKey(req.ObjectName+".key") {
		t.Fatalf("appliance key = %q (device key present %v)", key.ObjectName, srv.DeviceKey(req.ObjectName+".key"))
	}
	block, _ := pem.Decode(key.CSRPEM)
	if block == nil {
		t.Fatalf("CSR = %q", key.CSRPEM)
	}
	info, err := crypto.InspectCSR(block.Bytes)
	if err != nil || info.CommonName != "vip.example.test" || !slices.Equal(info.DNSNames, req.DNSNames) {
		t.Fatalf("CSR names = %+v %v, want the request's", info, err)
	}
	again, _, err := connector.RunApplianceKey(ctx, c, ops, req)
	if err != nil || !bytes.Equal(again.CSRPEM, key.CSRPEM) {
		t.Fatalf("a second request for the same object = %v, want the same CSR, not a new key", err)
	}

	certPEM := signApplianceCSR(t, key.CSRPEM)
	dep := connector.Deployment{Target: certkey, CertPEM: certPEM, Fingerprint: connector.CertificateFingerprint(certPEM)}
	if _, err := connector.RunApplianceInstall(ctx, c, ops, dep, key); err != nil {
		t.Fatalf("install against the appliance key: %v", err)
	}
	binding, ok := srv.Binding(certkey)
	if !ok || binding.Cert != connector.DeployedObjectName(certkey, dep.Fingerprint)+".crt" || binding.Key != req.ObjectName+".key" {
		t.Fatalf("certkey binding = %+v %v", binding, ok)
	}
	srv.BindVServer(certkey, "vs-web-443")
	if got, err := connector.RunReadback(ctx, c, ops, certkey); err != nil || connector.ClassifyReadback(got, dep.Fingerprint) != connector.ReadbackServing {
		t.Fatalf("readback = %+v %v, want the certificate serving", got, err)
	}
	if srv.DeviceKeyReads() != 0 {
		t.Fatalf("the connector read the appliance key %d times", srv.DeviceKeyReads())
	}
	if _, uploaded := srv.File(connector.DeployedObjectName(certkey, dep.Fingerprint) + ".key"); uploaded {
		t.Fatal("a key file was uploaded for an appliance-key install")
	}
	if srv.OpenSessions() != 0 {
		t.Fatalf("%d NITRO sessions left open", srv.OpenSessions())
	}
}

// A certificate for some other key is refused by the appliance and the certkey
// keeps what it had; a deployment carrying a private key is refused before the
// appliance is asked anything.
func TestNetScalerApplianceKeyInstallRefusesAMismatchedCertificate(t *testing.T) {
	srv := netscalertest.New(user, pass)
	defer srv.Close()
	c := netscaler.New(srv.URL(), user, []byte(pass))
	ops := connector.NewHTTPOps(srv.Client())
	ctx := context.Background()
	key, _, err := connector.RunApplianceKey(ctx, c, ops, connector.ApplianceKeyRequest{
		ObjectName: connector.ApplianceKeyObjectName(nsTargetID, 42), CommonName: "vip.example.test",
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
	foreign := signApplianceCSR(t, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: other.CSRDER}))
	dep := connector.Deployment{Target: certkey, CertPEM: foreign, Fingerprint: connector.CertificateFingerprint(foreign)}
	if _, err := connector.RunApplianceInstall(ctx, c, ops, dep, key); err == nil {
		t.Fatal("a certificate for another key was installed against the appliance key")
	}
	if _, bound := srv.Binding(certkey); bound {
		t.Fatal("the refused install changed the certkey")
	}
	dep.KeyPEM = []byte("-----BEGIN PRIVATE KEY-----")
	if _, err := connector.RunApplianceInstall(ctx, c, ops, dep, key); err == nil {
		t.Fatal("an appliance-key install carrying a private key was accepted")
	}
}

// ISE-O1: taking down a certificate whose key the appliance generated
// removes the certificate file, the job's key file and the CSR beside it;
// the certkey's current files are refused and stay; a key object that is not
// a job's is refused before any deletion.
func TestNetScalerTakedownRemovesTheJobsKeyAndCSRISEO1(t *testing.T) {
	srv := netscalertest.New(user, pass)
	defer srv.Close()
	c := netscaler.New(srv.URL(), user, []byte(pass))
	ops := connector.NewHTTPOps(srv.Client())
	ctx := context.Background()
	install := func(jobID int64) (string, string) {
		t.Helper()
		key, _, err := connector.RunApplianceKey(ctx, c, ops, connector.ApplianceKeyRequest{
			ObjectName: connector.ApplianceKeyObjectName(nsTargetID, jobID), CommonName: "vip.example.test",
			DNSNames: []string{"vip.example.test"},
		})
		if err != nil {
			t.Fatal(err)
		}
		certPEM := signApplianceCSR(t, key.CSRPEM)
		fp := connector.CertificateFingerprint(certPEM)
		if _, err := connector.RunApplianceInstall(ctx, c, ops, connector.Deployment{Target: certkey, CertPEM: certPEM, Fingerprint: fp}, key); err != nil {
			t.Fatal(err)
		}
		return key.ObjectName, fp
	}
	firstObject, firstFP := install(51)
	secondObject, secondFP := install(52)

	if _, err := connector.RunTakedown(ctx, c, ops, connector.Takedown{Target: certkey, Fingerprint: secondFP, KeyObject: secondObject}); !errors.Is(err, connector.ErrTakedownObjectBound) {
		t.Fatalf("takedown of the bound certificate = %v", err)
	}
	if !srv.DeviceKey(secondObject + ".key") {
		t.Fatal("a refused takedown removed the bound certificate's key")
	}
	if _, err := connector.RunTakedown(ctx, c, ops, connector.Takedown{Target: certkey, Fingerprint: firstFP, KeyObject: "vip-key"}); err == nil {
		t.Fatal("a key object that is not a job's was accepted")
	}
	if _, err := connector.RunTakedown(ctx, c, ops, connector.Takedown{Target: certkey, Fingerprint: firstFP, KeyObject: firstObject}); err != nil {
		t.Fatalf("takedown of the replaced certificate: %v", err)
	}
	for _, name := range []string{firstObject + ".key", firstObject + ".csr", connector.DeployedObjectName(certkey, firstFP) + ".crt"} {
		if _, left := srv.File(name); left {
			t.Fatalf("%s is still on the appliance", name)
		}
	}
	if srv.DeviceKey(firstObject + ".key") {
		t.Fatal("the replaced certificate's job key is still on the appliance")
	}
	if srv.OpenSessions() != 0 {
		t.Fatalf("%d NITRO sessions left open", srv.OpenSessions())
	}
}
