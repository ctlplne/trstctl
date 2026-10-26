// SPDX-License-Identifier: BUSL-1.1

package paloalto_test

import (
	"bytes"
	"context"
	"encoding/pem"
	"errors"
	"slices"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/connector"
	"trstctl.com/trstctl/internal/connector/paloalto"
	"trstctl.com/trstctl/internal/connector/paloalto/paloaltotest"
	"trstctl.com/trstctl/internal/crypto"
)

const (
	panTargetID = "5e6f7a8b-9c0d-4f3c-9a71-2d4e4b8a9c1d"
	panProfile  = "web-profile"
)

func signPANCSR(t *testing.T, csrPEM []byte) []byte {
	t.Helper()
	block, _ := pem.Decode(csrPEM)
	if block == nil || block.Type != "CERTIFICATE REQUEST" {
		t.Fatalf("the firewall returned no PEM CSR: %q", csrPEM)
	}
	ca, err := crypto.GenerateLockedKey(crypto.ECDSAP256)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(ca.Destroy)
	caDER, err := crypto.SelfSignedCACert(ca, "PAN-OS Appliance Test CA", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	leafDER, err := crypto.SignLeafFromCSR(caDER, ca, block.Bytes, time.Hour)
	if err != nil {
		t.Fatalf("sign the firewall CSR: %v", err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: leafDER})
}

// A122: the firewall generates the key and CSR in an object named for the job;
// the signed certificate is imported into that object and the SSL/TLS service
// profile bound to it, readback fingerprints the bound certificate, and a
// rollback binds the predecessor's object back without exporting its key. A
// reclaim after the install stops rather than generating a second key, and a
// predecessor object that is gone or holds another certificate is refused.
func TestPANOSGeneratesTheKeyOnTheFirewallAndRollsBackToItsOwnObject(t *testing.T) {
	srv := paloaltotest.New(testAPIKey)
	defer srv.Close()
	c := paloalto.New(srv.URL(), testAPIKey, paloalto.WithSSLTLSProfile(panProfile, "trstctl"))
	t.Cleanup(c.Close)
	ops := connector.NewHTTPOps(srv.Client())
	ctx := context.Background()

	request := func(jobID int64) connector.ApplianceKeyRequest {
		return connector.ApplianceKeyRequest{
			ObjectName: connector.ApplianceKeyObjectName(panTargetID, jobID),
			CommonName: "vip.example.test", DNSNames: []string{"vip.example.test", "api.example.test"},
			IPAddresses: []string{"192.0.2.10"},
		}
	}
	install := func(jobID int64) (connector.ApplianceKey, string) {
		t.Helper()
		req := request(jobID)
		key, _, err := connector.RunApplianceKey(ctx, c, ops, req)
		if err != nil {
			t.Fatalf("generate the key on the firewall: %v", err)
		}
		if !srv.DeviceKey(req.ObjectName) || !srv.Pending(req.ObjectName) {
			t.Fatalf("the firewall holds no pending key object %s", req.ObjectName)
		}
		block, _ := pem.Decode(key.CSRPEM)
		info, err := crypto.InspectCSR(block.Bytes)
		if err != nil || info.CommonName != "vip.example.test" || !slices.Equal(info.DNSNames, req.DNSNames) || len(info.IPAddresses) != 1 {
			t.Fatalf("CSR names = %+v %v", info, err)
		}
		again, _, err := connector.RunApplianceKey(ctx, c, ops, req)
		if err != nil || !bytes.Equal(again.CSRPEM, key.CSRPEM) {
			t.Fatalf("a second request for the same object = %v, want the same CSR", err)
		}
		certPEM := signPANCSR(t, key.CSRPEM)
		fp := connector.CertificateFingerprint(certPEM)
		if _, err := connector.RunApplianceInstall(ctx, c, ops, connector.Deployment{Target: certName, CertPEM: certPEM, Fingerprint: fp}, key); err != nil {
			t.Fatalf("install against the firewall key: %v", err)
		}
		if srv.Pending(req.ObjectName) || srv.ProfileCertificate(panProfile) != req.ObjectName {
			t.Fatalf("after the install the object is pending %v and the profile names %q", srv.Pending(req.ObjectName), srv.ProfileCertificate(panProfile))
		}
		return key, fp
	}
	first, firstFP := install(41)
	second, secondFP := install(42)
	if got, err := connector.RunReadback(ctx, c, ops, certName); err != nil || connector.ClassifyReadback(got, secondFP) != connector.ReadbackServing {
		t.Fatalf("readback = %+v %v, want the second certificate serving", got, err)
	}
	if _, err := connector.RunRollback(ctx, c, ops, connector.Rollback{
		Target: certName, PredecessorFingerprint: firstFP, PredecessorKeyObject: first.ObjectName,
	}); err != nil {
		t.Fatalf("roll back to the first firewall key: %v", err)
	}
	if got := srv.ProfileCertificate(panProfile); got != first.ObjectName {
		t.Fatalf("profile after the rollback = %q, want %q", got, first.ObjectName)
	}
	if got, err := connector.RunReadback(ctx, c, ops, certName); err != nil || connector.ClassifyReadback(got, firstFP) != connector.ReadbackServing {
		t.Fatalf("readback after the rollback = %+v %v, want the first certificate serving", got, err)
	}
	if _, _, err := connector.RunApplianceKey(ctx, c, ops, request(42)); !errors.Is(err, connector.ErrApplianceKeyAlreadyInstalled) {
		t.Fatalf("a reclaim after the install = %v, want ErrApplianceKeyAlreadyInstalled", err)
	}
	if _, err := connector.RunRollback(ctx, c, ops, connector.Rollback{
		Target: certName, PredecessorFingerprint: firstFP, PredecessorKeyObject: second.ObjectName,
	}); !errors.Is(err, connector.ErrNoPredecessorInstalled) {
		t.Fatalf("rollback to an object holding another certificate = %v, want ErrNoPredecessorInstalled", err)
	}
	srv.Remove(second.ObjectName)
	if _, err := connector.RunRollback(ctx, c, ops, connector.Rollback{
		Target: certName, PredecessorFingerprint: secondFP, PredecessorKeyObject: second.ObjectName,
	}); !errors.Is(err, connector.ErrNoPredecessorInstalled) {
		t.Fatalf("rollback to an object that is gone = %v, want ErrNoPredecessorInstalled", err)
	}
	if srv.KeyExports() != 0 {
		t.Fatalf("the connector asked to export a firewall key %d times", srv.KeyExports())
	}
}

// A certificate for another key is refused by the firewall and leaves the
// profile alone; an install carrying a private key, an object name a job was
// not assigned, and a target without an SSL/TLS service profile are refused
// before any call; names reach the firewall XML-escaped.
func TestPANOSApplianceKeyRefusals(t *testing.T) {
	srv := paloaltotest.New(testAPIKey)
	defer srv.Close()
	c := paloalto.New(srv.URL(), testAPIKey, paloalto.WithSSLTLSProfile(panProfile, "trstctl"))
	t.Cleanup(c.Close)
	ops := connector.NewHTTPOps(srv.Client())
	ctx := context.Background()

	key, _, err := connector.RunApplianceKey(ctx, c, ops, connector.ApplianceKeyRequest{
		ObjectName: connector.ApplianceKeyObjectName(panTargetID, 43), CommonName: "a<b>&c.example.test",
	})
	if err != nil {
		t.Fatalf("generate with markup in the common name: %v", err)
	}
	block, _ := pem.Decode(key.CSRPEM)
	if info, err := crypto.InspectCSR(block.Bytes); err != nil || info.CommonName != "a<b>&c.example.test" {
		t.Fatalf("CSR common name = %+v %v, want the name escaped and intact", info, err)
	}
	other, err := crypto.GenerateHostSubjectKey("vip.example.test", []string{"vip.example.test"})
	if err != nil {
		t.Fatal(err)
	}
	defer other.Destroy()
	foreign := signPANCSR(t, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: other.CSRDER}))
	dep := connector.Deployment{Target: certName, CertPEM: foreign, Fingerprint: connector.CertificateFingerprint(foreign)}
	if _, err := connector.RunApplianceInstall(ctx, c, ops, dep, key); err == nil {
		t.Fatal("a certificate for another key was imported into the firewall's key object")
	}
	if got := srv.ProfileCertificate(panProfile); got != "" || !srv.Pending(key.ObjectName) {
		t.Fatalf("the refused install left profile %q and pending %v", got, srv.Pending(key.ObjectName))
	}

	before := len(srv.Queries())
	dep.KeyPEM = []byte("-----BEGIN PRIVATE KEY-----")
	if _, err := connector.RunApplianceInstall(ctx, c, ops, dep, key); err == nil {
		t.Fatal("an appliance-key install carrying a private key was accepted")
	}
	if _, _, err := connector.RunApplianceKey(ctx, c, ops, connector.ApplianceKeyRequest{ObjectName: "web-prod", CommonName: "vip.example.test"}); err == nil {
		t.Fatal("a key was generated into an object name no job was assigned")
	}
	bare := paloalto.New(srv.URL(), testAPIKey)
	t.Cleanup(bare.Close)
	if _, _, err := connector.RunApplianceKey(ctx, bare, ops, connector.ApplianceKeyRequest{
		ObjectName: connector.ApplianceKeyObjectName(panTargetID, 44), CommonName: "vip.example.test",
	}); err == nil {
		t.Fatal("a target without an SSL/TLS service profile generated a key on the firewall")
	}
	if after := len(srv.Queries()); after != before {
		t.Fatalf("refused requests reached the firewall %d times", after-before)
	}
}
