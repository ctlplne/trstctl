// SPDX-License-Identifier: BUSL-1.1

package cisco_test

import (
	"bytes"
	"context"
	"encoding/pem"
	"errors"
	"slices"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/connector"
	"trstctl.com/trstctl/internal/connector/cisco"
	"trstctl.com/trstctl/internal/connector/cisco/ciscotest"
	"trstctl.com/trstctl/internal/crypto"
)

func signISECSR(t *testing.T, csrPEM []byte) []byte {
	t.Helper()
	block, _ := pem.Decode(csrPEM)
	if block == nil || block.Type != "CERTIFICATE REQUEST" {
		t.Fatalf("ISE returned no PEM CSR: %q", csrPEM)
	}
	ca, err := crypto.GenerateLockedKey(crypto.ECDSAP256)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(ca.Destroy)
	caDER, err := crypto.SelfSignedCACert(ca, "ISE Appliance Test CA", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	leafDER, err := crypto.SignLeafFromCSR(caDER, ca, block.Bytes, time.Hour)
	if err != nil {
		t.Fatalf("sign the ISE CSR: %v", err)
	}
	// Leaf then CA, as the relay assembles a serving chain; the bind sends
	// the leaf alone.
	return append(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: leafDER}),
		pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER})...)
}

// A122 (owner decision 2026-10-26): ISE generates the key and CSR on the node
// and names the request itself; the request ID comes back as the reference,
// and a request for that reference returns the same CSR instead of a new one.
// Binding the signed certificate makes a fingerprint-named system certificate
// holding ISE's key with the target's roles, readback sees it serving, a
// rollback moves the roles back to an earlier one, and a recorded request that
// is gone stops rather than making a second key.
func TestISEGeneratesTheKeyOnTheNodeAndReusesItsRequest(t *testing.T) {
	srv := ciscotest.New(user, []byte(pass))
	defer srv.Close()
	c := iseConnector(t, srv, "eap")
	ops := connector.NewHTTPOps(srv.Client())
	ctx := context.Background()

	install := func(job int64) (connector.ApplianceKey, string) {
		t.Helper()
		req := connector.ApplianceKeyRequest{
			ObjectName: connector.ApplianceKeyObjectName("4b8a9c1d-5e6f-4a7b-8c0d-0f3c9a712d4e", job),
			CommonName: "radius.example.test", DNSNames: []string{"radius.example.test"}, IPAddresses: []string{"192.0.2.20"},
		}
		key, _, err := connector.RunApplianceKey(ctx, c, ops, req)
		if err != nil || key.Reference == "" {
			t.Fatalf("generate on ISE = %+v, %v", key, err)
		}
		block, _ := pem.Decode(key.CSRPEM)
		info, err := crypto.InspectCSR(block.Bytes)
		if err != nil || info.CommonName != "radius.example.test" || !slices.Equal(info.DNSNames, req.DNSNames) || len(info.IPAddresses) != 1 {
			t.Fatalf("CSR names = %+v %v", info, err)
		}
		req.Reference = key.Reference
		before := srv.CSRsGenerated()
		again, _, err := connector.RunApplianceKey(ctx, c, ops, req)
		if err != nil || again.Reference != key.Reference || !bytes.Equal(again.CSRPEM, key.CSRPEM) || srv.CSRsGenerated() != before {
			t.Fatalf("a request for the recorded reference = %+v, %v (requests %d → %d); want the same CSR", again, err, before, srv.CSRsGenerated())
		}
		chain := signISECSR(t, key.CSRPEM)
		fp := connector.CertificateFingerprint(chain)
		if _, err := connector.RunApplianceInstall(ctx, c, ops, connector.Deployment{Target: name, CertPEM: chain, Fingerprint: fp}, key); err != nil {
			t.Fatalf("bind on ISE: %v", err)
		}
		if srv.RoleHolder("eap") != connector.DeployedObjectName(name, fp) || srv.PendingCSRs() != 0 {
			t.Fatalf("after the bind the EAP role is on %q with %d requests pending", srv.RoleHolder("eap"), srv.PendingCSRs())
		}
		if _, _, err := connector.RunApplianceKey(ctx, c, ops, req); !errors.Is(err, connector.ErrApplianceKeyAlreadyInstalled) {
			t.Fatalf("a retry after the bind = %v, want ErrApplianceKeyAlreadyInstalled", err)
		}
		return key, fp
	}
	_, firstFP := install(81)
	_, secondFP := install(82)
	for _, sc := range srv.SystemCertificates() {
		if !sc.DeviceKey || len(sc.PrivateKey) != 0 {
			t.Fatalf("system certificate %+v was not made with ISE's own key", sc)
		}
	}
	if got, err := connector.RunReadback(ctx, c, ops, name); err != nil || connector.ClassifyReadback(got, secondFP) != connector.ReadbackServing {
		t.Fatalf("readback = %+v %v, want the second certificate serving", got, err)
	}
	if _, err := connector.RunRollback(ctx, c, ops, connector.Rollback{Target: name, PredecessorFingerprint: firstFP}); err != nil {
		t.Fatalf("rollback to the first ISE-generated certificate: %v", err)
	}
	if srv.RoleHolder("eap") != connector.DeployedObjectName(name, firstFP) {
		t.Fatalf("EAP role after the rollback is on %q", srv.RoleHolder("eap"))
	}
}

// ISE refuses a certificate for any other key; an install carrying a key or no
// request ID and a target without a node are refused before any call.
func TestISEApplianceKeyRefusals(t *testing.T) {
	srv := ciscotest.New(user, []byte(pass))
	defer srv.Close()
	c := iseConnector(t, srv, "admin")
	ops := connector.NewHTTPOps(srv.Client())
	ctx := context.Background()
	key, _, err := connector.RunApplianceKey(ctx, c, ops, connector.ApplianceKeyRequest{
		ObjectName: "trstctl-4b8a9c1d-j90", CommonName: "ise.example.test",
	})
	if err != nil {
		t.Fatal(err)
	}
	other, err := crypto.GenerateHostSubjectKey("ise.example.test", []string{"ise.example.test"})
	if err != nil {
		t.Fatal(err)
	}
	defer other.Destroy()
	foreign := signISECSR(t, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: other.CSRDER}))
	dep := connector.Deployment{Target: name, CertPEM: foreign, Fingerprint: connector.CertificateFingerprint(foreign)}
	if _, err := connector.RunApplianceInstall(ctx, c, ops, dep, key); err == nil {
		t.Fatal("a certificate for another key was bound to ISE's request")
	}
	if srv.RoleHolder("admin") != "" || srv.PendingCSRs() != 1 {
		t.Fatalf("the refused bind left admin on %q and %d requests pending", srv.RoleHolder("admin"), srv.PendingCSRs())
	}
	calls := srv.Calls()
	withKey := dep
	withKey.KeyPEM = []byte("-----BEGIN PRIVATE KEY-----")
	if _, err := connector.RunApplianceInstall(ctx, c, ops, withKey, key); err == nil {
		t.Fatal("an appliance-key install carrying a private key was accepted")
	}
	if _, err := connector.RunApplianceInstall(ctx, c, ops, dep, connector.ApplianceKey{ObjectName: key.ObjectName}); err == nil {
		t.Fatal("an install without the ISE request ID was accepted")
	}
	legacy := cisco.New(srv.URL(), user, []byte(pass))
	defer legacy.Close()
	if _, _, err := connector.RunApplianceKey(ctx, legacy, ops, connector.ApplianceKeyRequest{ObjectName: "trstctl-4b8a9c1d-j91", CommonName: "x"}); err == nil {
		t.Fatal("a target without an ISE node generated a key")
	}
	if srv.Calls() != calls {
		t.Fatalf("refused requests reached ISE %d times", srv.Calls()-calls)
	}
}
