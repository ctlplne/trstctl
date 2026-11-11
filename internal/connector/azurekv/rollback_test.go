// SPDX-License-Identifier: BUSL-1.1

package azurekv_test

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"net/http"
	"strings"
	"testing"

	"trstctl.com/trstctl/internal/connector"
	"trstctl.com/trstctl/internal/connector/azurekv"
	"trstctl.com/trstctl/internal/connector/azurekv/azurekvtest"
)

func kvCert(label string) []byte {
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: []byte("kv-leaf-" + label)})
}

func kvKey(label string) []byte {
	return pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: []byte("kv-key-" + label)})
}

// A166-L1: Key Vault serves the newest version of a certificate by name, so a
// rollback makes the predecessor current again by importing that version's own
// retained secret as the newest version. Readback reports what the vault serves
// before and after; the predecessor's key comes from the vault, read once.
func TestRollbackReimportsThePredecessorVersionA166L1(t *testing.T) {
	srv := azurekvtest.New(token)
	defer srv.Close()
	c := azurekv.New(srv.URL(), azurekv.StaticToken([]byte(token)))
	ops := connector.NewHTTPOps(srv.Client())
	ctx := context.Background()
	predecessor, successor := kvCert("predecessor"), kvCert("successor")
	for _, dep := range []connector.Deployment{
		connector.NewDeployment(certName, predecessor, kvKey("predecessor")),
		connector.NewDeployment(certName, successor, kvKey("successor")),
	} {
		if _, err := connector.Run(ctx, c, ops, dep); err != nil {
			t.Fatal(err)
		}
	}
	if got := srv.Versions(certName); len(got) != 2 || !got[0].Exportable || !got[1].Exportable {
		t.Fatalf("versions after two deploys = %+v; want two exportable versions", got)
	}
	installed, err := connector.RunReadback(ctx, c, ops, certName)
	if err != nil || installed.Fingerprint != connector.CertificateFingerprint(successor) || installed.ObjectName != certName {
		t.Fatalf("readback before the rollback = %+v %v; want the successor", installed, err)
	}
	if _, err := connector.RunRollback(ctx, c, ops, connector.Rollback{Target: certName, PredecessorFingerprint: connector.CertificateFingerprint(predecessor)}); err != nil {
		t.Fatalf("rollback: %v", err)
	}
	versions := srv.Versions(certName)
	if len(versions) != 3 || !bytes.Contains(versions[2].PEM, predecessor) || !bytes.Contains(versions[2].PEM, kvKey("predecessor")) ||
		versions[2].ContentType != "application/x-pem-file" || !versions[2].Exportable {
		t.Fatalf("versions after the rollback = %d, newest %q; want the predecessor's key and chain imported again", len(versions), versions[len(versions)-1].PEM)
	}
	if srv.SecretReads() != 1 {
		t.Fatalf("secret reads = %d; want the predecessor version's alone", srv.SecretReads())
	}
	installed, err = connector.RunReadback(ctx, c, ops, certName)
	if err != nil || installed.Fingerprint != connector.CertificateFingerprint(predecessor) {
		t.Fatalf("readback after the rollback = %+v %v; want the predecessor", installed, err)
	}
	if !connector.CanRollback("azure-keyvault") || !connector.RollbackReimports("azure-keyvault") || connector.RollbackUnsupportedReason("azure-keyvault") != "" {
		t.Fatal("the rollback census does not list Key Vault as re-importing its predecessor")
	}
}

// A rollback whose predecessor no retained version holds imports nothing and
// says the predecessor is gone; one whose predecessor's key the vault will not
// return (not exportable) imports nothing and says why.
func TestRollbackRefusesAMissingOrUnexportablePredecessorA166L1(t *testing.T) {
	srv := azurekvtest.New(token)
	defer srv.Close()
	c := azurekv.New(srv.URL(), azurekv.StaticToken([]byte(token)))
	ops := connector.NewHTTPOps(srv.Client())
	ctx := context.Background()
	if _, err := connector.Run(ctx, c, ops, connector.NewDeployment(certName, kvCert("only"), kvKey("only"))); err != nil {
		t.Fatal(err)
	}
	_, err := connector.RunRollback(ctx, c, ops, connector.Rollback{Target: certName, PredecessorFingerprint: connector.CertificateFingerprint(kvCert("never-deployed"))})
	if !errors.Is(err, connector.ErrNoPredecessorInstalled) || len(srv.Versions(certName)) != 1 {
		t.Fatalf("a predecessor no version holds = %v, %d versions; want ErrNoPredecessorInstalled and nothing imported", err, len(srv.Versions(certName)))
	}

	// A version imported with a key that is not exportable, as an operator's
	// own import with that policy would be.
	locked := kvCert("locked")
	body := `{"value":"` + base64.StdEncoding.EncodeToString(append(kvKey("locked"), locked...)) +
		`","policy":{"key_props":{"exportable":false},"secret_props":{"contentType":"application/x-pem-file"}}}`
	req, err := http.NewRequest(http.MethodPut, srv.URL()+"/certificates/"+certName+"/import?api-version=7.4", strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", "Bearer "+token)
	resp, err := srv.Client().Do(req)
	if err != nil || resp.StatusCode != http.StatusOK {
		t.Fatalf("import a non-exportable version: %v", err)
	}
	_ = resp.Body.Close()
	if _, err := connector.Run(ctx, c, ops, connector.NewDeployment(certName, kvCert("after"), kvKey("after"))); err != nil {
		t.Fatal(err)
	}
	before := len(srv.Versions(certName))
	_, err = connector.RunRollback(ctx, c, ops, connector.Rollback{Target: certName, PredecessorFingerprint: connector.CertificateFingerprint(locked)})
	if err == nil || !strings.Contains(err.Error(), "not exportable") || len(srv.Versions(certName)) != before {
		t.Fatalf("a non-exportable predecessor = %v, %d versions (was %d); want refused with the reason and nothing imported", err, len(srv.Versions(certName)), before)
	}
}
