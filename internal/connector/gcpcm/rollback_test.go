// SPDX-License-Identifier: BUSL-1.1

package gcpcm_test

import (
	"context"
	"errors"
	"strings"
	"testing"

	"trstctl.com/trstctl/internal/connector"
	"trstctl.com/trstctl/internal/connector/gcpcm"
	"trstctl.com/trstctl/internal/connector/gcpcm/gcpcmtest"
)

const mapEntry = "web-map/web-entry"

var (
	secondCert = []byte("-----BEGIN CERTIFICATE-----\ngcp-leaf-2\n-----END CERTIFICATE-----\n")
	secondKey  = []byte("-----BEGIN PRIVATE KEY-----\ngcp-key-2\n-----END PRIVATE KEY-----\n")
)

func newMapEntryConn(t *testing.T, endpoint string) *gcpcm.Connector {
	t.Helper()
	entry, err := gcpcm.ParseCertificateMapEntry(mapEntry)
	if err != nil {
		t.Fatal(err)
	}
	return gcpcm.New(project, location, gcpcm.StaticToken([]byte(token)),
		gcpcm.WithEndpoint(endpoint), gcpcm.WithPollInterval(0), gcpcm.WithCertificateMapEntry(entry))
}

// A58: with a certificate map entry configured, each deploy creates a
// fingerprint-named Certificate resource and points the map entry at it, so
// the predecessor stays on the project and a rollback re-points the entry back
// to it without uploading any key. The predecessor must still exist; a missing
// one fails rather than reporting a rollback that changed nothing.
func TestDeployWithMapEntryIsFingerprintNamedAndRollbackRepointsTheEntry(t *testing.T) {
	srv := gcpcmtest.New(token)
	defer srv.Close()
	ops := connector.NewHTTPOps(srv.Client())
	c := newMapEntryConn(t, srv.URL())

	first := connector.NewDeployment(certID, sampleCert, sampleKey)
	if _, err := connector.Run(context.Background(), c, ops, first); err != nil {
		t.Fatalf("first deploy: %v", err)
	}
	second := connector.NewDeployment(certID, secondCert, secondKey)
	if _, err := connector.Run(context.Background(), c, ops, second); err != nil {
		t.Fatalf("second deploy: %v", err)
	}
	firstName := connector.DeployedObjectName(certID, first.Fingerprint)
	secondName := connector.DeployedObjectName(certID, second.Fingerprint)
	if _, ok := srv.Imported(firstName); !ok {
		t.Fatalf("the first deploy did not create certificate %q", firstName)
	}
	if _, ok := srv.Imported(secondName); !ok {
		t.Fatalf("the second deploy did not create certificate %q", secondName)
	}
	if _, ok := srv.Imported(certID); ok {
		t.Fatalf("a map-entry deploy patched the target-named certificate %q in place", certID)
	}
	if bound := srv.MapEntry(mapEntry); len(bound) != 1 || !strings.HasSuffix(bound[0], "/certificates/"+secondName) {
		t.Fatalf("map entry after two deploys = %v, want the second fingerprint-named certificate", bound)
	}

	installed, err := connector.RunReadback(context.Background(), c, ops, certID)
	if err != nil {
		t.Fatalf("readback: %v", err)
	}
	if !installed.Bound || installed.ObjectName != secondName || installed.Fingerprint != connector.FingerprintFromObjectName(secondName) {
		t.Fatalf("readback = %+v, want the bound second certificate", installed)
	}

	stats, result, err := connector.RunRollbackWithResult(context.Background(), c, ops, connector.Rollback{
		Target: certID, PredecessorFingerprint: first.Fingerprint, Reason: "drill",
	})
	if err != nil {
		t.Fatalf("rollback: %v", err)
	}
	if result.LegacyObject {
		t.Fatal("a fingerprint-named predecessor was reported as a legacy object")
	}
	if stats.Denied != 0 {
		t.Fatalf("rollback was denied %d operations outside its grant", stats.Denied)
	}
	if bound := srv.MapEntry(mapEntry); len(bound) != 1 || !strings.HasSuffix(bound[0], "/certificates/"+firstName) {
		t.Fatalf("map entry after rollback = %v, want the predecessor %q", bound, firstName)
	}
	if srv.PatchCalls() != 0 {
		t.Fatalf("map-entry deploys and rollback patched a certificate in place %d times", srv.PatchCalls())
	}
	if got := srv.UploadedKeys(); got != 2 {
		t.Fatalf("private keys uploaded = %d, want 2 (one per deploy, none for rollback)", got)
	}

	// A predecessor the project no longer holds cannot be re-bound.
	_, err = connector.RunRollback(context.Background(), c, ops, connector.Rollback{
		Target: certID, PredecessorFingerprint: "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
	})
	if !errors.Is(err, connector.ErrNoPredecessorInstalled) {
		t.Fatalf("rollback to a missing certificate = %v, want ErrNoPredecessorInstalled", err)
	}
	if bound := srv.MapEntry(mapEntry); len(bound) != 1 || !strings.HasSuffix(bound[0], "/certificates/"+firstName) {
		t.Fatalf("a failed rollback moved the map entry: %v", bound)
	}
}

// A deploy under the same fingerprint-named certificate is idempotent: the
// second attempt finds the resource and re-points the entry without failing.
func TestMapEntryDeployIsIdempotent(t *testing.T) {
	srv := gcpcmtest.New(token)
	defer srv.Close()
	ops := connector.NewHTTPOps(srv.Client())
	c := newMapEntryConn(t, srv.URL())
	dep := connector.NewDeployment(certID, sampleCert, sampleKey)
	for i := 0; i < 2; i++ {
		if _, err := connector.Run(context.Background(), c, ops, dep); err != nil {
			t.Fatalf("deploy %d: %v", i, err)
		}
	}
	if srv.CreateCalls() != 2 {
		t.Fatalf("create calls = %d, want 2 (the second is refused as already existing and tolerated)", srv.CreateCalls())
	}
	name := connector.DeployedObjectName(certID, dep.Fingerprint)
	if bound := srv.MapEntry(mapEntry); len(bound) != 1 || !strings.HasSuffix(bound[0], "/certificates/"+name) {
		t.Fatalf("map entry = %v, want %q", bound, name)
	}
}

// Without a certificate map entry the connector keeps its in-place patch of the
// target-named certificate, which leaves no predecessor to re-bind, so rollback
// and readback are refused as not configured rather than reported as done.
func TestWithoutMapEntryRollbackAndReadbackAreNotConfigured(t *testing.T) {
	srv := gcpcmtest.New(token)
	defer srv.Close()
	ops := connector.NewHTTPOps(srv.Client())
	legacy := newConn(srv.URL())
	if !connector.CanRollback("gcp-certificate-manager") {
		t.Error("the rollback census no longer lists gcp-certificate-manager; with a certificate map entry it re-points the entry")
	}
	if !connector.CanReadback("gcp-certificate-manager") {
		t.Error("the readback census no longer lists gcp-certificate-manager")
	}
	dep := connector.NewDeployment(certID, sampleCert, sampleKey)
	if _, err := connector.Run(context.Background(), legacy, ops, dep); err != nil {
		t.Fatalf("deploy: %v", err)
	}
	if _, ok := srv.Imported(certID); !ok {
		t.Fatal("a deploy without a map entry did not patch the target-named certificate")
	}
	if _, err := connector.RunRollback(context.Background(), legacy, ops, connector.Rollback{Target: certID, PredecessorFingerprint: dep.Fingerprint}); !errors.Is(err, connector.ErrRollbackNotConfigured) {
		t.Fatalf("rollback without a map entry = %v, want ErrRollbackNotConfigured", err)
	}
	if _, err := connector.RunReadback(context.Background(), legacy, ops, certID); !errors.Is(err, connector.ErrReadbackNotConfigured) {
		t.Fatalf("readback without a map entry = %v, want ErrReadbackNotConfigured", err)
	}
	for _, bad := range []string{"web-map", "web-map/", "/entry", "Web-Map/entry", "a/b/c", "web map/entry"} {
		if _, err := gcpcm.ParseCertificateMapEntry(bad); err == nil {
			t.Errorf("certificate map entry %q was accepted", bad)
		}
	}
	entry, err := gcpcm.ParseCertificateMapEntry(" web-map/web-entry ")
	if err != nil || entry.Map != "web-map" || entry.Entry != "web-entry" {
		t.Fatalf("parse = %+v %v", entry, err)
	}
}

// Certificate Manager ids are at most 63 lowercase characters; a target whose
// fingerprint-named id would not fit is refused before anything is uploaded.
func TestMapEntryDeployRefusesATargetNameThatCannotCarryAFingerprint(t *testing.T) {
	srv := gcpcmtest.New(token)
	defer srv.Close()
	ops := connector.NewHTTPOps(srv.Client())
	c := newMapEntryConn(t, srv.URL())
	long := strings.Repeat("a", 51)
	if _, err := connector.Run(context.Background(), c, ops, connector.NewDeployment(long, sampleCert, sampleKey)); err == nil || !strings.Contains(err.Error(), "50 characters") {
		t.Fatalf("deploy with a 51-character target = %v, want a refusal naming the limit", err)
	}
	if srv.CreateCalls() != 0 || srv.UploadedKeys() != 0 {
		t.Fatal("a refused deploy still contacted Certificate Manager")
	}
}
