// SPDX-License-Identifier: BUSL-1.1

package paloalto_test

import (
	"context"
	"errors"
	"testing"

	"trstctl.com/trstctl/internal/connector"
	"trstctl.com/trstctl/internal/connector/paloalto"
	"trstctl.com/trstctl/internal/connector/paloalto/paloaltotest"
)

// Re-bind rollback (A44). With an SSL/TLS service profile configured the
// connector imports each certificate under a fingerprint-carrying name, sets
// the profile's certificate to it and commits; rollback sets the profile back
// to the predecessor that is still on the firewall and commits again.
func TestRollbackRebindsTheSSLTLSProfileToThePredecessor(t *testing.T) {
	srv := paloaltotest.New(testAPIKey)
	defer srv.Close()
	c := paloalto.New(srv.URL(), testAPIKey, paloalto.WithSSLTLSProfile("web-profile", "trstctl"))
	t.Cleanup(c.Close)
	ops := connector.NewHTTPOps(srv.Client())

	firstCert := []byte("-----BEGIN CERTIFICATE-----\npan-leaf-one\n-----END CERTIFICATE-----\n")
	secondCert := []byte("-----BEGIN CERTIFICATE-----\npan-leaf-two\n-----END CERTIFICATE-----\n")
	first := connector.NewDeployment("web", firstCert, sampleKey)
	second := connector.NewDeployment("web", secondCert, sampleKey)
	for _, dep := range []connector.Deployment{first, second} {
		if _, err := connector.Run(context.Background(), c, ops, dep); err != nil {
			t.Fatalf("deploy: %v", err)
		}
	}
	firstName := connector.DeployedObjectName("web", first.Fingerprint)
	secondName := connector.DeployedObjectName("web", second.Fingerprint)
	if _, ok := srv.Object(firstName); !ok {
		t.Fatalf("the predecessor %q did not survive the second deploy", firstName)
	}
	if got := srv.ProfileCertificate("web-profile"); got != secondName {
		t.Fatalf("profile certificate = %q, want %q", got, secondName)
	}
	imports, commits := len(srv.Imports()), srv.Commits()
	if commits != 2 || srv.CommitAdmins()[0] != "trstctl" {
		t.Fatalf("commits after two deploys = %d admins %v, want 2 partial commits scoped to trstctl", commits, srv.CommitAdmins())
	}

	if _, err := connector.RunRollback(context.Background(), c, ops, connector.Rollback{Target: "web", PredecessorFingerprint: first.Fingerprint}); err != nil {
		t.Fatalf("rollback: %v", err)
	}
	if got := srv.ProfileCertificate("web-profile"); got != firstName {
		t.Fatalf("after rollback profile certificate = %q, want %q", got, firstName)
	}
	installed, err := connector.RunReadback(context.Background(), c, ops, "web")
	if err != nil || !installed.Bound || installed.ObjectName != firstName {
		t.Fatalf("readback after rollback = %+v err=%v; want the predecessor bound", installed, err)
	}
	if len(srv.Imports()) != imports || srv.Commits() != commits+1 {
		t.Fatalf("rollback imported material or skipped the commit: imports %d->%d commits %d->%d", imports, len(srv.Imports()), commits, srv.Commits())
	}
	if _, err := connector.RunRollback(context.Background(), c, ops, connector.Rollback{Target: "web", PredecessorFingerprint: "0000000000000000"}); !errors.Is(err, connector.ErrNoPredecessorInstalled) {
		t.Fatalf("rollback to an absent object = %v, want ErrNoPredecessorInstalled", err)
	}

	half := paloalto.New(srv.URL(), testAPIKey, paloalto.WithSSLTLSProfile("web-profile", ""))
	t.Cleanup(half.Close)
	if _, err := connector.Run(context.Background(), half, ops, first); err == nil {
		t.Fatal("a profile without commit_admin deployed; the partial commit would have no scope")
	}
	legacy := paloalto.New(srv.URL(), testAPIKey)
	t.Cleanup(legacy.Close)
	if _, err := connector.RunRollback(context.Background(), legacy, ops, connector.Rollback{Target: "web", PredecessorFingerprint: first.Fingerprint}); !errors.Is(err, connector.ErrRollbackNotConfigured) {
		t.Fatalf("rollback without ssl_tls_profile = %v, want ErrRollbackNotConfigured", err)
	}
	if _, err := connector.RunReadback(context.Background(), legacy, ops, "web"); !errors.Is(err, connector.ErrReadbackNotConfigured) {
		t.Fatalf("readback without ssl_tls_profile = %v, want ErrReadbackNotConfigured", err)
	}
}
