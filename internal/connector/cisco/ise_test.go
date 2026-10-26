// SPDX-License-Identifier: BUSL-1.1

package cisco_test

import (
	"bytes"
	"context"
	"errors"
	"net/http"
	"strings"
	"testing"

	"trstctl.com/trstctl/internal/connector"
	"trstctl.com/trstctl/internal/connector/cisco"
	"trstctl.com/trstctl/internal/connector/cisco/ciscotest"
)

func iseConnector(t *testing.T, srv *ciscotest.Server, roles ...string) *cisco.Connector {
	t.Helper()
	c := cisco.New(srv.URL(), user, []byte(pass), cisco.WithISENode(srv.Node(), roles))
	t.Cleanup(c.Close)
	return c
}

func iseDeployment(label string) connector.Deployment {
	cert := []byte("-----BEGIN CERTIFICATE-----\nise-" + label + "\n-----END CERTIFICATE-----\n")
	return connector.NewDeployment(name, cert, sampleKey)
}

// A122 (owner decision 2026-10-26): with node_hostname and certificate_roles,
// each deploy imports a fingerprint-named ISE system certificate bound to the
// roles, the predecessor stays in the node's store, readback reports the
// certificate serving the roles, and rollback moves the roles back without
// uploading anything. A predecessor that is gone is refused.
func TestISEDeploysRebindsAndReadsBackByRole(t *testing.T) {
	srv := ciscotest.New(user, []byte(pass))
	defer srv.Close()
	c := iseConnector(t, srv, "admin", "eap")
	ops := connector.NewHTTPOps(srv.Client())
	ctx := context.Background()

	first, second := iseDeployment("one"), iseDeployment("two")
	for _, dep := range []connector.Deployment{first, second} {
		if _, err := connector.Run(ctx, c, ops, dep); err != nil {
			t.Fatalf("ISE deploy: %v", err)
		}
	}
	firstName := connector.DeployedObjectName(name, first.Fingerprint)
	secondName := connector.DeployedObjectName(name, second.Fingerprint)
	if srv.RoleHolder("admin") != secondName || srv.RoleHolder("eap") != secondName {
		t.Fatalf("roles after two deploys: admin=%q eap=%q, want %q", srv.RoleHolder("admin"), srv.RoleHolder("eap"), secondName)
	}
	if len(srv.SystemCertificates()) != 2 {
		t.Fatalf("system store = %+v, want both certificates kept", srv.SystemCertificates())
	}
	got, err := connector.RunReadback(ctx, c, ops, name)
	if err != nil || connector.ClassifyReadback(got, second.Fingerprint) != connector.ReadbackServing {
		t.Fatalf("readback = %+v %v, want the second certificate serving", got, err)
	}

	calls := srv.Calls()
	if _, err := connector.RunRollback(ctx, c, ops, connector.Rollback{Target: name, PredecessorFingerprint: first.Fingerprint}); err != nil {
		t.Fatalf("rollback: %v", err)
	}
	if srv.RoleHolder("admin") != firstName || srv.RoleHolder("eap") != firstName {
		t.Fatalf("roles after rollback: admin=%q eap=%q, want %q", srv.RoleHolder("admin"), srv.RoleHolder("eap"), firstName)
	}
	for _, sc := range srv.SystemCertificates() {
		if sc.FriendlyName == firstName && !bytes.Equal(sc.Certificate, first.CertPEM) {
			t.Fatal("rollback re-uploaded the predecessor")
		}
	}
	if srv.Calls()-calls != 2 {
		t.Fatalf("rollback made %d calls, want a list and one role move", srv.Calls()-calls)
	}
	if got, err := connector.RunReadback(ctx, c, ops, name); err != nil || connector.ClassifyReadback(got, first.Fingerprint) != connector.ReadbackServing {
		t.Fatalf("readback after rollback = %+v %v", got, err)
	}

	srv.RemoveSystemCertificate(secondName)
	if _, err := connector.RunRollback(ctx, c, ops, connector.Rollback{Target: name, PredecessorFingerprint: second.Fingerprint}); !errors.Is(err, connector.ErrNoPredecessorInstalled) {
		t.Fatalf("rollback to a removed certificate = %v, want ErrNoPredecessorInstalled", err)
	}
}

// A certificate serving only some of the target's roles reads back as
// installed but not bound, and a target without a node keeps the legacy import
// and says its rollback and readback are not configured.
func TestISEReadbackAndLegacyTargets(t *testing.T) {
	srv := ciscotest.New(user, []byte(pass))
	defer srv.Close()
	ops := connector.NewHTTPOps(srv.Client())
	ctx := context.Background()

	dep := iseDeployment("partial")
	if _, err := connector.Run(ctx, iseConnector(t, srv, "admin", "portal"), ops, dep); err != nil {
		t.Fatalf("ISE deploy with the portal role: %v", err)
	}
	if _, err := connector.Run(ctx, iseConnector(t, srv, "portal"), ops, iseDeployment("portal-only")); err != nil {
		t.Fatal(err)
	}
	got, err := connector.RunReadback(ctx, iseConnector(t, srv, "admin", "portal"), ops, name)
	if err != nil || connector.ClassifyReadback(got, dep.Fingerprint) != connector.ReadbackInstalledNotBound {
		t.Fatalf("readback with the portal role moved away = %+v %v, want installed but not bound", got, err)
	}

	legacy := newConnector(t, srv.URL(), []byte(pass))
	if _, err := connector.RunRollback(ctx, legacy, ops, connector.Rollback{Target: name, PredecessorFingerprint: dep.Fingerprint}); !errors.Is(err, connector.ErrRollbackNotConfigured) {
		t.Fatalf("legacy rollback = %v, want ErrRollbackNotConfigured", err)
	}
	if _, err := connector.RunReadback(ctx, legacy, ops, name); !errors.Is(err, connector.ErrReadbackNotConfigured) {
		t.Fatalf("legacy readback = %v, want ErrReadbackNotConfigured", err)
	}
	for _, bad := range []struct {
		node  string
		roles []string
	}{{"ise-01", nil}, {"", []string{"admin"}}, {"ise-01", []string{"admin", "ADMIN"}}, {"ise-01", []string{"tacacs"}}} {
		if err := cisco.ValidateISETarget(bad.node, bad.roles); err == nil {
			t.Errorf("ValidateISETarget(%q, %v) accepted", bad.node, bad.roles)
		}
	}
	if err := cisco.ValidateISETarget("ise-01", []string{"eap", "radius"}); err != nil {
		t.Fatalf("a valid ISE target was refused: %v", err)
	}
}

// A refused ISE import surfaces its status without the response body, which
// can echo the private key back.
func TestISEImportFailureIsRedacted(t *testing.T) {
	srv := ciscotest.New(user, []byte(pass))
	defer srv.Close()
	srv.FailNext(http.StatusBadRequest, append([]byte(`{"error":"`), append(sampleKey, '"', '}')...))
	_, err := connector.Run(context.Background(), iseConnector(t, srv, "admin"), connector.NewHTTPOps(srv.Client()), iseDeployment("refused"))
	if err == nil || strings.Contains(err.Error(), "PRIVATE KEY") || strings.Contains(err.Error(), pass) || !strings.Contains(err.Error(), "400") {
		t.Fatalf("refused import error = %v", err)
	}
}
