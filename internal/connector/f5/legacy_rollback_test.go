// SPDX-License-Identifier: BUSL-1.1

package f5_test

import (
	"context"
	"errors"
	"testing"

	"trstctl.com/trstctl/internal/connector"
	"trstctl.com/trstctl/internal/connector/f5"
	"trstctl.com/trstctl/internal/connector/f5/f5test"
)

// A45: a predecessor installed under the target-derived name is re-bound only
// when the caller allows the legacy fallback, and the result says so.
func TestRollbackFallsBackToTheLegacyObjectOnlyWhenAllowed(t *testing.T) {
	srv := f5test.New(user, pass)
	defer srv.Close()
	c := f5.New(srv.URL(), profile, f5.WithBasicAuthBytes(user, []byte(pass)))
	ops := connector.NewHTTPOps(srv.Client())
	ctx := context.Background()

	legacy := connector.Deployment{Target: "app", CertPEM: predecessorCert, KeyPEM: sampleKey}
	if _, err := connector.Run(ctx, c, ops, legacy); err != nil {
		t.Fatalf("legacy deploy: %v", err)
	}
	if !srv.InstalledCert(profile + ".crt") {
		t.Fatal("test setup: the legacy deploy must install under the target-derived name")
	}
	current := connector.NewDeployment("app", sampleCert, sampleKey)
	if _, err := connector.Run(ctx, c, ops, current); err != nil {
		t.Fatalf("current deploy: %v", err)
	}
	predecessor := connector.NewDeployment("app", predecessorCert, sampleKey).Fingerprint

	if _, _, err := connector.RunRollbackWithResult(ctx, c, ops, connector.Rollback{Target: "app", PredecessorFingerprint: predecessor}); !errors.Is(err, connector.ErrNoPredecessorInstalled) {
		t.Fatalf("rollback without the legacy fallback = %v, want ErrNoPredecessorInstalled", err)
	}
	_, result, err := connector.RunRollbackWithResult(ctx, c, ops, connector.Rollback{Target: "app", PredecessorFingerprint: predecessor, AllowLegacyObject: true})
	if err != nil || !result.LegacyObject {
		t.Fatalf("legacy rollback = %+v err=%v", result, err)
	}
	if chain, _ := srv.Profile(profile); chain.Cert != profile+".crt" || chain.Key != profile+".key" {
		t.Fatalf("profile bound to %+v, want the legacy objects", chain)
	}
	srv.RemoveCert(profile + ".crt")
	if _, _, err := connector.RunRollbackWithResult(ctx, c, ops, connector.Rollback{Target: "app", PredecessorFingerprint: predecessor, AllowLegacyObject: true}); !errors.Is(err, connector.ErrNoPredecessorInstalled) {
		t.Fatalf("legacy rollback with the legacy object gone = %v, want ErrNoPredecessorInstalled", err)
	}
}
