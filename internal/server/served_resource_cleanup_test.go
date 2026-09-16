// SPDX-License-Identifier: MPL-2.0

package server

import (
	"context"
	"errors"
	"testing"

	"trstctl.com/trstctl/internal/bulkhead"
	"trstctl.com/trstctl/internal/config"
)

// A served fixture owns the same worker pools as a running server. Closing
// only its HTTP listener leaves every worker alive for the rest of the suite.
func TestServedFixtureReleasesEverySubsystemPool(t *testing.T) {
	for range 2 {
		var pools *bulkhead.Set
		t.Run("fixture", func(t *testing.T) {
			h := newServedHarness(t, config.Protocols{})
			pools = h.srv.bulk
		})
		if pools == nil {
			t.Fatal("fixture did not construct subsystem pools")
		}
		// If the assertion fails, still release the deliberately exposed leak.
		for _, stat := range pools.Stats() {
			err := pools.Submit(stat.Name, func() {})
			var rejected *bulkhead.Rejected
			if !errors.As(err, &rejected) || rejected.Reason != bulkhead.ReasonClosed {
				t.Errorf("fixture cleanup left %s accepting work: %v", stat.Name, err)
			}
		}
		pools.Close()
	}
}

// cleanupServedServer registers cleanup immediately after a successful Build.
// Register listener cleanup afterward so no request is using the server when
// its resources close. Tests own delivery: a cancelled context prevents teardown
// from sending deliberately pending commands to targets that may already be gone.
func cleanupServedServer(t *testing.T, srv *Server) {
	t.Helper()
	t.Cleanup(func() {
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		_ = srv.Shutdown(ctx)
	})
}

// Restart fixtures share their durable spine but own a fresh set of workers.
// Both assemblies must close, even when only the replacement serves requests.
func TestRestartedServedFixtureReleasesEverySubsystemPool(t *testing.T) {
	var assemblies []*bulkhead.Set
	t.Run("restart", func(t *testing.T) {
		h := newServedHarness(t, config.Protocols{})
		assemblies = append(assemblies, h.srv.bulk)
		restarted, err := Build(t.Context(), Deps{
			Store: h.store, Log: h.log, Signer: h.signer, SignAuthorizer: h.authz,
			CACertFile: h.caFile, KEK: h.kek,
		})
		if err != nil {
			t.Fatal(err)
		}
		cleanupServedServer(t, restarted)
		assemblies = append(assemblies, restarted.bulk)
	})
	if len(assemblies) != 2 {
		t.Fatalf("constructed %d assemblies, want original and restarted", len(assemblies))
	}
	for i, pools := range assemblies {
		for _, stat := range pools.Stats() {
			err := pools.Submit(stat.Name, func() {})
			var rejected *bulkhead.Rejected
			if !errors.As(err, &rejected) || rejected.Reason != bulkhead.ReasonClosed {
				t.Errorf("assembly %d left %s accepting work: %v", i, stat.Name, err)
			}
		}
		pools.Close()
	}
}
