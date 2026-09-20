// SPDX-License-Identifier: BUSL-1.1

package f5_test

import (
	"context"
	"net/http"
	"testing"

	"trstctl.com/trstctl/internal/connector"
	"trstctl.com/trstctl/internal/connector/f5"
	"trstctl.com/trstctl/internal/connector/f5/f5test"
)

// An F5 HA pair keeps certificate objects in separate stores, so the property
// that matters is that a deploy reaches BOTH peers. These drive the HAPair
// against two independent device doubles.

func haOps() connector.Ops { return connector.NewHTTPOps(http.DefaultClient) }

func TestF5HADeployReachesBothPeers(t *testing.T) {
	active := f5test.New(user, pass)
	defer active.Close()
	standby := f5test.New(user, pass)
	defer standby.Close()

	pair := f5.NewHAPair(
		f5.New(active.URL(), profile, f5.WithBasicAuthBytes(user, []byte(pass))),
		f5.New(standby.URL(), profile, f5.WithBasicAuthBytes(user, []byte(pass))),
	)
	dep := connector.NewDeployment("app", sampleCert, sampleKey)
	if _, err := connector.Run(context.Background(), pair, haOps(), dep); err != nil {
		t.Fatalf("ha deploy: %v", err)
	}

	base := connector.DeployedObjectName(profile, dep.Fingerprint)
	for name, srv := range map[string]*f5test.Server{"active": active, "standby": standby} {
		got, ok := srv.Uploaded(base + ".crt")
		if !ok || string(got) != string(sampleCert) {
			t.Fatalf("%s peer missing the deployed certificate at %s.crt (ok=%v)", name, base, ok)
		}
		chain, ok := srv.Profile(profile)
		if !ok || chain.Cert != base+".crt" {
			t.Fatalf("%s peer profile not bound to the deployed object: %+v (ok=%v)", name, chain, ok)
		}
	}
}

// A pair deploy that cannot reach the standby FAILS. Reporting success while
// one peer is behind is the exact defect this type exists to prevent.
func TestF5HADeployFailsWhenAPeerIsUnreachable(t *testing.T) {
	active := f5test.New(user, pass)
	defer active.Close()
	standby := f5test.New(user, pass)
	standby.Close() // the standby is down before the deploy

	pair := f5.NewHAPair(
		f5.New(active.URL(), profile, f5.WithBasicAuthBytes(user, []byte(pass))),
		f5.New(standby.URL(), profile, f5.WithBasicAuthBytes(user, []byte(pass))),
	)
	if _, err := connector.Run(context.Background(), pair, haOps(), connector.NewDeployment("app", sampleCert, sampleKey)); err == nil {
		t.Fatal("ha deploy reported success with the standby unreachable; a half-updated pair must fail")
	}
}

// Readback reports the pair serving only when BOTH peers are bound to the
// deployed certificate. A pair where the standby is behind reads not-bound.
func TestF5HAReadbackCatchesADivergentPeer(t *testing.T) {
	active := f5test.New(user, pass)
	defer active.Close()
	standby := f5test.New(user, pass)
	defer standby.Close()

	pair := f5.NewHAPair(
		f5.New(active.URL(), profile, f5.WithBasicAuthBytes(user, []byte(pass))),
		f5.New(standby.URL(), profile, f5.WithBasicAuthBytes(user, []byte(pass))),
	)
	dep := connector.NewDeployment("app", sampleCert, sampleKey)
	if _, err := connector.Run(context.Background(), pair, haOps(), dep); err != nil {
		t.Fatalf("ha deploy: %v", err)
	}
	got, err := connector.RunReadback(context.Background(), pair, haOps(), profile)
	if err != nil {
		t.Fatalf("ha readback: %v", err)
	}
	if connector.ClassifyReadback(got, dep.Fingerprint) != connector.ReadbackServing {
		t.Fatalf("a converged pair reads %q, want serving", connector.ClassifyReadback(got, dep.Fingerprint))
	}

	// Now push the standby back to a PREDECESSOR certificate — a different
	// fingerprint, the exact "standby left behind after a one-sided deploy"
	// state. The active node still serves the deployed cert.
	stale := connector.DeployedObjectName(profile, "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef")
	standby.BindProfile(profile, stale+".crt")
	got, err = connector.RunReadback(context.Background(), pair, haOps(), profile)
	if err != nil {
		t.Fatalf("ha readback after divergence: %v", err)
	}
	if verdict := connector.ClassifyReadback(got, dep.Fingerprint); verdict == connector.ReadbackServing {
		t.Fatalf("a pair with a divergent standby reads %q; the whole point of reading both peers is "+
			"that this must not read as serving", verdict)
	}
}
