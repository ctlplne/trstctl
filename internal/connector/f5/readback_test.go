// SPDX-License-Identifier: BUSL-1.1

package f5_test

import (
	"context"
	"testing"

	"trstctl.com/trstctl/internal/connector"
	"trstctl.com/trstctl/internal/connector/f5"
	"trstctl.com/trstctl/internal/connector/f5/f5test"
)

// The acceptance criterion for E2, stated as the epic states it: an F5 deploy
// whose VIP still serves the old certificate must be CAUGHT.
//
// This is the failure that reads as success everywhere else. The upload
// succeeds, the crypto object installs, the deploy returns nil, the receipt is
// green — and the virtual server keeps presenting the previous certificate
// because the profile that was patched is not the profile the VIP uses. Nothing
// in the deploy path can see it, because from the deploy's point of view every
// call it made worked.

func TestAProfileBoundToTheOldCertificateIsCaughtByReadback(t *testing.T) {
	t.Parallel()
	const (
		user = "admin"
		want = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
		old  = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	)
	srv := f5test.New(user, "pw")
	defer srv.Close()

	c := newReadbackConnector(t, srv, user)

	// The device is bound to the PREDECESSOR — the state a wrong profile
	// binding leaves behind after an otherwise-successful deploy.
	srv.BindProfile("clientssl-vip", connector.DeployedObjectName("trstctl", old))

	got, err := connector.RunReadback(context.Background(), c, connector.NewHTTPOps(srv.Client()), "clientssl-vip")
	if err != nil {
		t.Fatalf("readback: %v", err)
	}
	if verdict := connector.ClassifyReadback(got, want); verdict != connector.ReadbackDiverged {
		t.Fatalf("verdict = %q, want %q. A VIP still serving the predecessor is the exact "+
			"condition this epic exists to catch, and every other signal in the pipeline "+
			"reports it as a successful deploy", verdict, connector.ReadbackDiverged)
	}
}

func TestAProfileBoundToOurCertificateReadsAsServing(t *testing.T) {
	t.Parallel()
	const (
		user = "admin"
		want = "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"
	)
	srv := f5test.New(user, "pw")
	defer srv.Close()
	c := newReadbackConnector(t, srv, user)

	srv.BindProfile("clientssl-vip", connector.DeployedObjectName("trstctl", want))

	got, err := connector.RunReadback(context.Background(), c, connector.NewHTTPOps(srv.Client()), "clientssl-vip")
	if err != nil {
		t.Fatalf("readback: %v", err)
	}
	if verdict := connector.ClassifyReadback(got, want); verdict != connector.ReadbackServing {
		t.Fatalf("verdict = %q, want %q; a correctly bound profile must not read as a problem",
			verdict, connector.ReadbackServing)
	}
}

// A profile that does not exist is ABSENT, not diverged.
//
// The two send an operator to different places: absent means the configuration
// they think they are deploying to is not there, diverged means it is there and
// pointing elsewhere.
func TestAMissingProfileReadsAsAbsent(t *testing.T) {
	t.Parallel()
	const user = "admin"
	srv := f5test.New(user, "pw")
	defer srv.Close()
	c := newReadbackConnector(t, srv, user)

	got, err := connector.RunReadback(context.Background(), c, connector.NewHTTPOps(srv.Client()), "no-such-profile")
	if err != nil {
		t.Fatalf("readback: %v", err)
	}
	if verdict := connector.ClassifyReadback(got, "dddd"); verdict != connector.ReadbackAbsent {
		t.Errorf("verdict = %q, want %q", verdict, connector.ReadbackAbsent)
	}
}

// A family that cannot report installed state says so, rather than returning a
// verdict nobody measured.
func TestAFamilyThatCannotReadBackSaysSo(t *testing.T) {
	t.Parallel()
	for _, family := range []string{"cisco", "fortigate", "paloalto"} {
		if connector.CanReadback(family) {
			t.Errorf("%s is listed as readback-capable, but its API exposes no call that reports "+
				"an installed object separately from uploading one", family)
		}
	}
	for _, family := range connector.ReadbackCapableConnectors() {
		if !connector.DeviceProven(family) {
			t.Errorf("%s claims readback but has no device proof, so nothing exercises the call",
				family)
		}
	}
}

// newReadbackConnector builds an F5 connector pointed at the double.
func newReadbackConnector(t *testing.T, srv *f5test.Server, user string) connector.Connector {
	t.Helper()
	c := f5.New(srv.URL(), "clientssl-vip", f5.WithBasicAuthBytes(user, []byte("pw")))
	t.Cleanup(c.Close)
	return c
}
