// SPDX-License-Identifier: MPL-2.0

package ssh

import (
	"context"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/auditsink"
)

// TestSerialsDoNotRestartFromOneAcrossCAs is the regression guard for AUD-201
// follow-up C2/V20, mirroring internal/tsa/serial_uniqueness_test.go.
//
// CA.serial was an unseeded, unpersisted counter, so every process restart
// reissued serials 1, 2, 3 — and SSH revocation is serial-based with the
// distributed KRL outliving the process. After a restart a fresh certificate
// could take a serial already revoked in a host-held KRL (born revoked), and a
// revoke-by-serial issued after a restart killed a certificate from the
// previous run. The same commit fixed exactly this in the TSA and edited
// ssh.go without touching the serial.
//
// A fresh CA stands in for a restart.
func TestSerialsDoNotRestartFromOneAcrossCAs(t *testing.T) {
	ctx := context.Background()
	profile := Profile{Name: "users", AllowUserCerts: true, MaxTTL: time.Hour}

	const restarts = 12
	seen := make(map[uint64]int, restarts*3)
	for restart := 0; restart < restarts; restart++ {
		ca, _ := newCA(t, auditsink.Nop{})
		for i := 0; i < 3; i++ {
			issued, err := ca.IssueUserCert(ctx, profile, IssueRequest{
				SubjectPublicKey: subjectKey(t),
				KeyID:            "user@example",
				Principals:       []string{"user"},
				TTL:              time.Hour,
			})
			if err != nil {
				t.Fatalf("restart %d: issue: %v", restart, err)
			}
			if issued.Serial == 0 {
				t.Fatal("a certificate was issued with serial 0")
			}
			if prev, dup := seen[issued.Serial]; dup {
				t.Fatalf("serial %d was issued by two different CA instances (restart %d and %d); "+
					"a KRL that revokes it on one host revokes BOTH certificates, and a fresh "+
					"certificate can be born revoked", issued.Serial, prev, restart)
			}
			seen[issued.Serial] = restart
		}
	}
}

// TestSerialsIncreaseWithinOneCA keeps the in-process property: random seeding
// must not make serials arbitrary within a single run.
func TestSerialsIncreaseWithinOneCA(t *testing.T) {
	ctx := context.Background()
	ca, _ := newCA(t, auditsink.Nop{})
	profile := Profile{Name: "users", AllowUserCerts: true, MaxTTL: time.Hour}
	var prev uint64
	for i := 0; i < 5; i++ {
		issued, err := ca.IssueUserCert(ctx, profile, IssueRequest{
			SubjectPublicKey: subjectKey(t),
			KeyID:            "user@example",
			Principals:       []string{"user"},
			TTL:              time.Hour,
		})
		if err != nil {
			t.Fatal(err)
		}
		if i > 0 && issued.Serial != prev+1 {
			t.Fatalf("serial went %d -> %d; within one run serials must increment", prev, issued.Serial)
		}
		prev = issued.Serial
	}
}
