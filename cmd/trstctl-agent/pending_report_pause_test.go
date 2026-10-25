// SPDX-License-Identifier: BUSL-1.1

package main

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/agent/reportstate"
	"trstctl.com/trstctl/internal/crypto/mtls"
	"trstctl.com/trstctl/internal/custody"
)

// B13-R1: an agent re-enrolled against a rebuilt control plane still held a
// pending report sealed under its previous registration. The report store
// refuses it (it can never be sent under the new authority), and the agent
// used to exit on that refusal: no heartbeat, inventory or self-renewal, and no
// way forward. Now the refusal pauses job claims with a bounded reason naming
// the remedy, and --set-aside-pending-report moves that report aside, intact
// and unsent, from the identity on disk, so claims resume. A report the new
// registration can send is never moved, and a store owned by another process
// still stops the agent.
func TestReEnrolledAgentPausesClaimsUntilTheOperatorSetsTheOldReportAside(t *testing.T) {
	dir := t.TempDir()
	ca, err := mtls.NewCA("re-enrolled-ca")
	if err != nil {
		t.Fatal(err)
	}
	caFile := filepath.Join(dir, "ca.pem")
	if err := os.WriteFile(caFile, ca.BundlePEM(), 0o600); err != nil {
		t.Fatal(err)
	}
	o := agentOptions{caBundle: caFile, commonName: "re-enrolled-agent", serverName: "control-plane",
		keyPath: filepath.Join(dir, "agent.key"), certPath: filepath.Join(dir, "agent.crt")}
	enroll := func(registration string) *mtls.AgentIdentity {
		t.Helper()
		id, err := mtls.GenerateAgentKey(o.commonName)
		if err != nil {
			t.Fatal(err)
		}
		csr, err := id.CSR()
		if err != nil {
			t.Fatal(err)
		}
		chain, err := ca.SignClientCSRWithTenant(csr, "re-enrolled-tenant", []string{mtls.AgentRoleHost}, time.Hour,
			"https://trstctl.com/agent/tenant-registration/v1/re-enrolled-tenant/"+registration)
		if err != nil {
			t.Fatal(err)
		}
		if err := id.UseCertificate(chain); err != nil {
			t.Fatal(err)
		}
		if err := id.Save(o.keyPath, o.certPath); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(id.Destroy)
		return id
	}

	original := enroll("before-rebuild")
	store, err := openAgentReportState(o, original, ca.BundlePEM(), o.serverName, true)
	if err != nil {
		t.Fatal(err)
	}
	unsent := reportstate.Observation{JobID: 90, Attempt: 1, Outcome: "executed", Detail: []byte("revocation health findings"),
		EvidenceDigest: "digest", Custody: &custody.Record{Origin: custody.OriginHostAgent, GeneratedBy: "re-enrolled-agent"}}
	if err := store.Put(unsent); err != nil {
		t.Fatal(err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	if moved, err := setAsidePendingReportFor(o); err != nil || moved != "" {
		t.Fatalf("a report the registration can still send was set aside at %q (%v)", moved, err)
	}

	reEnrolled := enroll("after-rebuild")
	_, err = openAgentReportState(o, reEnrolled, ca.BundlePEM(), o.serverName, true)
	if err == nil {
		t.Fatal("the new registration opened a report sealed under the old one")
	}
	reason, paused := pendingReportPause(err)
	if !paused {
		t.Fatalf("refusal %v stops the agent; it must pause claims", err)
	}
	if len(reason) > pendingReportErrorLimit || !strings.Contains(reason, "--set-aside-pending-report") ||
		!strings.Contains(reason, "re-enrollment") || strings.Contains(reason, "revocation health findings") {
		t.Fatalf("pause reason %q: want bounded, naming the cause and the flag, without report contents", reason)
	}

	moved, err := setAsidePendingReportFor(o)
	if err != nil || filepath.Dir(moved) != filepath.Join(dir, "pending-reports") {
		t.Fatalf("set-aside = %q (%v)", moved, err)
	}
	store, err = openAgentReportState(o, reEnrolled, ca.BundlePEM(), o.serverName, true)
	if err != nil {
		t.Fatalf("claims do not resume after the set-aside: %v", err)
	}
	if pending, err := store.Pending(); pending != nil || err != nil {
		t.Fatalf("pending after set-aside = %v (%v)", pending, err)
	}
	if _, err := openAgentReportState(o, reEnrolled, ca.BundlePEM(), o.serverName, true); err == nil {
		t.Fatal("a second process opened the same report store")
	} else if _, paused := pendingReportPause(err); paused {
		t.Fatalf("store ownership conflict %v paused claims; a second agent process must stop", err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	if again, err := setAsidePendingReportFor(o); err != nil || again != "" {
		t.Fatalf("second set-aside = %q (%v), want nothing to move", again, err)
	}
	if _, paused := pendingReportPause(errors.New("reportstate: an absolute private directory and identity binding are required")); paused {
		t.Fatal("an unusable store directory paused claims; it must stop the agent")
	}
}
