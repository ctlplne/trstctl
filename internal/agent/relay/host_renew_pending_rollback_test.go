// SPDX-License-Identifier: BUSL-1.1

package relay_test

import (
	"errors"
	"net/http"
	"path/filepath"
	"testing"

	"trstctl.com/trstctl/internal/agent/relay"
	"trstctl.com/trstctl/internal/agent/transport"
	"trstctl.com/trstctl/internal/crypto/certinfo"
	"trstctl.com/trstctl/internal/crypto/tlsprobe"
)

// A successor that failed its live gate keeps its sealed key on the host so
// the same job can resume. Once the control plane rolls that successor back,
// the slot is stale: the next host-generated job for the target must be able
// to generate a fresh key instead of being refused as "another job's key".
func TestRollingBackAFailedSuccessorFreesThePendingHostKey(t *testing.T) {
	predecessor, err := tlsprobe.NewServingTestServer("rollback.example.test")
	if err != nil {
		t.Fatal(err)
	}
	defer predecessor.Close()
	successor, err := tlsprobe.NewServingTestServer("rollback.example.test")
	if err != nil {
		t.Fatal(err)
	}
	defer successor.Close()
	successorInfo, err := certinfo.Inspect(successor.LeafPEM)
	if err != nil {
		t.Fatal(err)
	}

	root := t.TempDir()
	state, err := relay.NewHostRollbackStore(filepath.Join(root, "rollback-state"), "tenant-a")
	if err != nil {
		t.Fatal(err)
	}
	profile := hostProfileForNginx(t, root)
	config := mustJSON(t, map[string]string{
		"cert_path": filepath.Join(root, "server.crt"),
		"key_path":  filepath.Join(root, "server.key"),
	})
	deploy := &fakeChannel{
		jobs: []relay.Job{intentJob(t, 10, relay.DeployIntent{
			Connector: "nginx", Target: "edge", TargetID: "target-a", TargetConfig: config, Fingerprint: "first",
		})},
		material: map[string][]byte{"credential.cert_pem": predecessor.LeafPEM, "credential.key_pem": []byte(testKeyPEM)},
	}
	if _, err := relay.RunOnceWithSelfUpgradeAndHostRollback(t.Context(), deploy, http.DefaultClient, profile, nil, nil, state, 1, 30); err != nil {
		t.Fatal(err)
	}

	renewal := func(jobID int64) relay.Job {
		return relay.Job{JobID: jobID, Kind: relay.KindEndpointRenew, Attempt: 1, Payload: mustJSON(t, relay.DeployIntent{
			Connector: "nginx", Target: "edge", TargetID: "target-a", TargetConfig: config,
			SubjectCommonName: "rollback.example.test", SubjectDNSNames: []string{"rollback.example.test"},
			VerifyAddress: predecessor.Addr, VerifyServerName: "rollback.example.test",
		})}
	}
	// The listener keeps serving the predecessor, so the signed successor fails
	// its live gate and its sealed key stays pending for job 11.
	failed := &renewChannel{certPEM: successor.LeafPEM, fpr: successorInfo.SHA256Fingerprint}
	failed.jobs = []relay.Job{renewal(11)}
	if _, err := relay.RunOnceWithSelfUpgradeAndHostRollback(t.Context(), failed, http.DefaultClient, profile, nil, nil, state, 1, 30); err != nil {
		t.Fatal(err)
	}
	if failed.signCalls != 1 || len(failed.reports) != 1 || failed.reports[0].outcome != transport.OutcomeVerifyFailed {
		t.Fatalf("failed successor: signs=%d reports=%+v; want one verify_failed report", failed.signCalls, failed.reports)
	}

	rollback := &fakeChannel{jobs: []relay.Job{rollbackJob(t, 12, relay.RollbackIntent{
		Connector: "nginx", Target: "edge", TargetID: "target-a", TargetConfig: config,
		PredecessorFingerprint: "first", SuccessorFingerprint: successorInfo.SHA256Fingerprint,
		VerifyAddress: predecessor.Addr, VerifyServerName: "rollback.example.test",
	})}}
	if _, err := relay.RunOnceWithSelfUpgradeAndHostRollback(t.Context(), rollback, http.DefaultClient, profile, nil, nil, state, 1, 30); err != nil {
		t.Fatal(err)
	}
	if len(rollback.reports) != 1 || rollback.reports[0].outcome != transport.OutcomeVerified {
		t.Fatalf("rollback reports = %+v, want verified", rollback.reports)
	}

	// A new job for the same target generates its own key.
	next := &renewChannel{signErr: errors.New("stop before deployment")}
	next.jobs = []relay.Job{renewal(13)}
	if _, err := relay.RunOnceWithSelfUpgradeAndHostRollback(t.Context(), next, http.DefaultClient, profile, nil, nil, state, 1, 30); err != nil {
		t.Fatal(err)
	}
	if next.signCalls != 1 {
		t.Fatalf("after rollback the next renewal signed %d CSRs (reports %+v); the rolled-back successor's pending key still blocks the target", next.signCalls, next.reports)
	}
}
