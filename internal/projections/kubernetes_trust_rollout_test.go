// SPDX-License-Identifier: BUSL-1.1

package projections_test

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/google/uuid"

	"trstctl.com/trstctl/internal/crypto/mtls"
	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/projections"
	"trstctl.com/trstctl/internal/store"
)

type rolloutFixture struct {
	t   *testing.T
	ctx context.Context
	st  *store.Store
	log *events.Log
}

func (f rolloutFixture) apply(tenantID, eventType string, payload any) error {
	f.t.Helper()
	data, err := json.Marshal(payload)
	if err != nil {
		f.t.Fatal(err)
	}
	ev, err := f.log.Append(f.ctx, events.Event{Type: eventType, TenantID: tenantID, Data: data})
	if err != nil {
		f.t.Fatal(err)
	}
	return projections.New(f.st).Apply(f.ctx, ev)
}

// report sends one cluster's posture with a single TrustBundle observation.
func (f rolloutFixture) report(cluster, bundleName, state, reason, hash string) string {
	f.t.Helper()
	reportID := uuid.NewString()
	payload, err := projections.MarshalKubernetesPostureReport(projections.KubernetesControllerPostureReported{
		ReportID: reportID, AgentID: uuid.NewString(), ClusterID: cluster, ReconcileIntervalSeconds: 30,
		CertificateSigning: projections.KubernetesPostureSection{Complete: true, Resources: []projections.KubernetesPostureResource{}},
		TrustBundles: projections.KubernetesPostureSection{Complete: true, Resources: []projections.KubernetesPostureResource{{
			Name: bundleName, UID: "bundle-uid", ResourceVersion: "7", State: state, Reason: reason, PublicHash: hash,
		}}},
	})
	if err != nil {
		f.t.Fatal(err)
	}
	ev, err := f.log.Append(f.ctx, events.Event{Type: projections.EventKubernetesControllerPostureReported, TenantID: tenantA, Data: payload})
	if err != nil {
		f.t.Fatal(err)
	}
	if err := projections.New(f.st).Apply(f.ctx, ev); err != nil {
		f.t.Fatal(err)
	}
	return reportID
}

func (f rolloutFixture) rollout(id string) store.KubernetesTrustRollout {
	f.t.Helper()
	r, err := f.st.GetKubernetesTrustRollout(f.ctx, tenantA, id)
	if err != nil {
		f.t.Fatal(err)
	}
	return r
}

func clusterStates(r store.KubernetesTrustRollout) []string {
	out := make([]string, 0, len(r.Clusters))
	for _, c := range r.Clusters {
		out = append(out, c.State)
	}
	return out
}

// A138: a rollout dispatches its canary alone; each cluster is verified only
// by its own report of the bundle with the rollout's hash (an older bundle or a
// report from a cluster not yet dispatched changes nothing, a failure is
// recorded with its reason); a verified canary dispatches the rest; pausing
// holds the canary gate; all verified completes; a newer rollout of the same
// name supersedes it; and nothing crosses tenants.
func TestKubernetesTrustRolloutVerifiesEachClusterFromItsOwnReport(t *testing.T) {
	f := rolloutFixture{t: t, ctx: context.Background(), st: newStore(t), log: openLog(t)}
	ca, err := mtls.NewCA("rollout projection CA")
	if err != nil {
		t.Fatal(err)
	}
	bundle, hash, err := projections.NormalizeKubernetesTrustBundlePEM(string(ca.BundlePEM()))
	if err != nil {
		t.Fatal(err)
	}
	canary, second := "sha256:"+strings.Repeat("a", 64), "sha256:"+strings.Repeat("b", 64)
	start := projections.KubernetesTrustRolloutStarted{
		RolloutID: uuid.NewString(), Name: "platform-roots", CABundlePEM: bundle, BundleSHA256: hash,
		ConfigMapName: "platform-roots", Key: "ca-bundle.pem", Namespaces: []string{"apps"}, Clusters: []string{canary, second},
	}
	if err := f.apply(tenantA, projections.EventKubernetesTrustRolloutStarted, start); err != nil {
		t.Fatal(err)
	}
	r := f.rollout(start.RolloutID)
	if r.State != store.KubernetesTrustRolloutRunning || strings.Join(clusterStates(r), ",") != "dispatched,waiting" {
		t.Fatalf("started rollout = %s %v", r.State, clusterStates(r))
	}
	desired := func(cluster string) []store.KubernetesDesiredTrustBundle {
		t.Helper()
		out, err := f.st.DesiredKubernetesTrustBundles(f.ctx, tenantA, cluster)
		if err != nil {
			t.Fatal(err)
		}
		return out
	}
	if got := desired(canary); len(got) != 1 || got[0].BundleSHA256 != hash || got[0].CABundlePEM != bundle {
		t.Fatalf("desired bundles for the canary = %+v", got)
	}
	if got := desired(second); len(got) != 0 {
		t.Fatalf("a waiting cluster was sent the bundle: %+v", got)
	}

	f.report(second, "platform-roots", "ready", "distributed", hash)
	f.report(canary, "platform-roots", "ready", "distributed", strings.Repeat("e", 64))
	if got := clusterStates(f.rollout(start.RolloutID)); strings.Join(got, ",") != "dispatched,waiting" {
		t.Fatalf("an undispatched cluster or an older bundle moved the rollout: %v", got)
	}
	f.report(canary, "platform-roots", "failed", "controller_error", "")
	r = f.rollout(start.RolloutID)
	if r.Clusters[0].State != store.KubernetesTrustClusterFailed || r.Clusters[0].Reason != "controller_error" || r.Clusters[1].State != store.KubernetesTrustClusterWaiting {
		t.Fatalf("after a failed canary = %+v", r.Clusters)
	}
	verifying := f.report(canary, "platform-roots", "ready", "distributed", hash)
	r = f.rollout(start.RolloutID)
	if r.Clusters[0].State != store.KubernetesTrustClusterVerified || r.Clusters[0].ReportID != verifying || r.Clusters[0].VerifiedAt == nil ||
		r.Clusters[1].State != store.KubernetesTrustClusterDispatched || r.Clusters[1].DispatchedAt == nil {
		t.Fatalf("after the canary verified = %+v", r.Clusters)
	}
	if got := desired(second); len(got) != 1 {
		t.Fatalf("the dispatched cluster was not sent the bundle: %+v", got)
	}

	if err := f.apply(tenantA, projections.EventKubernetesTrustRolloutPaused, projections.KubernetesTrustRolloutControlled{RolloutID: start.RolloutID}); err != nil {
		t.Fatal(err)
	}
	if f.rollout(start.RolloutID).State != store.KubernetesTrustRolloutPaused {
		t.Fatal("pause did not pause the rollout")
	}
	f.report(second, "platform-roots", "ready", "distributed", hash)
	if r := f.rollout(start.RolloutID); r.State != store.KubernetesTrustRolloutCompleted || strings.Join(clusterStates(r), ",") != "verified,verified" {
		t.Fatalf("a rollout whose clusters all verified = %s %v", r.State, clusterStates(r))
	}
	// A stale resume after completion changes nothing.
	if err := f.apply(tenantA, projections.EventKubernetesTrustRolloutResumed, projections.KubernetesTrustRolloutControlled{RolloutID: start.RolloutID}); err != nil {
		t.Fatal(err)
	}
	if f.rollout(start.RolloutID).State != store.KubernetesTrustRolloutCompleted {
		t.Fatal("a stale resume reopened a completed rollout")
	}

	next := start
	next.RolloutID = uuid.NewString()
	next.Clusters = []string{second}
	if err := f.apply(tenantA, projections.EventKubernetesTrustRolloutStarted, next); err != nil {
		t.Fatal(err)
	}
	if got := desired(second); len(got) != 1 || got[0].RolloutID != next.RolloutID {
		t.Fatalf("the newest rollout of a name did not win: %+v", got)
	}
	if got := desired(canary); len(got) != 1 || got[0].RolloutID != start.RolloutID {
		t.Fatalf("a cluster the newer rollout does not target lost its bundle: %+v", got)
	}

	if other, err := f.st.ListKubernetesTrustRollouts(f.ctx, tenantB); err != nil || len(other) != 0 {
		t.Fatalf("tenant B saw tenant A's rollouts: %+v %v", other, err)
	}
	if other, err := f.st.DesiredKubernetesTrustBundles(f.ctx, tenantB, canary); err != nil || len(other) != 0 {
		t.Fatalf("tenant B's cluster was sent tenant A's bundle: %+v %v", other, err)
	}
}

// A138: the projection refuses a rollout that is not public certificates, whose
// hash does not match its bundle, or that names a cluster twice.
func TestKubernetesTrustRolloutRefusesInvalidStarts(t *testing.T) {
	ca, err := mtls.NewCA("rollout validation CA")
	if err != nil {
		t.Fatal(err)
	}
	bundle, hash, err := projections.NormalizeKubernetesTrustBundlePEM(string(ca.BundlePEM()))
	if err != nil {
		t.Fatal(err)
	}
	valid := projections.KubernetesTrustRolloutStarted{
		RolloutID: uuid.NewString(), Name: "roots", CABundlePEM: bundle, BundleSHA256: hash,
		ConfigMapName: "roots", Key: "ca-bundle.pem", Namespaces: []string{"apps"}, Clusters: []string{"sha256:" + strings.Repeat("a", 64)},
	}
	if err := projections.ValidateKubernetesTrustRolloutStarted(valid); err != nil {
		t.Fatalf("a valid rollout was refused: %v", err)
	}
	for name, edit := range map[string]func(*projections.KubernetesTrustRolloutStarted){
		"private key": func(p *projections.KubernetesTrustRolloutStarted) {
			p.CABundlePEM = "-----BEGIN PRIVATE KEY-----\nS0VZ\n-----END PRIVATE KEY-----\n"
		},
		"hash mismatch": func(p *projections.KubernetesTrustRolloutStarted) { p.BundleSHA256 = strings.Repeat("0", 64) },
		"duplicate cluster": func(p *projections.KubernetesTrustRolloutStarted) {
			p.Clusters = []string{p.Clusters[0], p.Clusters[0]}
		},
		"bad name":         func(p *projections.KubernetesTrustRolloutStarted) { p.Name = "Roots!" },
		"no namespaces":    func(p *projections.KubernetesTrustRolloutStarted) { p.Namespaces = nil },
		"cluster id shape": func(p *projections.KubernetesTrustRolloutStarted) { p.Clusters = []string{"cluster-a"} },
	} {
		candidate := valid
		candidate.Clusters = append([]string(nil), valid.Clusters...)
		edit(&candidate)
		if err := projections.ValidateKubernetesTrustRolloutStarted(candidate); err == nil {
			t.Fatalf("%s: an invalid rollout was accepted", name)
		}
	}
}
