// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"

	"trstctl.com/trstctl/internal/api"
	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/crypto/mtls"
	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/orchestrator"
	"trstctl.com/trstctl/internal/projections"
	"trstctl.com/trstctl/internal/store"
)

// CR-431 and CR-759. Check the served endpoint and its immutable event rather
// than trusting that rejected requests were dropped or that a 201 was canonical.
func TestServedKubernetesTrustRolloutAdmitsOnlyCanonicalPublicTargets(t *testing.T) {
	h := newOperatingServedHarness(t, config.Protocols{})
	cluster := "sha256:" + strings.Repeat("a", 64)
	seedKubernetesPosture(t, h, projections.KubernetesControllerPostureReported{
		ReportID: uuid.NewString(), AgentID: uuid.NewString(), ClusterID: cluster, ReconcileIntervalSeconds: 30,
		CertificateSigning: projections.KubernetesPostureSection{Complete: true, Resources: []projections.KubernetesPostureResource{}},
		TrustBundles:       projections.KubernetesPostureSection{Complete: true, Resources: []projections.KubernetesPostureResource{}},
	})
	ca, err := mtls.NewCA("served public trust fixture")
	if err != nil {
		t.Fatal(err)
	}
	bundle := string(ca.BundlePEM())
	token := seedScopedToken(t, h.store, h.tenant, "certs:write")
	const path = "/api/v1/kubernetes/trust-rollouts"
	request := func(name string) map[string]any {
		return map[string]any{"name": name, "ca_bundle_pem": bundle, "namespaces": []string{"apps"}, "clusters": []string{cluster}}
	}
	for _, tc := range []struct {
		name   string
		status int
		field  string
		value  any
	}{
		{"public-notes", http.StatusUnprocessableEntity, "ca_bundle_pem", "fixture public notes\n" + bundle},
		{"dotted-target", http.StatusBadRequest, "config_map_name", "app..roots"},
		{"protected-target", http.StatusBadRequest, "config_map_name", "trstctl-secrets-csi"},
		{"wrong-namespace", http.StatusBadRequest, "namespaces", []string{"apps", "bad namespace"}},
		{"invalid-data-key", http.StatusBadRequest, "key", "..fixture"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			body := request(tc.name)
			body[tc.field] = tc.value
			if status, _ := secretsReq(t, h, http.MethodPost, path, token, body); status != tc.status {
				t.Errorf("admission returned HTTP %d, want %d", status, tc.status)
			}
		})
	}
	if h.hasEvent(t, projections.EventKubernetesTrustRolloutStarted) {
		t.Error("a refused trust request appended a rollout start")
	}
	valid := request("public-roots")
	valid["ca_bundle_pem"] = strings.ReplaceAll(bundle, "\n", "\r\n")
	status, response := secretsReq(t, h, http.MethodPost, path, token, valid)
	if status != http.StatusCreated {
		t.Fatalf("well-formed public request = HTTP %d: %s", status, response)
	}
	var view api.KubernetesTrustRollout
	if err := json.Unmarshal(response, &view); err != nil || view.CABundlePEM != bundle || view.BundleSHA256 != crypto.SHA256Hex([]byte(bundle)) {
		t.Errorf("response did not contain the canonical public bundle and hash, err=%v", err)
	}
	starts := 0
	err = h.log.Replay(t.Context(), 0, func(event events.Event) error {
		if event.Type != projections.EventKubernetesTrustRolloutStarted || event.TenantID != h.tenant {
			return nil
		}
		starts++
		var payload projections.KubernetesTrustRolloutStarted
		if err := json.Unmarshal(event.Data, &payload); err != nil {
			return err
		}
		if event.SchemaVersion != 2 || payload.CABundlePEM != bundle || payload.BundleSHA256 != view.BundleSHA256 || event.Actor == nil {
			t.Errorf("journal start did not contain canonical v2 public data and audit actor, schema=%d", event.SchemaVersion)
		}
		return nil
	})
	if err != nil || starts != 1 {
		t.Fatalf("journal held %d starts, err=%v, want exactly one", starts, err)
	}
}

// CR-431. An upgrade keeps the exact durable response and the original journal.
// A retained source without projection is recovered only by ordered replay.
func TestServedKubernetesTrustRolloutRecoversExactRetainedStarts(t *testing.T) {
	const dedup = 100 * time.Millisecond
	h := newServedHarnessWithEventOptions(t, config.Protocols{}, []events.OpenOption{
		events.WithRequiredPrivacyEventPolicies(), events.WithDuplicateWindowForTesting(dedup),
	})
	registerServedTenant(t, h, "Operating trust durability fixture")
	projector := projections.New(h.store)
	token := seedScopedToken(t, h.store, h.tenant, "certs:write")
	const path = "/api/v1/kubernetes/trust-rollouts"
	canary := "sha256:" + strings.Repeat("a", 64)
	earlierOnly := "sha256:" + strings.Repeat("b", 64)
	laterOnly := "sha256:" + strings.Repeat("c", 64)
	type request struct {
		Name          string   `json:"name"`
		CABundlePEM   string   `json:"ca_bundle_pem"`
		ConfigMapName string   `json:"config_map_name"`
		Key           string   `json:"key"`
		Namespaces    []string `json:"namespaces"`
		Clusters      []string `json:"clusters"`
	}
	fixture := func(name string, clusters ...string) request {
		t.Helper()
		ca, err := mtls.NewCA("public rollout durability fixture")
		if err != nil {
			t.Fatal(err)
		}
		return request{name, string(ca.BundlePEM()), name, "ca-bundle.pem", []string{"apps"}, clusters}
	}
	appendStart := func(key string, req request, version int, project bool) string {
		t.Helper()
		id := uuid.NewSHA1(uuid.NameSpaceOID, []byte("kubernetes-trust-rollout\x00"+h.tenant+"\x00"+key)).String()
		payload, err := json.Marshal(projections.KubernetesTrustRolloutStarted{
			RolloutID: id, Name: req.Name, CABundlePEM: req.CABundlePEM, BundleSHA256: crypto.SHA256Hex([]byte(req.CABundlePEM)),
			ConfigMapName: req.ConfigMapName, Key: req.Key, Namespaces: req.Namespaces, Clusters: req.Clusters,
		})
		if err != nil {
			t.Fatal(err)
		}
		event, err := h.log.Append(t.Context(), events.Event{
			ID: orchestrator.KubernetesTrustRolloutEventID(h.tenant, id, "start", ""), TenantID: h.tenant,
			Type: projections.EventKubernetesTrustRolloutStarted, SchemaVersion: version, Data: payload,
		})
		if err != nil {
			t.Fatal(err)
		}
		if project {
			if err := projector.Apply(t.Context(), event); err != nil {
				t.Fatal(err)
			}
		}
		return id
	}
	desired := func(cluster string) []store.KubernetesDesiredTrustBundle {
		t.Helper()
		out, err := h.store.DesiredKubernetesTrustBundles(t.Context(), h.tenant, cluster)
		if err != nil {
			t.Fatal(err)
		}
		return out
	}
	startCount := func() int {
		t.Helper()
		var count int
		if err := h.log.Replay(t.Context(), 0, func(event events.Event) error {
			if event.TenantID == h.tenant && event.Type == projections.EventKubernetesTrustRolloutStarted {
				count++
			}
			return nil
		}); err != nil {
			t.Fatal(err)
		}
		return count
	}

	prior := fixture("ordered-roots", canary, earlierOnly)
	priorID := appendStart("fixture-prior", prior, 1, true)
	interrupted := fixture(prior.Name, canary, laterOnly)
	interrupted.CABundlePEM = strings.TrimSpace(strings.ReplaceAll(interrupted.CABundlePEM, "\n", "\r\n")) + "\n"
	interruptedID := appendStart("fixture-interrupted", interrupted, 1, false)
	seedKubernetesPosture(t, h, projections.KubernetesControllerPostureReported{
		ReportID: uuid.NewString(), AgentID: uuid.NewString(), ClusterID: canary, ReconcileIntervalSeconds: 30,
		CertificateSigning: projections.KubernetesPostureSection{Complete: true, Resources: []projections.KubernetesPostureResource{}},
		TrustBundles: projections.KubernetesPostureSection{Complete: true, Resources: []projections.KubernetesPostureResource{{
			Name: prior.Name, UID: "public-fixture", ResourceVersion: "1", State: "ready", Reason: "distributed", PublicHash: crypto.SHA256Hex([]byte(prior.CABundlePEM)),
		}}},
	})
	latestID := appendStart("fixture-latest", fixture(prior.Name, canary, laterOnly), 2, true)
	if warm := desired(earlierOnly); len(warm) != 1 || warm[0].RolloutID != priorID {
		t.Fatalf("fixture did not establish the warm projection ordering gap: %+v", warm)
	}
	rollouts := func() []store.KubernetesTrustRollout {
		t.Helper()
		out, err := h.store.ListKubernetesTrustRollouts(t.Context(), h.tenant)
		if err != nil {
			t.Fatal(err)
		}
		return out
	}
	allDesired := func() map[string][]store.KubernetesDesiredTrustBundle {
		return map[string][]store.KubernetesDesiredTrustBundle{canary: desired(canary), earlierOnly: desired(earlierOnly), laterOnly: desired(laterOnly)}
	}
	beforeRollouts, beforeDesired := rollouts(), allDesired()
	retainedID := orchestrator.KubernetesTrustRolloutEventID(h.tenant, interruptedID, "start", "")
	retainedBefore, found, err := h.log.EventByID(t.Context(), retainedID)
	if err != nil || !found || retainedBefore.SchemaVersion != 1 {
		t.Fatalf("missing exact legacy source before retry: %v", err)
	}
	if status, _ := secretsReqKey(t, h, http.MethodPost, path, token, "fixture-interrupted", interrupted); status != http.StatusServiceUnavailable {
		t.Fatalf("interrupted start retry = HTTP %d, want 503 before ordered recovery", status)
	}
	if _, err := h.store.GetKubernetesTrustRollout(t.Context(), h.tenant, interruptedID); !errors.Is(err, store.ErrKubernetesTrustRolloutNotFound) || startCount() != 3 {
		t.Fatalf("retry changed the retained source or missing projection, err=%v", err)
	}
	if !reflect.DeepEqual(beforeRollouts, rollouts()) || !reflect.DeepEqual(beforeDesired, allDesired()) {
		t.Fatal("the 503 retry changed the existing rollout or desired view")
	}
	if err := projector.Rebuild(t.Context(), h.log); err != nil {
		t.Fatalf("ordered rebuild: %v", err)
	}
	if earlier := desired(earlierOnly); len(earlier) != 0 {
		t.Fatalf("earlier-only cluster got a dispatch absent from source order: %+v", earlier)
	}
	if latest := desired(canary); len(latest) != 1 || latest[0].RolloutID != latestID || len(desired(laterOnly)) != 0 {
		t.Fatalf("rebuilt desired state selected an unexpected rollout: %+v", latest)
	}
	checkRollout := func(id, state, first, second string) store.KubernetesTrustRollout {
		t.Helper()
		got, err := h.store.GetKubernetesTrustRollout(t.Context(), h.tenant, id)
		if err != nil || got.State != state || len(got.Clusters) != 2 || got.Clusters[0].State != first || got.Clusters[1].State != second {
			t.Fatalf("ordered rollout %s = %s %+v, err=%v", id, got.State, got.Clusters, err)
		}
		return got
	}
	priorRead := checkRollout(priorID, store.KubernetesTrustRolloutSuperseded, store.KubernetesTrustClusterVerified, store.KubernetesTrustClusterWaiting)
	if priorRead.Clusters[0].ObservedHash != crypto.SHA256Hex([]byte(prior.CABundlePEM)) || priorRead.Clusters[0].ReportID == "" ||
		priorRead.Clusters[1].ClusterID != earlierOnly || priorRead.Clusters[1].DispatchedAt != nil {
		t.Fatalf("prior rollout did not retain the observed canary and earlier-only waiting cluster: %+v", priorRead.Clusters)
	}
	interruptedRead := checkRollout(interruptedID, store.KubernetesTrustRolloutSuperseded, store.KubernetesTrustClusterDispatched, store.KubernetesTrustClusterWaiting)
	checkRollout(latestID, store.KubernetesTrustRolloutRunning, store.KubernetesTrustClusterDispatched, store.KubernetesTrustClusterWaiting)
	retainedAfter, found, err := h.log.EventByID(t.Context(), retainedID)
	if err != nil || !found || retainedAfter.SchemaVersion != 1 || retainedAfter.Sequence != retainedBefore.Sequence || !bytes.Equal(retainedAfter.Data, retainedBefore.Data) ||
		interruptedRead.CABundlePEM != interrupted.CABundlePEM || interruptedRead.BundleSHA256 != crypto.SHA256Hex([]byte(interrupted.CABundlePEM)) {
		t.Fatalf("ordered rebuild changed original v1 bytes or hash: %v", err)
	}
	status, body := secretsReqKey(t, h, http.MethodPost, path, token, "fixture-interrupted", interrupted)
	var recovered api.KubernetesTrustRollout
	if err := json.Unmarshal(body, &recovered); status != http.StatusCreated || err != nil || recovered.ID != interruptedID ||
		recovered.State != store.KubernetesTrustRolloutSuperseded || recovered.CABundlePEM != interrupted.CABundlePEM || startCount() != 3 {
		t.Fatalf("retained v1 retry = HTTP %d, id=%s state=%s, parse=%v", status, recovered.ID, recovered.State, err)
	}
	if status, cached := secretsReqKey(t, h, http.MethodPost, path, token, "fixture-interrupted", interrupted); status != http.StatusCreated || !bytes.Equal(cached, body) {
		t.Fatal("completed v1 key did not return its exact result")
	}
	changed := interrupted
	changed.Key = "other.pem"
	if status, _ := secretsReqKey(t, h, http.MethodPost, path, token, "fixture-interrupted", changed); status != http.StatusConflict {
		t.Fatalf("changed v1 retry = HTTP %d, want 409", status)
	}

	legacy := fixture("completed-legacy-roots", canary)
	legacy.CABundlePEM = "fixture public notes\n" + legacy.CABundlePEM
	legacyID := appendStart("fixture-legacy-success", legacy, 1, true)
	bindingBody, err := json.Marshal(legacy)
	if err != nil {
		t.Fatal(err)
	}
	binding := crypto.SHA256Hex([]byte("kubernetes-trust-rollout\x00secrets-test\x00" + string(bindingBody)))
	legacyBody, err := json.Marshal(api.KubernetesTrustRollout{ID: legacyID, Name: legacy.Name, CABundlePEM: legacy.CABundlePEM})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := h.srv.idem.DoDurableEffectBound(t.Context(), h.tenant, "fixture-legacy-success", binding, func(context.Context) ([]byte, error) {
		return json.Marshal(map[string]any{"s": http.StatusCreated, "b": json.RawMessage(legacyBody), "h": binding})
	}); err != nil {
		t.Fatal(err)
	}
	if status, cached := secretsReqKey(t, h, http.MethodPost, path, token, "fixture-legacy-success", legacy); status != http.StatusCreated || !bytes.Equal(cached, legacyBody) {
		t.Fatalf("the historical completed response changed, HTTP %d", status)
	}

	current := fixture("current-retained-roots", canary)
	currentID := appendStart("fixture-current", current, 2, true)
	time.Sleep(3 * dedup)
	status, body = secretsReqKey(t, h, http.MethodPost, path, token, "fixture-current", current)
	if err := json.Unmarshal(body, &recovered); status != http.StatusCreated || err != nil || recovered.ID != currentID || startCount() != 5 {
		t.Fatalf("retained v2 retry beyond broker dedup = HTTP %d, id=%s, parse=%v", status, recovered.ID, err)
	}

	concurrent := fixture("concurrent-public-roots", canary)
	var wait sync.WaitGroup
	var responses [2][]byte
	var statuses [2]int
	for i := range responses {
		wait.Go(func() {
			statuses[i], responses[i] = secretsReqKey(t, h, http.MethodPost, path, token, "fixture-concurrent", concurrent)
		})
	}
	wait.Wait()
	if statuses != [2]int{http.StatusCreated, http.StatusCreated} || !bytes.Equal(responses[0], responses[1]) || startCount() != 6 {
		t.Fatalf("concurrent retries did not converge to one result and one start: %v", statuses)
	}
}
