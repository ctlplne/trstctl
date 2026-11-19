// SPDX-License-Identifier: BUSL-1.1

package k8s

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"sync/atomic"
	"testing"

	"trstctl.com/trstctl/internal/agent/destination"
	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/crypto/mtls"
)

const fixtureTrustRolloutID = "11111111-1111-4111-8111-111111111111"

func publicTrustFixture(t *testing.T) string {
	t.Helper()
	ca, err := mtls.NewCA("Kubernetes trust test public root")
	if err != nil {
		t.Fatal(err)
	}
	return string(ca.BundlePEM())
}

// CR-431. Only the current bundle's owned ConfigMap can be changed, including
// when a new object appears between a read and attempted create or update.
func TestTrustConfigMapRespectsTheLiveOwner(t *testing.T) {
	bundle := publicTrustFixture(t)
	for _, tc := range []struct {
		name       string
		firstRead  int
		firstOwned bool
		wantReads  int32
		wantWrites int32
		conflict   bool
	}{
		{"foreign", http.StatusOK, false, 1, 0, false},
		{"forbidden read", http.StatusForbidden, false, 1, 0, false},
		{"foreign after create conflict", http.StatusNotFound, false, 2, 1, true},
		{"foreign after update conflict", http.StatusOK, true, 2, 1, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var gets, writes atomic.Int32
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Method == http.MethodGet {
					read := gets.Add(1)
					if read == 1 && tc.firstRead != http.StatusOK {
						w.WriteHeader(tc.firstRead)
						return
					}
					labels := map[string]string{"app.kubernetes.io/managed-by": "fixture-operator"}
					if read == 1 && tc.firstOwned {
						labels = map[string]string{"app.kubernetes.io/managed-by": "trstctl-agent", "trstctl.com/trust-bundle": "public-roots"}
					}
					_ = json.NewEncoder(w).Encode(map[string]any{
						"metadata": map[string]any{"name": "app-roots", "resourceVersion": "1", "labels": labels},
						"data":     map[string]string{"ca-bundle.pem": "fixture-owned-data"},
					})
					return
				}
				write := writes.Add(1)
				if tc.conflict && write == 1 {
					w.WriteHeader(http.StatusConflict)
				}
			}))
			defer srv.Close()
			dst := configMapDestination{client: New(srv.URL, "fixture", "apps", srv.Client()), namespace: "apps", name: "app-roots", bundleName: "public-roots"}
			wrote, err := dst.Install(t.Context(), "ca-bundle.pem", bundle, crypto.SHA256Hex([]byte(bundle)))
			if wrote || err == nil || gets.Load() != tc.wantReads || writes.Load() != tc.wantWrites {
				t.Fatalf("Install = %v, %v, with %d reads and %d writes, want refusal with %d reads and %d writes", wrote, err, gets.Load(), writes.Load(), tc.wantReads, tc.wantWrites)
			}
		})
	}
}

// CR-431, CR-759 and PLAN-SIB-30. A failed preflight cannot touch an early
// valid target while it is still inspecting the remainder of the bundle.
func TestTrustBundlePreflightsEveryTarget(t *testing.T) {
	bundle := publicTrustFixture(t)
	for _, tc := range []struct {
		name   string
		bundle string
		change func(map[string]any)
	}{
		{"denied suffix", "public-roots", func(target map[string]any) { target["namespaces"] = []any{"apps", "outside"} }},
		{"system namespace", "public-roots", func(target map[string]any) { target["namespaces"] = []any{"apps", "kube-public"} }},
		{"invalid namespace", "public-roots", func(target map[string]any) { target["namespaces"] = []any{"apps", "bad namespace"} }},
		{"non-string namespace", "public-roots", func(target map[string]any) { target["namespaces"] = []any{"apps", 22} }},
		{"duplicate namespace", "public-roots", func(target map[string]any) { target["namespaces"] = []any{"apps", "apps"} }},
		{"protected bundle", "trstctl-ca-bundle", func(map[string]any) {}},
		{"protected ConfigMap", "public-roots", func(target map[string]any) { target["configMapName"] = "trstctl-secrets-csi" }},
		{"dotted ConfigMap", "public-roots", func(target map[string]any) { target["configMapName"] = "app..roots" }},
		{"empty ConfigMap", "public-roots", func(target map[string]any) { target["configMapName"] = "" }},
		{"invalid data key", "public-roots", func(target map[string]any) { target["key"] = "..fixture" }},
		{"null data key", "public-roots", func(target map[string]any) { target["key"] = nil }},
		{"wrong type Secret", "public-roots", func(target map[string]any) { target["secret"] = "app-ca" }},
		{"dotted Secret", "public-roots", func(target map[string]any) { target["secret"] = map[string]any{"name": "app..roots"} }},
		{"invalid Secret key", "public-roots", func(target map[string]any) { target["secret"] = map[string]any{"name": "app-ca", "key": "..fixture"} }},
		{"null ClusterTrustBundle", "public-roots", func(target map[string]any) { target["clusterTrustBundle"] = nil }},
		{"dotted ClusterTrustBundle", "public-roots", func(target map[string]any) { target["clusterTrustBundle"] = map[string]any{"name": "app..roots"} }},
		{"label too long", strings.Repeat("r", 64), func(map[string]any) {}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var requests atomic.Int32
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				requests.Add(1)
				w.WriteHeader(http.StatusNotFound)
			}))
			defer srv.Close()
			controller, err := NewIssuerController(New(srv.URL, "fixture", "apps", srv.Client()), nil, DefaultIssuerGroup, runSignerURL, fixtureTrustPolicy(t, false, "apps"))
			if err != nil {
				t.Fatal(err)
			}
			obj := runTrustBundle(tc.bundle, bundle, "apps")
			tc.change(obj["spec"].(map[string]any)["target"].(map[string]any))
			wrote, _, _, err := controller.distributeTrustBundle(t.Context(), obj)
			if wrote != 0 || err == nil || requests.Load() != 0 {
				t.Fatalf("distribution = %d, %v with %d target requests, want a preflight refusal before any target requests", wrote, err, requests.Load())
			}
		})
	}
}

// PLAN-SIB-29. Invalid coordinates are rejected in the generic Secret path
// and by the native certificate's already-Ready existence check.
func TestSecretOperationsRejectInvalidCoordinatesBeforeRequest(t *testing.T) {
	var requests atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		requests.Add(1)
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()
	client := New(srv.URL, "fixture", "apps", srv.Client())
	controller, err := NewIssuerController(client, nil, DefaultIssuerGroup, runSignerURL)
	if err != nil {
		t.Fatal(err)
	}
	credential := destination.Credential{CertPEM: []byte(publicTrustFixture(t))}
	for _, coords := range [][2]string{{"bad namespace", "app-roots"}, {"apps", "app..roots"}} {
		dst := NewSecretDestination(client, coords[0], coords[1])
		installErr := dst.Install(t.Context(), credential)
		_, readErr := dst.InstallAndRead(t.Context(), credential)
		_, statusErr := dst.Status(t.Context())
		_, nativeErr := controller.secretPresent(t.Context(), coords[0], coords[1])
		if installErr == nil || readErr == nil || statusErr == nil || nativeErr == nil || requests.Load() != 0 {
			t.Errorf("invalid coordinates issued %d requests, errors = [%v, %v, %v, %v]", requests.Load(), installErr, readErr, statusErr, nativeErr)
		}
	}
}

// CR-431. The desired endpoint, the stored object path and the CSI reader each
// enforce local opt-in, including when the object predates the agent restart.
func TestRemoteTrustNeedsLocalConsentAtEveryReader(t *testing.T) {
	bundle := publicTrustFixture(t)
	hash := crypto.SHA256Hex([]byte(bundle))
	obj := runTrustBundle("public-roots", bundle, "apps")
	fakeMeta(obj)["labels"] = map[string]any{"app.kubernetes.io/managed-by": "trstctl-agent"}
	fakeMeta(obj)["annotations"] = map[string]any{trustRolloutAnnotation: fixtureTrustRolloutID, "trstctl.com/rollout-sha256": hash}
	var configMaps, trustReads atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.Path, "/configmaps") {
			configMaps.Add(1)
			w.WriteHeader(http.StatusNotFound)
			return
		}
		trustReads.Add(1)
		_ = json.NewEncoder(w).Encode(obj)
	}))
	defer srv.Close()
	client := New(srv.URL, "fixture", "apps", srv.Client())
	controller, err := NewIssuerController(client, nil, DefaultIssuerGroup, runSignerURL)
	if err != nil {
		t.Fatal(err)
	}
	desired := DesiredTrustBundle{RolloutID: fixtureTrustRolloutID, Name: "public-roots", CABundlePEM: bundle, BundleSHA256: hash, ConfigMapName: "public-roots-ca", Key: "ca-bundle.pem", Namespaces: []string{"apps"}}
	if _, err := controller.ApplyDesiredTrustBundles(t.Context(), []DesiredTrustBundle{desired}); err == nil || trustReads.Load() != 0 {
		t.Errorf("opted-out desired receiver did not refuse before communicating with the API: %d requests, %v", trustReads.Load(), err)
	}
	if _, _, _, err := controller.distributeTrustBundle(t.Context(), obj); err == nil || configMaps.Load() != 0 {
		t.Errorf("opted-out stored rollout did not refuse before contacting targets: %d requests, %v", configMaps.Load(), err)
	}
	if got, err := client.TrustBundlePEM(t.Context(), "public-roots"); err == nil || len(got) != 0 {
		t.Errorf("opted-out CSI source returned %d public bytes, %v", len(got), err)
	}
}

// CR-431. Only the canonical public certificate envelope can reach targets
// and file consumers. The raw fixture text is intentionally inert.
func TestTrustBundlePEMRejectsTextAndCanonicalizesCertificates(t *testing.T) {
	first, second := publicTrustFixture(t), publicTrustFixture(t)
	unformatted := strings.ReplaceAll(first, "\n", "\r\n") + "\n\n" + second
	want := first + second
	got, hash, err := trustBundlePEM(map[string]any{"caBundlePEM": unformatted})
	if err != nil || got != want || hash != crypto.SHA256Hex([]byte(want)) {
		t.Errorf("public bundle canonicalization = %d bytes, %s, %v", len(got), hash, err)
	}
	if _, _, err := trustBundlePEM(map[string]any{"caBundlePEM": "fixture public notes\n" + first}); err == nil {
		t.Error("trust parser accepted non-certificate text")
	}
}

// CR-431. A generic managed-by label is insufficient to revise a TrustBundle.
// Both create and update conflicts must read the current owner before retrying.
func TestDesiredTrustBundleRequiresPriorRolloutOwnership(t *testing.T) {
	bundle := publicTrustFixture(t)
	for _, tc := range []struct {
		name      string
		conflict  string
		wantReads int32
		wantPosts int32
		wantPuts  int32
	}{
		{name: "existing", wantReads: 1},
		{name: "foreign after create conflict", conflict: http.MethodPost, wantReads: 2, wantPosts: 1},
		{name: "foreign after update conflict", conflict: http.MethodPut, wantReads: 2, wantPuts: 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var gets, posts, puts atomic.Int32
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				switch r.Method {
				case http.MethodGet:
					first := gets.Add(1) == 1
					if first && tc.conflict == http.MethodPost {
						w.WriteHeader(http.StatusNotFound)
						return
					}
					obj := runTrustBundle("public-roots", bundle, "apps")
					meta := fakeMeta(obj)
					meta["labels"] = map[string]any{"app.kubernetes.io/managed-by": "trstctl-agent"}
					meta["resourceVersion"] = "8"
					if first && tc.conflict == http.MethodPut {
						meta["resourceVersion"] = "7"
						meta["annotations"] = map[string]any{trustRolloutAnnotation: "22222222-2222-4222-8222-222222222222"}
					}
					_ = json.NewEncoder(w).Encode(obj)
				case http.MethodPost:
					posts.Add(1)
					w.WriteHeader(http.StatusConflict)
				case http.MethodPut:
					first := puts.Add(1) == 1
					if first && tc.conflict == http.MethodPut {
						var obj map[string]any
						if err := json.NewDecoder(r.Body).Decode(&obj); err != nil || fakeMeta(obj)["resourceVersion"] != "7" {
							t.Errorf("the update lost the admitted object's resourceVersion: %v", err)
						}
						w.WriteHeader(http.StatusConflict)
					}
				}
			}))
			defer srv.Close()
			controller, err := NewIssuerController(New(srv.URL, "fixture", "apps", srv.Client()), nil, DefaultIssuerGroup, runSignerURL, fixtureTrustPolicy(t, true, "apps"))
			if err != nil {
				t.Fatal(err)
			}
			desired := DesiredTrustBundle{
				RolloutID: fixtureTrustRolloutID, Name: "public-roots", CABundlePEM: bundle, BundleSHA256: crypto.SHA256Hex([]byte(bundle)),
				ConfigMapName: "public-roots-ca", Key: "ca-bundle.pem", Namespaces: []string{"apps"},
			}
			if wrote, err := controller.ApplyDesiredTrustBundles(t.Context(), []DesiredTrustBundle{desired}); wrote != 0 || err == nil ||
				gets.Load() != tc.wantReads || posts.Load() != tc.wantPosts || puts.Load() != tc.wantPuts {
				t.Fatalf("apply = %d, %v, GETs=%d POSTs=%d PUTs=%d", wrote, err, gets.Load(), posts.Load(), puts.Load())
			}
		})
	}
}

// CR-431. Missing local consent blocks only the affected bundle. A claimed
// remote origin without agent ownership also forbids status writes.
func TestTrustReconcileIsolatesPermanentRefusals(t *testing.T) {
	bundle := publicTrustFixture(t)
	remote := runTrustBundle("stored-rollout", bundle, "apps")
	fakeMeta(remote)["labels"] = map[string]any{"app.kubernetes.io/managed-by": "trstctl-agent"}
	fakeMeta(remote)["annotations"] = map[string]any{trustRolloutAnnotation: fixtureTrustRolloutID, "trstctl.com/rollout-sha256": crypto.SHA256Hex([]byte(bundle))}
	unowned := runTrustBundle("claimed-rollout", bundle, "apps")
	fakeMeta(unowned)["annotations"] = map[string]any{trustRolloutAnnotation: fixtureTrustRolloutID}
	local := runTrustBundle("local-roots", bundle, "apps")
	var remoteTargets, unownedStatus, localTargets atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && r.URL.Path == trustBundleCollectionPath():
			_ = json.NewEncoder(w).Encode(map[string]any{"items": []map[string]any{unowned, remote, local}})
		case r.Method == http.MethodGet && strings.Contains(r.URL.Path, "/configmaps/"):
			if strings.HasSuffix(r.URL.Path, "/local-roots-ca") {
				localTargets.Add(1)
			} else {
				remoteTargets.Add(1)
			}
			w.WriteHeader(http.StatusNotFound)
		case strings.HasSuffix(r.URL.Path, "/claimed-rollout/status"):
			unownedStatus.Add(1)
			_ = json.NewEncoder(w).Encode(unowned)
		case strings.HasSuffix(r.URL.Path, "/stored-rollout/status"):
			_ = json.NewEncoder(w).Encode(remote)
		case strings.HasSuffix(r.URL.Path, "/local-roots/status"):
			_ = json.NewEncoder(w).Encode(local)
		case r.Method == http.MethodGet:
			_ = json.NewEncoder(w).Encode(map[string]any{"items": []any{}})
		default:
			w.WriteHeader(http.StatusCreated)
		}
	}))
	defer srv.Close()
	controller, err := NewIssuerController(New(srv.URL, "fixture", "apps", srv.Client()), nil, DefaultIssuerGroup, runSignerURL, fixtureTrustPolicy(t, false, "apps"))
	if err != nil {
		t.Fatal(err)
	}
	result, err := controller.Reconcile(t.Context(), "apps")
	if result.TrustBundlesDistributed != 1 || result.TrustBundleComplete || result.TrustBundleFailureCode != "reconcile_failed" || err == nil || remoteTargets.Load() != 0 || unownedStatus.Load() != 0 || localTargets.Load() != 1 {
		t.Fatalf("reconcile = %d, %v, remote target GETs=%d unowned status writes=%d local target GETs=%d", result.TrustBundlesDistributed, err, remoteTargets.Load(), unownedStatus.Load(), localTargets.Load())
	}
	posture := result.TrustBundlePosture
	if len(posture) != 3 || posture[0].State != "failed" || posture[1].State != "failed" || posture[2].State != "ready" {
		t.Fatalf("reconcile posture = %+v", posture)
	}
}

func fixtureTrustPolicy(t *testing.T, remote bool, namespaces string) TrustDistributionPolicy {
	t.Helper()
	policy, err := ParseTrustDistributionPolicy(remote, namespaces)
	if err != nil {
		t.Fatal(err)
	}
	return policy
}

// CR-431. Readmission stamps the exact canonical hash and replaces the full
// former remote spec. A legacy dispatch with a different recorded hash cannot
// rewrite the newly admitted object.
func TestRemoteTrustReadmissionReplacesLegacyTargetAndPreservesHash(t *testing.T) {
	bundle := publicTrustFixture(t)
	hash := crypto.SHA256Hex([]byte(bundle))
	api := newFakeAPI(resTrustBundles, resConfigMaps, resSecrets)
	legacy := runTrustBundle("public-roots", bundle, "apps")
	fakeMeta(legacy)["labels"] = map[string]any{"app.kubernetes.io/managed-by": "trstctl-agent"}
	fakeMeta(legacy)["annotations"] = map[string]any{trustRolloutAnnotation: fixtureTrustRolloutID}
	target := legacy["spec"].(map[string]any)["target"].(map[string]any)
	target["secret"] = map[string]any{"name": "old-fixture-target"}
	api.seed(resTrustBundles, legacy)
	srv := httptest.NewServer(api.handler())
	defer srv.Close()
	client := New(srv.URL, "fixture", "apps", srv.Client())
	controller, err := NewIssuerController(client, nil, DefaultIssuerGroup, runSignerURL, fixtureTrustPolicy(t, true, "apps"))
	if err != nil {
		t.Fatal(err)
	}
	source := NewTrustBundleSource(client, true)
	if got, err := source.TrustBundlePEM(t.Context(), "public-roots"); err == nil || len(got) != 0 {
		t.Fatal("legacy CR was eligible for a CSI read without its admitted hash")
	}
	desired := DesiredTrustBundle{RolloutID: "22222222-2222-4222-8222-222222222222", Name: "public-roots", CABundlePEM: bundle, BundleSHA256: hash,
		ConfigMapName: "public-roots-ca", Key: "ca-bundle.pem", Namespaces: []string{"apps"}}
	if wrote, err := controller.ApplyDesiredTrustBundles(t.Context(), []DesiredTrustBundle{desired}); err != nil || wrote != 1 {
		t.Fatalf("re-admit legacy CR = %d, %v", wrote, err)
	}
	live, _ := api.get(resTrustBundles, "", desired.Name)
	annotations, _ := fakeMeta(live)["annotations"].(map[string]any)
	target = live["spec"].(map[string]any)["target"].(map[string]any)
	if _, optionalRemains := target["secret"]; optionalRemains || annotations[trustRolloutAnnotation] != desired.RolloutID || annotations[trustRolloutHashAnnotation] != hash {
		t.Fatal("re-admission did not replace invalid remote targets and bind the revised rollout")
	}
	if got, err := source.TrustBundlePEM(t.Context(), desired.Name); err != nil || string(got) != bundle {
		t.Fatalf("admitted CR did not return its exact public PEM: %v", err)
	}
	if wrote, err := controller.ApplyDesiredTrustBundles(t.Context(), []DesiredTrustBundle{desired}); err != nil || wrote != 0 {
		t.Fatalf("converged revision should not trigger a write: %d, %v", wrote, err)
	}
	for _, legacyInput := range []string{
		strings.TrimSpace(strings.ReplaceAll(bundle, "\n", "\r\n")) + "\n",
		"fixture public notes\n" + bundle,
	} {
		before := api.totalWrites()
		old := desired
		old.CABundlePEM = legacyInput
		old.BundleSHA256 = crypto.SHA256Hex([]byte(legacyInput))
		if wrote, err := controller.ApplyDesiredTrustBundles(t.Context(), []DesiredTrustBundle{old}); err == nil || wrote != 0 || api.totalWrites() != before {
			t.Fatalf("legacy dispatch should not change its encoding or create a remote CR: %d, %v", wrote, err)
		}
	}
}

// CR-431. The shared reconcile check also protects the watch entry point
// before any mutation of an object with a foreign remote-origin claim.
func TestTrustBundleWatchDoesNotWriteToUnownedRemoteObjects(t *testing.T) {
	f := startRunFixture(t)
	bundle := runTrustBundle("watch-claimed-roots", string(f.ca.BundlePEM()), "apps")
	fakeMeta(bundle)["annotations"] = map[string]any{trustRolloutAnnotation: fixtureTrustRolloutID}
	f.api.seed(resTrustBundles, bundle)
	eventually(t, "watch reports the unowned remote bundle as failed", func() bool {
		report, ok := f.lastReport()
		return ok && !report.TrustBundles.Complete && len(report.TrustBundles.Resources) == 1 && report.TrustBundles.Resources[0].State == "failed"
	})
	if writes := f.api.writeCount(http.MethodPut, resTrustBundles); writes != 0 {
		t.Fatalf("watch wrote %d status updates on an unowned object", writes)
	}
	if writes := f.api.writeCount(http.MethodPost, resConfigMaps); writes != 0 {
		t.Fatalf("watch installed %d targets for an unowned object", writes)
	}
}

// CR-431. Ownership labels on a protected ConfigMap do not authorize reads or
// writes through a TrustBundle target.
func TestTrustBundleLeavesReservedOwnedConfigMapAlone(t *testing.T) {
	for _, targetName := range []string{"trstctl-ca-bundle", "trstctl-secrets-csi"} {
		t.Run(targetName, func(t *testing.T) {
			api := newFakeAPI(resConfigMaps)
			const sameBundle = "public-roots"
			original := api.seed(resConfigMaps, map[string]any{
				"metadata": map[string]any{"name": targetName, "namespace": "apps", "labels": trustObjectLabels(sameBundle)},
				"data":     map[string]any{"ca-bundle.pem": "retained-fixture-data", "application": "fixture"},
			})
			inner := api.handler()
			var requests atomic.Int32
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				requests.Add(1)
				inner.ServeHTTP(w, r)
			}))
			defer srv.Close()
			dst := configMapDestination{client: New(srv.URL, "fixture", "apps", srv.Client()), namespace: "apps", name: targetName, bundleName: sameBundle}
			bundle := publicTrustFixture(t)
			if wrote, err := dst.Install(t.Context(), "ca-bundle.pem", bundle, crypto.SHA256Hex([]byte(bundle))); wrote || err == nil || requests.Load() != 0 {
				t.Fatalf("protected target was contacted: wrote=%v error=%v requests=%d", wrote, err, requests.Load())
			}
			retained, _ := api.get(resConfigMaps, "apps", targetName)
			if !reflect.DeepEqual(retained, original) {
				t.Fatal("protected target changed despite refusal")
			}
		})
	}
}
