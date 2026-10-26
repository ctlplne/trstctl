// SPDX-License-Identifier: BUSL-1.1

package k8s

import (
	"context"
	"encoding/base64"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/crypto/mtls"
)

const (
	runSignerURL      = "https://trstctl.test/api/v1/ca/authorities/a1/issue"
	resClusterIssuers = "trstctl.com/v1alpha1/clusterissuers"
	resIssuers        = "trstctl.com/v1alpha1/issuers"
	resCertificates   = "trstctl.com/v1alpha1/certificates"
	resTrustBundles   = "trstctl.com/v1alpha1/trustbundles"
	resCSRs           = "certificates.k8s.io/v1/certificatesigningrequests"
	resConfigMaps     = "v1/configmaps"
	resSecrets        = "v1/secrets"
)

// runFixture runs the event-driven controller against a fake API server that
// serves no cert-manager resources, with resync and heartbeat an hour away so
// only watch events can drive it.
type runFixture struct {
	api     *fakeAPI
	ca      *mtls.CA
	mu      sync.Mutex
	reports []ControllerPostureReport
}

func startRunFixture(t *testing.T) *runFixture {
	t.Helper()
	ca, err := mtls.NewCA("run fixture CA")
	if err != nil {
		t.Fatal(err)
	}
	f := &runFixture{
		api: newFakeAPI(resClusterIssuers, resIssuers, resCertificates, resTrustBundles, resCSRs, resConfigMaps, resSecrets),
		ca:  ca,
	}
	srv := httptest.NewServer(f.api.handler())
	controller, err := NewIssuerController(New(srv.URL, "tok", "apps", srv.Client()), SignerFunc(func(_ context.Context, csrDER []byte, ttl time.Duration) ([]byte, error) {
		return ca.SignClientCSR(csrDER, ttl)
	}), DefaultIssuerGroup, runSignerURL)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		done <- controller.Run(ctx, RunOptions{
			ClusterID: "sha256:" + strings.Repeat("a", 64), ReportEvery: time.Hour, Resync: time.Hour,
			Report: func(_ context.Context, report ControllerPostureReport) {
				f.mu.Lock()
				defer f.mu.Unlock()
				f.reports = append(f.reports, report)
			},
		})
	}()
	t.Cleanup(func() {
		cancel()
		if err := <-done; err != nil {
			t.Errorf("Run: %v", err)
		}
		srv.Close()
	})
	return f
}

func (f *runFixture) lastReport() (ControllerPostureReport, bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.reports) == 0 {
		return ControllerPostureReport{}, false
	}
	return f.reports[len(f.reports)-1], true
}

func runTrustBundle(name, bundlePEM string, namespaces ...string) map[string]any {
	targets := make([]any, 0, len(namespaces))
	for _, namespace := range namespaces {
		targets = append(targets, namespace)
	}
	return map[string]any{
		"apiVersion": trstctlAPIVersion, "kind": "TrustBundle", "metadata": map[string]any{"name": name},
		"spec": map[string]any{"caBundlePEM": bundlePEM, "target": map[string]any{"configMapName": name + "-ca", "namespaces": targets}},
	}
}

func configMapBundle(f *runFixture, namespace, name string) string {
	obj, ok := f.api.get(resConfigMaps, namespace, name)
	if !ok {
		return ""
	}
	data, _ := obj["data"].(map[string]any)
	value, _ := data["ca-bundle.pem"].(string)
	return value
}

// quiet waits until the controller has made no API write for a second.
func quiet(t *testing.T, f *runFixture) int {
	t.Helper()
	last := f.api.totalWrites()
	stableSince := time.Now()
	deadline := time.Now().Add(10 * time.Second)
	for time.Since(stableSince) < time.Second {
		if time.Now().After(deadline) {
			t.Fatalf("the controller kept writing: %v", f.api.writes)
		}
		time.Sleep(50 * time.Millisecond)
		if now := f.api.totalWrites(); now != last {
			last, stableSince = now, time.Now()
		}
	}
	return last
}

// A137: TrustBundles are distributed from watch events (resync is an hour
// away), a converged bundle causes no further writes, a deleted or edited
// ConfigMap is put back, a new target namespace is filled, and the posture
// report that follows is complete — with cert-manager not installed.
func TestRunDistributesTrustBundlesFromWatchEvents(t *testing.T) {
	f := startRunFixture(t)
	bundle := string(f.ca.BundlePEM())
	time.Sleep(200 * time.Millisecond) // let the informers list an empty cluster first
	f.api.seed(resTrustBundles, runTrustBundle("roots", bundle, "apps", "payments"))
	eventually(t, "the bundle reaches both namespaces", func() bool {
		return configMapBundle(f, "apps", "roots-ca") == bundle && configMapBundle(f, "payments", "roots-ca") == bundle
	})
	eventually(t, "the bundle is marked Ready", func() bool {
		obj, _ := f.api.get(resTrustBundles, "", "roots")
		return isReady(obj)
	})
	writes := quiet(t, f)
	time.Sleep(time.Second)
	if now := f.api.totalWrites(); now != writes {
		t.Fatalf("a converged bundle kept writing: %d writes became %d (%v)", writes, now, f.api.writes)
	}

	f.api.remove(resConfigMaps, "payments", "roots-ca")
	eventually(t, "a deleted ConfigMap is restored", func() bool { return configMapBundle(f, "payments", "roots-ca") == bundle })
	f.api.mutate(resConfigMaps, "apps", "roots-ca", func(obj map[string]any) {
		obj["data"] = map[string]any{"ca-bundle.pem": "tampered", "other.pem": "kept"}
	})
	eventually(t, "an edited ConfigMap is restored", func() bool { return configMapBundle(f, "apps", "roots-ca") == bundle })
	if obj, _ := f.api.get(resConfigMaps, "apps", "roots-ca"); obj["data"].(map[string]any)["other.pem"] != "kept" {
		t.Fatal("restoring the bundle dropped another key in the ConfigMap")
	}

	f.api.mutate(resTrustBundles, "", "roots", func(obj map[string]any) {
		obj["spec"].(map[string]any)["target"].(map[string]any)["namespaces"] = []any{"apps", "payments", "billing"}
	})
	eventually(t, "a new target namespace is filled and counted", func() bool {
		obj, _ := f.api.get(resTrustBundles, "", "roots")
		status, _ := obj["status"].(map[string]any)
		return configMapBundle(f, "billing", "roots-ca") == bundle && status["targets"] == float64(3)
	})
	eventually(t, "a complete posture report follows", func() bool {
		report, ok := f.lastReport()
		return ok && report.TrustBundles.Complete && len(report.TrustBundles.Resources) == 1 &&
			report.TrustBundles.Resources[0].State == "ready" && len(report.TrustBundles.Resources[0].PublicHash) == 64 &&
			report.CertificateRequests.Complete && report.CertificateSigning.Complete
	})
}

// A137: an invalid bundle is reported failed and not retried on a timer; it
// is reconsidered when it changes.
func TestRunReportsAnInvalidTrustBundleWithoutRetrying(t *testing.T) {
	f := startRunFixture(t)
	f.api.seed(resTrustBundles, runTrustBundle("bad", "-----BEGIN PRIVATE KEY-----\nS0VZ\n-----END PRIVATE KEY-----\n", "apps"))
	eventually(t, "the invalid bundle is reported failed", func() bool {
		report, ok := f.lastReport()
		return ok && !report.TrustBundles.Complete && report.TrustBundles.FailureCode == "reconcile_failed" &&
			len(report.TrustBundles.Resources) == 1 && report.TrustBundles.Resources[0].State == "failed"
	})
	if f.api.writeCount(http.MethodPost, resConfigMaps) != 0 || f.api.writeCount(http.MethodPut, resTrustBundles) != 0 {
		t.Fatalf("an invalid bundle was written: %v", f.api.writes)
	}
	f.api.mutate(resTrustBundles, "", "bad", func(obj map[string]any) {
		obj["spec"].(map[string]any)["caBundlePEM"] = string(f.ca.BundlePEM())
	})
	eventually(t, "the corrected bundle is distributed", func() bool { return configMapBundle(f, "apps", "bad-ca") != "" })
}

// A144: an approved native CSR is signed from its watch event, including one
// approved after it was created, with cert-manager absent.
func TestRunSignsApprovedCSRsAsTheyAreApproved(t *testing.T) {
	f := startRunFixture(t)
	f.api.seed(resClusterIssuers, map[string]any{
		"metadata": map[string]any{"name": "platform"}, "spec": map[string]any{"signerURL": runSignerURL},
	})
	request := func(name string, approved bool) map[string]any {
		key, err := mtls.GenerateAgentKey(name + ".apps.svc")
		if err != nil {
			t.Fatal(err)
		}
		der, err := key.CSR()
		if err != nil {
			t.Fatal(err)
		}
		obj := map[string]any{
			"metadata": map[string]any{"name": name},
			"spec": map[string]any{
				"request":    base64.StdEncoding.EncodeToString(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der})),
				"signerName": "trstctl.com/platform",
			},
		}
		if approved {
			obj["status"] = map[string]any{"conditions": []any{map[string]any{"type": "Approved", "status": "True"}}}
		}
		return obj
	}
	signed := func(name string) bool {
		obj, _ := f.api.get(resCSRs, "", name)
		status, _ := obj["status"].(map[string]any)
		cert, _ := status["certificate"].(string)
		return cert != ""
	}
	f.api.seed(resCSRs, request("approved", true))
	f.api.seed(resCSRs, request("later", false))
	eventually(t, "the approved CSR is signed", func() bool { return signed("approved") })
	time.Sleep(300 * time.Millisecond)
	if signed("later") {
		t.Fatal("an unapproved CSR was signed")
	}
	f.api.mutate(resCSRs, "", "later", func(obj map[string]any) {
		obj["status"] = map[string]any{"conditions": []any{map[string]any{"type": "Approved", "status": "True"}}}
	})
	eventually(t, "a CSR approved later is signed", func() bool { return signed("later") })
}

// A144: a native trstctl Certificate is issued into its Secret, renewed two
// thirds of the way through its validity without waiting for a resync, and
// reissued when its Secret is deleted or its spec changes.
func TestRunIssuesAndRenewsNativeCertificates(t *testing.T) {
	f := startRunFixture(t)
	f.api.seed(resClusterIssuers, map[string]any{
		"metadata": map[string]any{"name": "short"}, "spec": map[string]any{"signerURL": runSignerURL, "ttlSeconds": 3},
	})
	f.api.seed(resCertificates, map[string]any{
		"metadata": map[string]any{"name": "web", "namespace": "apps"},
		"spec": map[string]any{
			"secretName": "web-tls", "dnsNames": []any{"web.apps.svc"},
			"issuerRef": map[string]any{"name": "short", "kind": "ClusterIssuer", "group": DefaultIssuerGroup},
		},
	})
	certificate := func() string {
		obj, _ := f.api.get(resSecrets, "apps", "web-tls")
		data, _ := obj["data"].(map[string]any)
		value, _ := data["tls.crt"].(string)
		return value
	}
	eventually(t, "the certificate is issued into its Secret", func() bool { return certificate() != "" })
	first := certificate()
	// The Secret is written before the status that records it.
	eventually(t, "the issuance is recorded in status", func() bool {
		obj, _ := f.api.get(resCertificates, "apps", "web")
		status, _ := obj["status"].(map[string]any)
		return stringField(status, "renewalTime") != ""
	})
	obj, _ := f.api.get(resCertificates, "apps", "web")
	status, _ := obj["status"].(map[string]any)
	renewAt, err := time.Parse(time.RFC3339, stringField(status, "renewalTime"))
	if err != nil || !isReady(obj) || stringField(status, "specHash") == "" || stringField(status, "notAfter") == "" {
		t.Fatalf("issued status = %v (%v)", status, err)
	}
	if until := time.Until(renewAt); until > 3*time.Second {
		t.Fatalf("renewal is %s away for a three-second certificate", until)
	}
	eventually(t, "the certificate is renewed before it expires", func() bool { return certificate() != "" && certificate() != first })

	f.api.remove(resSecrets, "apps", "web-tls")
	f.api.mutate(resCertificates, "apps", "web", func(obj map[string]any) {
		obj["spec"].(map[string]any)["dnsNames"] = []any{"web.apps.svc", "www.apps.svc"}
	})
	eventually(t, "a changed spec is reissued into a recreated Secret", func() bool {
		obj, _ := f.api.get(resCertificates, "apps", "web")
		status, _ := obj["status"].(map[string]any)
		spec, _ := obj["spec"].(map[string]any)
		return certificate() != "" && stringField(status, "specHash") == nativeSpecHash(spec)
	})
}

// The full Reconcile pass no longer stops at a cluster without cert-manager:
// it still signs native CSRs and distributes trust bundles, and its second
// pass over the converged bundle writes nothing.
func TestReconcileWithoutCertManagerSignsCSRsAndDistributesBundles(t *testing.T) {
	ca, err := mtls.NewCA("full pass CA")
	if err != nil {
		t.Fatal(err)
	}
	api := newFakeAPI(resClusterIssuers, resIssuers, resCertificates, resTrustBundles, resCSRs, resConfigMaps, resSecrets)
	srv := httptest.NewServer(api.handler())
	defer srv.Close()
	controller, err := NewIssuerController(New(srv.URL, "tok", "apps", srv.Client()), SignerFunc(func(_ context.Context, csrDER []byte, ttl time.Duration) ([]byte, error) {
		return ca.SignClientCSR(csrDER, ttl)
	}), DefaultIssuerGroup, runSignerURL)
	if err != nil {
		t.Fatal(err)
	}
	api.seed(resClusterIssuers, map[string]any{"metadata": map[string]any{"name": "platform"}, "spec": map[string]any{"signerURL": runSignerURL}})
	key, err := mtls.GenerateAgentKey("db.apps.svc")
	if err != nil {
		t.Fatal(err)
	}
	der, err := key.CSR()
	if err != nil {
		t.Fatal(err)
	}
	api.seed(resCSRs, map[string]any{
		"metadata": map[string]any{"name": "db"},
		"spec": map[string]any{
			"request":    base64.StdEncoding.EncodeToString(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der})),
			"signerName": "trstctl.com/platform",
		},
		"status": map[string]any{"conditions": []any{map[string]any{"type": "Approved", "status": "True"}}},
	})
	api.seed(resTrustBundles, runTrustBundle("roots", string(ca.BundlePEM()), "apps"))

	result, err := controller.Reconcile(context.Background(), "apps")
	if err != nil {
		t.Fatalf("Reconcile without cert-manager: %v", err)
	}
	if !result.CertificateRequestComplete || result.KubernetesCSRsSigned != 1 || result.TrustBundlesDistributed != 1 || !result.TrustBundleComplete {
		t.Fatalf("result = %+v, want the CSR signed and the bundle distributed", result)
	}
	before := api.totalWrites()
	again, err := controller.Reconcile(context.Background(), "apps")
	if err != nil || again.TrustBundlesDistributed != 0 || again.KubernetesCSRsSigned != 0 {
		t.Fatalf("second pass = %+v, %v", again, err)
	}
	if after := api.totalWrites(); after != before {
		t.Fatalf("a second pass over converged objects wrote %d times: %v", after-before, api.writes)
	}
	if posture := again.TrustBundlePosture; len(posture) != 1 || posture[0].State != "ready" || posture[0].Reason != "already_ready" {
		t.Fatalf("converged bundle posture = %+v", posture)
	}
}

// A138: a TrustBundle the control plane rolls out here is created as the
// agent's own object (and then distributed by the watch-driven controller), a
// repeat changes nothing, a changed bundle updates it, someone else's object of
// the same name is left alone, and a bundle that does not match its hash is
// refused.
func TestApplyDesiredTrustBundlesCreatesUpdatesAndRefuses(t *testing.T) {
	f := startRunFixture(t)
	srv := httptest.NewServer(f.api.handler())
	defer srv.Close()
	controller, err := NewIssuerController(New(srv.URL, "tok", "apps", srv.Client()), SignerFunc(func(context.Context, []byte, time.Duration) ([]byte, error) {
		return nil, nil
	}), DefaultIssuerGroup, runSignerURL)
	if err != nil {
		t.Fatal(err)
	}
	bundle, hash, err := trustBundlePEM(map[string]any{"caBundlePEM": string(f.ca.BundlePEM())})
	if err != nil {
		t.Fatal(err)
	}
	desired := DesiredTrustBundle{
		RolloutID: "11111111-1111-4111-8111-111111111111", Name: "platform-roots", CABundlePEM: bundle, BundleSHA256: hash,
		ConfigMapName: "platform-roots", Key: "ca-bundle.pem", Namespaces: []string{"apps"},
	}
	ctx := context.Background()
	if n, err := controller.ApplyDesiredTrustBundles(ctx, []DesiredTrustBundle{desired}); err != nil || n != 1 {
		t.Fatalf("first apply = %d, %v", n, err)
	}
	obj, ok := f.api.get(resTrustBundles, "", "platform-roots")
	if !ok || fakeMeta(obj)["labels"].(map[string]any)["app.kubernetes.io/managed-by"] != "trstctl-agent" ||
		fakeMeta(obj)["annotations"].(map[string]any)[trustRolloutAnnotation] != desired.RolloutID {
		t.Fatalf("applied TrustBundle = %v", obj)
	}
	eventually(t, "the running controller distributes the rolled-out bundle", func() bool {
		return configMapBundle(f, "apps", "platform-roots") == bundle
	})
	if n, err := controller.ApplyDesiredTrustBundles(ctx, []DesiredTrustBundle{desired}); err != nil || n != 0 {
		t.Fatalf("repeat apply = %d, %v", n, err)
	}
	moved := desired
	moved.RolloutID, moved.Namespaces = "22222222-2222-4222-8222-222222222222", []string{"apps", "payments"}
	if n, err := controller.ApplyDesiredTrustBundles(ctx, []DesiredTrustBundle{moved}); err != nil || n != 1 {
		t.Fatalf("changed apply = %d, %v", n, err)
	}
	eventually(t, "the new namespace receives the bundle", func() bool { return configMapBundle(f, "payments", "platform-roots") == bundle })

	f.api.seed(resTrustBundles, map[string]any{"metadata": map[string]any{"name": "someone-elses"}, "spec": map[string]any{"caBundlePEM": bundle}})
	foreign := desired
	foreign.Name = "someone-elses"
	if _, err := controller.ApplyDesiredTrustBundles(ctx, []DesiredTrustBundle{foreign}); err == nil || !strings.Contains(err.Error(), "not created by the agent") {
		t.Fatalf("apply over a foreign TrustBundle = %v", err)
	}
	mismatched := desired
	mismatched.Name, mismatched.BundleSHA256 = "mismatched", strings.Repeat("0", 64)
	if _, err := controller.ApplyDesiredTrustBundles(ctx, []DesiredTrustBundle{mismatched}); err == nil {
		t.Fatal("a bundle that does not match its hash was applied")
	}
	if _, exists := f.api.get(resTrustBundles, "", "mismatched"); exists {
		t.Fatal("a mismatched bundle was written")
	}
}
