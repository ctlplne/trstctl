// SPDX-License-Identifier: BUSL-1.1

package projections_test

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/projections"
	"trstctl.com/trstctl/internal/store"
)

func TestKubernetesControllerPostureEventProjectsTenantReadModels(t *testing.T) {
	ctx := context.Background()
	st := newStore(t)
	log := openLog(t)
	report := projections.KubernetesControllerPostureReported{
		ReportID:  "33333333-3333-3333-3333-333333333333",
		AgentID:   "44444444-4444-4444-4444-444444444444",
		ClusterID: "sha256:" + strings.Repeat("a", 64), ReconcileIntervalSeconds: 30,
		CertificateSigning: projections.KubernetesPostureSection{Complete: true, Resources: []projections.KubernetesPostureResource{{
			Name: "web-csr", UID: "csr-uid", ResourceVersion: "17", State: "ready", Reason: "signed", PublicHash: strings.Repeat("b", 64),
		}}},
		TrustBundles: projections.KubernetesPostureSection{Complete: true, Resources: []projections.KubernetesPostureResource{{
			Name: "corp-roots", UID: "bundle-uid", ResourceVersion: "9", State: "ready", Reason: "distributed", PublicHash: strings.Repeat("c", 64),
		}}},
	}
	payload, err := projections.MarshalKubernetesPostureReport(report)
	if err != nil {
		t.Fatal(err)
	}
	ev, err := log.Append(ctx, events.Event{Type: projections.EventKubernetesControllerPostureReported, TenantID: tenantA, Data: payload})
	if err != nil {
		t.Fatal(err)
	}
	if err := projections.New(st).Apply(ctx, ev); err != nil {
		t.Fatal(err)
	}
	for capability, wantName := range map[string]string{
		store.KubernetesPostureCertificateSigningRequests: "web-csr",
		store.KubernetesPostureTrustBundles:               "corp-roots",
	} {
		rows, err := st.ListKubernetesControllerPosture(ctx, tenantA, capability)
		if err != nil || len(rows) != 1 || len(rows[0].Resources) != 1 || rows[0].Resources[0].Name != wantName || !rows[0].ReconcileComplete {
			t.Fatalf("%s rows = %+v err=%v", capability, rows, err)
		}
		other, err := st.ListKubernetesControllerPosture(ctx, tenantB, capability)
		if err != nil || len(other) != 0 {
			t.Fatalf("tenant B saw tenant A %s posture: %+v err=%v", capability, other, err)
		}
	}
}

func TestKubernetesControllerPostureProjectionRejectsUnknownPayloadFields(t *testing.T) {
	ctx := context.Background()
	st := newStore(t)
	payload := map[string]any{
		"report_id":                    "33333333-3333-3333-3333-333333333333",
		"agent_id":                     "44444444-4444-4444-4444-444444444444",
		"cluster_id":                   "sha256:" + strings.Repeat("a", 64),
		"reconcile_interval_seconds":   30,
		"certificate_signing_requests": map[string]any{"complete": true, "resources": []any{}},
		"trust_bundles":                map[string]any{"complete": true, "resources": []any{}},
		"raw_private_key":              "must never enter the event",
	}
	raw, _ := json.Marshal(payload)
	err := projections.New(st).Apply(ctx, events.Event{
		Type: projections.EventKubernetesControllerPostureReported, TenantID: tenantA,
		Time: time.Now().UTC(), Sequence: 1, Data: raw,
	})
	if err == nil || !strings.Contains(err.Error(), "unknown field") {
		t.Fatalf("unknown credential-shaped event field error = %v", err)
	}
}

func TestKubernetesControllerPostureContractRejectsUnboundedOrNonMetadataValues(t *testing.T) {
	base := projections.KubernetesControllerPostureReported{
		ReportID:  "33333333-3333-3333-3333-333333333333",
		AgentID:   "44444444-4444-4444-4444-444444444444",
		ClusterID: "sha256:" + strings.Repeat("a", 64), ReconcileIntervalSeconds: 30,
		CertificateSigning: projections.KubernetesPostureSection{Complete: true, Resources: []projections.KubernetesPostureResource{{
			Name: "web-csr", UID: "csr-uid", ResourceVersion: "17", State: "ready", Reason: "signed", PublicHash: strings.Repeat("b", 64),
		}}},
		TrustBundles: projections.KubernetesPostureSection{Complete: true, Resources: []projections.KubernetesPostureResource{}},
	}
	for name, mutate := range map[string]func(*projections.KubernetesControllerPostureReported){
		"inline credential characters": func(report *projections.KubernetesControllerPostureReported) {
			report.CertificateSigning.Resources[0].UID = "-----BEGIN PRIVATE KEY-----"
		},
		"non digest public hash": func(report *projections.KubernetesControllerPostureReported) {
			report.CertificateSigning.Resources[0].PublicHash = "raw-csr"
		},
		"arbitrary failure text": func(report *projections.KubernetesControllerPostureReported) {
			report.TrustBundles.Complete = false
			report.TrustBundles.FailureCode = "token=secret"
		},
		"unbounded resources": func(report *projections.KubernetesControllerPostureReported) {
			resource := report.CertificateSigning.Resources[0]
			report.CertificateSigning.Resources = make([]projections.KubernetesPostureResource, 2001)
			for i := range report.CertificateSigning.Resources {
				report.CertificateSigning.Resources[i] = resource
				report.CertificateSigning.Resources[i].UID = "uid-" + fmt.Sprint(i)
			}
		},
	} {
		t.Run(name, func(t *testing.T) {
			report := base
			report.CertificateSigning.Resources = append([]projections.KubernetesPostureResource(nil), base.CertificateSigning.Resources...)
			mutate(&report)
			if _, err := projections.MarshalKubernetesPostureReport(report); err == nil {
				t.Fatal("invalid Kubernetes posture report was accepted")
			}
		})
	}
}
