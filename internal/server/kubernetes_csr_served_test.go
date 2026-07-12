// SPDX-License-Identifier: MPL-2.0

package server

import (
	"context"
	"encoding/json"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"trstctl.com/trstctl/internal/agent/transport"
	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/projections"
)

func TestServedKubernetesPostureReportUsesAuthenticatedAgentEventProjection(t *testing.T) {
	h := newServedHarness(t, config.Protocols{}, withAgentChannel)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	channelCtx, cancelChannel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { defer close(done); h.srv.serveAgentChannel(channelCtx, ln) }()
	t.Cleanup(func() { cancelChannel(); <-done })

	agent := enrollAgent(t, h, "k8s-controller-1", "agent.trstctl.local")
	creds, err := agent.Credentials()
	if err != nil {
		t.Fatal(err)
	}
	conn, err := transport.Dial(ln.Addr().String(), creds)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	client := transport.NewAgentClient(conn)
	request := &transport.KubernetesPostureRequest{
		ReportID:  "33333333-3333-3333-3333-333333333333",
		ClusterID: "sha256:" + strings.Repeat("a", 64), ReconcileIntervalSeconds: 30,
		CertificateSigning: transport.KubernetesPostureSection{Complete: true, Resources: []transport.KubernetesPostureResource{{
			Name: "web-csr", UID: "csr-uid", ResourceVersion: "17", State: "ready", Reason: "signed", PublicHash: strings.Repeat("b", 64),
		}}},
		TrustBundles: transport.KubernetesPostureSection{Complete: true, Resources: []transport.KubernetesPostureResource{{
			Name: "corp-roots", UID: "bundle-uid", ResourceVersion: "9", State: "ready", Reason: "distributed", PublicHash: strings.Repeat("c", 64),
		}}},
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	receipt, err := client.ReportKubernetesPosture(ctx, request)
	if err != nil {
		t.Fatalf("authenticated Kubernetes posture report: %v", err)
	}
	if receipt.TenantID != h.tenant || receipt.ReportID != request.ReportID || receipt.RecordedAtUnix == 0 {
		t.Fatalf("Kubernetes posture receipt = %+v", receipt)
	}
	if !h.hasEvent(t, projections.EventKubernetesControllerPostureReported) {
		t.Fatal("Kubernetes posture report did not append its source event")
	}
	if err := h.log.Replay(ctx, 0, func(event events.Event) error {
		if event.Type != projections.EventKubernetesControllerPostureReported {
			return nil
		}
		body := strings.ToLower(string(event.Data))
		for _, forbidden := range []string{"private_key", "csr_der", "certificate_pem", "ca_bundle_pem", "bearer", "token"} {
			if strings.Contains(body, forbidden) {
				t.Fatalf("Kubernetes posture event contains %q: %s", forbidden, event.Data)
			}
		}
		if event.Actor == nil || event.Actor.Subject != "agent:k8s-controller-1" {
			t.Fatalf("Kubernetes posture event actor = %+v, want authenticated agent", event.Actor)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	rows, err := h.store.ListKubernetesControllerPosture(ctx, h.tenant, "certificate-signing-requests")
	if err != nil || len(rows) != 1 || len(rows[0].Resources) != 1 || rows[0].Resources[0].Name != "web-csr" {
		t.Fatalf("projected Kubernetes posture = %+v err=%v", rows, err)
	}

	before := servedEventCount(t, h, projections.EventKubernetesControllerPostureReported)
	replayed, err := client.ReportKubernetesPosture(ctx, request)
	if err != nil || replayed.RecordedAtUnix != receipt.RecordedAtUnix {
		t.Fatalf("idempotent Kubernetes posture replay = %+v err=%v", replayed, err)
	}
	if after := servedEventCount(t, h, projections.EventKubernetesControllerPostureReported); after != before {
		t.Fatalf("idempotent replay appended %d events, want 0", after-before)
	}

	changed := *request
	changed.CertificateSigning.Resources = append([]transport.KubernetesPostureResource(nil), request.CertificateSigning.Resources...)
	changed.CertificateSigning.Resources[0].ResourceVersion = "18"
	if _, err := client.ReportKubernetesPosture(ctx, &changed); status.Code(err) != codes.AlreadyExists {
		t.Fatalf("changed metadata reused report id: %v, want AlreadyExists", err)
	}
}

func TestServedKubernetesCertificateSigningRequestCAPK8S04(t *testing.T) {
	h := newServedHarness(t, config.Protocols{})
	tok := seedScopedToken(t, h.store, h.tenant, "certs:read")

	status, body := secretsReq(t, h, http.MethodGet, "/api/v1/kubernetes/certificate-signing-requests", tok, nil)
	if status != http.StatusServiceUnavailable {
		t.Fatalf("Kubernetes CSR posture before report: status %d body %s, want 503", status, body)
	}
	seedKubernetesPosture(t, h, projections.KubernetesControllerPostureReported{
		ReportID:  "33333333-3333-3333-3333-333333333333",
		AgentID:   "44444444-4444-4444-4444-444444444444",
		ClusterID: "sha256:" + strings.Repeat("a", 64), ReconcileIntervalSeconds: 30,
		CertificateSigning: projections.KubernetesPostureSection{Complete: true, Resources: []projections.KubernetesPostureResource{
			{Name: "web-csr", UID: "csr-uid", ResourceVersion: "17", State: "ready", Reason: "signed", PublicHash: strings.Repeat("b", 64)},
			{Name: "db-csr", UID: "db-uid", ResourceVersion: "18", State: "pending", Reason: "approval_pending", PublicHash: strings.Repeat("c", 64)},
		}},
		TrustBundles: projections.KubernetesPostureSection{Complete: true, Resources: []projections.KubernetesPostureResource{{
			Name: "corp-roots", UID: "bundle-uid", ResourceVersion: "9", State: "ready", Reason: "distributed", PublicHash: strings.Repeat("d", 64),
		}}},
	})

	status, body = secretsReq(t, h, http.MethodGet, "/api/v1/kubernetes/certificate-signing-requests", tok, nil)
	if status != http.StatusOK {
		t.Fatalf("Kubernetes CSR posture: status %d body %s", status, body)
	}
	if strings.Contains(strings.ToUpper(string(body)), "PRIVATE KEY") || strings.Contains(string(body), "controller_flow") || strings.Contains(string(body), "BEGIN CERTIFICATE REQUEST") {
		t.Fatalf("Kubernetes CSR posture leaked payload/static descriptor data: %s", body)
	}
	var got struct {
		Capability string `json:"capability"`
		Served     bool   `json:"served"`
		LastSync   string `json:"last_sync"`
		Summary    struct {
			Observed int `json:"observed"`
			Ready    int `json:"ready"`
			Pending  int `json:"pending"`
		} `json:"summary"`
		Objects []struct {
			Name            string `json:"name"`
			UID             string `json:"uid"`
			ResourceVersion string `json:"resource_version"`
			State           string `json:"state"`
			PublicHash      string `json:"public_hash"`
		} `json:"objects"`
	}
	if err := json.Unmarshal(body, &got); err != nil {
		t.Fatalf("decode Kubernetes CSR posture: %v (%s)", err, body)
	}
	if got.Capability != "CAP-K8S-04" || !got.Served || got.LastSync == "" || got.Summary.Observed != 2 || got.Summary.Ready != 1 || got.Summary.Pending != 1 {
		t.Fatalf("Kubernetes CSR posture = %+v", got)
	}
	if len(got.Objects) != 2 || got.Objects[0].Name != "web-csr" || got.Objects[0].UID != "csr-uid" || got.Objects[0].ResourceVersion != "17" || got.Objects[0].State != "ready" || len(got.Objects[0].PublicHash) != 64 {
		t.Fatalf("Kubernetes CSR objects = %+v", got.Objects)
	}

	// A later real reconcile event for the same cluster replaces the projection;
	// the route must reflect changed Kubernetes resource state, not cached prose.
	seedKubernetesPosture(t, h, projections.KubernetesControllerPostureReported{
		ReportID:  "55555555-5555-5555-5555-555555555555",
		AgentID:   "44444444-4444-4444-4444-444444444444",
		ClusterID: "sha256:" + strings.Repeat("a", 64), ReconcileIntervalSeconds: 30,
		CertificateSigning: projections.KubernetesPostureSection{Complete: true, Resources: []projections.KubernetesPostureResource{{
			Name: "web-csr", UID: "csr-uid", ResourceVersion: "21", State: "pending", Reason: "approval_pending", PublicHash: strings.Repeat("e", 64),
		}}},
		TrustBundles: projections.KubernetesPostureSection{Complete: true, Resources: []projections.KubernetesPostureResource{{
			Name: "corp-roots", UID: "bundle-uid", ResourceVersion: "9", State: "ready", Reason: "distributed", PublicHash: strings.Repeat("d", 64),
		}}},
	})
	status, body = secretsReq(t, h, http.MethodGet, "/api/v1/kubernetes/certificate-signing-requests", tok, nil)
	if status != http.StatusOK {
		t.Fatalf("changed Kubernetes CSR posture: status %d body %s", status, body)
	}
	var changed struct {
		Summary struct {
			Observed int `json:"observed"`
			Pending  int `json:"pending"`
		} `json:"summary"`
		Objects []struct {
			ResourceVersion string `json:"resource_version"`
			PublicHash      string `json:"public_hash"`
		} `json:"objects"`
	}
	if err := json.Unmarshal(body, &changed); err != nil || changed.Summary.Observed != 1 || changed.Summary.Pending != 1 || len(changed.Objects) != 1 || changed.Objects[0].ResourceVersion != "21" || changed.Objects[0].PublicHash != strings.Repeat("e", 64) {
		t.Fatalf("route did not reflect changed Kubernetes object: %+v err=%v body=%s", changed, err, body)
	}
}

func seedKubernetesPosture(t *testing.T, h *servedHarness, report projections.KubernetesControllerPostureReported) {
	t.Helper()
	payload, err := projections.MarshalKubernetesPostureReport(report)
	if err != nil {
		t.Fatal(err)
	}
	ev, err := h.log.Append(context.Background(), events.Event{
		Type: projections.EventKubernetesControllerPostureReported, TenantID: h.tenant, Data: payload,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := projections.New(h.store).Apply(context.Background(), ev); err != nil {
		t.Fatal(err)
	}
}
