// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/store"
)

// Q6-O2: an operator registers a Kubernetes token decoy and gets the manifest
// that plants it; the cluster's audit webhook, with a token that holds only
// decoys:events.report, sends its batches; a read of the decoy's Secret and a
// use of its token each alert once per reader, naming the principal or the
// client; a retired decoy matches nothing; and the webhook token can do
// nothing else.
func TestServedKubernetesDecoyAuditEventsAlertOncePerReaderQ6O2(t *testing.T) {
	ctx := context.Background()
	h := newServedHarness(t, config.Protocols{})
	registerServedTenant(t, h, "q6o2-decoys")
	cluster := "q6o2-" + strings.ReplaceAll(uuid.NewString()[:8], "-", "")
	operator := seedServedAPIToken(t, ctx, h.store, h.tenant, "decoy-planter", []string{"secrets:write", "secrets:read"})
	webhook := seedServedAPIToken(t, ctx, h.store, h.tenant, "system:apiserver-audit", []string{"decoys:events.report"})

	register := map[string]any{"cluster": cluster, "namespace": "ci", "service_account": "deployer", "name": "ci deployer bait", "placement": "ci namespace"}
	code, body := doBearer(t, h.ts, http.MethodPost, "/api/v1/secrets/honeytokens/kubernetes", operator, "q6o2-register-"+cluster, register)
	if code != http.StatusCreated {
		t.Fatalf("register: %d %s", code, body)
	}
	var registered struct {
		store.HoneyToken
		Manifest    string `json:"manifest"`
		AuditPolicy string `json:"audit_policy"`
	}
	if err := json.Unmarshal(body, &registered); err != nil {
		t.Fatal(err)
	}
	if registered.Kind != "kubernetes" || registered.K8sCluster != cluster || registered.K8sSecret != "deployer-token" ||
		!strings.Contains(registered.Manifest, "type: kubernetes.io/service-account-token") ||
		!strings.Contains(registered.AuditPolicy, "system:serviceaccount:ci:deployer") {
		t.Fatalf("registration = %s", body)
	}
	if code, body := doBearer(t, h.ts, http.MethodPost, "/api/v1/secrets/honeytokens/kubernetes", operator, "q6o2-register-again-"+cluster, register); code != http.StatusConflict {
		t.Fatalf("a second live decoy for the service account: %d %s", code, body)
	}

	alerts := func() []string {
		t.Helper()
		rows, err := h.store.SystemPool().Query(ctx,
			`SELECT convert_from(payload, 'UTF8')::jsonb->>'detail' FROM outbox
			  WHERE tenant_id = $1 AND destination = 'notification.honeytoken'
			    AND convert_from(payload, 'UTF8')::jsonb->>'detail' LIKE '%' || $2 || '%' ORDER BY id`, h.tenant, cluster)
		if err != nil {
			t.Fatal(err)
		}
		defer rows.Close()
		var out []string
		for rows.Next() {
			var d string
			if err := rows.Scan(&d); err != nil {
				t.Fatal(err)
			}
			out = append(out, d)
		}
		return out
	}
	event := func(id, verb, user, uri, ua string, objectRef map[string]any, code int) map[string]any {
		return map[string]any{"kind": "Event", "apiVersion": "audit.k8s.io/v1", "level": "Metadata", "auditID": id, "stage": "ResponseComplete",
			"verb": verb, "requestURI": uri, "user": map[string]any{"username": user}, "sourceIPs": []string{"172.18.0.1"},
			"userAgent": ua, "objectRef": objectRef, "responseStatus": map[string]any{"code": code},
			"requestReceivedTimestamp": time.Now().UTC().Format(time.RFC3339Nano)}
	}
	secretRef := map[string]any{"resource": "secrets", "namespace": "ci", "name": "deployer-token", "apiVersion": "v1"}
	post := func(token string, items ...map[string]any) (int, map[string]int) {
		t.Helper()
		code, body := doBearer(t, h.ts, http.MethodPost, "/api/v1/secrets/honeytokens/kubernetes/clusters/"+cluster+"/audit-events", token, "",
			map[string]any{"kind": "EventList", "apiVersion": "audit.k8s.io/v1", "items": items})
		var report map[string]int
		_ = json.Unmarshal(body, &report)
		return code, report
	}
	read := event("a1", "get", "kubernetes-admin", "/api/v1/namespaces/ci/secrets/deployer-token", "kubectl/v1.35.0", secretRef, 200)
	other := event("a2", "get", "kubernetes-admin", "/api/v1/namespaces/ci/secrets/registry", "kubectl/v1.35.0",
		map[string]any{"resource": "secrets", "namespace": "ci", "name": "registry"}, 200)
	if code, report := post(webhook, read, other); code != http.StatusOK || report["events"] != 2 || report["matched"] != 1 || report["recorded"] != 1 {
		t.Fatalf("first batch: %d %v", code, report)
	}
	if got := alerts(); len(got) != 1 || !strings.Contains(got[0], "ci/deployer on cluster "+cluster) ||
		!strings.Contains(got[0], "token Secret read: get secrets (200)") || !strings.Contains(got[0], "by kubernetes-admin from 172.18.0.1") {
		t.Fatalf("alerts after a read of the decoy's Secret = %v", got)
	}
	again := event("a3", "get", "kubernetes-admin", "/api/v1/namespaces/ci/secrets/deployer-token", "kubectl/v1.35.0", secretRef, 200)
	use := event("a4", "list", "system:serviceaccount:ci:deployer", "/api/v1/namespaces/ci/pods", "kubectl/v1.35.0 (linux/amd64)",
		map[string]any{"resource": "pods", "namespace": "ci"}, 403)
	if code, report := post(webhook, again, use); code != http.StatusOK || report["matched"] != 2 {
		t.Fatalf("second batch: %d %v", code, report)
	}
	got := alerts()
	if len(got) != 2 || !strings.Contains(got[1], "token used: list pods (403) /api/v1/namespaces/ci/pods by kubectl/v1.35.0 (linux/amd64) from 172.18.0.1") {
		t.Fatalf("alerts after the same reader again and a use of the token = %v; want one more, for the use", got)
	}
	decoy, err := h.store.GetHoneyToken(ctx, h.tenant, registered.ID)
	if err != nil || decoy.State != "triggered" || decoy.TriggerSubject != "kubernetes-admin from 172.18.0.1" || decoy.Readers != 2 || decoy.Reads != 3 {
		t.Fatalf("decoy after the batches = %+v, %v", decoy, err)
	}

	if code, _ := post(operator, read); code != http.StatusForbidden {
		t.Fatalf("a secrets:write token posted audit events: %d", code)
	}
	for _, path := range []string{"/api/v1/secrets/honeytokens/kubernetes", "/api/v1/secrets/store", "/api/v1/certificates"} {
		if code, body := doBearer(t, h.ts, http.MethodGet, path, webhook, "", nil); code != http.StatusForbidden {
			t.Fatalf("the audit webhook token read %s: %d %s", path, code, body)
		}
	}
	if code, body := doBearer(t, h.ts, http.MethodPost, "/api/v1/secrets/honeytokens/kubernetes/clusters/Not_A_Cluster/audit-events", webhook, "",
		map[string]any{"items": []any{}}); code != http.StatusBadRequest {
		t.Fatalf("a malformed cluster name: %d %s", code, body)
	}
	huge := make([]map[string]any, 4001)
	for i := range huge {
		huge[i] = map[string]any{"stage": "ResponseComplete"}
	}
	if code, _ := post(webhook, huge...); code != http.StatusRequestEntityTooLarge {
		t.Fatalf("an oversized batch: %d", code)
	}

	code, body = doBearer(t, h.ts, http.MethodGet, "/api/v1/secrets/honeytokens/kubernetes", operator, "", nil)
	if code != http.StatusOK || !strings.Contains(string(body), registered.ID) {
		t.Fatalf("list: %d %s", code, body)
	}
	if code, body := doBearer(t, h.ts, http.MethodPost, fmt.Sprintf("/api/v1/secrets/honeytokens/kubernetes/%s/retire", registered.ID), operator, "q6o2-retire-"+cluster, nil); code != http.StatusOK || !strings.Contains(string(body), `"state":"revoked"`) {
		t.Fatalf("retire: %d %s", code, body)
	}
	if code, report := post(webhook, event("a5", "get", "mallory", "/api/v1/namespaces/ci/secrets/deployer-token", "curl/8", secretRef, 200)); code != http.StatusOK || report["matched"] != 0 {
		t.Fatalf("a read after retirement: %d %v; want nothing matched", code, report)
	}
	if got := alerts(); len(got) != 2 {
		t.Fatalf("%d alerts after retirement, want 2", len(got))
	}
	code, body = doBearer(t, h.ts, http.MethodPost, "/api/v1/secrets/honeytokens/kubernetes", operator, "q6o2-register-new-"+cluster, register)
	if code != http.StatusCreated || strings.Contains(string(body), registered.ID) {
		t.Fatalf("registering the retired decoy's service account again: %d %s; want a new decoy", code, body)
	}
}
