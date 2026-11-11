// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/connector"
	"trstctl.com/trstctl/internal/connector/acm"
	"trstctl.com/trstctl/internal/connector/acm/acmtest"
)

// A166-L2: an AWS Certificate Manager target that names the Elastic Load
// Balancing listener serving it is rollable through the served route. Each
// deploy imports a new ACM certificate tagged with its fingerprint and points
// the listener at it, so the predecessor stays in the account; the rollback,
// queued as a control_plane row and executed by the outbox worker, points the
// listener back at the predecessor, uploading nothing, and the receipt says
// so. Before, every ACM rollback was refused ("keeps no previous version").
func TestServedACMListenerRollbackRepointsTheListenerA166L2(t *testing.T) {
	const (
		accessKey = "AKIDA166L2"
		secretKey = "stand-in-acm-signing-value" // #nosec G101 -- a stand-in fixture value, not a credential (CWE-798)
		listener  = "arn:aws:elasticloadbalancing:us-east-1:000000000000:listener/app/a166l2/0123456789abcdef/fedcba9876543210"
		targetID  = "a166l2-web"
	)
	acmSrv := acmtest.New(accessKey, secretKey)
	t.Cleanup(acmSrv.Close)
	elb := acmtest.NewELB(accessKey, secretKey, listener)
	t.Cleanup(elb.Close)
	registry := connector.NewRegistry(func(string) connector.Ops { return connector.NewHTTPOps(acmSrv.Client()) })
	registry.Register(acm.New("us-east-1", acm.Credentials{AccessKeyID: accessKey, SecretAccessKey: []byte(secretKey)},
		acm.WithEndpoint(acmSrv.URL()), acm.WithListener(listener), acm.WithELBEndpoint(elb.URL())))
	h := newOperatingServedHarness(t, config.Protocols{}, func(d *Deps) {
		d.LifecycleRenewBefore = 31 * 24 * time.Hour
		d.ConnectorRegistry = registry
	})
	tok := seedScopedToken(t, h.store, h.tenant,
		"owners:read", "owners:write", "identities:read", "identities:write",
		"certs:read", "certs:issue", "connectors:read", "connectors:write", "lifecycle:read",
	)
	call := func(method, path string, in any, want int) []byte {
		t.Helper()
		status, body := secretsReq(t, h, method, path, tok, in)
		if status != want {
			t.Fatalf("%s %s = %d %s", method, path, status, body)
		}
		return body
	}
	var target, owner, ident struct {
		ID string `json:"id"`
	}
	_ = json.Unmarshal(call(http.MethodPost, "/api/v1/connectors/targets", map[string]any{
		"name": targetID, "connector": "aws-acm",
		"config": map[string]any{"endpoint": acmSrv.URL(), "region": "us-east-1", "access_key_id": accessKey,
			"secret_access_key_ref": "secret://connectors/aws-acm/a166l2", "listener_arn": listener, "elb_endpoint": elb.URL()},
	}, http.StatusCreated), &target)
	_ = json.Unmarshal(call(http.MethodPost, "/api/v1/owners", map[string]any{"kind": "workload", "name": "a166l2-owner"}, http.StatusCreated), &owner)
	_ = json.Unmarshal(call(http.MethodPost, "/api/v1/identities", map[string]any{"kind": "x509_certificate", "name": "a166l2.served.test", "owner_id": owner.ID}, http.StatusCreated), &ident)
	call(http.MethodPost, "/api/v1/identities/"+ident.ID+"/connector-target", map[string]any{"target_id": target.ID}, http.StatusOK)
	call(http.MethodPost, "/api/v1/identities/"+ident.ID+"/transitions", map[string]any{"to": "issued", "reason": "a166l2 issue"}, http.StatusOK)
	if err := h.srv.Drain(t.Context()); err != nil {
		t.Fatalf("drain issue and deploy: %v", err)
	}
	first := connectorDeliveriesForIdentity(t, h, tok, ident.ID)
	if len(first.Items) != 1 || first.Items[0].Status != "delivered" {
		t.Fatalf("first delivery = %+v raw=%s", first.Items, first.Raw)
	}
	predecessor, err := h.store.GetCertificateByFingerprint(t.Context(), h.tenant, first.Items[0].Fingerprint)
	if err != nil || predecessor.NotAfter == nil {
		t.Fatalf("load delivered leaf: %+v %v", predecessor, err)
	}
	if queued, err := h.srv.runLifecycleOnceAt(t.Context(), predecessor.NotAfter.Add(-12*time.Hour)); err != nil || queued != 1 {
		t.Fatalf("scheduled renewals = %d %v, want 1", queued, err)
	}
	if err := h.srv.Drain(t.Context()); err != nil {
		t.Fatalf("drain renewal: %v", err)
	}
	arns := acmSrv.ARNs()
	if len(arns) != 2 || elb.Serving() != arns[1] {
		t.Fatalf("after the renewal: %d certificates, listener on %q; want two, the successor served", len(arns), elb.Serving())
	}
	if imported, _ := acmSrv.Imported(arns[0]); imported.Tags[acm.FingerprintTag] != predecessor.Fingerprint {
		t.Fatalf("the predecessor's ACM certificate is tagged %v; want its fingerprint", imported.Tags)
	}
	status, body := secretsReq(t, h, http.MethodGet, "/api/v1/connectors/targets/"+target.ID, tok, nil)
	var readiness struct {
		RollbackReadiness struct {
			Model                  string `json:"model"`
			Ready                  bool   `json:"ready"`
			PredecessorFingerprint string `json:"predecessor_fingerprint"`
		} `json:"rollback_readiness"`
	}
	if status != http.StatusOK || json.Unmarshal(body, &readiness) != nil || readiness.RollbackReadiness.Model != "re-bind" ||
		!readiness.RollbackReadiness.Ready || readiness.RollbackReadiness.PredecessorFingerprint != predecessor.Fingerprint {
		t.Fatalf("rollback readiness after the renewal = %d %s; want ready on the predecessor", status, body)
	}
	imports, modifies := acmSrv.Calls(), elb.Modifies()
	status, body = secretsReq(t, h, http.MethodPost, "/api/v1/connectors/targets/"+target.ID+"/rollback", tok, map[string]any{
		"identity_id": ident.ID, "reason": "a166l2 rollback drill",
	})
	if status != http.StatusOK || !jsonContains(t, body, "rollback_queued") {
		t.Fatalf("rollback request: status %d body %s", status, body)
	}
	var role string
	if err := h.store.WithTenant(t.Context(), h.tenant, func(tx pgx.Tx) error {
		return tx.QueryRow(context.Background(),
			`SELECT required_agent_role FROM outbox WHERE tenant_id=$1 AND destination='connector.rollback' ORDER BY id DESC LIMIT 1`,
			h.tenant).Scan(&role)
	}); err != nil || role != string(connector.VantageControlPlane) {
		t.Fatalf("rollback row required_agent_role = %q (%v), want control_plane", role, err)
	}
	if elb.Modifies() != modifies {
		t.Fatal("the rollback request handler touched the load balancer; only the outbox worker may")
	}
	if err := h.srv.Drain(t.Context()); err != nil {
		t.Fatalf("drain rollback: %v", err)
	}
	if elb.Serving() != arns[0] || elb.Modifies() != modifies+1 || acmSrv.Calls() != imports {
		t.Fatalf("after the rollback the listener serves %q (%d changes, %d imports); want the predecessor %q, one change, nothing uploaded",
			elb.Serving(), elb.Modifies()-modifies, acmSrv.Calls()-imports, arns[0])
	}
	afterRollback := connectorDeliveriesForIdentity(t, h, tok, ident.ID)
	found := false
	for _, item := range afterRollback.Items {
		if item.Destination != "connector.rollback" || item.Status == "rollback_queued" {
			continue
		}
		found = true
		if item.Status != "rolled_back" || item.Fingerprint != predecessor.Fingerprint || item.Connector != "aws-acm" ||
			!strings.Contains(item.Detail, "No key was uploaded") {
			t.Fatalf("rollback result receipt = %+v", item)
		}
	}
	if !found {
		t.Fatalf("no rollback result receipt was recorded: %s", afterRollback.Raw)
	}
}
