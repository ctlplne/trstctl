// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/crypto/certinfo"
	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/notify"
	"trstctl.com/trstctl/internal/orchestrator"
	"trstctl.com/trstctl/internal/projections"
	"trstctl.com/trstctl/internal/store"
)

// B4-8: an operator rollback pauses automatic renewal of that identity on
// that target until an operator resumes it. The scheduler holds the paused
// identity while renewing its unpaused sibling, the identity and target views
// show the hold, the lifecycle plan names it, expiry alerts keep firing, and
// the resume is an audited event carrying the operator.
func TestServedOperatorRollbackPausesAutomaticRenewalOnThatTargetUntilResumed(t *testing.T) {
	h := newOperatingServedHarness(t, config.Protocols{}, func(d *Deps) {
		d.LifecycleRenewBefore = 30 * 24 * time.Hour
		d.LifecycleAlertBefore = 30 * 24 * time.Hour
	})
	ctx := t.Context()
	tok := seedScopedToken(t, h.store, h.tenant, "identities:read", "identities:write", "connectors:read", "lifecycle:read")
	owner, err := h.srv.orch.CreateOwner(ctx, h.tenant, "workload", "b4-8 owner", "")
	if err != nil {
		t.Fatal(err)
	}
	target := func(name string) string {
		t.Helper()
		id := uuid.NewString()
		cfg, _ := json.Marshal(map[string]any{"profile": "lab-nginx", "cert_path": "/srv/" + name + ".crt", "key_path": "/srv/" + name + ".key", "verify_address": "10.0.0.48:443"})
		if err := h.store.UpsertDeploymentTarget(ctx, store.DeploymentTarget{ID: id, TenantID: h.tenant, Name: "lab/" + name, Type: "nginx", Config: cfg, Enabled: true, EnabledSet: true}); err != nil {
			t.Fatal(err)
		}
		return id
	}
	// A deployed identity on its target with a short-lived issued leaf: due.
	deployed := func(name, targetID string) (store.Identity, store.Certificate) {
		t.Helper()
		attrs, _ := json.Marshal(map[string]any{"deployment_target_id": targetID, "connector": "nginx", "target": "lab/" + name, "dns_names": []string{name}})
		ident, err := h.srv.orch.CreateIdentity(ctx, h.tenant, store.Identity{Kind: store.KindX509Certificate, Name: name, OwnerID: owner.ID, Attributes: attrs})
		if err != nil {
			t.Fatal(err)
		}
		ident.Status = "deployed"
		if err := h.store.UpsertIdentity(ctx, ident); err != nil {
			t.Fatal(err)
		}
		key, err := crypto.GenerateHostSubjectKey(name, []string{name})
		if err != nil {
			t.Fatal(err)
		}
		defer key.Destroy()
		issued, err := h.srv.issueLeafWithValidity(ctx, key.CSRDER, 72*time.Hour, crypto.LeafProfile{ClampTTLToIssuer: true})
		if err != nil {
			t.Fatal(err)
		}
		info, err := certinfo.Inspect(issued.DER)
		if err != nil {
			t.Fatal(err)
		}
		// Recorded without a validity anchor, like an inventoried leaf: the
		// sweep then uses the fixed lead, and a 72h leaf is inside 30d.
		cert, err := h.srv.orch.RecordCertificate(ctx, h.tenant, store.Certificate{
			OwnerID: &owner.ID, Subject: info.Subject, SANs: info.DNSNames, Issuer: info.Issuer,
			Serial: info.SerialNumber, Fingerprint: info.SHA256Fingerprint, KeyAlgorithm: info.KeyAlgorithm,
			Source: "issued", CertificateDER: issued.DER, NotBefore: &info.NotBefore, NotAfter: &info.NotAfter,
		})
		if err != nil {
			t.Fatal(err)
		}
		return ident, cert
	}
	targetA, targetB := target("b48-a"), target("b48-b")
	pausedIdent, pausedCert := deployed("b48-a.example.test", targetA)
	freeIdent, _ := deployed("b48-b.example.test", targetB)

	// The operator rolled target A back: renewal of that identity there is held.
	if err := h.srv.orch.PauseIdentityRenewal(ctx, h.tenant, pausedIdent.ID, targetA, "operator rollback: drill"); err != nil {
		t.Fatalf("pause: %v", err)
	}
	statusOf := func(id string) string {
		t.Helper()
		ident, err := h.store.GetIdentity(ctx, h.tenant, id)
		if err != nil {
			t.Fatal(err)
		}
		return ident.Status
	}
	if _, err := h.srv.RunLifecycleOnce(ctx); err != nil {
		t.Fatalf("lifecycle sweep: %v", err)
	}
	if got := statusOf(freeIdent.ID); got == "deployed" {
		t.Fatalf("the unpaused identity was not renewed by the sweep (status %q); the fixture is not due", got)
	}
	if got := statusOf(pausedIdent.ID); got != "deployed" {
		t.Fatalf("the paused identity moved to %q; automatic renewal must hold on a rolled-back target", got)
	}

	// The hold is visible on the identity, on the target and in the plan.
	status, body := secretsReq(t, h, http.MethodGet, "/api/v1/identities/"+pausedIdent.ID, tok, nil)
	if status != http.StatusOK || !strings.Contains(string(body), `"renewal_paused":[{"target_id":"`+targetA+`"`) || !strings.Contains(string(body), "operator rollback: drill") {
		t.Fatalf("identity view: %d %s; want the pause on target A with its reason", status, body)
	}
	status, body = secretsReq(t, h, http.MethodGet, "/api/v1/connectors/targets/"+targetA, tok, nil)
	if status != http.StatusOK || !strings.Contains(string(body), `"renewal_paused_identities":["`+pausedIdent.ID+`"]`) {
		t.Fatalf("target view: %d %s; want the paused identity listed", status, body)
	}
	status, body = secretsReq(t, h, http.MethodGet, "/api/v1/connectors/targets/"+targetB, tok, nil)
	if status != http.StatusOK || strings.Contains(string(body), "renewal_paused_identities") {
		t.Fatalf("other target view: %d %s; want no pause", status, body)
	}
	plan, err := h.srv.LifecycleAutomationPlan(ctx, h.tenant, time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	planned := false
	for _, item := range plan.Items {
		if item.IdentityID == pausedIdent.ID {
			planned = item.RenewalSource == "paused_by_operator_rollback"
		}
	}
	if !planned {
		t.Fatalf("lifecycle plan does not report the pause: %+v", plan.Items)
	}

	// Expiry alerts still fire for the paused identity's certificate.
	var alerts int
	if err := h.store.WithTenant(ctx, h.tenant, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT count(*) FROM outbox WHERE tenant_id=$1 AND destination=$2 AND idempotency_key=$3`, h.tenant, notify.DestinationExpiry, "expiry:"+pausedCert.ID).Scan(&alerts)
	}); err != nil {
		t.Fatal(err)
	}
	if alerts == 0 {
		t.Fatal("no expiry alert was queued for the paused identity's certificate; a pause holds renewal, never the warning")
	}

	// Resuming an unpaused target is refused; resuming the paused one is an
	// audited event and the next sweep renews the identity.
	if status, body := secretsReqKey(t, h, http.MethodPost, "/api/v1/identities/"+pausedIdent.ID+"/renewal/resume", tok, "b48-resume-wrong", map[string]any{"target_id": targetB}); status != http.StatusConflict {
		t.Fatalf("resume on an unpaused target: %d %s; want 409", status, body)
	}
	status, body = secretsReqKey(t, h, http.MethodPost, "/api/v1/identities/"+pausedIdent.ID+"/renewal/resume", tok, "b48-resume", map[string]any{"target_id": targetA})
	if status != http.StatusOK || !strings.Contains(string(body), `"renewal_paused":[]`) {
		t.Fatalf("resume: %d %s; want the identity with no pause", status, body)
	}
	resumed := false
	if err := h.log.Replay(ctx, 1, func(e events.Event) error {
		if e.Type == projections.EventIdentityRenewalResumed && e.TenantID == h.tenant {
			resumed = e.Actor != nil && e.Actor.Subject != "" && strings.Contains(string(e.Data), targetA)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if !resumed {
		t.Fatal("the resume did not append identity.renewal_resumed with the operator as its actor")
	}
	if _, err := h.srv.RunLifecycleOnce(ctx); err != nil {
		t.Fatalf("lifecycle sweep after resume: %v", err)
	}
	if got := statusOf(pausedIdent.ID); got == "deployed" {
		t.Fatalf("after the resume the identity still reads %q; the next sweep must renew it", got)
	}
	_ = orchestrator.StateRenewing
}
