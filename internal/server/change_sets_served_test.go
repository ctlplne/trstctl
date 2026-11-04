// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"encoding/json"
	"encoding/pem"
	"net/http"
	"strings"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/api"
	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/crypto/certtest"
	"trstctl.com/trstctl/internal/store"
)

func changeSetServedFixture(t *testing.T) api.ChangeSet {
	t.Helper()
	now := time.Now().UTC()
	der, err := certtest.TLSLeaf("Payments Issuing CA", now.Add(-time.Hour), now.Add(365*24*time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	disabled := false
	return api.ChangeSet{
		Name:     "onboard payments",
		Profiles: []api.BaselineProfile{{Name: "payments-web", Spec: json.RawMessage(`{"allowed_key_algorithms":["ECDSA"],"allowed_protocols":["acme"],"max_validity":"720h"}`)}},
		Issuers: []api.BaselineIssuer{{Key: "payments-ca", Name: "Payments Issuing CA", Kind: string(store.IssuerX509CA),
			Chain: []string{string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))}}},
		DeploymentTargets: []api.BaselineDeploymentTarget{{Key: "payments-lb", Name: "payments-lb", Connector: "f5",
			Config: json.RawMessage(`{"address_ref":"payments-lb"}`), Enabled: &disabled}},
		Members: []api.BaselineMember{{Subject: "dev@payments.example", Email: "dev@payments.example", Roles: []string{"viewer"}}},
		Owners: []api.ChangeOwner{{Key: "payments", Kind: "team", Name: "Payments", Email: "payments@payments.example",
			ApplicationID: "app-42", Service: "checkout", Environment: "production", EscalationChain: []string{"payments-oncall"}}},
	}
}

// A248: a reviewed change set never runs malformed, over-broad, carrying a
// secret, or beyond its author's permissions; its plan shows exactly what
// applying would do; applying needs the reviewed plan, writes every object
// through the operator's own commands, reads each back, and refuses a plan
// the tenant has moved past. The same intent in any order or under any name
// plans to the same digests.
func TestServedReviewedChangeSetsA248(t *testing.T) {
	h := newOperatingServedHarness(t, config.Protocols{})
	author := seedScopedTokenSubject(t, h.store, h.tenant, "change-author", "changes:write",
		"profiles:write", "issuers:write", "connectors:write", "access:role.assign", "owners:write", "owners:read")
	narrow := seedScopedTokenSubject(t, h.store, h.tenant, "narrow-author", "changes:write", "profiles:write", "owners:write")
	unprivileged := seedScopedTokenSubject(t, h.store, h.tenant, "profile-writer", "profiles:write", "owners:write")
	cs := changeSetServedFixture(t)
	// variant is cs, deep-copied, then edited: the same CA certificate throughout.
	variant := func(edit func(*api.ChangeSet)) api.ChangeSet {
		t.Helper()
		raw, err := json.Marshal(cs)
		if err != nil {
			t.Fatal(err)
		}
		var out api.ChangeSet
		if err := json.Unmarshal(raw, &out); err != nil {
			t.Fatal(err)
		}
		edit(&out)
		return out
	}

	plan := func(token string, set any) (int, api.ChangePlan, string) {
		t.Helper()
		code, body := secretsReqKey(t, h, http.MethodPost, "/api/v1/changes/plan", token, "", set)
		var p api.ChangePlan
		if code == http.StatusOK {
			if err := json.Unmarshal(body, &p); err != nil {
				t.Fatal(err)
			}
		}
		return code, p, string(body)
	}
	apply := func(token, key string, set api.ChangeSet, digest string) (int, api.ChangeApplication, string) {
		t.Helper()
		code, body := secretsReqKey(t, h, http.MethodPost, "/api/v1/changes/apply", token, key, api.ChangeApplyRequest{ChangeSet: set, PlanDigest: digest})
		var out api.ChangeApplication
		if code == http.StatusOK {
			if err := json.Unmarshal(body, &out); err != nil {
				t.Fatal(err)
			}
		}
		return code, out, string(body)
	}
	nothingWritten := func(when string) {
		t.Helper()
		if _, err := h.store.GetActiveProfile(t.Context(), h.tenant, "payments-web"); !store.IsNotFound(err) {
			t.Fatalf("%s: the change set's profile was written (%v)", when, err)
		}
		if _, err := h.store.GetTenantMember(t.Context(), h.tenant, "dev@payments.example"); !store.IsNotFound(err) {
			t.Fatalf("%s: the change set's member was written (%v)", when, err)
		}
	}

	// Malformed, over-broad, secret-bearing and unauthorized sets never run.
	if code, _, body := plan(author, map[string]any{"name": "x", "profiles": []any{}, "unknown_field": true}); code != http.StatusBadRequest {
		t.Fatalf("a malformed set = %d %s", code, body)
	}
	if code, _, body := plan(author, api.ChangeSet{Name: "empty"}); code != http.StatusUnprocessableEntity || !strings.Contains(body, "no objects") {
		t.Fatalf("an empty set = %d %s", code, body)
	}
	broad := variant(func(c *api.ChangeSet) { c.Members[0].Subject = "*@payments.example" })
	if code, _, body := plan(author, broad); code != http.StatusUnprocessableEntity || !strings.Contains(body, "pattern") {
		t.Fatalf("an over-broad set = %d %s", code, body)
	}
	inline := variant(func(c *api.ChangeSet) {
		c.DeploymentTargets[0].Config = json.RawMessage(`{"address_ref":"payments-lb","password":"hunter2"}`)
	})
	if code, _, body := plan(author, inline); code != http.StatusUnprocessableEntity || !strings.Contains(body, "not inline secret values") {
		t.Fatalf("a target with an inline secret = %d %s", code, body)
	}
	secret := variant(func(c *api.ChangeSet) { c.Owners[0].Service = "trst_" + strings.Repeat("Q", 40) })
	if code, _, body := plan(author, secret); code != http.StatusUnprocessableEntity || !strings.Contains(body, "never secret values") ||
		!strings.Contains(body, "owners[0].service") {
		t.Fatalf("a secret-bearing set = %d %s", code, body)
	}
	if code, _, body := plan(narrow, cs); code != http.StatusForbidden || !strings.Contains(body, "access:role.assign") {
		t.Fatalf("a set beyond its author's permissions = %d %s", code, body)
	}
	if code, _, body := plan(unprivileged, cs); code != http.StatusForbidden {
		t.Fatalf("a caller without changes:write = %d %s", code, body)
	}
	self := variant(func(c *api.ChangeSet) { c.Members[0].Subject = "change-author" })
	if code, _, body := plan(author, self); code != http.StatusForbidden || !strings.Contains(body, "self role assignment") {
		t.Fatalf("a self role grant = %d %s", code, body)
	}
	admin := variant(func(c *api.ChangeSet) { c.Members[0].Roles = []string{"admin"} })
	if code, _, body := plan(author, admin); code != http.StatusForbidden || !strings.Contains(body, "only an administrator") {
		t.Fatalf("an administrator grant by a non-administrator = %d %s", code, body)
	}
	if code, _, body := apply(author, "a248-apply-secret", secret, "sha256:anything"); code != http.StatusUnprocessableEntity {
		t.Fatalf("applying a secret-bearing set = %d %s", code, body)
	}
	nothingWritten("after the refusals")

	// The plan lists exactly what applying would do.
	code, first, body := plan(author, cs)
	if code != http.StatusOK || first.Changes != 5 || len(first.Items) != 5 {
		t.Fatalf("plan = %d %s", code, body)
	}
	byKind := map[string]api.ChangePlanItem{}
	for _, item := range first.Items {
		if item.Action != api.ChangeCreate {
			t.Fatalf("%s %s plans %s on an empty tenant", item.Kind, item.Key, item.Action)
		}
		byKind[item.Kind] = item
	}
	if got := byKind["member"]; len(got.Grants) != 1 || got.Grants[0] != "roles viewer" || got.Identities[0] != "member dev@payments.example" {
		t.Fatalf("member item = %+v", got)
	}
	if got := byKind["deployment_target"]; len(got.Destinations) != 1 || !strings.Contains(got.Destinations[0], "f5 target payments-lb") ||
		len(got.Credentials) != 1 || !strings.Contains(got.Credentials[0], "address_ref names the stored secret payments-lb") {
		t.Fatalf("target item = %+v", got)
	}
	if got := byKind["owner"]; got.Effects[0] != "owner.created" || !strings.Contains(got.Destinations[0], "payments-oncall") {
		t.Fatalf("owner item = %+v", got)
	}
	if got := byKind["profile"]; got.Effects[0] != "profile.created" || !strings.Contains(got.Verification, got.ExpectedDigest) {
		t.Fatalf("profile item = %+v", got)
	}
	nothingWritten("after planning")

	// The same intent, reordered and renamed, plans to the same digests.
	reordered := variant(func(c *api.ChangeSet) {
		c.Name = "the same request, drafted elsewhere"
		c.Members[0].Roles = []string{"viewer"}
		c.Profiles[0].Spec = json.RawMessage(`{"max_validity":"720h","allowed_protocols":["acme"],"allowed_key_algorithms":["ECDSA"]}`)
	})
	if code, again, body := plan(author, reordered); code != http.StatusOK || again.ChangeSetDigest != first.ChangeSetDigest || again.PlanDigest != first.PlanDigest {
		t.Fatalf("the same intent planned differently = %d %s", code, body)
	}

	// Applying needs the reviewed plan.
	if code, _, body := apply(author, "a248-apply-wrong", cs, "sha256:not-the-plan"); code != http.StatusConflict || !strings.Contains(body, "stale") {
		t.Fatalf("applying an unreviewed plan = %d %s", code, body)
	}
	nothingWritten("after a refused apply")
	code, applied, body := apply(author, "a248-apply", cs, first.PlanDigest)
	if code != http.StatusOK || !applied.Complete || len(applied.Results) != 5 {
		t.Fatalf("apply = %d %s", code, body)
	}
	for _, r := range applied.Results {
		if !r.Verified || (r.Outcome != "created" && r.Outcome != "updated") {
			t.Fatalf("%s %s applied %s, verified %v (%s)", r.Kind, r.Key, r.Outcome, r.Verified, r.Error)
		}
	}
	member, err := h.store.GetTenantMember(t.Context(), h.tenant, "dev@payments.example")
	if err != nil || member.Source != "change_set" || strings.Join(member.Roles, ",") != "viewer" {
		t.Fatalf("member after apply = %+v, %v", member, err)
	}

	// Planning again finds nothing to do; a replayed apply answers the same.
	if code, after, body := plan(author, cs); code != http.StatusOK || after.Changes != 0 || after.PlanDigest == first.PlanDigest {
		t.Fatalf("plan after apply = %d %s", code, body)
	}
	if code, replay, body := apply(author, "a248-apply", cs, first.PlanDigest); code != http.StatusOK || replay.PlanDigest != applied.PlanDigest {
		t.Fatalf("replayed apply = %d %s", code, body)
	}

	// A plan the tenant moved past is refused: the owner changed after review.
	edited := variant(func(c *api.ChangeSet) { c.Owners[0].Service = "checkout-v2" })
	code, reviewed, body := plan(author, edited)
	if code != http.StatusOK || reviewed.Changes != 1 {
		t.Fatalf("plan of an owner edit = %d %s", code, body)
	}
	ownerID := ""
	for _, item := range reviewed.Items {
		if item.Kind == "owner" {
			ownerID = item.ObjectID
		}
	}
	if code, body := secretsReqKey(t, h, http.MethodPut, "/api/v1/owners/"+ownerID, author, "a248-owner-edit",
		map[string]any{"kind": "team", "name": "Payments", "email": "payments@payments.example", "application_id": "app-42",
			"service": "checkout-elsewhere", "environment": "production", "escalation_chain": []string{"payments-oncall"}}); code != http.StatusOK {
		t.Fatalf("operator edit of the owner = %d %s", code, body)
	}
	if code, _, body := apply(author, "a248-apply-stale", edited, reviewed.PlanDigest); code != http.StatusConflict || !strings.Contains(body, "stale") {
		t.Fatalf("applying a plan the tenant moved past = %d %s", code, body)
	}
	owner, err := h.store.GetOwner(t.Context(), h.tenant, ownerID)
	if err != nil || owner.Service != "checkout-elsewhere" {
		t.Fatalf("the stale apply changed the owner: %+v, %v", owner, err)
	}
}
