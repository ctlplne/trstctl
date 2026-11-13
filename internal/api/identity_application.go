// SPDX-License-Identifier: BUSL-1.1

package api

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"slices"
	"strings"
	"time"

	"trstctl.com/trstctl/internal/authz"
	"trstctl.com/trstctl/internal/orchestrator"
	"trstctl.com/trstctl/internal/store"
)

// A244: one certificate's application view. Everything that decides what
// happens to it, read in one place: its owner and application, the profile
// and the exact issuer, where it is delivered and whether anything saw it
// served (and from which vantage), its approvals and what superseded them, the
// next automated action and any failed prerequisite, its alerts, the actions
// that apply (recover, revoke, retire), and the settings a new certificate can
// reuse. It is a read: every action names the route that performs it.

// Inventory states (A244).
const (
	inventoryRequested = "requested"
	inventoryIssued    = "issued"
	inventoryDelivered = "delivered"
	inventoryServed    = "served"
	inventoryRevoked   = "revoked"
	inventoryRetired   = "retired"
)

// inventoryState is what the inventory says an identity's certificate is:
// requested; issued (its active certificate has not been delivered);
// delivered (a target took the active certificate); served (it was seen
// served — read back by the delivering connector, or observed by an endpoint
// verification); revoked; retired.
func inventoryState(status string, e store.InventoryEvidence, found bool) string {
	switch status {
	case "requested":
		return inventoryRequested
	case "revoked":
		return inventoryRevoked
	case "retired":
		return inventoryRetired
	}
	switch {
	case !found || !e.Active:
		return inventoryIssued
	case e.ReceiptStatus == "verified" || e.ObservedVantage != "":
		return inventoryServed
	default:
		return inventoryDelivered
	}
}

type applicationOwner struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	Kind        string `json:"kind"`
	Application string `json:"application,omitempty"`
	Service     string `json:"service,omitempty"`
	Environment string `json:"environment,omitempty"`
}

type applicationIssuer struct {
	// Source is platform, private or external; ID and Name name the
	// authority the identity is bound to.
	Source string `json:"source"`
	ID     string `json:"id,omitempty"`
	Name   string `json:"name,omitempty"`
	// CertificateIssuer is the exact issuer name of the active certificate.
	CertificateIssuer string `json:"certificate_issuer,omitempty"`
}

// applicationEnrollment is how the identity's certificates were enrolled
// (A244-L4): the path that issued its first certificate and the one that
// issued the active certificate, as each issuing front end named it (api,
// agent, acme, est, scep, cmp, broker, attested, ephemeral). Empty is
// unrecorded: issued before paths were kept.
type applicationEnrollment struct {
	FirstMethod        string `json:"first_method,omitempty"`
	FirstCertificateID string `json:"first_certificate_id,omitempty"`
	CurrentMethod      string `json:"current_method,omitempty"`
}

type applicationProfile struct {
	Name             string `json:"name"`
	Version          int    `json:"version"`
	SpecDigest       string `json:"spec_digest"`
	RequiresApproval bool   `json:"requires_approval"`
	// EnrollmentMethods are the enrollment protocols the profile permits;
	// empty permits any.
	EnrollmentMethods []string `json:"enrollment_methods"`
}

// applicationPlanStep is one step of the value-free review plan: what the
// next issuance or renewal does, and exactly what each step acts on.
type applicationPlanStep struct {
	// Action is approve, issue, deploy or verify.
	Action string `json:"action"`
	// Subject is the profile (approve), the issuer (issue), the destination
	// (deploy) or the vantage that saw the destination last (verify); empty
	// for verify when nothing has observed the destination yet.
	Subject string `json:"subject"`
}

type applicationCertificate struct {
	ID          string     `json:"id"`
	Fingerprint string     `json:"fingerprint"`
	Serial      string     `json:"serial"`
	Status      string     `json:"status"`
	NotAfter    *time.Time `json:"not_after,omitempty"`
}

type applicationDestination struct {
	TargetID  string `json:"target_id"`
	Name      string `json:"name"`
	Connector string `json:"connector"`
	Revision  string `json:"revision"`
	Enabled   bool   `json:"enabled"`
	// VerifyAddress is the endpoint the destination serves, as its target
	// names it (verify_address). The scheduler verifies it every interval,
	// first against the certificate delivered there (A244-L1). Empty, nothing
	// observes the destination: its inventory stays delivered until the
	// target names one or something else sees the certificate served.
	VerifyAddress string `json:"verify_address,omitempty"`
	// LastDelivery is the latest completed delivery to it.
	LastDeliveryStatus      string     `json:"last_delivery_status,omitempty"`
	LastDeliveryFingerprint string     `json:"last_delivery_fingerprint,omitempty"`
	LastDeliveryAt          *time.Time `json:"last_delivery_at,omitempty"`
}

type applicationServed struct {
	Fingerprint string `json:"fingerprint"`
	// Vantage is connector (the delivering connector read it back), local (the
	// serving host's agent) or relay (a network agent, as a client sees it).
	Vantage        string     `json:"vantage"`
	At             *time.Time `json:"at,omitempty"`
	MatchesCurrent bool       `json:"matches_current"`
}

type applicationApproval struct {
	ID        string    `json:"id"`
	Status    string    `json:"status"`
	Action    string    `json:"action"`
	CreatedAt time.Time `json:"created_at"`
	ExpiresAt time.Time `json:"expires_at"`
	// Changed names what moved since the approval was asked for: profile,
	// destination, issuer or identity (what the identity itself puts into
	// the certificate, A245-L5); empty when none did.
	Changed []string `json:"changed"`
}

type applicationRenewal struct {
	Due             bool       `json:"due"`
	NotAfter        *time.Time `json:"not_after,omitempty"`
	Source          string     `json:"source,omitempty"`
	NextAction      string     `json:"next_action"`
	LatestRunStatus string     `json:"latest_run_status,omitempty"`
	// Blockers are the failed prerequisites of the next automated action.
	Blockers []string `json:"blockers"`
}

type applicationAlert struct {
	ID          string    `json:"id"`
	Kind        string    `json:"kind,omitempty"`
	Destination string    `json:"destination"`
	Status      string    `json:"status"`
	CreatedAt   time.Time `json:"created_at"`
}

type applicationAction struct {
	Action    string `json:"action"`
	Available bool   `json:"available"`
	Reason    string `json:"reason,omitempty"`
	Method    string `json:"method"`
	Path      string `json:"path"`
}

type applicationDefaults struct {
	OwnerID      string `json:"owner_id,omitempty"`
	ProfileName  string `json:"profile_name,omitempty"`
	IssuerSource string `json:"issuer_source,omitempty"`
	IssuerID     string `json:"issuer_id,omitempty"`
	Connector    string `json:"connector,omitempty"`
}

type identityApplicationView struct {
	Identity       identityResponse        `json:"identity"`
	InventoryState string                  `json:"inventory_state"`
	Owner          *applicationOwner       `json:"owner,omitempty"`
	Issuer         applicationIssuer       `json:"issuer"`
	Profile        *applicationProfile     `json:"profile,omitempty"`
	Certificate    *applicationCertificate `json:"certificate,omitempty"`
	Enrollment     *applicationEnrollment  `json:"enrollment,omitempty"`
	Destination    *applicationDestination `json:"destination,omitempty"`
	Served         *applicationServed      `json:"served,omitempty"`
	Approvals      []applicationApproval   `json:"approvals"`
	Renewal        applicationRenewal      `json:"renewal"`
	Alerts         []applicationAlert      `json:"alerts"`
	Actions        []applicationAction     `json:"actions"`
	Defaults       applicationDefaults     `json:"defaults"`
	ReviewPlan     []applicationPlanStep   `json:"review_plan"`
}

type identityApplicationAttributes struct {
	Profile    string `json:"profile_name"`
	Target     string `json:"deployment_target_id"`
	Source     string `json:"issuing_authority_source"`
	IssuerID   string `json:"issuing_authority_id"`
	IssuerName string `json:"issuing_authority_name"`
}

func (a *API) getIdentityApplicationView(w http.ResponseWriter, r *http.Request) {
	tenantID, ok := a.tenant(r)
	if !ok {
		a.writeProblem(w, problemUnauthorized())
		return
	}
	view, err := a.identityApplicationView(r.Context(), tenantID, r.PathValue("id"))
	if err != nil {
		a.writeError(w, err)
		return
	}
	a.writeJSON(w, http.StatusOK, view)
}

func (a *API) identityApplicationView(ctx context.Context, tenantID, id string) (identityApplicationView, error) {
	identity, err := a.store.GetIdentity(ctx, tenantID, id)
	if err != nil {
		return identityApplicationView{}, err
	}
	var attrs identityApplicationAttributes
	if len(identity.Attributes) > 0 {
		_ = json.Unmarshal(identity.Attributes, &attrs)
	}
	view := identityApplicationView{
		Identity: toIdentityResponse(identity), Approvals: []applicationApproval{}, Alerts: []applicationAlert{},
		Actions: []applicationAction{}, Renewal: applicationRenewal{Blockers: []string{}}, ReviewPlan: []applicationPlanStep{},
		Issuer: applicationIssuer{Source: attrs.Source, ID: attrs.IssuerID, Name: attrs.IssuerName},
		Defaults: applicationDefaults{OwnerID: identity.OwnerID, ProfileName: attrs.Profile,
			IssuerSource: attrs.Source, IssuerID: attrs.IssuerID},
	}
	if view.Issuer.Source == "" {
		view.Issuer.Source, view.Issuer.ID = store.PlatformIssuerSource, store.PlatformIssuerID
	}
	if identity.OwnerID != "" {
		if owner, err := a.store.GetOwner(ctx, tenantID, identity.OwnerID); err == nil {
			view.Owner = &applicationOwner{ID: owner.ID, Name: owner.Name, Kind: string(owner.Kind),
				Application: owner.ApplicationID, Service: owner.Service, Environment: owner.Environment}
		} else if !store.IsNotFound(err) {
			return identityApplicationView{}, err
		}
	}
	profileName := attrs.Profile
	if a.orch != nil {
		// The profile the next issuance applies, resolved as issuance resolves
		// it: the identity's own, the one retained from its first issuance,
		// else the served default. An issuance approval binds that profile, so
		// it is what "changed" compares with; reading the identity's attribute
		// alone said every approval under the served default had a changed
		// profile (found with A245-L5).
		requirement, err := a.issuanceProfileRequirement(ctx, tenantID, id, a.gate.Profile)
		var notActive *orchestrator.ProfileNotActiveError
		switch {
		case err == nil:
			profileName = requirement.ProfileName
		case errors.As(err, &notActive):
			profileName = ""
		default:
			return identityApplicationView{}, err
		}
	}
	if profileName != "" {
		if rec, err := a.store.GetActiveProfile(ctx, tenantID, profileName); err == nil {
			var spec struct {
				RequiresApproval bool     `json:"requires_approval"`
				AllowedProtocols []string `json:"allowed_protocols"`
			}
			_ = json.Unmarshal(rec.Spec, &spec)
			view.Profile = &applicationProfile{Name: profileName, Version: rec.Version,
				SpecDigest: store.ProfileSpecDigest(rec.Spec), RequiresApproval: spec.RequiresApproval,
				EnrollmentMethods: append([]string{}, spec.AllowedProtocols...)}
		} else if !store.IsNotFound(err) {
			return identityApplicationView{}, err
		}
	}
	certs, err := a.store.IdentityRevocationCertificates(ctx, tenantID, id, 101)
	if err != nil {
		return identityApplicationView{}, err
	}
	for i := len(certs) - 1; i >= 0; i-- {
		if certs[i].Status == "active" {
			c := certs[i]
			view.Certificate = &applicationCertificate{ID: c.ID, Fingerprint: c.Fingerprint, Serial: c.Serial, Status: c.Status, NotAfter: c.NotAfter}
			view.Issuer.CertificateIssuer = c.Issuer
			view.Enrollment = &applicationEnrollment{CurrentMethod: c.EnrollmentProtocol}
			break
		}
	}
	// A244-L4: the method that first enrolled the identity's certificate, which
	// the profile's permitted protocols can't tell.
	if firstID, firstMethod, err := a.store.IdentityFirstEnrollment(ctx, tenantID, id); err != nil {
		return identityApplicationView{}, err
	} else if firstID != "" {
		if view.Enrollment == nil {
			view.Enrollment = &applicationEnrollment{}
		}
		view.Enrollment.FirstMethod, view.Enrollment.FirstCertificateID = firstMethod, firstID
	}
	if attrs.Target != "" {
		if target, err := a.store.GetDeploymentTarget(ctx, tenantID, attrs.Target); err == nil {
			view.Destination = &applicationDestination{TargetID: target.ID, Name: target.Name, Connector: target.Type,
				Revision: target.RevisionID, Enabled: target.Enabled, VerifyAddress: targetVerifyAddress(target.Config)}
			view.Defaults.Connector = target.Type
		} else if !store.IsNotFound(err) {
			return identityApplicationView{}, err
		}
	}
	evidence, err := a.store.IdentityInventoryEvidence(ctx, tenantID, []string{id})
	if err != nil {
		return identityApplicationView{}, err
	}
	e, found := evidence[id]
	view.InventoryState = inventoryState(identity.Status, e, found)
	view.Identity.InventoryState = view.InventoryState
	if found {
		if view.Destination != nil {
			at := e.DeliveredAt
			view.Destination.LastDeliveryStatus, view.Destination.LastDeliveryFingerprint, view.Destination.LastDeliveryAt = e.ReceiptStatus, e.Fingerprint, &at
		}
		current := view.Certificate != nil && view.Certificate.Fingerprint == e.Fingerprint
		switch {
		case e.ObservedVantage != "":
			view.Served = &applicationServed{Fingerprint: e.Fingerprint, Vantage: e.ObservedVantage, At: e.ObservedAt, MatchesCurrent: current}
		case e.ReceiptStatus == "verified":
			at := e.DeliveredAt
			view.Served = &applicationServed{Fingerprint: e.Fingerprint, Vantage: "connector", At: &at, MatchesCurrent: current}
		}
	}
	approvals, err := a.store.IdentityApprovals(ctx, tenantID, id, 10)
	if err != nil {
		return identityApplicationView{}, err
	}
	identityDigest, err := store.IdentityIssuanceDigest(identity)
	if err != nil {
		return identityApplicationView{}, err
	}
	for _, request := range approvals {
		view.Approvals = append(view.Approvals, applicationApproval{ID: request.ID, Status: request.Status, Action: request.Action,
			CreatedAt: request.CreatedAt, ExpiresAt: request.ExpiresAt, Changed: approvalChanges(request, view, identityDigest)})
	}
	if a.lifecycleAutomationPlan != nil {
		plan, err := a.lifecycleAutomationPlan.LifecycleAutomationPlan(ctx, tenantID, time.Now().UTC())
		if err != nil {
			return identityApplicationView{}, err
		}
		for _, item := range plan.Items {
			if item.IdentityID != id {
				continue
			}
			view.Renewal = applicationRenewal{Due: item.Due, NotAfter: item.NotAfter, Source: item.RenewalSource,
				LatestRunStatus: item.LatestRunStatus, Blockers: append([]string{}, item.Blockers...)}
			break
		}
	}
	view.Renewal.NextAction = nextAutomatedAction(identity.Status, view.Renewal)
	rows, err := a.store.ListNotificationOutboxPageWithOrder(ctx, tenantID, 0, 200, "", true)
	if err != nil {
		return identityApplicationView{}, err
	}
	for _, row := range rows {
		n := toNotificationResponse(row)
		if n.IdentityID != id || len(view.Alerts) == 10 {
			continue
		}
		view.Alerts = append(view.Alerts, applicationAlert{ID: n.ID, Kind: n.Kind, Destination: n.Destination, Status: n.Status, CreatedAt: n.CreatedAt})
	}
	view.Actions = applicationActions(identity)
	view.ReviewPlan = applicationReviewPlan(identity.Status, view)
	return view, nil
}

// applicationReviewPlan is what the next issuance or renewal does, step by
// step, naming exactly what each step acts on and never a value. A revoked or
// retired certificate has no next issuance.
func applicationReviewPlan(status string, view identityApplicationView) []applicationPlanStep {
	plan := []applicationPlanStep{}
	if status == "revoked" || status == "retired" {
		return plan
	}
	if view.Profile != nil && view.Profile.RequiresApproval {
		plan = append(plan, applicationPlanStep{Action: "approve", Subject: view.Profile.Name})
	}
	issuer := view.Issuer.Source
	if id := view.Issuer.ID; id != "" {
		issuer += ":" + id
	}
	plan = append(plan, applicationPlanStep{Action: "issue", Subject: issuer})
	if view.Destination != nil {
		plan = append(plan, applicationPlanStep{Action: "deploy", Subject: view.Destination.Name + " (" + view.Destination.Connector + ")"})
		verify := applicationPlanStep{Action: "verify"}
		if view.Served != nil {
			verify.Subject = view.Served.Vantage
		}
		plan = append(plan, verify)
	}
	return plan
}

// approvalChanges names what moved since an approval was asked for, read
// from its evidence: the profile revision, the destination (target or its
// revision), the issuer, and what the identity itself puts into the
// certificate (identityDigest is its IdentityIssuanceDigest now).
func approvalChanges(request store.OperationApprovalRequest, view identityApplicationView, identityDigest string) []string {
	changed := []string{}
	use, err := store.OperationApprovalUseFromRequest(request)
	if err != nil || use.Issuance == nil {
		return changed
	}
	b := use.Issuance
	if b.ProfileID != "" && (view.Profile == nil || view.Profile.Version != b.ProfileVersion || view.Profile.SpecDigest != b.ProfileSpecDigest) {
		changed = append(changed, "profile")
	}
	if b.DestinationTargetID != "" && (view.Destination == nil || view.Destination.TargetID != b.DestinationTargetID ||
		view.Destination.Revision != b.DestinationRevision) {
		changed = append(changed, "destination")
	}
	if b.IssuerSource != "" && (view.Issuer.Source != b.IssuerSource || view.Issuer.ID != b.IssuerID) {
		changed = append(changed, "issuer")
	}
	if b.IdentityDigest != "" && b.IdentityDigest != identityDigest {
		changed = append(changed, "identity")
	}
	return changed
}

// nextAutomatedAction says what the scheduler does next for the identity.
func nextAutomatedAction(status string, renewal applicationRenewal) string {
	switch {
	case status == "requested":
		return "issue on request"
	case status == "revoked" || status == "retired":
		return "none"
	case status == "renewal_failed":
		return "renewal retry"
	case len(renewal.Blockers) > 0:
		return "blocked"
	case renewal.Due:
		return "renew now"
	case renewal.Source != "":
		return "renew before expiry"
	default:
		return "none scheduled"
	}
}

// applicationActions are the recover, revoke and retire actions with whether
// they apply now and the route that performs each.
func applicationActions(identity store.Identity) []applicationAction {
	base := "/api/v1/identities/" + identity.ID
	active := slices.Contains([]string{"issued", "deployed", "renewing", "renewal_failed"}, identity.Status)
	recover := applicationAction{Action: "recover", Method: http.MethodPost, Path: base + "/transitions"}
	switch {
	case identity.Status == "renewal_failed":
		recover.Available = true
	case len(store.IdentityRenewalPauses(identity.Attributes)) > 0:
		recover.Available, recover.Path = true, base+"/renewal/resume"
	default:
		recover.Reason = "nothing to recover: renewal has not failed and no rollback holds it"
	}
	revoke := applicationAction{Action: "revoke", Available: active, Method: http.MethodPost, Path: base + "/transitions"}
	if !active {
		revoke.Reason = "only an issued or deployed certificate can be revoked"
	}
	retire := applicationAction{Action: "retire", Available: identity.Status == "revoked", Method: http.MethodPost, Path: base + "/transitions"}
	if !retire.Available {
		retire.Reason = "a certificate is retired after it is revoked"
	}
	if strings.TrimSpace(identity.Status) == "retired" {
		revoke.Reason, retire.Reason = "retired", "retired"
	}
	return []applicationAction{recover, revoke, retire}
}

func identityApplicationRoutes(a *API) []route {
	return []route{
		{method: "GET", path: "/api/v1/identities/{id}/application", opID: "getIdentityApplicationView",
			summary: "Show one certificate's application view: owner, profile, exact issuer, destination, served evidence and vantage, approvals, next automated action, alerts and actions",
			handler: a.getIdentityApplicationView, pathParams: []param{pathString("id", "identity ID")},
			resSchema: "IdentityApplicationView", successCode: "200", perm: authz.IdentitiesRead},
	}
}

func identityApplicationSchemas() map[string]*Schema {
	strs := &Schema{Type: "array", Items: str()}
	states := []string{inventoryRequested, inventoryIssued, inventoryDelivered, inventoryServed, inventoryRevoked, inventoryRetired}
	return map[string]*Schema{
		"IdentityApplicationView": object(map[string]*Schema{
			"identity":        ref("Identity"),
			"inventory_state": {Type: "string", Enum: states},
			"owner": object(map[string]*Schema{
				"id": uuid(), "name": str(), "kind": str(), "application": str(), "service": str(), "environment": str(),
			}, "id", "name", "kind"),
			"issuer": object(map[string]*Schema{
				"source": {Type: "string", Enum: []string{"platform", "private", "external"}}, "id": str(), "name": str(),
				"certificate_issuer": str(),
			}, "source"),
			"profile": object(map[string]*Schema{
				"name": str(), "version": {Type: "integer"}, "spec_digest": str(), "requires_approval": {Type: "boolean"},
				"enrollment_methods": strs,
			}, "name", "version", "spec_digest", "requires_approval", "enrollment_methods"),
			"certificate": object(map[string]*Schema{
				"id": uuid(), "fingerprint": str(), "serial": str(), "status": str(), "not_after": timestamp(),
			}, "id", "fingerprint", "serial", "status"),
			"enrollment": {Type: "object", Description: "How the identity's certificates were enrolled (A244-L4): the path that issued its first certificate and the one that issued the active certificate (api, agent, acme, est, scep, cmp, broker, attested, ephemeral); empty is unrecorded.",
				Properties: map[string]*Schema{"first_method": str(), "first_certificate_id": uuid(), "current_method": str()}},
			"destination": object(map[string]*Schema{
				"target_id": uuid(), "name": str(), "connector": str(), "revision": str(), "enabled": {Type: "boolean"},
				"verify_address":       {Type: "string", Description: "The endpoint the destination serves, from its target's verify_address, verified every interval (A244-L1); empty when nothing observes the destination."},
				"last_delivery_status": str(), "last_delivery_fingerprint": str(), "last_delivery_at": timestamp(),
			}, "target_id", "name", "connector", "revision", "enabled"),
			"served": object(map[string]*Schema{
				"fingerprint": str(), "vantage": {Type: "string", Enum: []string{"connector", "local", "relay"}},
				"at": timestamp(), "matches_current": {Type: "boolean"},
			}, "fingerprint", "vantage", "matches_current"),
			"approvals": {Type: "array", Items: object(map[string]*Schema{
				"id": uuid(), "status": str(), "action": str(), "created_at": timestamp(), "expires_at": timestamp(),
				"changed": {Type: "array", Items: &Schema{Type: "string", Enum: []string{"profile", "destination", "issuer", "identity"}}},
			}, "id", "status", "action", "created_at", "expires_at", "changed")},
			"renewal": object(map[string]*Schema{
				"due": {Type: "boolean"}, "not_after": timestamp(), "source": str(), "next_action": str(),
				"latest_run_status": str(), "blockers": strs,
			}, "due", "next_action", "blockers"),
			"alerts": {Type: "array", Items: object(map[string]*Schema{
				"id": str(), "kind": str(), "destination": str(), "status": str(), "created_at": timestamp(),
			}, "id", "destination", "status", "created_at")},
			"actions": {Type: "array", Items: object(map[string]*Schema{
				"action": {Type: "string", Enum: []string{"recover", "revoke", "retire"}}, "available": {Type: "boolean"},
				"reason": str(), "method": str(), "path": str(),
			}, "action", "available", "method", "path")},
			"defaults": object(map[string]*Schema{
				"owner_id": str(), "profile_name": str(), "issuer_source": str(), "issuer_id": str(), "connector": str(),
			}),
			"review_plan": {Type: "array", Items: object(map[string]*Schema{
				"action": {Type: "string", Enum: []string{"approve", "issue", "deploy", "verify"}}, "subject": str(),
			}, "action", "subject")},
		}, "identity", "inventory_state", "issuer", "approvals", "renewal", "alerts", "actions", "defaults", "review_plan"),
	}
}

// targetVerifyAddress is a deployment target's verify_address, the endpoint it
// serves, or empty.
func targetVerifyAddress(config json.RawMessage) string {
	var fields struct {
		VerifyAddress string `json:"verify_address"`
	}
	if len(config) == 0 || json.Unmarshal(config, &fields) != nil {
		return ""
	}
	return strings.TrimSpace(fields.VerifyAddress)
}
