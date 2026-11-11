// SPDX-License-Identifier: BUSL-1.1

package api

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"slices"
	"strings"
	"time"
	"unicode"

	googleuuid "github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"trstctl.com/trstctl/internal/authz"
	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/crypto/secret"
	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/projections"
	"trstctl.com/trstctl/internal/store"
	"trstctl.com/trstctl/internal/usage"
)

// A236: environment promotion. A promotion copies one environment's secrets
// (or one folder of them) into another environment of the same project, as new
// versions written in one batch. The caller first previews a value-free plan
// and applies it by its digest; the apply recomputes the plan, so a secret
// changed since the preview makes the digest stale, and the batch reserves
// every name at its planned version, so nothing changes between the check and
// the write. References into the source environment are pointed at the same
// key in the target. Every reference of a changed secret must resolve in the
// target as the caller may read it, hop by hop, without a cycle; otherwise the
// item is blocked and nothing is applied. Secrets only in the target are left
// alone and listed as kept.

var applicationSecretVersionBatchNamespace = googleuuid.MustParse("9e783bba-616c-5da7-b334-8235249d5821")

const (
	secretPromotionLimit     = 100
	secretPromotionKeptLimit = 500

	secretPromotionCreate    = "create"
	secretPromotionUpdate    = "update"
	secretPromotionUnchanged = "unchanged"
	secretPromotionBlocked   = "blocked"
)

type secretPromotionRequest struct {
	From       string `json:"from"`
	To         string `json:"to"`
	Folder     string `json:"folder,omitempty"`
	PlanDigest string `json:"plan_digest,omitempty"`
}

type secretPromotionItem struct {
	Key                 string   `json:"key"`
	SourceName          string   `json:"source_name"`
	SourceVersion       int      `json:"source_version"`
	TargetName          string   `json:"target_name"`
	TargetVersion       int      `json:"target_version"`
	Action              string   `json:"action"`
	Reason              string   `json:"reason,omitempty"`
	References          []string `json:"references,omitempty"`
	RewrittenReferences int      `json:"rewritten_references,omitempty"`
	// OwnerID and OwnerName are the owner a created target secret takes from
	// its source (A236-L2); an update keeps the target's own owner.
	OwnerID   string `json:"owner_id,omitempty"`
	OwnerName string `json:"owner_name,omitempty"`
}

type secretPromotionPlan struct {
	Project    string                `json:"project"`
	From       string                `json:"from"`
	To         string                `json:"to"`
	Folder     string                `json:"folder,omitempty"`
	PlanDigest string                `json:"plan_digest"`
	Items      []secretPromotionItem `json:"items"`
	Kept       []string              `json:"kept"`
	Changes    int                   `json:"changes"`
	Blocked    int                   `json:"blocked"`
}

type secretVersionBatchItemResponse struct {
	Name      string    `json:"name"`
	Version   int       `json:"version"`
	UpdatedAt time.Time `json:"updated_at"`
}

// secretVersionBatchReceipt answers an applied promotion or restore. A plan
// with nothing to change answers with no batch and no items.
type secretVersionBatchReceipt struct {
	BatchID    string                           `json:"batch_id,omitempty"`
	Operation  string                           `json:"operation"`
	PlanDigest string                           `json:"plan_digest"`
	Items      []secretVersionBatchItemResponse `json:"items"`
}

func (a *API) secretPromotionRoutes() []route {
	project := []param{pathString("project", "secrets project slug")}
	return []route{
		{method: "POST", path: "/api/v1/secrets/projects/{project}/promotions/preview", opID: "previewSecretPromotion",
			summary: "Preview promoting an environment's secrets (or one folder of them) into another environment: a value-free plan and its digest",
			handler: a.previewSecretPromotion, pathParams: project, reqSchema: "SecretPromotionRequest",
			resSchema: "SecretPromotionPlan", successCode: "200", perm: authz.SecretsRead},
		{method: "POST", path: "/api/v1/secrets/projects/{project}/promotions", opID: "applySecretPromotion",
			summary: "Apply a reviewed promotion plan by its digest as one batch of new versions; a secret changed since the preview makes it stale",
			handler: a.applySecretPromotion, pathParams: project, reqSchema: "SecretPromotionRequest",
			resSchema: "SecretVersionBatchReceipt", successCode: "201", mutation: true, perm: authz.SecretsWrite},
	}
}

func secretVersionBatchSchemas() map[string]*Schema {
	item := object(map[string]*Schema{"name": str(), "version": {Type: "integer"}, "updated_at": timestamp()},
		"name", "version", "updated_at")
	return map[string]*Schema{
		"SecretPromotionRequest": object(map[string]*Schema{
			"from": str(), "to": str(), "folder": str(), "plan_digest": str(),
		}, "from", "to"),
		"SecretPromotionItem": object(map[string]*Schema{
			"key": str(), "source_name": str(), "source_version": {Type: "integer"},
			"target_name": str(), "target_version": {Type: "integer"},
			"action": {Type: "string", Enum: []string{secretPromotionCreate, secretPromotionUpdate,
				secretPromotionUnchanged, secretPromotionBlocked}},
			"reason": str(), "references": {Type: "array", Items: str()}, "rewritten_references": {Type: "integer"},
			"owner_id":   {Type: "string", Format: "uuid", Description: "A236-L2: the owner a created target secret takes from its source; absent for an update, which keeps the target's owner, or a source with no owner"},
			"owner_name": {Type: "string", Description: "A236-L2: that owner's name"},
		}, "key", "source_name", "source_version", "target_name", "target_version", "action"),
		"SecretPromotionPlan": object(map[string]*Schema{
			"project": str(), "from": str(), "to": str(), "folder": str(), "plan_digest": str(),
			"items": {Type: "array", Items: ref("SecretPromotionItem")}, "kept": {Type: "array", Items: str()},
			"changes": {Type: "integer"}, "blocked": {Type: "integer"},
		}, "project", "from", "to", "plan_digest", "items", "kept", "changes", "blocked"),
		"SecretVersionBatchReceipt": object(map[string]*Schema{
			"batch_id": str(), "operation": {Type: "string", Enum: []string{
				store.ApplicationSecretBatchPromotion, store.ApplicationSecretBatchRestore}},
			"plan_digest": str(), "items": {Type: "array", Items: item},
		}, "operation", "plan_digest", "items"),
	}
}

func (a *API) previewSecretPromotion(w http.ResponseWriter, r *http.Request) {
	if a.secrets == nil || a.store == nil {
		a.writeProblem(w, secretsDisabledProblem())
		return
	}
	tenantID, ok := a.tenant(r)
	if !ok {
		a.writeProblem(w, problemUnauthorized())
		return
	}
	var req secretPromotionRequest
	if err := decodeJSON(r, &req); err != nil {
		a.writeError(w, errWithStatus(http.StatusBadRequest, err))
		return
	}
	planned, err := a.planSecretPromotion(r.Context(), tenantID, r.PathValue("project"), req)
	if err != nil {
		a.writeError(w, err)
		return
	}
	defer planned.wipe()
	a.writeJSON(w, http.StatusOK, planned.plan)
}

//trstctl:mutation
func (a *API) applySecretPromotion(w http.ResponseWriter, r *http.Request) {
	if a.secrets == nil || a.store == nil {
		a.writeProblem(w, secretsDisabledProblem())
		return
	}
	project := r.PathValue("project")
	idempotencyKey := r.Header.Get("Idempotency-Key")
	if idempotencyKey == "" {
		a.writeError(w, errStatus(http.StatusBadRequest, "Idempotency-Key header is required for mutations"))
		return
	}
	var req secretPromotionRequest
	if err := decodeJSON(r, &req); err != nil {
		a.writeError(w, errWithStatus(http.StatusBadRequest, err))
		return
	}
	if _, err := hex.DecodeString(req.PlanDigest); err != nil || len(req.PlanDigest) != 64 {
		a.writeError(w, errStatus(http.StatusBadRequest, "plan_digest from a promotion preview is required"))
		return
	}
	principal, err := requestPrincipalSubject(r.Context())
	if err != nil {
		a.writeError(w, err)
		return
	}
	tenantID, ok := a.tenant(r)
	if !ok {
		a.writeProblem(w, problemUnauthorized())
		return
	}
	keyDigest, binding, err := a.applicationSecretRequestBinding(
		tenantID, idempotencyKey, principal, r.Method, r.URL.EscapedPath(), "promote", "native", project, req)
	if err != nil {
		a.writeError(w, err)
		return
	}
	a.mutateBound(w, r, idempotencyKey, binding, func(ctx context.Context, authorizedTenant string) (int, any, error) {
		if authorizedTenant != tenantID {
			return 0, nil, errors.New("api: secret promotion tenant changed")
		}
		authorize, err := a.secretPromotionApproval(ctx, tenantID, project, req)
		if err != nil {
			return 0, nil, err
		}
		return withStoredSecretCreationFence(ctx, tenantID, func(work context.Context) (int, any, error) {
			receipt, err := a.executeApprovedSecretVersionBatch(work, tenantID, store.ApplicationSecretBatchPromotion,
				idempotencyKey, keyDigest, binding, req.PlanDigest, authorize,
				func(ctx context.Context) ([]projections.ApplicationSecretBatchVersionItem, int, error) {
					return a.sealSecretPromotion(ctx, tenantID, project, req)
				})
			if err != nil {
				return 0, nil, err
			}
			if receipt.BatchID == "" {
				return http.StatusOK, receipt, nil
			}
			return http.StatusCreated, receipt, nil
		})
	})
}

// secretPromotionApprovalKind is the approval request kind of a promotion
// into a restricted environment (A236-L1); its resource is
// "<project>/<environment>".
const secretPromotionApprovalKind = "secret_promotion"

// secretPromotionApproval is four-eyes for a promotion into a restricted
// environment (A236-L1): an exact single-use approval of this plan, decided by
// a second member who holds write there. A promotion into an open environment
// needs none (nil).
func (a *API) secretPromotionApproval(ctx context.Context, tenantID, project string, req secretPromotionRequest) (func(context.Context) (*store.OperationApprovalUse, error), error) {
	_, envs, _, err := a.store.GetSecretProject(ctx, tenantID, project)
	if errors.Is(err, store.ErrSecretProjectNotFound) {
		return nil, errStatus(http.StatusNotFound, "no such secrets project")
	}
	if err != nil {
		return nil, err
	}
	restricted := false
	for _, env := range envs {
		if env.Slug == req.To {
			restricted = env.Restricted
		}
	}
	if !restricted {
		return nil, nil
	}
	return func(ctx context.Context) (*store.OperationApprovalUse, error) {
		return a.authorizeSecretPromotion(ctx, tenantID, project, req)
	}, nil
}

// authorizeSecretPromotion asks for, or finds, the exact approval of this
// plan. Until a second member approves it the answer is 403 naming the
// request, which the requester applies again once it is approved.
func (a *API) authorizeSecretPromotion(ctx context.Context, tenantID, project string, req secretPromotionRequest) (*store.OperationApprovalUse, error) {
	if a.gate.Checker == nil {
		return nil, errStatus(http.StatusForbidden, "a promotion into a restricted environment needs four-eyes approval, and no approval store is configured")
	}
	exact, ok := a.gate.Checker.(ExactApprovalChecker)
	if !ok {
		return nil, errStatus(http.StatusForbidden, "a promotion into a restricted environment needs exact single-use approval authority")
	}
	principal, _ := ctx.Value(principalCtxKey).(authz.Principal)
	if principal.Subject == "" {
		return nil, errStatus(http.StatusUnauthorized, "an authenticated requester is required")
	}
	folder := strings.TrimSpace(req.Folder)
	name := project + ": " + req.From + " into " + req.To
	if folder != "" {
		name += " (folder " + folder + ")"
	}
	intent := ApprovalIntent{
		TenantID: tenantID, ResourceKind: secretPromotionApprovalKind, ResourceID: project + "/" + req.To,
		ResourceName: name, Action: "promote", Requester: principal.Subject,
		FromState: "plan:" + req.PlanDigest, ToState: req.To, TargetVersion: 1,
		Reason:       "promote " + name + " by the reviewed plan " + req.PlanDigest,
		EvidenceRefs: []string{"plan_digest:" + req.PlanDigest},
	}
	authority, approved, reason := exact.AuthorizeApproval(ctx, intent)
	if authority.RequestID == "" || authority.IntentDigest == "" ||
		authority.Requester != principal.Subject || authority.ResourceKind != intent.ResourceKind ||
		authority.ResourceID != intent.ResourceID || authority.Action != intent.Action ||
		authority.FromState != intent.FromState || authority.ToState != intent.ToState ||
		authority.TargetVersion != intent.TargetVersion || authority.RequiredApprovals <= 0 {
		return nil, approvalAPIError(store.ErrApprovalDrifted)
	}
	if !approved {
		if reason == "" {
			reason = "this exact promotion awaits a second member's approval"
		}
		return nil, errStatus(http.StatusForbidden, fmt.Sprintf(
			"dual control: approval_required:%s request_id=%s intent_digest=%s: %s",
			intent.ResourceID, authority.RequestID, authority.IntentDigest, reason))
	}
	return &store.OperationApprovalUse{
		RequestID: authority.RequestID, IntentDigest: authority.IntentDigest,
		Requester: authority.Requester, ResourceKind: authority.ResourceKind,
		ResourceID: authority.ResourceID, Action: authority.Action,
		FromState: authority.FromState, ToState: authority.ToState,
		TargetVersion: authority.TargetVersion, RequiredApprovals: authority.RequiredApprovals,
		Reason: authority.Reason, EvidenceRefs: authority.EvidenceRefs,
	}, nil
}

type secretPromotionPlanned struct {
	plan   secretPromotionPlan
	values map[string][]byte // target name → promoted plaintext (references rewritten)
}

func (p *secretPromotionPlanned) wipe() {
	for name, value := range p.values {
		secret.Wipe(value)
		delete(p.values, name)
	}
}

func validSecretFolder(folder string) bool {
	return folder == "" || len(folder) <= 256 && validApplicationSecretImportPath(folder)
}

// planSecretPromotion builds the reviewed plan. Values never leave it: the
// caller gets names, versions, actions and reasons, and the digest binds them
// plus the version of every stored secret a changed value reaches.
func (a *API) planSecretPromotion(ctx context.Context, tenantID, project string, req secretPromotionRequest) (*secretPromotionPlanned, error) {
	_, envs, _, err := a.store.GetSecretProject(ctx, tenantID, project)
	if errors.Is(err, store.ErrSecretProjectNotFound) {
		return nil, errStatus(http.StatusNotFound, "no such secrets project")
	}
	if err != nil {
		return nil, err
	}
	known := map[string]bool{}
	for _, env := range envs {
		known[env.Slug] = true
	}
	switch {
	case !known[req.From] || !known[req.To]:
		return nil, errStatus(http.StatusBadRequest, "from and to must be environments of this project")
	case req.From == req.To:
		return nil, errStatus(http.StatusBadRequest, "from and to must be different environments")
	case !validSecretFolder(req.Folder):
		return nil, errStatus(http.StatusBadRequest, "folder is a relative path without empty or dot segments, at most 256 bytes")
	}
	envFrom, envTo := project+"/"+req.From+"/", project+"/"+req.To+"/"
	if ok, err := a.secretScopeAllows(ctx, tenantID, envFrom, false); err != nil {
		return nil, err
	} else if !ok {
		return nil, errStatus(http.StatusForbidden, "the source environment is restricted to its members")
	}
	if ok, err := a.secretScopeAllows(ctx, tenantID, envTo, true); err != nil {
		return nil, err
	} else if !ok {
		return nil, errStatus(http.StatusForbidden, "the target environment is restricted to members with write access")
	}
	srcPrefix, dstPrefix := envFrom, envTo
	if req.Folder != "" {
		srcPrefix += req.Folder + "/"
		dstPrefix += req.Folder + "/"
	}
	hidden, err := a.hiddenSecretPrefixes(ctx, tenantID)
	if err != nil {
		return nil, err
	}
	sources, err := a.store.ListSecretNamesUnder(ctx, tenantID, []string{srcPrefix}, hidden, secretPromotionLimit+1)
	if err != nil {
		return nil, err
	}
	if len(sources) > secretPromotionLimit {
		return nil, errStatus(http.StatusBadRequest, "a promotion moves at most 100 secrets at once; narrow it with a folder")
	}
	planned := &secretPromotionPlanned{
		plan: secretPromotionPlan{Project: project, From: req.From, To: req.To, Folder: req.Folder,
			Items: []secretPromotionItem{}, Kept: []string{}},
		values: map[string][]byte{},
	}
	now := time.Now().UTC()
	targets := map[string]bool{}
	for _, src := range sources {
		item, err := a.planPromotedSecret(ctx, tenantID, src.Name, envFrom, envTo, now, planned.values)
		if err != nil {
			planned.wipe()
			return nil, err
		}
		if item == nil {
			continue // deleted since the listing
		}
		targets[item.TargetName] = true
		planned.plan.Items = append(planned.plan.Items, *item)
	}
	reached, resolved := map[string]int{}, map[string]bool{}
	for i := range planned.plan.Items {
		item := &planned.plan.Items[i]
		if item.Action != secretPromotionCreate && item.Action != secretPromotionUpdate {
			continue
		}
		reason, err := a.promotionReferenceProblem(ctx, tenantID, item.TargetName, planned.values, reached, resolved, nil)
		if err != nil {
			planned.wipe()
			return nil, err
		}
		if reason != "" {
			item.Action, item.Reason = secretPromotionBlocked, reason
		}
	}
	kept, err := a.store.ListSecretNamesUnder(ctx, tenantID, []string{dstPrefix}, hidden, secretPromotionKeptLimit)
	if err != nil {
		planned.wipe()
		return nil, err
	}
	for _, rec := range kept {
		if !targets[rec.Name] {
			planned.plan.Kept = append(planned.plan.Kept, rec.Name)
		}
	}
	for _, item := range planned.plan.Items {
		switch item.Action {
		case secretPromotionCreate, secretPromotionUpdate:
			planned.plan.Changes++
		case secretPromotionBlocked:
			planned.plan.Blocked++
		}
	}
	material, err := json.Marshal(struct {
		Domain  string              `json:"domain"`
		Plan    secretPromotionPlan `json:"plan"`
		Reached map[string]int      `json:"reached"`
	}{"trstctl.secret.promotion-plan.v1", planned.plan, reached})
	if err != nil {
		planned.wipe()
		return nil, err
	}
	planned.plan.PlanDigest = crypto.SHA256Hex(material)
	return planned, nil
}

// planPromotedSecret plans one source secret. It returns nil when the source
// is gone. The promoted value is added to values unless the item is blocked.
func (a *API) planPromotedSecret(
	ctx context.Context, tenantID, sourceName, envFrom, envTo string, now time.Time, values map[string][]byte,
) (*secretPromotionItem, error) {
	key := strings.TrimPrefix(sourceName, envFrom)
	item := &secretPromotionItem{Key: key, SourceName: sourceName, TargetName: envTo + key}
	source, err := a.secrets.be.Store.GetSecret(ctx, tenantID, sourceName)
	if errors.Is(err, store.ErrSecretNotFound) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	item.SourceVersion = source.Version
	var targetSealed []byte
	if target, err := a.secrets.be.Store.GetSecret(ctx, tenantID, item.TargetName); err == nil {
		item.TargetVersion, targetSealed = target.Version, target.Sealed
	} else if !errors.Is(err, store.ErrSecretNotFound) {
		return nil, err
	}
	state, err := a.secrets.be.Store.SecretVersionCredentialState(ctx, tenantID, sourceName, source.Version, now)
	if err != nil {
		return nil, err
	}
	if state.State != "" {
		item.Action, item.Reason = secretPromotionBlocked, secretCredentialStateReason(state)
		return item, nil
	}
	plain, err := a.secrets.open(ctx, tenantID, source.Sealed, sealAAD(tenantID, sourceName))
	if err != nil {
		return nil, err
	}
	value, rewritten := rewriteSecretReferences(plain, envFrom, envTo)
	secret.Wipe(plain)
	item.RewrittenReferences = rewritten
	for _, ref := range secretReferenceNames(value) {
		if !validSecretReferenceName(ref) {
			secret.Wipe(value)
			item.Action, item.Reason = secretPromotionBlocked, "a reference is not a valid secret name"
			item.References = nil
			return item, nil
		}
		item.References = append(item.References, ref)
	}
	item.Action = secretPromotionCreate
	if item.TargetVersion == 0 && source.OwnerID != "" {
		// A236-L2: the created secret takes its source's owner, if that owner
		// is still one of the tenant's.
		if owner, err := a.store.GetOwner(ctx, tenantID, source.OwnerID); err == nil {
			item.OwnerID, item.OwnerName = owner.ID, owner.Name
		} else if !store.IsNotFound(err) {
			secret.Wipe(value)
			return nil, err
		}
	}
	if item.TargetVersion > 0 {
		item.Action = secretPromotionUpdate
		current, err := a.secrets.open(ctx, tenantID, targetSealed, sealAAD(tenantID, item.TargetName))
		if err != nil {
			secret.Wipe(value)
			return nil, err
		}
		if bytes.Equal(current, value) {
			item.Action = secretPromotionUnchanged
		}
		secret.Wipe(current)
	}
	values[item.TargetName] = value
	return item, nil
}

// promotionReferenceProblem walks name's references in the target as it will
// be: a planned value first, else the stored secret as the caller may read it
// (a hop the caller may not read answers exactly like a missing one). It
// returns why the chain cannot resolve, or "" when it does.
func (a *API) promotionReferenceProblem(
	ctx context.Context, tenantID, name string, planned map[string][]byte,
	reached map[string]int, resolved map[string]bool, stack []string,
) (string, error) {
	if resolved[name] {
		return "", nil
	}
	if slices.Contains(stack, name) {
		return "reference cycle: " + strings.Join(append(slices.Clone(stack), name), " → "), nil
	}
	if len(stack) >= secretReferenceLimit {
		return "the reference chain is deeper than 32 secrets", nil
	}
	value, ok := planned[name]
	if !ok {
		missing := secretReferenceStart + name + "} does not resolve in the target"
		if err := a.requireSecretRead(ctx, tenantID, name); errors.Is(err, store.ErrSecretNotFound) {
			return missing, nil
		} else if err != nil {
			return "", err
		}
		rec, err := a.secrets.be.Store.GetSecret(ctx, tenantID, name)
		if errors.Is(err, store.ErrSecretNotFound) {
			return missing, nil
		}
		if err != nil {
			return "", err
		}
		plain, err := a.secrets.open(ctx, tenantID, rec.Sealed, sealAAD(tenantID, name))
		if err != nil {
			return "", err
		}
		defer secret.Wipe(plain)
		reached[name] = rec.Version
		value = plain
	}
	for _, ref := range secretReferenceNames(value) {
		if !validSecretReferenceName(ref) {
			return "a reference is not a valid secret name", nil
		}
		reason, err := a.promotionReferenceProblem(ctx, tenantID, ref, planned, reached, resolved, append(stack, name))
		if reason != "" || err != nil {
			return reason, err
		}
	}
	resolved[name] = true
	return "", nil
}

// secretReferenceNames lists value's ${secret.<name>} references the way
// expandSecretReferences reads them: an unterminated reference is plain text.
func secretReferenceNames(value []byte) []string {
	var out []string
	rest := value
	for {
		idx := bytes.Index(rest, []byte(secretReferenceStart))
		if idx < 0 {
			return out
		}
		body := rest[idx+len(secretReferenceStart):]
		end := bytes.IndexByte(body, secretReferenceEnd)
		if end < 0 {
			return out
		}
		out = append(out, string(body[:end]))
		rest = body[end+1:]
	}
}

// validSecretReferenceName keeps anything that is not a plausible secret name
// out of plans and reasons, so a value that happens to contain the reference
// syntax is never echoed.
func validSecretReferenceName(name string) bool {
	if name == "" || len(name) > 512 {
		return false
	}
	for _, r := range name {
		if unicode.IsControl(r) || unicode.IsSpace(r) {
			return false
		}
	}
	return true
}

// rewriteSecretReferences points every reference into the source environment
// at the same key in the target; other references are kept as written.
func rewriteSecretReferences(value []byte, from, to string) ([]byte, int) {
	out := make([]byte, 0, len(value))
	rewritten := 0
	rest := value
	for {
		idx := bytes.Index(rest, []byte(secretReferenceStart))
		if idx < 0 {
			return append(out, rest...), rewritten
		}
		body := rest[idx+len(secretReferenceStart):]
		end := bytes.IndexByte(body, secretReferenceEnd)
		if end < 0 {
			return append(out, rest...), rewritten
		}
		out = append(out, rest[:idx+len(secretReferenceStart)]...)
		if name := body[:end]; bytes.HasPrefix(name, []byte(from)) {
			out = append(append(out, to...), name[len(from):]...)
			rewritten++
		} else {
			out = append(out, name...)
		}
		out = append(out, secretReferenceEnd)
		rest = body[end+1:]
	}
}

func secretCredentialStateReason(state store.SecretCredentialState) string {
	switch state.State {
	case store.SecretCredentialRetired:
		return "this version's credential was retired at its provider by rotation " + state.CommandID
	case store.SecretCredentialRetiring:
		return "this version's credential is being retired at its provider by rotation " + state.CommandID
	case store.SecretCredentialRevoked:
		return "this version's credential was revoked when rotation " + state.CommandID + " rolled back"
	case store.SecretCredentialExpired:
		return "this version's lease expired at " + state.At.UTC().Format(time.RFC3339)
	}
	return ""
}

// sealSecretPromotion recomputes the plan and seals its changed values under
// their target names. A different digest is a stale plan; a blocked item
// blocks the whole promotion.
func (a *API) sealSecretPromotion(
	ctx context.Context, tenantID, project string, req secretPromotionRequest,
) ([]projections.ApplicationSecretBatchVersionItem, int, error) {
	planned, err := a.planSecretPromotion(ctx, tenantID, project, req)
	if err != nil {
		return nil, 0, err
	}
	defer planned.wipe()
	if planned.plan.PlanDigest != req.PlanDigest {
		return nil, 0, &apiError{status: http.StatusConflict,
			detail: "the plan changed since the preview: review the new plan and apply its digest",
			ext:    map[string]any{"code": "plan_stale", "plan": planned.plan}}
	}
	if planned.plan.Blocked > 0 {
		return nil, 0, &apiError{status: http.StatusConflict,
			detail: "the plan has blocked items; nothing was promoted",
			ext:    map[string]any{"code": "plan_blocked", "plan": planned.plan}}
	}
	var items []projections.ApplicationSecretBatchVersionItem
	creates := 0
	for _, item := range planned.plan.Items {
		if item.Action != secretPromotionCreate && item.Action != secretPromotionUpdate {
			continue
		}
		sealed, err := a.secrets.seal(ctx, tenantID, planned.values[item.TargetName], sealAAD(tenantID, item.TargetName))
		if err != nil {
			return nil, 0, err
		}
		items = append(items, projections.ApplicationSecretBatchVersionItem{
			Name: item.TargetName, ExpectedVersion: item.TargetVersion, ResultVersion: item.TargetVersion + 1,
			Sealed: sealed, SourceName: item.SourceName, SourceVersion: item.SourceVersion, OwnerID: item.OwnerID,
		})
		if item.TargetVersion == 0 {
			creates++
		}
	}
	slices.SortFunc(items, func(x, y projections.ApplicationSecretBatchVersionItem) int { return strings.Compare(x.Name, y.Name) })
	return items, creates, nil
}

// executeSecretVersionBatch runs one promotion or restore: an exact retry
// answers from its receipt or completes its reserved batch; a first request
// calls prepare for the sealed items, reserves every name at its expected
// version, appends the one event and projects it.
func (a *API) executeSecretVersionBatch(
	ctx context.Context, tenantID, operation, idempotencyKey, keyDigest, binding, planDigest string,
	prepare func(context.Context) ([]projections.ApplicationSecretBatchVersionItem, int, error),
) (secretVersionBatchReceipt, error) {
	return a.executeApprovedSecretVersionBatch(ctx, tenantID, operation, idempotencyKey, keyDigest, binding, planDigest, nil, prepare)
}

// executeApprovedSecretVersionBatch is executeSecretVersionBatch for a batch
// that may need an exact approval (A236-L1). authorize runs only for a new
// batch with something to write — after prepare, before anything is recorded —
// and the approval it returns rides in the event for the projection to consume
// with the versions. A retry of a recorded batch replays its receipt without
// asking again.
func (a *API) executeApprovedSecretVersionBatch(
	ctx context.Context, tenantID, operation, idempotencyKey, keyDigest, binding, planDigest string,
	authorize func(context.Context) (*store.OperationApprovalUse, error),
	prepare func(context.Context) ([]projections.ApplicationSecretBatchVersionItem, int, error),
) (secretVersionBatchReceipt, error) {
	out := secretVersionBatchReceipt{Operation: operation, PlanDigest: planDigest, Items: []secretVersionBatchItemResponse{}}
	if a.secrets.be.Store == nil || a.secrets.be.EventLog == nil || a.secrets.be.CommandMAC == nil {
		return out, errors.New("api: event-sourced secret batches are unavailable")
	}
	epoch, err := a.applicationSecretTenantEpoch(ctx, tenantID)
	if err != nil {
		return out, err
	}
	eventID := googleuuid.NewSHA1(applicationSecretVersionBatchNamespace,
		[]byte(tenantID+"\x00"+epoch+"\x00"+operation+"\x00"+keyDigest)).String()
	if receipt, err := a.secrets.be.Store.GetApplicationSecretImportReceipt(ctx, tenantID, eventID); err == nil {
		if !crypto.ConstantTimeEqual([]byte(receipt.RequestBinding), []byte(binding)) {
			return out, applicationSecretMutationError(store.ErrIdempotencyConflict)
		}
		return secretVersionBatchResult(out, eventID, receipt.Items), nil
	} else if !store.IsNotFound(err) {
		return out, err
	}
	var payload projections.ApplicationSecretBatchVersion
	batch, err := a.secrets.be.Store.GetApplicationSecretImportBatch(ctx, tenantID, eventID)
	switch {
	case err == nil:
		if batch.Operation != operation || !crypto.ConstantTimeEqual([]byte(batch.RequestBinding), []byte(binding)) {
			return out, applicationSecretMutationError(store.ErrIdempotencyConflict)
		}
		if err := json.Unmarshal(batch.Payload, &payload); err != nil {
			return out, err
		}
	case store.IsNotFound(err):
		items, creates, err := prepare(ctx)
		if err != nil {
			return out, err
		}
		if len(items) == 0 {
			return out, nil
		}
		if operation != store.ApplicationSecretBatchMigration {
			// A243: a promotion or restore does not write a secret that a
			// migration's export system still writes.
			for _, item := range items {
				if err := a.requireSecretWriterIsStore(ctx, tenantID, item.Name); err != nil {
					return out, err
				}
			}
		}
		if creates > 0 {
			if err := usage.AllowCreateCount(ctx, tenantID, usage.MeterSecretsStored, creates); err != nil {
				return out, err
			}
		}
		var approval *store.OperationApprovalUse
		if authorize != nil {
			if approval, err = authorize(ctx); err != nil {
				return out, err
			}
		}
		evidence, err := a.secretVersionBatchEvidence(tenantID, epoch, idempotencyKey, operation, planDigest, items)
		if err != nil {
			return out, err
		}
		payload = projections.ApplicationSecretBatchVersion{
			TenantEpoch: epoch, IdempotencyKeyDigest: keyDigest, RequestBinding: binding,
			CommandEvidence: evidence, Surface: "native", Operation: operation, PlanDigest: planDigest, Items: items,
			Approval: approval,
		}
		raw, err := json.Marshal(payload)
		if err != nil {
			return out, err
		}
		actor := applicationSecretActorFromContext(ctx)
		if actor == nil {
			secret.Wipe(raw)
			return out, errStatus(http.StatusUnauthorized, "an authenticated actor is required")
		}
		names := make([]string, 0, len(items))
		for _, item := range items {
			names = append(names, item.Name)
		}
		batch = store.ApplicationSecretImportBatch{
			TenantID: tenantID, EventID: eventID, TenantEpoch: epoch, RequestBinding: binding,
			Payload: raw, Actor: actor, EventTime: time.Now().UTC(), Names: names, Operation: operation,
		}
	default:
		return out, err
	}
	defer secret.Wipe(batch.Payload)
	fences := make([]store.ApplicationSecretVersionFence, 0, len(payload.Items))
	for _, item := range payload.Items {
		fences = append(fences, store.ApplicationSecretVersionFence{Name: item.Name, ExpectedVersion: item.ExpectedVersion})
	}
	err = a.secrets.be.Store.RunApplicationSecretVersionBatchCommand(ctx, batch, fences,
		func(barrierCtx context.Context, canonical store.ApplicationSecretImportBatch) error {
			event, err := a.appendApplicationSecretImportEvent(barrierCtx, events.Event{
				ID: eventID, Type: projections.EventApplicationSecretBatchVersioned, TenantID: tenantID,
				Time: canonical.EventTime, SchemaVersion: projections.ApplicationSecretBatchVersionSchemaVersion,
				Data: canonical.Payload, Actor: canonical.Actor,
			})
			if err != nil {
				return err
			}
			projector := projections.New(a.secrets.be.Store)
			return a.secrets.be.Store.WithTenant(barrierCtx, tenantID, func(tx pgx.Tx) error {
				return projector.ApplyTx(barrierCtx, tx, event)
			})
		})
	if err != nil {
		return out, secretVersionBatchError(err)
	}
	receipt, err := a.secrets.be.Store.GetApplicationSecretImportReceipt(ctx, tenantID, eventID)
	if err != nil {
		return out, err
	}
	// Each new version is audited like a single write; a restored version
	// names the version it restored.
	written := map[string]store.ApplicationSecretImportItem{}
	for _, item := range receipt.Items {
		written[item.Name] = item
	}
	for _, item := range payload.Items {
		var recovered *int
		if operation == store.ApplicationSecretBatchRestore {
			source := item.SourceVersion
			recovered = &source
		}
		a.auditSecretVersion(ctx, tenantID, store.Secret{Name: item.Name, Version: item.ResultVersion,
			Sealed: item.Sealed, UpdatedAt: written[item.Name].UpdatedAt}, recovered)
	}
	return secretVersionBatchResult(out, eventID, receipt.Items), nil
}

func secretVersionBatchResult(out secretVersionBatchReceipt, eventID string, items []store.ApplicationSecretImportItem) secretVersionBatchReceipt {
	out.BatchID = eventID
	for _, item := range items {
		out.Items = append(out.Items, secretVersionBatchItemResponse{Name: item.Name, Version: item.Version, UpdatedAt: item.UpdatedAt})
	}
	return out
}

func secretVersionBatchError(err error) error {
	switch {
	case errors.Is(err, store.ErrApplicationSecretBatchStale):
		return &apiError{status: http.StatusConflict, detail: "a secret changed after the plan was made: preview again",
			ext: map[string]any{"code": "plan_stale"}}
	case errors.Is(err, store.ErrApplicationSecretMutationInFlight):
		return &apiError{status: http.StatusConflict, detail: "a secret in the plan is being changed by another command: retry when it finishes",
			ext: map[string]any{"code": "in_flight"}}
	}
	return applicationSecretMutationError(err)
}

func (a *API) secretVersionBatchEvidence(
	tenantID, epoch, idempotencyKey, operation, planDigest string, items []projections.ApplicationSecretBatchVersionItem,
) (string, error) {
	type evidenceItem struct {
		Name            string `json:"name"`
		ExpectedVersion int    `json:"expected_version"`
		SourceName      string `json:"source_name"`
		SourceVersion   int    `json:"source_version"`
		SealedSHA256    string `json:"sealed_sha256"`
		OwnerID         string `json:"owner_id,omitempty"`
	}
	list := make([]evidenceItem, 0, len(items))
	for _, item := range items {
		list = append(list, evidenceItem{Name: item.Name, ExpectedVersion: item.ExpectedVersion,
			SourceName: item.SourceName, SourceVersion: item.SourceVersion, SealedSHA256: crypto.SHA256Hex(item.Sealed),
			OwnerID: item.OwnerID})
	}
	material, err := json.Marshal(struct {
		TenantID       string         `json:"tenant_id"`
		TenantEpoch    string         `json:"tenant_epoch"`
		IdempotencyKey string         `json:"idempotency_key_sha256"`
		Operation      string         `json:"operation"`
		PlanDigest     string         `json:"plan_digest"`
		Items          []evidenceItem `json:"items"`
	}{tenantID, epoch, crypto.SHA256Hex([]byte(idempotencyKey)), operation, planDigest, list})
	if err != nil {
		return "", err
	}
	mac, err := a.secrets.be.CommandMAC([]byte("trstctl.api.application-secret-batch-version.v1"), material)
	if err != nil {
		return "", err
	}
	defer secret.Wipe(mac)
	if len(mac) != 32 {
		return "", errors.New("api: versioned secret batch MAC has invalid length")
	}
	return hex.EncodeToString(mac), nil
}
