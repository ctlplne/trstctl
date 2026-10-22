// SPDX-License-Identifier: LicenseRef-trstctl-EE

package provider

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"strconv"
	"strings"

	"trstctl.com/trstctl/ee/enterpriseauth/scim"
	"trstctl.com/trstctl/internal/crypto/secret"
)

// providerSCIMBulkMaxOperations bounds one Provider-plane Bulk request (A89).
const providerSCIMBulkMaxOperations = 100

// bulk serves POST /provider/scim/v2/Bulk (RFC 7644 §3.7). Each operation
// runs in order through the same identity logic the single User routes use,
// under its own idempotency key derived from the request's key and position,
// so a replayed Bulk request re-reads every recorded event instead of
// appending twice. A POST's bulkId names its created operator for later
// operations; failOnErrors stops the request after that many failures. Group
// operations are refused per operation: the Provider plane changes a role by
// writing the User, and a leaver is an explicit User active:false or DELETE.
func (h *providerSCIMHandler) bulk(w http.ResponseWriter, r *http.Request, token SCIMToken) {
	raw, ok := readProviderSCIMBody(w, r)
	if !ok {
		return
	}
	defer secret.Wipe(raw)
	var req scim.BulkRequest
	if len(raw) == 0 || json.Unmarshal(raw, &req) != nil {
		writeProviderSCIMError(w, http.StatusBadRequest, "invalidSyntax", "malformed SCIM Bulk request")
		return
	}
	if err := scim.ValidateBulkRequest(req, providerSCIMBulkMaxOperations); err != nil {
		var refusal scim.BulkRefusal
		if errors.As(err, &refusal) {
			writeProviderSCIMError(w, refusal.Status, refusal.ScimType, refusal.Detail)
			return
		}
		writeProviderSCIMError(w, http.StatusBadRequest, "invalidValue", err.Error())
		return
	}
	if h.access == nil || h.mutations == nil {
		writeProviderSCIMError(w, http.StatusServiceUnavailable, "", "provider SCIM mutation spine is not configured")
		return
	}
	base := providerSCIMBase(r)
	key := providerSCIMMutationKey(r, token, raw)
	binding := providerSCIMBinding(r, token, raw)
	out := scim.NewBulkResponse()
	resolved := map[string]string{}
	failures := 0
	for i, op := range req.Operations {
		result := h.bulkOperation(r.Context(), token, base, op, resolved, key+":op:"+strconv.Itoa(i), binding)
		out.Operations = append(out.Operations, result)
		if result.Failed() {
			failures++
			if req.FailOnErrors > 0 && failures >= req.FailOnErrors {
				break
			}
		}
	}
	writeProviderSCIM(w, http.StatusOK, out)
}

func (h *providerSCIMHandler) bulkOperation(ctx context.Context, token SCIMToken, base string, op scim.BulkOperation, resolved map[string]string, key, binding string) scim.BulkResult {
	method := strings.ToUpper(strings.TrimSpace(op.Method))
	fail := func(err error) scim.BulkResult {
		status, scimType, detail := providerSCIMMutationStatus(err)
		return scim.FailedResult(op, status, scimType, detail)
	}
	resource, id, err := scim.BulkTarget(op.Path, resolved)
	if err != nil {
		return fail(err)
	}
	if resource != "Users" {
		return fail(scim.BulkRefusal{Status: http.StatusBadRequest, ScimType: "invalidPath",
			Detail: "the Provider plane changes a role by writing the User; group operations are not accepted in Bulk"})
	}
	data, err := scim.ResolveBulkIDs(op.Data, resolved)
	if err != nil {
		return fail(err)
	}
	var (
		status   int
		identity OperatorIdentity
		body     any
	)
	switch method {
	case http.MethodPost:
		in, activePresent, derr := decodeProviderSCIMUser(data)
		if derr != nil {
			return fail(scim.BulkRefusal{Status: http.StatusBadRequest, ScimType: "invalidSyntax", Detail: "malformed SCIM user"})
		}
		if !activePresent {
			in.Active = true
		}
		identity, err = h.upsertUser(ctx, token, "", in, key, binding)
		status = http.StatusCreated
	case http.MethodPut, http.MethodPatch, http.MethodDelete:
		if id == "" {
			return fail(scim.BulkRefusal{Status: http.StatusBadRequest, ScimType: "invalidPath", Detail: "operation path must name a user id"})
		}
		current, rerr := h.access.ResolveOperator(ctx, id)
		if rerr != nil {
			return fail(ErrNotFound)
		}
		identity, status, err = h.bulkUserChange(ctx, token, method, current, data, key, binding)
	}
	if err != nil {
		return fail(err)
	}
	result := scim.BulkResult{Method: method, BulkID: strings.TrimSpace(op.BulkID), Status: strconv.Itoa(status)}
	if method == http.MethodPost && result.BulkID != "" {
		resolved[result.BulkID] = identity.ID
	}
	if status != http.StatusNoContent {
		body = operatorIdentityToSCIM(identity, base)
	}
	result.Location = base + "/Users/" + url.PathEscape(identity.ID)
	result.Response = body
	return result
}

// bulkUserChange applies a PUT, PATCH or DELETE to an existing operator with
// exactly the single-route semantics.
func (h *providerSCIMHandler) bulkUserChange(ctx context.Context, token SCIMToken, method string, current OperatorIdentity, data json.RawMessage, key, binding string) (OperatorIdentity, int, error) {
	switch method {
	case http.MethodPut:
		in, activePresent, err := decodeProviderSCIMUser(data)
		if err != nil {
			return OperatorIdentity{}, 0, scim.BulkRefusal{Status: http.StatusBadRequest, ScimType: "invalidSyntax", Detail: "malformed SCIM user"}
		}
		if !activePresent {
			in.Active = current.Active
		}
		identity, err := h.upsertUser(ctx, token, current.ID, in, key, binding)
		return identity, http.StatusOK, err
	case http.MethodPatch:
		var patch scim.PatchOp
		if err := scim.DecodeBulkData(data, &patch); err != nil {
			return OperatorIdentity{}, 0, err
		}
		in := operatorIdentityToSCIM(current, "")
		if err := scim.ApplyUserPatch(&in.User, patch.Operations); err != nil {
			return OperatorIdentity{}, 0, scim.BulkRefusal{Status: http.StatusBadRequest, ScimType: "invalidValue", Detail: "invalid SCIM user patch"}
		}
		identity, err := h.upsertUser(ctx, token, current.ID, in, key, binding)
		return identity, http.StatusOK, err
	default:
		identity := current
		identity.Active = false
		identity.UpdatedAt = h.clock().UTC()
		identity.DeprovisionedAt = identity.UpdatedAt
		identity.Source = "scim:" + token.Name
		recorded, err := h.emitIdentity(ctx, token, EventOperatorOffboarded, identity, key, binding)
		return recorded, http.StatusNoContent, err
	}
}

// providerSCIMMutationStatus maps a mutation error to its SCIM status; the
// single routes' writeMutationError and each Bulk operation share it.
func providerSCIMMutationStatus(err error) (int, string, string) {
	var refusal scim.BulkRefusal
	switch {
	case errors.As(err, &refusal):
		return refusal.Status, refusal.ScimType, refusal.Detail
	case errors.Is(err, ErrNotFound):
		return http.StatusNotFound, "", "user not found"
	case errors.Is(err, ErrMutationConflict):
		return http.StatusConflict, "uniqueness", "idempotency key was reused for a different SCIM command"
	case errors.Is(err, ErrMutationPersistence):
		return http.StatusInternalServerError, "", "provider workforce change could not be recorded; retry the same command"
	default:
		return http.StatusBadRequest, "invalidValue", err.Error()
	}
}
