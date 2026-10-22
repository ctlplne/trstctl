// SPDX-License-Identifier: LicenseRef-trstctl-EE

package enterpriseauth

import (
	"bytes"
	"context"
	"net/http"
	"net/url"
	"strconv"
	"strings"

	"trstctl.com/trstctl/ee/enterpriseauth/scim"
	"trstctl.com/trstctl/internal/crypto/secret"
)

// scimBulkMaxOperations bounds one Bulk request (RFC 7644 §3.7, A72). It is
// advertised in ServiceProviderConfig; a larger request is refused whole.
const scimBulkMaxOperations = 100

// scimBulk serves POST /scim/v2/Bulk: every operation runs in order through
// the same per-operation logic the single routes use, a POST's bulkId names
// its created resource for the operations after it, and failOnErrors stops
// the request after that many failures. The whole request is one idempotent
// mutation: a replay under the same key returns the recorded response rather
// than running the operations again.
func (a *scimHandler) scimBulk(w http.ResponseWriter, r *http.Request) {
	tok, raw, ok := a.prepareSCIMMutation(w, r)
	if !ok {
		return
	}
	defer secret.Wipe(raw)
	var req scim.BulkRequest
	if !decodeSCIMRaw(w, raw, &req) {
		return
	}
	if err := scim.ValidateBulkRequest(req, scimBulkMaxOperations); err != nil {
		writeSCIMMappedError(w, err)
		return
	}
	key, prevKey := scimIdempotencyKey(r, raw)
	a.scimMutate(w, r, tok, key, prevKey, raw, func(ctx context.Context, _ string) (int, any, error) {
		return http.StatusOK, a.runSCIMBulk(ctx, tok, scimBase(r), req), nil
	})
}

func (a *scimHandler) runSCIMBulk(ctx context.Context, tok scimToken, base string, req scim.BulkRequest) scim.BulkResponse {
	out := scim.NewBulkResponse()
	resolved := map[string]string{}
	failures := 0
	for _, op := range req.Operations {
		result := a.scimBulkOperation(ctx, tok, base, op, resolved)
		out.Operations = append(out.Operations, result)
		if result.Failed() {
			failures++
			if req.FailOnErrors > 0 && failures >= req.FailOnErrors {
				break
			}
		}
	}
	return out
}

// scimBulkOperation runs one operation against the resource its path names.
// A bulkId reference ("bulkId:<id>") in the path or in any string value of
// the data resolves to the id a POST earlier in the same request created; an
// unresolved reference fails that operation alone.
func (a *scimHandler) scimBulkOperation(ctx context.Context, tok scimToken, base string, op scim.BulkOperation, resolved map[string]string) scim.BulkResult {
	method := strings.ToUpper(strings.TrimSpace(op.Method))
	result := scim.BulkResult{Method: method, BulkID: strings.TrimSpace(op.BulkID)}
	fail := func(err error) scim.BulkResult {
		status, scimType, detail := scimMappedError(err)
		return scim.FailedResult(op, status, scimType, detail)
	}
	resource, id, err := scim.BulkTarget(op.Path, resolved)
	if err != nil {
		return fail(err)
	}
	data, err := scim.ResolveBulkIDs(op.Data, resolved)
	if err != nil {
		return fail(err)
	}
	var (
		status    int
		body      any
		createdID string
	)
	switch resource + " " + method {
	case "Users POST":
		var in scim.User
		if err := scim.DecodeBulkData(data, &in); err != nil {
			return fail(err)
		}
		if !bytes.Contains(data, []byte(`"active"`)) {
			in.Active = true
		}
		subject, subjectErr := scimLoginSubject(tok, in)
		if subjectErr != nil {
			return fail(subjectErr)
		}
		status, body, createdID, err = a.opCreateUser(ctx, tok, base, subject, in)
	case "Users PUT":
		var in scim.User
		if err := scim.DecodeBulkData(data, &in); err != nil {
			return fail(err)
		}
		if in.UserName == "" && tok.SubjectAttribute == "userName" {
			in.UserName = id
		}
		status, body, err = a.opPutUser(ctx, tok, base, id, in)
	case "Users PATCH":
		var patch scim.PatchOp
		if err := scim.DecodeBulkData(data, &patch); err != nil {
			return fail(err)
		}
		status, body, err = a.opPatchUser(ctx, tok, base, id, patch)
	case "Users DELETE":
		status, body, err = a.opDeleteUser(ctx, tok, id)
	case "Groups POST":
		var in scim.Group
		if err := scim.DecodeBulkData(data, &in); err != nil {
			return fail(err)
		}
		status, body, createdID, err = a.opCreateGroup(ctx, tok, base, in)
	case "Groups PATCH":
		var patch scim.PatchOp
		if err := scim.DecodeBulkData(data, &patch); err != nil {
			return fail(err)
		}
		if err := scimGroupPatchRename(id, patch); err != nil {
			return fail(err)
		}
		status, body, err = a.opPatchGroup(ctx, tok, base, id, patch)
	case "Groups DELETE":
		status, body, err = a.opDeleteGroup(ctx, tok, id)
	default:
		return fail(scimHTTPError{status: http.StatusBadRequest, scimType: "invalidPath", detail: method + " is not supported on " + op.Path})
	}
	if err != nil {
		return fail(err)
	}
	if createdID != "" && result.BulkID != "" {
		resolved[result.BulkID] = createdID
	}
	if id == "" {
		id = createdID
	}
	if id != "" {
		result.Location = base + "/" + resource + "/" + url.PathEscape(id)
	}
	result.Status = strconv.Itoa(status)
	result.Response = body
	return result
}
