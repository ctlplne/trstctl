// SPDX-License-Identifier: LicenseRef-trstctl-EE

package scim

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/url"
	"strconv"
	"strings"
)

// BulkRequest is RFC 7644 §3.7.1 (A72/A89). Both planes decode it with the
// same rules; what each operation may touch is the plane's decision.
type BulkRequest struct {
	Schemas      []string        `json:"schemas"`
	FailOnErrors int             `json:"failOnErrors,omitempty"`
	Operations   []BulkOperation `json:"Operations"`
}

// BulkOperation is one operation of a Bulk request.
type BulkOperation struct {
	Method string          `json:"method"`
	Path   string          `json:"path"`
	BulkID string          `json:"bulkId,omitempty"`
	Data   json.RawMessage `json:"data,omitempty"`
}

// BulkResult is one operation's outcome (RFC 7644 §3.7.3).
type BulkResult struct {
	Method   string `json:"method"`
	BulkID   string `json:"bulkId,omitempty"`
	Location string `json:"location,omitempty"`
	Status   string `json:"status"`
	Response any    `json:"response,omitempty"`
}

// BulkResponse is RFC 7644 §3.7.3.
type BulkResponse struct {
	Schemas    []string     `json:"schemas"`
	Operations []BulkResult `json:"Operations"`
}

// NewBulkResponse starts an empty response.
func NewBulkResponse() BulkResponse {
	return BulkResponse{Schemas: []string{SchemaBulkResponse}, Operations: []BulkResult{}}
}

// Failed reports whether a result carries an error status.
func (r BulkResult) Failed() bool {
	status, err := strconv.Atoi(r.Status)
	return err != nil || status >= http.StatusBadRequest
}

// BulkRefusal is why a Bulk request, or one operation of it, was refused
// before anything ran. It carries the SCIM status, type and detail.
type BulkRefusal struct {
	Status   int
	ScimType string
	Detail   string
}

func (e BulkRefusal) Error() string { return e.Detail }

// FailedResult builds the result of an operation that was refused.
func FailedResult(op BulkOperation, status int, scimType, detail string) BulkResult {
	return BulkResult{Method: strings.ToUpper(strings.TrimSpace(op.Method)), BulkID: strings.TrimSpace(op.BulkID),
		Status: strconv.Itoa(status), Response: NewError(status, scimType, detail)}
}

// HasSchema reports whether the schemas list names want.
func HasSchema(schemas []string, want string) bool {
	for _, s := range schemas {
		if s == want {
			return true
		}
	}
	return false
}

// ValidateBulkRequest checks the request's shape before any operation runs:
// the schema, the operation count against the advertised maximum, a
// non-negative failOnErrors, supported methods, a bulkId on every POST, and
// unique bulkIds.
func ValidateBulkRequest(req BulkRequest, maxOperations int) error {
	if !HasSchema(req.Schemas, SchemaBulkRequest) {
		return BulkRefusal{Status: http.StatusBadRequest, ScimType: "invalidSyntax", Detail: "schemas must name the SCIM BulkRequest"}
	}
	if len(req.Operations) == 0 {
		return BulkRefusal{Status: http.StatusBadRequest, ScimType: "invalidValue", Detail: "Operations is required"}
	}
	if len(req.Operations) > maxOperations {
		return BulkRefusal{Status: http.StatusRequestEntityTooLarge, ScimType: "tooMany", Detail: "Bulk request exceeds maxOperations"}
	}
	if req.FailOnErrors < 0 {
		return BulkRefusal{Status: http.StatusBadRequest, ScimType: "invalidValue", Detail: "failOnErrors must not be negative"}
	}
	seen := map[string]bool{}
	for i, op := range req.Operations {
		method := strings.ToUpper(strings.TrimSpace(op.Method))
		switch method {
		case http.MethodPost, http.MethodPut, http.MethodPatch, http.MethodDelete:
		default:
			return BulkRefusal{Status: http.StatusBadRequest, ScimType: "invalidValue", Detail: "operation " + strconv.Itoa(i) + " has an unsupported method"}
		}
		if method == http.MethodPost && strings.TrimSpace(op.BulkID) == "" {
			return BulkRefusal{Status: http.StatusBadRequest, ScimType: "invalidValue", Detail: "operation " + strconv.Itoa(i) + " is a POST without a bulkId"}
		}
		if id := strings.TrimSpace(op.BulkID); id != "" {
			if seen[id] {
				return BulkRefusal{Status: http.StatusBadRequest, ScimType: "invalidValue", Detail: "bulkId " + id + " is used more than once"}
			}
			seen[id] = true
		}
	}
	return nil
}

// BulkTarget reads "/Users", "/Users/{id}", "/Groups" or "/Groups/{id}" from
// an operation path, with or without the plane's /scim/v2 prefix, resolving a
// "bulkId:<id>" path reference to the id an earlier POST created.
func BulkTarget(path string, resolved map[string]string) (resource, id string, err error) {
	trimmed := strings.TrimSpace(path)
	if i := strings.Index(trimmed, "/scim/v2/"); i >= 0 {
		trimmed = trimmed[i+len("/scim/v2"):]
	}
	parts := strings.Split(strings.Trim(trimmed, "/"), "/")
	if len(parts) == 0 || len(parts) > 2 || (parts[0] != "Users" && parts[0] != "Groups") {
		return "", "", BulkRefusal{Status: http.StatusBadRequest, ScimType: "invalidPath", Detail: "operation path must be /Users[/{id}] or /Groups[/{id}]"}
	}
	resource = parts[0]
	if len(parts) == 2 {
		unescaped, uerr := url.PathUnescape(parts[1])
		if uerr != nil || strings.TrimSpace(unescaped) == "" {
			return "", "", BulkRefusal{Status: http.StatusBadRequest, ScimType: "invalidPath", Detail: "operation path names an invalid resource id"}
		}
		id = strings.TrimSpace(unescaped)
		if strings.HasPrefix(id, "bulkId:") {
			target, ok := resolved[strings.TrimPrefix(id, "bulkId:")]
			if !ok {
				return "", "", BulkRefusal{Status: http.StatusBadRequest, ScimType: "invalidValue", Detail: "operation path references a bulkId no earlier POST created"}
			}
			id = target
		}
	}
	return resource, id, nil
}

// ResolveBulkIDs replaces every whole string value of the form "bulkId:<id>"
// in the operation data with the id that bulkId created; a userName that
// merely contains the text is left alone, and an unknown reference fails the
// operation.
func ResolveBulkIDs(data json.RawMessage, resolved map[string]string) (json.RawMessage, error) {
	if !bytes.Contains(data, []byte(`"bulkId:`)) {
		return data, nil
	}
	var value any
	if err := json.Unmarshal(data, &value); err != nil {
		return nil, BulkRefusal{Status: http.StatusBadRequest, ScimType: "invalidSyntax", Detail: "malformed operation data"}
	}
	rewritten, err := resolveBulkValue(value, resolved)
	if err != nil {
		return nil, err
	}
	return json.Marshal(rewritten)
}

func resolveBulkValue(v any, resolved map[string]string) (any, error) {
	switch t := v.(type) {
	case string:
		if strings.HasPrefix(t, "bulkId:") {
			target, ok := resolved[strings.TrimPrefix(t, "bulkId:")]
			if !ok {
				return nil, BulkRefusal{Status: http.StatusBadRequest, ScimType: "invalidValue", Detail: "operation data references a bulkId no earlier POST created"}
			}
			return target, nil
		}
		return t, nil
	case []any:
		for i := range t {
			next, err := resolveBulkValue(t[i], resolved)
			if err != nil {
				return nil, err
			}
			t[i] = next
		}
		return t, nil
	case map[string]any:
		for k := range t {
			next, err := resolveBulkValue(t[k], resolved)
			if err != nil {
				return nil, err
			}
			t[k] = next
		}
		return t, nil
	default:
		return v, nil
	}
}

// DecodeBulkData decodes one operation's data, refusing an absent or
// malformed body by name.
func DecodeBulkData(data json.RawMessage, dst any) error {
	if len(bytes.TrimSpace(data)) == 0 {
		return BulkRefusal{Status: http.StatusBadRequest, ScimType: "invalidSyntax", Detail: "operation data is required"}
	}
	if err := json.Unmarshal(data, dst); err != nil {
		return BulkRefusal{Status: http.StatusBadRequest, ScimType: "invalidSyntax", Detail: "malformed operation data"}
	}
	return nil
}
