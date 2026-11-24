// SPDX-License-Identifier: BUSL-1.1

package api

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"

	"trstctl.com/trstctl/internal/crypto/secret"
)

func decodeJSON(r *http.Request, v any) error {
	return decodeJSONWithLimit(r, v, defaultRESTJSONBodyLimit)
}

func decodeJSONWithLimit(r *http.Request, v any, limit int64) error {
	return decodeJSONWithLimitOptions(r, v, limit, false)
}

func decodeJSONWithLimitOptions(r *http.Request, v any, limit int64, strict bool) error {
	return decodeJSONWithLimitOptionsEmpty(r, v, limit, strict, false)
}

// decodeOptionalJSON keeps the same size limit and malformed-body checks as
// decodeJSON, but accepts a truly empty wire body for optional request bodies.
func decodeOptionalJSON(r *http.Request, v any) error {
	return decodeJSONWithLimitOptionsEmpty(r, v, defaultRESTJSONBodyLimit, false, true)
}

func decodeJSONWithLimitOptionsEmpty(r *http.Request, v any, limit int64, strict, allowEmpty bool) error {
	if r.Body == nil {
		if allowEmpty {
			return nil
		}
		return errStatus(http.StatusBadRequest, "request body is required")
	}
	if limit <= 0 {
		limit = defaultRESTJSONBodyLimit
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, limit+1))
	if err != nil {
		return errStatus(http.StatusBadRequest, "invalid JSON body: "+err.Error())
	}
	defer secret.Wipe(body)
	if int64(len(body)) > limit {
		return errStatus(http.StatusRequestEntityTooLarge, fmt.Sprintf("JSON request body too large; maximum is %d bytes", limit))
	}
	if allowEmpty && len(body) == 0 {
		return nil
	}
	dec := json.NewDecoder(bytes.NewReader(body))
	if strict {
		dec.DisallowUnknownFields()
	}
	if err := dec.Decode(v); err != nil {
		return errStatus(http.StatusBadRequest, fmt.Sprintf("invalid JSON body: %v", err))
	}
	var extra json.RawMessage
	err = dec.Decode(&extra)
	if err == nil {
		return errStatus(http.StatusBadRequest, "invalid JSON body: multiple JSON values are not allowed")
	}
	if !errors.Is(err, io.EOF) {
		return errStatus(http.StatusBadRequest, fmt.Sprintf("invalid JSON body: %v", err))
	}
	return nil
}

func jsonBodyStringField(r *http.Request, field string) (string, error) {
	if r.Body == nil {
		return "", nil
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, defaultRESTJSONBodyLimit+1))
	_ = r.Body.Close()
	r.Body = io.NopCloser(bytes.NewReader(body))
	if err != nil {
		return "", errStatus(http.StatusBadRequest, "invalid JSON body")
	}
	if len(body) == 0 {
		return "", nil
	}
	if len(body) > defaultRESTJSONBodyLimit {
		return "", errStatus(http.StatusRequestEntityTooLarge, "request body too large")
	}
	// Decode the top-level keys in wire order. A map silently loses repeated
	// keys, while a struct accepts case variants and lets the last one win.
	// Refuse both so the profile used for admission is exactly the value the
	// handler's ordinary struct decode will act on.
	dec := json.NewDecoder(bytes.NewReader(body))
	opening, err := dec.Token()
	if err != nil || opening != json.Delim('{') {
		return "", errStatus(http.StatusBadRequest, "invalid JSON body")
	}
	var value string
	seen := false
	for dec.More() {
		keyToken, err := dec.Token()
		if err != nil {
			return "", errStatus(http.StatusBadRequest, "invalid JSON body")
		}
		key, ok := keyToken.(string)
		if !ok {
			return "", errStatus(http.StatusBadRequest, "invalid JSON body")
		}
		if strings.EqualFold(key, field) && (key != field || seen) {
			return "", errStatus(http.StatusBadRequest, field+" must appear exactly once with canonical spelling")
		}
		var raw json.RawMessage
		if err := dec.Decode(&raw); err != nil {
			return "", errStatus(http.StatusBadRequest, "invalid JSON body")
		}
		if key == field {
			seen = true
			if err := json.Unmarshal(raw, &value); err != nil {
				return "", errStatus(http.StatusBadRequest, field+" must be a string")
			}
		}
	}
	closing, err := dec.Token()
	if err != nil || closing != json.Delim('}') {
		return "", errStatus(http.StatusBadRequest, "invalid JSON body")
	}
	var extra json.RawMessage
	if err := dec.Decode(&extra); !errors.Is(err, io.EOF) {
		return "", errStatus(http.StatusBadRequest, "invalid JSON body")
	}
	return strings.TrimSpace(value), nil
}
