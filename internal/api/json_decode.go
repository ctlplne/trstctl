// SPDX-License-Identifier: MPL-2.0

package api

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"

	"trstctl.com/trstctl/internal/crypto/secret"
)

func decodeJSON(r *http.Request, v any) error {
	return decodeJSONWithLimit(r, v, defaultRESTJSONBodyLimit)
}

func decodeJSONWithLimit(r *http.Request, v any, limit int64) error {
	return decodeJSONWithLimitOptions(r, v, limit, false)
}

func decodeJSONWithLimitOptions(r *http.Request, v any, limit int64, strict bool) error {
	if r.Body == nil {
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
