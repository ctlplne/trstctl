// SPDX-License-Identifier: MPL-2.0

package api

import (
	"encoding/base64"
	"errors"
	"net/http"
	"strconv"

	"trstctl.com/trstctl/internal/store"
)

// pageParams parses cursor-pagination query parameters, returning the page size
// and the keyset start id.
func (a *API) pageParams(r *http.Request) (limit int, after string, err error) {
	limit, err = pageLimit(r)
	if err != nil {
		return 0, "", err
	}
	after = store.ZeroUUID
	if c := r.URL.Query().Get("cursor"); c != "" {
		id, decodeErr := decodeCursor(c)
		if decodeErr != nil {
			return 0, "", errors.New("invalid cursor")
		}
		after = id
	}
	return limit, after, nil
}

// pageLimit parses just the page-size query parameter (1-100, default 20). It is
// shared by handlers that decode their own keyset cursor, such as the certificate
// inventory's composite expiry cursor (SPINE-006).
func pageLimit(r *http.Request) (int, error) {
	limit := 20
	if s := r.URL.Query().Get("limit"); s != "" {
		n, err := strconv.Atoi(s)
		if err != nil || n < 1 || n > 100 {
			return 0, errors.New("limit must be an integer between 1 and 100")
		}
		limit = n
	}
	return limit, nil
}

func encodeCursor(id string) string {
	return base64.RawURLEncoding.EncodeToString([]byte(id))
}

func decodeCursor(cursor string) (string, error) {
	decoded, err := base64.RawURLEncoding.DecodeString(cursor)
	if err != nil {
		return "", err
	}
	if len(decoded) != 36 { // A UUID in canonical text form.
		return "", errors.New("cursor is not a valid id")
	}
	return string(decoded), nil
}
