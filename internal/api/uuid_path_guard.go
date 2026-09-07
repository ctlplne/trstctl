// SPDX-License-Identifier: MPL-2.0

package api

import (
	"net/http"

	googleuuid "github.com/google/uuid"
)

// requireUUIDPathParams rejects a malformed value for any uuid-typed path
// parameter with a 400 problem before the handler runs, so a uuid-typed store
// query never receives a non-uuid string and no route answers a bad id with an
// internal error. A well-formed but absent id still reaches the store and
// resolves to 404 (DP2-047).
func (a *API) requireUUIDPathParams(params []param, next http.HandlerFunc) http.HandlerFunc {
	var names []string
	for _, p := range params {
		if p.format == "uuid" {
			names = append(names, p.name)
		}
	}
	if len(names) == 0 {
		return next
	}
	return func(w http.ResponseWriter, r *http.Request) {
		for _, name := range names {
			if _, err := googleuuid.Parse(r.PathValue(name)); err != nil {
				a.writeError(w, errStatus(http.StatusBadRequest, name+" must be a valid UUID"))
				return
			}
		}
		next(w, r)
	}
}
