// SPDX-License-Identifier: MPL-2.0

package api

import (
	"net/http"
	"strings"

	googleuuid "github.com/google/uuid"
)

// validateOwnerID stops an API subject such as "oidc|dev-1" from reaching a
// PostgreSQL uuid cast. Authentication subjects identify callers; owner UUIDs
// identify tenant rows. Treating those two labels as interchangeable is both a
// type error and the cause of AUD-78's generic HTTP 500.
func validateOwnerID(raw string) (string, error) {
	value := strings.TrimSpace(raw)
	if value == "" {
		return "", errStatus(http.StatusBadRequest, "owner_id is required")
	}
	parsed, err := googleuuid.Parse(value)
	if err != nil || parsed == googleuuid.Nil {
		return "", errStatus(http.StatusBadRequest, "owner_id must be a valid UUID")
	}
	return parsed.String(), nil
}
