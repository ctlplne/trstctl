// SPDX-License-Identifier: MPL-2.0

package api

import (
	"encoding/base64"
	"errors"
	"net/http"
	"strings"
	"time"

	googleuuid "github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"trstctl.com/trstctl/internal/store"
)

// Keep the timestamp in the cursor: an older page must still be readable after
// a receipt is updated or removed. Refreshing page one discovers newer activity.
func encodeConnectorReceiptCursor(r store.ConnectorDeliveryReceipt) string {
	return base64.RawURLEncoding.EncodeToString([]byte(r.UpdatedAt.UTC().Format(time.RFC3339Nano) + "|" + r.ID))
}

func (a *API) connectorReceiptPageParams(r *http.Request, tenantID string) (int, *time.Time, string, error) {
	limit, err := pageLimit(r)
	if err != nil {
		return 0, nil, "", errStatus(http.StatusBadRequest, err.Error())
	}
	cursor := r.URL.Query().Get("cursor")
	if cursor == "" {
		return limit, nil, store.ZeroUUID, nil
	}
	invalid := func() (int, *time.Time, string, error) {
		return 0, nil, "", errStatus(http.StatusBadRequest, "invalid or expired delivery cursor")
	}
	if len(cursor) > 256 {
		return invalid()
	}
	decoded, err := base64.RawURLEncoding.DecodeString(cursor)
	if err != nil {
		return invalid()
	}
	timestamp, id, composite := strings.Cut(string(decoded), "|")
	if !composite {
		id = string(decoded)
	}
	if len(id) != 36 || googleuuid.Validate(id) != nil {
		return invalid()
	}
	if composite {
		at, err := time.Parse(time.RFC3339Nano, timestamp)
		if err != nil {
			return invalid()
		}
		return limit, &at, id, nil
	}
	// Preserve UUID-only cursors already issued by older installations. The
	// lookup is tenant-bound; a foreign or deleted anchor reveals no receipt.
	if id == store.ZeroUUID {
		return limit, nil, id, nil
	}
	row, err := a.store.GetConnectorDeliveryReceipt(r.Context(), tenantID, id)
	if errors.Is(err, pgx.ErrNoRows) {
		return invalid()
	}
	if err != nil {
		return 0, nil, "", err
	}
	return limit, &row.UpdatedAt, id, nil
}
