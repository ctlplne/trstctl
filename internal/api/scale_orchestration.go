// SPDX-License-Identifier: MPL-2.0

package api

import (
	"net/http"
	"time"

	"trstctl.com/trstctl/internal/perfcontract"
)

func (a *API) getScaleOrchestration(w http.ResponseWriter, _ *http.Request) {
	a.writeJSON(w, http.StatusOK, perfcontract.ScaleOrchestration(time.Now().UTC().Format(time.RFC3339)))
}
