package api

import (
	"net/http"
	"time"

	"trstctl.com/trstctl/internal/perfcontract"
)

func (a *API) getActiveActiveIssuance(w http.ResponseWriter, _ *http.Request) {
	a.writeJSON(w, http.StatusOK, perfcontract.ActiveActiveIssuance(time.Now().UTC().Format(time.RFC3339)))
}
