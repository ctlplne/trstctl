package api

import (
	"net/http"

	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/license"
)

type editionsResponse struct {
	license.Info
	FIPS crypto.FIPSStatus `json:"fips"`
}

func (a *API) licenseManager() *license.Manager {
	if a != nil && a.license != nil {
		return a.license
	}
	return license.Community()
}

func (a *API) getEditions(w http.ResponseWriter, _ *http.Request) {
	fips, err := crypto.PowerOnSelfTest(false)
	if err != nil {
		a.writeError(w, errStatus(http.StatusServiceUnavailable, "crypto power-on self-test failed"))
		return
	}
	a.writeJSON(w, http.StatusOK, editionsResponse{
		Info: a.licenseManager().Info(),
		FIPS: fips,
	})
}
