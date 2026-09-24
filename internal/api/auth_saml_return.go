// SPDX-License-Identifier: BUSL-1.1

package api

import (
	"net/http"

	"trstctl.com/trstctl/internal/auth"
)

const (
	samlReturnCookie0 = "trstctl_saml_return_0"
	samlReturnCookie1 = "trstctl_saml_return_1"
	samlReturnPurpose = "tenant-saml-return"
	// Two bounded cookies retain the full 4096-byte raw destination, including
	// UTF-8, while each serialized Set-Cookie stays below browser 4096-byte limits.
	samlReturnPartLimit = 3500
)

func (a *API) setSAMLReturnCookies(w http.ResponseWriter, r *http.Request, state, requestID string) error {
	raw := r.URL.Query().Get("return_to")
	if safeLoginReturnPath(raw) == "" {
		a.clearCookie(w, samlReturnCookie0)
		a.clearCookie(w, samlReturnCookie1)
		return nil
	}
	// Retain raw input: URL normalization can expand valid UTF-8 beyond 4096
	// bytes, so applying the raw-input bound to normalized output would lose it.
	token, err := a.auth.Sessions.SealLoginReturn(samlReturnPurpose, state, requestID, raw)
	if err != nil {
		return err
	}
	mid := len(token) / 2
	if mid == 0 || len(token)-mid > samlReturnPartLimit {
		return auth.ErrLoginReturn
	}
	a.setTransientCookie(w, samlReturnCookie0, token[:mid])
	a.setTransientCookie(w, samlReturnCookie1, token[mid:])
	return nil
}

func (a *API) samlReturnPath(r *http.Request, state, requestID string) (string, error) {
	var parts [2]string
	var counts [2]int
	for _, cookie := range r.Cookies() {
		switch cookie.Name {
		case samlReturnCookie0:
			counts[0]++
			parts[0] = cookie.Value
		case samlReturnCookie1:
			counts[1]++
			parts[1] = cookie.Value
		}
	}
	// Existing in-flight SP logins and logins without an override keep the
	// configured default. A partial, duplicate or tampered override fails closed.
	if counts[0] == 0 && counts[1] == 0 {
		return "", nil
	}
	if counts[0] != 1 || counts[1] != 1 || len(parts[0]) == 0 || len(parts[1]) == 0 ||
		len(parts[0]) > samlReturnPartLimit || len(parts[1]) > samlReturnPartLimit {
		return "", auth.ErrLoginReturn
	}
	return a.auth.Sessions.OpenLoginReturn(samlReturnPurpose, state, requestID, parts[0]+parts[1])
}
