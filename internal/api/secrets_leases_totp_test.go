// SPDX-License-Identifier: BUSL-1.1

package api

import (
	"errors"
	"fmt"
	"net/http"
	"testing"

	"trstctl.com/trstctl/internal/dynsecret"
)

// A239: renewing a one-time code's lease is a client error that says what to
// do instead, never an internal error.
func TestRenewingAOneTimeCodeLeaseIsUnprocessableA239(t *testing.T) {
	err := dynamicLeaseError(fmt.Errorf("renew lease-1: %w", dynsecret.ErrLeaseNotRenewable))
	var apiErr *apiError
	if !errors.As(err, &apiErr) || apiErr.status != http.StatusUnprocessableEntity || apiErr.detail != "a one-time code can't be renewed; issue a new lease for the next code" {
		t.Fatalf("mapped to %#v", err)
	}
}
