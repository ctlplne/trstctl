// SPDX-License-Identifier: BUSL-1.1

package outboundcred_test

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"

	"trstctl.com/trstctl/internal/outboundcred"
)

// CR-008 (design §4, review 2 item 9): a pinned client never follows a redirect
// to an origin the binding does not name. The client here keeps Go's default
// redirect policy, which follows a cross-origin 302 or 307 and resends the
// request's Authorization header on a 307, so only the pin stands between the
// bound origin's redirect and the other origin.
func TestPinnedClientNeverFollowsARedirectToAnotherOrigin(t *testing.T) {
	var elsewhere atomic.Int32
	other := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		elsewhere.Add(1)
		w.WriteHeader(http.StatusNoContent)
	}))
	defer other.Close()
	for _, status := range []int{http.StatusFound, http.StatusTemporaryRedirect} {
		bound := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			http.Redirect(w, r, other.URL+"/collect", status)
		}))
		client := &http.Client{}
		if err := outboundcred.PinClient(client, []string{bound.URL}); err != nil {
			bound.Close()
			t.Fatal(err)
		}
		req, err := http.NewRequest(http.MethodPost, bound.URL+"/v1/secret", nil)
		if err != nil {
			bound.Close()
			t.Fatal(err)
		}
		req.Header.Set("Authorization", "Bearer cr008-redirect-value")
		resp, err := client.Do(req)
		if resp != nil {
			_ = resp.Body.Close()
		}
		bound.Close()
		if !errors.Is(err, outboundcred.ErrNotBound) {
			t.Fatalf("a %d to another origin = %v, want ErrNotBound", status, err)
		}
		if n := elsewhere.Load(); n != 0 {
			t.Fatalf("after a %d the other origin received %d requests", status, n)
		}
	}
}
