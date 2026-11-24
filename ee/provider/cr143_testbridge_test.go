// SPDX-License-Identifier: LicenseRef-trstctl-EE

package provider

import (
	"testing"
	"time"

	corestore "trstctl.com/trstctl/internal/store"
)

// These test-only helpers let the external package import the licensed privacy
// catalog without making this package import its parent.
func CR143TestStore(t *testing.T) *corestore.Store {
	t.Helper()
	st := openProviderStore(t)
	truncateProviderAuthority(t, st)
	return st
}

func CR143TestSCIM(t *testing.T, st *corestore.Store, rt *AuthorityRuntime) func(string, string, string) (int, string) {
	t.Helper()
	s := newA221SCIM(t, NewPGAccessStore(st), rt.Mutations, func() time.Time { return time.Now().UTC() })
	return func(method, path, body string) (int, string) {
		rec := s.call(method, path, body)
		return rec.Code, rec.Body.String()
	}
}
