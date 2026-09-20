// SPDX-License-Identifier: BUSL-1.1

package cmp

// AllowUnauthenticatedClientsForTest opens the served CMP mount to callers
// with NO anchor-verified protection identity. It lives in an export_test
// seam — compiled only into this package's test binary — so the
// accept-everything escape hatch CANNOT be linked into a production build
// (AUD-201 follow-up H2/V18; precedent: acme's AcceptAll in dvmethod's
// internal test file). The differential harnesses (OpenSSL client, licensed
// seam) authenticate their clients at a different layer and drive the parser
// through this seam.
func (s *Server) AllowUnauthenticatedClientsForTest() {
	s.allowAnonymous = true
}
