// SPDX-License-Identifier: BUSL-1.1

package server

import "context"

// RunCredentialUsageRecorder records the API-token uses this replica noted
// (M1). Every replica runs it: each one serves requests.
func (s *Server) RunCredentialUsageRecorder(ctx context.Context) {
	if s.api != nil {
		s.api.RunCredentialUsageRecorder(ctx)
	}
}

// DrainCredentialUsage records every use this replica noted, now.
func (s *Server) DrainCredentialUsage(ctx context.Context) error {
	if s.api == nil {
		return nil
	}
	return s.api.DrainCredentialUsage(ctx)
}
