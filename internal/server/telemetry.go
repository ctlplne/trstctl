// SPDX-License-Identifier: MPL-2.0

package server

import (
	"context"

	"trstctl.com/trstctl/internal/store"
)

type storeTelemetryCounter struct {
	store *store.Store
}

func (c storeTelemetryCounter) CredentialCounts(ctx context.Context) (map[string]int, error) {
	counts := map[string]int{}
	if c.store == nil {
		return counts, nil
	}
	return c.store.TelemetryCredentialCounts(ctx)
}

func (s *Server) RunTelemetry(ctx context.Context) {
	if s == nil || s.telemetry == nil {
		return
	}
	s.telemetry.Run(ctx)
}
