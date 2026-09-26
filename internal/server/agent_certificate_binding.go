// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"context"
	"fmt"
	"strings"

	"github.com/google/uuid"
	"trstctl.com/trstctl/internal/agent/enroll"
	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/crypto/certinfo"
	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/orchestrator"
	"trstctl.com/trstctl/internal/store"
)

// This URI is a signed identifier, never a network destination. The event ID
// identifies one registration even when a UUID is reused or history is rebuilt.
const agentRegistrationURIPrefix = "https://trstctl.com/agent/tenant-registration/v1/"

func agentCertificateBinding(st *store.Store, log *events.Log) enroll.ClientCertificateBinding {
	return func(ctx context.Context, tenantID string, previous []byte) ([]string, error) {
		return agentCertificateAuthorityURIs(ctx, st, log, tenantID, previous)
	}
}

func agentCertificateAuthorityURIs(ctx context.Context, st *store.Store, log *events.Log, tenantID string, previous []byte) ([]string, error) {
	parsed, err := uuid.Parse(tenantID)
	if err != nil {
		return nil, fmt.Errorf("agent tenant registration requires a tenant UUID: %w", err)
	}
	tenantID = parsed.String()
	authority, err := orchestrator.ResolveLiveTenantRegistrationAuthority(ctx, log, st, tenantID)
	if err != nil {
		return nil, err
	}
	expected := agentRegistrationURIPrefix + tenantID + "/" + crypto.SHA256Hex([]byte(authority.EventID))
	if len(previous) > 0 {
		info, err := certinfo.Inspect(previous)
		if err != nil {
			return nil, fmt.Errorf("%w: invalid prior agent certificate", enroll.ErrUnauthenticatedRenewal)
		}
		found := 0
		for _, uri := range info.URIs {
			if !strings.HasPrefix(uri, agentRegistrationURIPrefix) {
				continue
			}
			if uri != expected {
				return nil, fmt.Errorf("%w: agent certificate belongs to another tenant registration; enroll again", enroll.ErrUnauthenticatedRenewal)
			}
			found++
		}
		if found != 1 {
			return nil, fmt.Errorf("%w: agent certificate lacks one current tenant registration binding; enroll again", enroll.ErrUnauthenticatedRenewal)
		}
	}
	return []string{expected}, nil
}
