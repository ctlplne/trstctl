// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/google/uuid"
	"trstctl.com/trstctl/internal/agent/enroll"
	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/crypto/certinfo"
	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/orchestrator"
	"trstctl.com/trstctl/internal/projections"
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

// agentCertificateRecorded keeps the original enrollment and its public leaf
// together in the source event. The session lock covers the empty-name race
// across replicas while the append and projection run in their own transactions.
func agentCertificateRecorded(st *store.Store, log *events.Log) enroll.CertificateRecorded {
	return func(ctx context.Context, tenantID, name string, previous, leafDER []byte) error {
		issued, err := certinfo.Inspect(leafDER)
		if err != nil {
			return err
		}
		if issued.CommonName != name {
			return errors.New("agent certificate does not match its enrollment name")
		}
		agentID := agentRowID(tenantID, name)
		return st.WithIdentityIssuanceFence(ctx, tenantID, "agent-enrollment:"+agentID, func(locked context.Context) error {
			var eventType string
			var schema int
			var payload any
			var eventID string
			if len(previous) == 0 {
				registration, err := agentCertificateAuthorityURIs(locked, st, log, tenantID, nil)
				if err != nil {
					return fmt.Errorf("agent enrollment registration binding is unavailable: %w", err)
				}
				if len(registration) != 1 {
					return errors.New("agent enrollment requires exactly one registration binding")
				}
				eventID = uuid.NewSHA1(uuid.NameSpaceURL, []byte("trstctl.agent.cert.enrolled/v1\x00"+tenantID+"\x00"+agentID+"\x00"+registration[0])).String()
				if prior, found, err := log.EventByID(locked, eventID); err != nil {
					return err
				} else if found {
					if prior.Type != projections.EventAgentCertEnrolled || prior.TenantID != tenantID {
						return events.ErrConflictingEventIdentity
					}
					if err := projections.New(st).Apply(locked, prior); err != nil {
						return err
					}
					return store.ErrAgentNameAlreadyEnrolled
				}
				available, err := st.AgentNameAvailableForEnrollment(locked, tenantID, agentID)
				if err != nil {
					return err
				}
				if !available {
					return store.ErrAgentNameAlreadyEnrolled
				}
				eventType, schema = projections.EventAgentCertEnrolled, projections.AgentCertEnrolledPublicIDsSchemaVersion
				payload = projections.AgentCertEnrolledPublicWire(projections.AgentCertEnrolled{ID: agentID, Agent: name,
					Serial: issued.SerialNumber, Fingerprint: issued.SHA256Fingerprint, NotAfter: issued.NotAfter})
			} else {
				old, err := certinfo.Inspect(previous)
				if err != nil || old.CommonName != name {
					return enroll.ErrUnauthenticatedRenewal
				}
				bound, matches, err := st.AgentCertificateMatches(locked, tenantID, agentID, old.SerialNumber, old.SHA256Fingerprint)
				if err != nil {
					return err
				}
				if bound && !matches {
					return enroll.ErrUnauthenticatedRenewal
				}
				eventType, schema = projections.EventAgentCertRenewed, projections.AgentCertRenewedBindingSchemaVersion
				payload = projections.AgentCertRenewed{ID: agentID, Agent: name,
					OldSerial: old.SerialNumber, OldFingerprint: old.SHA256Fingerprint, OldNotAfter: &old.NotAfter,
					NewSerial:      issued.SerialNumber,
					NewFingerprint: issued.SHA256Fingerprint, NotAfter: &issued.NotAfter}
			}
			wire, err := json.Marshal(payload)
			if err != nil {
				return err
			}
			ev, err := log.Append(locked, events.Event{ID: eventID, Type: eventType, TenantID: tenantID, SchemaVersion: schema, Data: wire})
			if err != nil {
				return err
			}
			if eventID != "" && !bytes.Equal(ev.Data, wire) {
				return events.ErrConflictingEventIdentity
			}
			return projections.New(st).Apply(locked, ev)
		})
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
