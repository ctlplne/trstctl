// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/google/uuid"
	"trstctl.com/trstctl/internal/crypto/certinfo"
	"trstctl.com/trstctl/internal/crypto/mtls"
	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/orchestrator"
	"trstctl.com/trstctl/internal/projections"
	"trstctl.com/trstctl/internal/store"
)

var errAgentCertificateNotEnrolled = errors.New("agent certificate is not bound to its enrolled name")

// ensureAgentCertificateBinding gives pre-upgrade agents one safe transition.
// The earliest retained heartbeat/renewal serial anchors a name; each recorded
// renewal may extend that chain. An unrecorded same-name certificate, or two
// conflicting historical chains, requires a fresh operator-authorized
// enrollment. The one-time legacy binding is itself an immutable event.
func ensureAgentCertificateBinding(ctx context.Context, st *store.Store, log *events.Log, info mtls.PeerCertInfo) error {
	if st == nil || log == nil {
		return errors.New("agent certificate binding authority is unavailable")
	}
	agentID := agentRowID(info.TenantID, info.CommonName)
	bound, matches, err := st.AgentCertificateMatches(ctx, info.TenantID, agentID, info.Serial, info.FingerprintSHA256)
	if err != nil {
		return err
	}
	if bound {
		if !matches {
			return errAgentCertificateNotEnrolled
		}
		return nil
	}
	return st.WithIdentityIssuanceFence(ctx, info.TenantID, "agent-enrollment:"+agentID, func(locked context.Context) error {
		bound, matches, err := st.AgentCertificateMatches(locked, info.TenantID, agentID, info.Serial, info.FingerprintSHA256)
		if err != nil {
			return err
		}
		if bound {
			if !matches {
				return errAgentCertificateNotEnrolled
			}
			return nil
		}
		registration, err := agentCertificateAuthorityURIs(locked, st, log, info.TenantID, info.LeafDER)
		if err != nil || len(registration) != 1 {
			return errAgentCertificateNotEnrolled
		}
		enrolledID := uuid.NewSHA1(uuid.NameSpaceURL, []byte("trstctl.agent.cert.enrolled/v1\x00"+info.TenantID+"\x00"+agentID+"\x00"+registration[0])).String()
		if prior, found, err := log.EventByID(locked, enrolledID); err != nil {
			return err
		} else if found {
			if prior.Type != projections.EventAgentCertEnrolled || prior.TenantID != info.TenantID {
				return events.ErrConflictingEventIdentity
			}
			if err := projections.New(st).Apply(locked, prior); err != nil {
				return err
			}
			_, matches, err := st.AgentCertificateMatches(locked, info.TenantID, agentID, info.Serial, info.FingerprintSHA256)
			if err != nil {
				return err
			}
			if !matches {
				return errAgentCertificateNotEnrolled
			}
			return nil
		}
		legacyID := uuid.NewSHA1(uuid.NameSpaceURL, []byte("trstctl.agent.cert.legacy_bound/v1\x00"+info.TenantID+"\x00"+agentID+"\x00"+registration[0])).String()
		if prior, found, err := log.EventByID(locked, legacyID); err != nil {
			return err
		} else if found {
			if prior.Type != projections.EventAgentCertLegacyBound || prior.TenantID != info.TenantID {
				return events.ErrConflictingEventIdentity
			}
			if err := projections.New(st).Apply(locked, prior); err != nil {
				return err
			}
			_, matches, err := st.AgentCertificateMatches(locked, info.TenantID, agentID, info.Serial, info.FingerprintSHA256)
			if err != nil {
				return err
			}
			if !matches {
				return errAgentCertificateNotEnrolled
			}
			return nil
		}
		authority, err := orchestrator.ResolveLiveTenantRegistrationAuthority(locked, log, st, info.TenantID)
		if err != nil {
			return err
		}
		allowed, ambiguous, err := legacyAgentSerials(locked, log, info.TenantID, agentID, authority.EventSequence+1)
		if err != nil {
			return err
		}
		if ambiguous || !allowed[strings.ToLower(info.Serial)] {
			return errAgentCertificateNotEnrolled
		}
		leaf, err := certinfo.Inspect(info.LeafDER)
		if err != nil || leaf.CommonName != info.CommonName {
			return errAgentCertificateNotEnrolled
		}
		wire, err := json.Marshal(projections.AgentCertEnrolled{ID: agentID, Agent: info.CommonName,
			Serial: info.Serial, Fingerprint: info.FingerprintSHA256, NotAfter: leaf.NotAfter})
		if err != nil {
			return err
		}
		ev, err := log.Append(locked, events.Event{ID: legacyID, Type: projections.EventAgentCertLegacyBound,
			TenantID: info.TenantID, SchemaVersion: 1, Data: wire})
		if err != nil {
			return err
		}
		if ev.Type != projections.EventAgentCertLegacyBound || ev.TenantID != info.TenantID || string(ev.Data) != string(wire) {
			return events.ErrConflictingEventIdentity
		}
		if err := projections.New(st).Apply(locked, ev); err != nil {
			return fmt.Errorf("project legacy agent certificate binding: %w", err)
		}
		return nil
	})
}

// legacyAgentSerials reads only two event types in the current tenant lifecycle.
// The first recorded certificate is the anchor. A later unlinked serial makes
// the history ambiguous and cannot be silently chosen by arrival order.
func legacyAgentSerials(ctx context.Context, log *events.Log, tenantID, agentID string, from uint64) (map[string]bool, bool, error) {
	head, err := log.LastSequence(ctx)
	if err != nil {
		return nil, false, err
	}
	allowed := make(map[string]bool)
	if from > head {
		return allowed, false, nil
	}
	ambiguous := false
	err = log.ReplayTenantTypesThrough(ctx, tenantID, from, head,
		[]string{projections.EventAgentHeartbeat, projections.EventAgentCertRenewed}, func(e events.Event) error {
			var fact struct {
				ID         string `json:"id"`
				CertSerial string `json:"cert_serial"`
				OldSerial  string `json:"old_serial"`
				NewSerial  string `json:"new_serial"`
			}
			if err := json.Unmarshal(e.Data, &fact); err != nil {
				return err
			}
			if fact.ID != agentID {
				return nil
			}
			switch e.Type {
			case projections.EventAgentHeartbeat:
				serial := strings.ToLower(fact.CertSerial)
				if serial == "" {
					return nil
				}
				if len(allowed) == 0 {
					allowed[serial] = true
				} else if !allowed[serial] {
					ambiguous = true
				}
			case projections.EventAgentCertRenewed:
				old, next := strings.ToLower(fact.OldSerial), strings.ToLower(fact.NewSerial)
				if old == "" || next == "" {
					return nil
				}
				if len(allowed) == 0 {
					allowed[old] = true
				}
				if allowed[old] {
					allowed[next] = true
				} else {
					ambiguous = true
				}
			}
			return nil
		})
	return allowed, ambiguous, err
}
