// SPDX-License-Identifier: BUSL-1.1

package projections

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"

	"trstctl.com/trstctl/internal/custody"
	"trstctl.com/trstctl/internal/events"
)

// Owner decision 2026-10-24: certificates issued before their issuing path
// recorded custody read as "not recorded". Where the certificate's own retained
// issuance event proves the origin, the projection derives it from that event
// and marks it derived, naming the rule and the event; every other certificate
// stays unrecorded. Because the derivation is a function of the event alone, a
// rebuild reproduces it exactly (AN-2).
//
// A rule proves an origin only from what the certificate.recorded event says
// (its source, its issuance key, whether it replaces a predecessor, whether it
// came from the external CA worker) and from the event's time. The time matters
// because a rule describes the code that wrote the event, and code that could
// write that shape differently did not exist before the cutoff: a binary cannot
// record an event earlier than the commit it was built from. Each cutoff is
// the moment the path began recording custody on its own event, so a
// derivation never second-guesses a path that records it.

var (
	// csrFirstIdentityIssuance: identity issuance began honoring a requester's
	// CSR (2026-08-03). Before it, the path always generated the subject key.
	csrFirstIdentityIssuance = time.Date(2026, 8, 3, 5, 9, 37, 0, time.UTC)
	// issuanceEventCustody: identity issuance, renewal, Kubernetes
	// auto-issuance and ephemeral issuance began carrying key_origin on their
	// own event (2026-08-04).
	issuanceEventCustody = time.Date(2026, 8, 4, 12, 8, 31, 0, time.UTC)
	// attestedSVIDCustody: attested X.509-SVID issuance began recording
	// requester custody (2026-08-30).
	attestedSVIDCustody = time.Date(2026, 8, 30, 23, 0, 49, 0, time.UTC)
	// agentBrokerCustody: agent broker issuance began recording requester
	// custody (2026-08-31).
	agentBrokerCustody = time.Date(2026, 8, 31, 6, 58, 33, 0, time.UTC)
	// externalCAShared: identity issuance could select an external CA from
	// this moment (2026-09-05), so the external CA worker's event shape stopped
	// implying the CSR-only external CA order route.
	externalCAShared = time.Date(2026, 9, 5, 10, 27, 52, 0, time.UTC)
	// protocolEnrollmentCustody: ACME, EST, SCEP and CMP issuance began
	// recording requester custody (2026-09-12).
	protocolEnrollmentCustody = time.Date(2026, 9, 12, 17, 35, 28, 0, time.UTC)
)

// pqcMigrationIssuanceKeys are the issuance keys of the PQC migration reissue,
// the one caller of the generic protocol issuer that builds its CSR from a key
// it generated itself. It always named the protocol acme.
var pqcMigrationIssuanceKeys = []string{"protocol-issue:pqc-migration:", "protocol-issue:licensed-crypto-migration:"}

// DeriveKeyOrigin returns the rule that proves where the key of the
// certificate this event recorded came from, or false when no rule does.
func DeriveKeyOrigin(e events.Event, p CertificateRecorded) (custody.DerivationRule, bool) {
	if e.Type != EventCertificateRecorded || p.KeyOrigin != "" || p.ObservationOnly ||
		schemaVersionOf(e) == CertificateApprovalEventSchemaVersion || e.Time.IsZero() {
		return custody.DerivationNone, false
	}
	source, key, at := p.Source, p.IssuanceIdempotencyKey, e.Time
	switch {
	case source == "protocol:acme" && hasAnyPrefix(key, pqcMigrationIssuanceKeys):
		return custody.DerivedPQCMigrationReissue, true
	case protocolEnrollmentSource(source) && strings.HasPrefix(key, "protocol-issue:") && at.Before(protocolEnrollmentCustody):
		return custody.DerivedProtocolEnrollment, true
	case source == "issued" && strings.HasPrefix(key, "renew:") && p.ReplacesID != nil && *p.ReplacesID != "" &&
		at.Before(issuanceEventCustody):
		return custody.DerivedIdentityRenewal, true
	case source == "issued" && strings.HasPrefix(key, "issue:") && at.Before(csrFirstIdentityIssuance):
		return custody.DerivedIdentityIssuance, true
	case source == "discovery:k8s_ingress_gateway" && strings.HasPrefix(key, "k8s-auto:") && at.Before(issuanceEventCustody):
		return custody.DerivedKubernetesAutoIssuance, true
	case strings.HasPrefix(source, "ephemeral:") && strings.HasPrefix(key, "ephemeral-issue:") && at.Before(issuanceEventCustody):
		return custody.DerivedEphemeralCredential, true
	case strings.HasPrefix(source, "attested:") && strings.HasPrefix(key, "attested-issue:") && at.Before(attestedSVIDCustody):
		return custody.DerivedAttestedSVID, true
	case strings.HasPrefix(source, "broker:") && strings.HasPrefix(key, "broker-issue:") && at.Before(agentBrokerCustody):
		return custody.DerivedAgentBroker, true
	case AuthenticatedExternalIssuer(e, p) != "" && at.Before(externalCAShared):
		return custody.DerivedExternalCAOrder, true
	}
	return custody.DerivationNone, false
}

func protocolEnrollmentSource(source string) bool {
	switch source {
	case "protocol:acme", "protocol:est", "protocol:scep", "protocol:cmp":
		return true
	default:
		return false
	}
}

func hasAnyPrefix(value string, prefixes []string) bool {
	for _, prefix := range prefixes {
		if strings.HasPrefix(value, prefix) {
			return true
		}
	}
	return false
}

var errKeyOriginDerivationRebuild = errors.New("derived key origins need rebuild")

// Older binaries projected these certificates with no origin at all. Scan
// retained, already-applied events once on upgrade (then only the unexamined
// tail) and rebuild atomically if a live row lacks an origin its retained
// event now proves — the same recovery the external issuer provenance uses.
func (p *Projector) keyOriginDerivationNeedsRebuild(ctx context.Context, log *events.Log) (bool, error) {
	var needsRebuild bool
	err := log.WithHistoryRead(ctx, func(readCtx context.Context) error {
		applied, checked, err := p.store.KeyOriginDerivationRecoveryCursor(readCtx)
		if err != nil {
			return err
		}
		head, err := projectionHistoryHead(readCtx, log)
		if err != nil {
			return err
		}
		if applied > head {
			return fmt.Errorf("projections: key origin derivation checkpoint %d beyond history head %d", applied, head)
		}
		from := checked + 1
		if checked > applied {
			from = 1
		}
		if from > applied {
			return nil
		}
		err = replayProjectionThrough(readCtx, log, from, applied, func(e events.Event) error {
			if e.Type != EventCertificateRecorded {
				return nil
			}
			if err := ValidateSchemaVersion(e); err != nil {
				return err
			}
			var fact CertificateRecorded
			if err := json.Unmarshal(e.Data, &fact); err != nil {
				return err
			}
			if _, derived := DeriveKeyOrigin(e, fact); !derived {
				return nil
			}
			cert, err := p.store.GetCertificateByFingerprint(readCtx, e.TenantID, fact.Fingerprint)
			if errors.Is(err, pgx.ErrNoRows) {
				return nil // tenant offboarded or its certificate was erased
			}
			if err != nil {
				return err
			}
			if cert.KeyOrigin == "" {
				needsRebuild = true
				return errKeyOriginDerivationRebuild
			}
			return nil
		})
		if errors.Is(err, errKeyOriginDerivationRebuild) {
			return nil
		}
		if err != nil {
			return err
		}
		return p.store.MarkKeyOriginDerivationCheckedThrough(readCtx, applied)
	})
	return needsRebuild, err
}
