// SPDX-License-Identifier: BUSL-1.1

package release

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"reflect"
	"slices"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"

	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/custody"
	"trstctl.com/trstctl/internal/decommission/depstate"
	decstore "trstctl.com/trstctl/internal/decommission/store"
	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/orchestrator"
	corestore "trstctl.com/trstctl/internal/store"
)

type Receipt struct {
	KeyID             string `json:"key_id"`
	CertificateID     string `json:"certificate_id"`
	CeremonyID        string `json:"ceremony_id"`
	ReleaseEventID    string `json:"release_event_id"`
	CertificateSHA256 string `json:"certificate_sha256"`
	Status            string `json:"status"`
}

type Coordinator struct {
	store      *corestore.Store
	log        *events.Log
	reviewer   *Reviewer
	projection *decstore.DependencyProjection
}

// A preview cannot authorize a stale operational state. The claim transaction
// locks the certificate row and rechecks these facts before reserving an event.
type lockedCertificateFacts struct {
	status             string
	keyOrigin          string
	notAfter           *time.Time
	deploymentLocation string
	lastSeen           *time.Time
}

type lockedDependencyFacts struct {
	registered int64
	accounted  *int64
	released   *int64
	erased     *int64
}

func (f lockedDependencyFacts) validate(sourceSequence uint64) error {
	if f.registered <= 0 || uint64(f.registered) != sourceSequence ||
		f.accounted != nil || f.released != nil || f.erased != nil {
		return fmt.Errorf("%w: exact CA leaf is no longer outstanding", ErrConflict)
	}
	return nil
}

func (f lockedCertificateFacts) validate(review Review, now time.Time) error {
	if f.notAfter == nil || !f.notAfter.Equal(review.NotAfter) ||
		f.deploymentLocation != "" || f.lastSeen != nil {
		return fmt.Errorf("%w: locked certificate eligibility changed after review", ErrConflict)
	}
	switch review.Reason {
	case depstate.ReleaseReasonExpiredRequesterCustody:
		if f.status != "active" || f.keyOrigin != string(custody.OriginRequester) || !now.After(*f.notAfter) {
			return fmt.Errorf("%w: locked requester certificate is no longer expired and active", ErrConflict)
		}
	case depstate.ReleaseReasonRevokedUnservedHostCustody:
		if f.status != "revoked" || f.keyOrigin != string(custody.OriginHostAgent) {
			return fmt.Errorf("%w: locked host certificate is no longer revoked", ErrConflict)
		}
	default:
		return ErrInvalid
	}
	return nil
}

func NewCoordinator(store *corestore.Store, log *events.Log) *Coordinator {
	return &Coordinator{store: store, log: log, reviewer: NewReviewer(store, log),
		projection: decstore.NewDependencyProjection(store)}
}

// Execute reserves an exact event before publishing it. Once the PostgreSQL
// claim commits, caller cancellation cannot turn an ambiguous result into a
// different event or reopen cancellation/approval for the same ceremony.
func (c *Coordinator) Execute(ctx context.Context, tenantID, keyID, ceremonyID string, request Request) (Receipt, error) {
	if c == nil || c.store == nil || c.log == nil || c.reviewer == nil || c.projection == nil {
		return Receipt{}, fmt.Errorf("%w: release coordinator unavailable", ErrInvalid)
	}
	actor, found := events.ActorFromContext(ctx)
	if !found || strings.TrimSpace(actor.Subject) == "" || tenantID == "" || keyID == "" || ceremonyID == "" {
		return Receipt{}, fmt.Errorf("%w: authenticated actor, tenant, key and ceremony are required", ErrInvalid)
	}
	command, err := c.store.GetCACeremonyEffectCommand(ctx, tenantID, ceremonyID)
	if errors.Is(err, pgx.ErrNoRows) {
		command, err = c.claim(ctx, tenantID, keyID, ceremonyID, request, actor)
		if err != nil {
			// A competing claim can win while this request is validating.
			// Compare against the winner; never replace its immutable event.
			if winner, getErr := c.store.GetCACeremonyEffectCommand(ctx, tenantID, ceremonyID); getErr == nil {
				command, err = winner, nil
			}
		}
	}
	if err != nil {
		return Receipt{}, err
	}
	// The first writer owns this ceremony forever. A different body cannot use
	// the same claim, including after its transient payload is scrubbed.
	retained := command.Event
	if command.Status == "completed" {
		var ok bool
		retained, ok, err = c.log.EventByID(ctx, command.Event.ID)
		if err != nil || !ok {
			return Receipt{}, fmt.Errorf("%w: completed release has no immutable event: %v", ErrConflict, err)
		}
	}
	decoded, err := depstate.Decode(retained)
	if err != nil {
		return Receipt{}, err
	}
	var v depstate.DependencyReleasedV2
	switch retained := decoded.(type) {
	case depstate.DependencyReleasedV2:
		v = retained
	case depstate.DependencyReleasedV3:
		v = retained.DependencyReleasedV2
	default:
		return Receipt{}, fmt.Errorf("%w: ceremony has no supported release event", ErrConflict)
	}
	if v.TenantID != tenantID || v.KeyID != keyID || v.CeremonyID != ceremonyID ||
		v.Dependent != (depstate.Dependent{Class: depstate.DependentCredential, ID: request.CertificateID}) ||
		v.CertificateSHA256 != strings.ToLower(strings.TrimSpace(request.ExpectedCertificateSHA256)) ||
		v.Reason != strings.TrimSpace(request.Reason) || v.RiskAccepted != request.RiskAccepted {
		return Receipt{}, fmt.Errorf("%w: ceremony already has a different exact release", ErrConflict)
	}
	// Finish the claimed command after a lost client response too. A bounded
	// background context continues through an ordinary HTTP disconnect.
	recoveryCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 30*time.Second)
	defer cancel()
	if err := c.reconcile(recoveryCtx, command); err != nil {
		return Receipt{}, fmt.Errorf("%w: CA dependent release command %s remains pending: %v",
			orchestrator.ErrEffectIndeterminate, command.Event.ID, err)
	}
	return Receipt{KeyID: keyID, CertificateID: v.Dependent.ID, CeremonyID: ceremonyID,
		ReleaseEventID: command.Event.ID, CertificateSHA256: v.CertificateSHA256,
		Status: "released"}, nil
}

func (c *Coordinator) claim(ctx context.Context, tenantID, keyID, ceremonyID string, request Request, actor events.Actor) (corestore.CACeremonyEffectCommand, error) {
	var command corestore.CACeremonyEffectCommand
	review, err := c.reviewer.Preview(ctx, tenantID, keyID, request, time.Now().UTC())
	if err != nil {
		return command, err
	}
	err = c.store.WithPrivacyRecoveryBarrier(ctx, tenantID, "CA dependent release claim", func(barrierCtx context.Context) error {
		return c.store.WithTenant(barrierCtx, tenantID, func(tx pgx.Tx) error {
			// Match the projector's dependent -> certificate -> ceremony lock order.
			var dependency lockedDependencyFacts
			if err := tx.QueryRow(barrierCtx, `SELECT registered_ordinal,accounted_ordinal,released_ordinal,erasure_ordinal
				FROM decommission_dependents WHERE tenant_id=$1 AND key_id=$2
				AND dependent_class='credential' AND dependent_id=$3 FOR UPDATE`,
				tenantID, keyID, review.CertificateID).Scan(&dependency.registered,
				&dependency.accounted, &dependency.released, &dependency.erased); err != nil {
				return err
			}
			if err := dependency.validate(review.SourceSequence); err != nil {
				return err
			}
			var sourceID, fingerprint, serial string
			var facts lockedCertificateFacts
			var der []byte
			if err := tx.QueryRow(barrierCtx, `SELECT issuance_event_id,fingerprint,serial,certificate_der,
				status,key_origin,not_after,deployment_location,last_seen_at
				FROM certificates WHERE tenant_id=$1 AND id=$2 FOR UPDATE`,
				tenantID, review.CertificateID).Scan(&sourceID, &fingerprint, &serial, &der,
				&facts.status, &facts.keyOrigin, &facts.notAfter, &facts.deploymentLocation, &facts.lastSeen); err != nil {
				return err
			}
			if sourceID != review.SourceEventID || serial != review.Serial ||
				!strings.EqualFold(fingerprint, review.CertificateSHA256) ||
				crypto.SHA256Hex(der) != review.CertificateSHA256 {
				return ErrConflict
			}
			if err := facts.validate(review, time.Now().UTC()); err != nil {
				return err
			}
			if review.Reason == depstate.ReleaseReasonRevokedUnservedHostCustody {
				var eventID, fingerprint, status string
				var sequence int64
				if err := tx.QueryRow(barrierCtx, `SELECT event_id,projected_sequence,fingerprint,status
					FROM certificate_revocation_authority_fences
					WHERE tenant_id=$1 AND ca_id=$2 AND serial=$3`, tenantID, keyID, review.Serial).
					Scan(&eventID, &sequence, &fingerprint, &status); err != nil {
					return fmt.Errorf("%w: exact local revocation receipt disappeared: %v", ErrConflict, err)
				}
				if status != "completed" || eventID != review.RevocationEventID ||
					sequence <= 0 || uint64(sequence) != review.RevocationSequence ||
					fingerprint != review.CertificateSHA256 {
					return fmt.Errorf("%w: exact local revocation receipt changed", ErrConflict)
				}
			}
			ceremony, approvals, err := c.store.ValidateKeyCeremonyWithApprovalEvidenceTx(
				barrierCtx, tx, tenantID, ceremonyID, review.Purpose())
			if err != nil {
				return err
			}
			if ceremony.Threshold < 2 || len(approvals) < ceremony.Threshold {
				return ErrConflict
			}
			v := review.releasePayload()
			v.CeremonyID, v.Actor = ceremonyID, actor.Subject
			for _, approval := range approvals {
				v.ApprovalEventIDs = append(v.ApprovalEventIDs, approval.EventID)
			}
			slices.Sort(v.ApprovalEventIDs)
			var payload depstate.Payload = v
			if review.Reason == depstate.ReleaseReasonRevokedUnservedHostCustody {
				payload = depstate.DependencyReleasedV3{DependencyReleasedV2: v,
					RevocationEventID: review.RevocationEventID, RevocationSequence: review.RevocationSequence}
			}
			ev, err := depstate.Encode(payload)
			if err != nil {
				return err
			}
			ev.ID = events.NewID()
			ev.Time = time.Now().UTC().Truncate(time.Microsecond)
			ev.Actor = &actor
			command = corestore.CACeremonyEffectCommand{TenantID: tenantID,
				CeremonyID: ceremonyID, KeyID: keyID, CertificateID: review.CertificateID,
				Event: ev, Status: "pending"}
			return c.store.ReserveCACeremonyEffectCommandTx(barrierCtx, tx, command)
		})
	})
	var unique *pgconn.PgError
	if errors.As(err, &unique) && unique.Code == "23505" &&
		strings.HasPrefix(unique.ConstraintName, "ca_ceremony_effect_commands_") {
		return command, fmt.Errorf("%w: exact CA leaf or ceremony already has a durable release claim", ErrConflict)
	}
	return command, err
}

func (c *Coordinator) reconcile(ctx context.Context, command corestore.CACeremonyEffectCommand) error {
	return c.store.WithPrivacyRecoveryBarrier(ctx, command.TenantID, "CA dependent release recovery", func(barrierCtx context.Context) error {
		return c.store.WithTenant(barrierCtx, command.TenantID, func(tx pgx.Tx) error {
			current, err := c.store.LockCACeremonyEffectCommandTx(barrierCtx, tx, command.TenantID, command.CeremonyID)
			if err != nil {
				return err
			}
			if current.Status == "completed" {
				return nil
			}
			if current.Event.ID != command.Event.ID || !bytes.Equal(current.Event.Data, command.Event.Data) ||
				!reflect.DeepEqual(current.Event.Actor, command.Event.Actor) {
				return ErrConflict
			}
			retained, found, err := c.log.EventByID(barrierCtx, current.Event.ID)
			if err != nil {
				return err
			}
			if found {
				if retained.TenantID != current.Event.TenantID || retained.Type != current.Event.Type ||
					retained.SchemaVersion != current.Event.SchemaVersion || !retained.Time.Equal(current.Event.Time) ||
					!bytes.Equal(retained.Data, current.Event.Data) ||
					!reflect.DeepEqual(retained.Actor, current.Event.Actor) {
					return ErrConflict
				}
			} else {
				retained, err = c.log.Append(barrierCtx, current.Event)
				if err != nil {
					return err
				}
			}
			return c.projection.ApplyTx(barrierCtx, tx, retained)
		})
	})
}

// ReconcilePending is called on startup and after a lost response. It never
// invents a new command; it publishes only the saved first-writer bytes.
func (c *Coordinator) ReconcilePending(ctx context.Context) (int, error) {
	tenants, err := c.store.ListTenants(ctx)
	if err != nil {
		return 0, err
	}
	healed := 0
	for _, tenant := range tenants {
		for {
			pending, err := c.store.ListPendingCACeremonyEffects(ctx, tenant.TenantID, 100)
			if err != nil {
				return healed, err
			}
			if len(pending) == 0 {
				break
			}
			for _, command := range pending {
				if err := c.reconcile(ctx, command); err != nil {
					return healed, err
				}
				healed++
			}
		}
	}
	return healed, nil
}
