// SPDX-License-Identifier: LicenseRef-trstctl-EE

package reconcile

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	"trstctl.com/trstctl/ee/reconcile/canon/reducers"
	"trstctl.com/trstctl/ee/reconcile/canon/reducers/kmip"
	"trstctl.com/trstctl/ee/reconcile/digest"
	"trstctl.com/trstctl/ee/reconcile/plan/remediation"
	"trstctl.com/trstctl/ee/reconcile/quarantine"
	"trstctl.com/trstctl/ee/reconcile/rounds"
	"trstctl.com/trstctl/ee/reconcile/witness"
	"trstctl.com/trstctl/internal/editionseam"
	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/idem"
	"trstctl.com/trstctl/internal/orchestrator"
	"trstctl.com/trstctl/internal/projections"
	"trstctl.com/trstctl/internal/server"
	corestore "trstctl.com/trstctl/internal/store"
)

const (
	defaultVaultAuthority    = "vault"
	defaultCloudKMSAuthority = "cloud-kms"
	defaultSelfAuthority     = "trstctl-self"
	defaultCAAuthority       = "trstctl-ca"
	defaultKMIPAuthority     = "kmip"
)

// RuntimeConfig supplies core-owned substrate to the EE XREC assembly. The
// fields are generic core seams; no XREC type is added to core.
type RuntimeConfig struct {
	Store       *corestore.Store
	Log         *events.Log
	Idempotency idem.Idempotencer
	Signer      server.SignerProvider
	Logger      *slog.Logger
	// Schedules are the reconciliation rounds to run. Empty means nothing
	// compares anything — which the served agreement report states as
	// collecting=false rather than letting zero witnesses read as agreement.
	Schedules []rounds.Config
	// RoundInterval is how often the rounds worker checks for due schedules.
	// Zero means the worker default (one minute); tests shorten it.
	RoundInterval time.Duration
}

// Runtime is the XREC object graph mounted by cmd/trstctl/ee_attach.go. The
// "trstctl-self" and "trstctl-ca" authorities are store-backed (epic C4); the
// vault, cloud-kms and kmip reducers keep nil sources — fail-closed — until
// operator config supplies external credentials and endpoints.
type Runtime struct {
	Reducers                 *reducers.Registry
	ObservationSandbox       *reducers.ObservationSandbox
	WitnessRecorder          *witness.Recorder
	RemediationManager       *remediation.Manager
	RemediationOperationGate remediation.OperationGrant
	QuarantineState          quarantine.AdmissionState
	QuarantineProjection     *quarantine.StateProjection
	// DriftProjection is the agreement state the round scheduler accumulates:
	// witness counts per authority and class, how long resolved witnesses took,
	// and how many are still open (epic C4).
	//
	// Exposed because until C4 it was NOT. The projection was constructed here,
	// wired into ProjectionOptions, and dropped on the floor — it accumulated
	// every authority's divergence history into a struct no caller could reach.
	// XREC had reducers, digests, witnesses, quarantine and remediation, and no
	// way for an operator to be told any authority disagreed with another.
	DriftProjection *rounds.DriftProjection
	// RoundsScheduled is how many reconciliation schedules the rounds worker
	// was given, served so the agreement surface can distinguish "no divergence
	// found" from "nothing is looking". Zero schedules means the worker parks
	// and the drift projection counts nothing — not because the authorities
	// agree, but because no round compares them; the surface reports that as
	// collecting=false rather than letting silence read as agreement.
	//
	// With C4, a deployment that DOES schedule rounds gets the whole chain:
	// store-backed authorities observed, digests signed in the isolated signer,
	// disagreements witnessed into the ledger, quarantine admission updated,
	// and the drift projection rebuilt from those events.
	RoundsScheduled          int
	IssuanceAdmission        server.AdmissionHook
	ProjectionOptions        []projections.Option
	BackgroundWorkers        []server.BackgroundWorker
	RemediationOutboxFactory editionseam.LicensedOutboxFactory
	QuarantineOutboxFactory  editionseam.LicensedOutboxFactory
}

// NewRuntime builds the shipped XREC runtime object graph. The two
// control-plane authorities are registered with store-backed sources; external
// reducers keep nil sources so observation of an unconfigured authority fails
// closed rather than pretending it is healthy.
// NewRuntime assembles the whole XREC system — reducers, digester, round
// scheduler, witness recorder, quarantine manager and remediation manager — into
// the single runtime the attach seam mounts (XREC-claim-16), and drives the
// end-to-end method it implements (XREC-claim-1).
func NewRuntime(cfg RuntimeConfig) (*Runtime, error) {
	var (
		quarantineLog quarantine.EventAppender
		roundsLog     rounds.EventAppender
		witnessLog    witness.EventAppender
	)
	if cfg.Log != nil {
		quarantineLog = cfg.Log
		roundsLog = cfg.Log
		witnessLog = cfg.Log
	}

	reducerRegistry := reducers.NewRegistry()
	if err := reducerRegistry.Register(defaultVaultAuthority, reducers.NewVaultReducer(reducerConfig(defaultVaultAuthority, reducers.ModePoll), nil)); err != nil {
		return nil, err
	}
	if err := reducerRegistry.Register(defaultCloudKMSAuthority, reducers.NewCloudKMSReducer(reducerConfig(defaultCloudKMSAuthority, reducers.ModePoll), nil)); err != nil {
		return nil, err
	}
	// C4: the first two DURABLE authority adapters. "trstctl-self" is the
	// certificate inventory's view and "trstctl-ca" is the internal CA issuance
	// ledger's view — independently written state the platform already keeps
	// under RLS, projected onto the shared assertion vocabulary in
	// storesource.go. Before this every reducer had a nil source, so a
	// scheduled round observed nothing and errored: "collecting" reported the
	// schedule count while no authority was ever read. Without a store the
	// sources stay nil and observation still fails closed.
	var selfSource reducers.SelfInventorySource
	var caLedgerSource reducers.SelfInventorySource
	if cfg.Store != nil {
		selfSource = newStoreInventorySource(cfg.Store)
		caLedgerSource = newStoreCALedgerSource(cfg.Store)
	}
	if err := reducerRegistry.Register(defaultSelfAuthority, reducers.NewSelfReducer(defaultSelfAuthority, selfSource)); err != nil {
		return nil, err
	}
	if err := reducerRegistry.Register(defaultCAAuthority, reducers.NewSelfReducer(defaultCAAuthority, caLedgerSource)); err != nil {
		return nil, err
	}
	kmipClient := kmip.NewClient(defaultKMIPAuthority, nil)
	_ = kmipClient
	if err := reducerRegistry.Register(defaultKMIPAuthority, kmip.NewReducer(reducerConfig(defaultKMIPAuthority, reducers.ModePoll), nil)); err != nil {
		return nil, err
	}

	quarantineState := quarantine.NewMemoryState()
	// XREC containment must survive a restart. NewRuntime IS the restart path
	// (cmd/trstctl/ee_attach.go calls it on every boot) and it previously
	// allocated an empty map and loaded nothing, so every quarantined tenant was
	// admitted again. The quarantine read model is a projection of
	// xrec.quarantine.entered / xrec.quarantine.released (AN-2), registered below
	// so the core projector resets it and replays the log from sequence 0 on boot.
	quarantineProjection := quarantine.NewStateProjection(quarantineState)
	quarantineManager := quarantine.NewManager(quarantine.Options{
		Log:         quarantineLog,
		Idempotency: cfg.Idempotency,
		State:       quarantineState,
		Policy:      quarantine.ReferencePolicy(),
	})
	driftProjection := rounds.NewDriftProjection(time.Hour)
	// AUD-1: schedules now come from operator config. Before this the variable
	// was always empty, so the rounds worker hit its len(Schedules)==0 guard on
	// the first tick and blocked forever — a registered, healthy-looking worker
	// that compared nothing for the life of the process.
	roundSchedules := cfg.Schedules

	var remediationManager *remediation.Manager
	if cfg.Store != nil {
		var err error
		remediationManager, err = remediation.NewManager(cfg.Store, orchestrator.NewOutbox(cfg.Store))
		if err != nil {
			return nil, err
		}
	}

	witnessRecorder := witness.NewRecorder(witnessLog, cfg.Idempotency)
	return &Runtime{
		Reducers:                 reducerRegistry,
		ObservationSandbox:       reducers.NewObservationSandbox(reducers.ReadOnlyObservationGrant("xrec"), nil),
		WitnessRecorder:          witnessRecorder,
		RemediationManager:       remediationManager,
		RemediationOperationGate: remediation.NewOperationGrant("rotate-key", "disable-key", "delete-secret"),
		QuarantineState:          quarantineState,
		QuarantineProjection:     quarantineProjection,
		DriftProjection:          driftProjection,
		RoundsScheduled:          len(roundSchedules),
		IssuanceAdmission:        quarantineManager,
		ProjectionOptions:        []projections.Option{projections.WithEventProjection(quarantineProjection), rounds.WithDriftProjection(driftProjection)},
		BackgroundWorkers: rounds.NewWorkers(rounds.WorkerOptions{
			Log:       roundsLog,
			Source:    &runtimeDigestSource{reducers: reducerRegistry, signer: cfg.Signer},
			Schedules: roundSchedules,
			Interval:  cfg.RoundInterval,
			// C4: the disagreement sink closes the loop the scheduler could not.
			// A round that detects two authorities committing to different
			// state now produces a signed witness in the ledger and a
			// quarantine admission decision, instead of appending nothing.
			Sink: &witnessEmitter{
				signer:     cfg.Signer,
				recorder:   witnessRecorder,
				quarantine: quarantineManager,
				now:        func() time.Time { return time.Now().UTC() },
			},
			Logger: cfg.Logger,
		}),
		RemediationOutboxFactory: remediation.NewLicensedOutboxFactory(),
		QuarantineOutboxFactory:  quarantine.NewLicensedOutboxFactory(quarantineState),
	}, nil
}

func reducerConfig(authorityID string, mode reducers.ObservationMode) reducers.ReducerConfig {
	return reducers.ReducerConfig{
		AuthorityID: authorityID,
		Scope:       authorityID,
		Mode:        mode,
		Grant:       reducers.ReadOnlyObservationGrant(authorityID),
	}
}

type runtimeDigestSource struct {
	reducers *reducers.Registry
	signer   server.SignerProvider
}

func (s *runtimeDigestSource) DigestForRound(ctx context.Context, req rounds.DigestRequest) (rounds.PlaneObservation, error) {
	if s == nil || s.reducers == nil {
		return rounds.PlaneObservation{}, fmt.Errorf("xrec runtime: reducer registry is not configured")
	}
	observation, err := s.reducers.Observe(ctx, req.AuthorityID, req.TenantID)
	if err != nil {
		return rounds.PlaneObservation{}, err
	}
	built, err := digest.Build(digest.BuildRequest{
		Set:         observation.Set,
		AuthorityID: req.AuthorityID,
		Watermark: digest.Watermark{
			Position:   observation.Watermark.Position,
			ObservedAt: observation.Watermark.ObservedAt.UTC().Unix(),
		},
		GeneratedAt: time.Now().UTC().Unix(),
	})
	if err != nil {
		return rounds.PlaneObservation{}, err
	}
	if s.signer == nil || s.signer.Client() == nil {
		return rounds.PlaneObservation{}, fmt.Errorf("xrec runtime: signer is not configured")
	}
	signed, err := digest.Sign(ctx, s.signer.Client(), built.Body, "")
	if err != nil {
		return rounds.PlaneObservation{}, err
	}
	// The set and tree travel WITH the signed digest so a disagreement can be
	// witnessed against exactly the state the digest committed to, not a
	// re-observation racing the authority (epic C4).
	return rounds.PlaneObservation{Digest: signed, Set: observation.Set, Tree: built.Tree}, nil
}
