// SPDX-License-Identifier: LicenseRef-trstctl-EE

package reconcile

import (
	"context"
	"fmt"
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
	defaultKMIPAuthority     = "kmip"
)

// RuntimeConfig supplies core-owned substrate to the EE XREC assembly. The
// fields are generic core seams; no XREC type is added to core.
type RuntimeConfig struct {
	Store       *corestore.Store
	Log         *events.Log
	Idempotency idem.Idempotencer
	Signer      server.SignerProvider
}

// Runtime is the XREC object graph mounted by cmd/trstctl/ee_attach.go. Nil
// external sources keep the runtime fail-closed until INT-WIRE/config supplies
// durable authority adapters; the binary still owns the real product path.
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
	// RoundsScheduled is how many reconciliation schedules the rounds worker was
	// given. ZERO TODAY, and that is why it is served rather than assumed.
	//
	// rounds.Worker returns immediately when it has no schedules, and nothing
	// calls witness.Recorder.RecordWitness in production, so no round runs and no
	// witness is ever recorded. The drift projection therefore counts nothing —
	// not because the authorities agree, but because nothing is looking.
	//
	// Without this the agreement surface cannot tell those apart: its replay
	// watermark advances with the event log like any projection, so it would
	// report "consumed events, raised no divergence" on a deployment where
	// divergence is undetectable. That is the exact false reassurance the surface
	// exists to refuse, and it would have shipped inside it.
	RoundsScheduled          int
	IssuanceAdmission        server.AdmissionHook
	ProjectionOptions        []projections.Option
	BackgroundWorkers        []server.BackgroundWorker
	RemediationOutboxFactory editionseam.LicensedOutboxFactory
	QuarantineOutboxFactory  editionseam.LicensedOutboxFactory
}

// NewRuntime builds the shipped XREC runtime object graph. Authority reducers
// are registered with nil sources so observation fails closed rather than
// pretending an unconfigured authority is healthy.
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
	if err := reducerRegistry.Register(defaultSelfAuthority, reducers.NewSelfReducer(defaultSelfAuthority, nil)); err != nil {
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
	// No schedules are configured yet — reconciliation rounds are not driven by
	// this runtime. Named as a variable rather than omitted so the count can be
	// served, and so the day schedules arrive there is one place to fill in.
	var roundSchedules []rounds.Config

	var remediationManager *remediation.Manager
	if cfg.Store != nil {
		var err error
		remediationManager, err = remediation.NewManager(cfg.Store, orchestrator.NewOutbox(cfg.Store))
		if err != nil {
			return nil, err
		}
	}

	return &Runtime{
		Reducers:                 reducerRegistry,
		ObservationSandbox:       reducers.NewObservationSandbox(reducers.ReadOnlyObservationGrant("xrec"), nil),
		WitnessRecorder:          witness.NewRecorder(witnessLog, cfg.Idempotency),
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

func (s *runtimeDigestSource) DigestForRound(ctx context.Context, req rounds.DigestRequest) (digest.SignedDigest, error) {
	if s == nil || s.reducers == nil {
		return digest.SignedDigest{}, fmt.Errorf("xrec runtime: reducer registry is not configured")
	}
	observation, err := s.reducers.Observe(ctx, req.AuthorityID, req.TenantID)
	if err != nil {
		return digest.SignedDigest{}, err
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
		return digest.SignedDigest{}, err
	}
	if s.signer == nil || s.signer.Client() == nil {
		return digest.SignedDigest{}, fmt.Errorf("xrec runtime: signer is not configured")
	}
	return digest.Sign(ctx, s.signer.Client(), built.Body, "")
}
