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
	QuarantineState          *quarantine.MemoryState
	IssuanceAdmission        server.AdmissionHook
	ProjectionOptions        []projections.Option
	BackgroundWorkers        []server.BackgroundWorker
	RemediationOutboxFactory editionseam.LicensedOutboxFactory
	QuarantineOutboxFactory  editionseam.LicensedOutboxFactory
}

// NewRuntime builds the shipped XREC runtime object graph. Authority reducers
// are registered with nil sources so observation fails closed rather than
// pretending an unconfigured authority is healthy.
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
	quarantineManager := quarantine.NewManager(quarantine.Options{
		Log:         quarantineLog,
		Idempotency: cfg.Idempotency,
		State:       quarantineState,
		Policy:      quarantine.ReferencePolicy(),
	})
	driftProjection := rounds.NewDriftProjection(time.Hour)

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
		IssuanceAdmission:        quarantineManager,
		ProjectionOptions:        []projections.Option{rounds.WithDriftProjection(driftProjection)},
		BackgroundWorkers: rounds.NewWorkers(rounds.WorkerOptions{
			Log:    roundsLog,
			Source: &runtimeDigestSource{reducers: reducerRegistry, signer: cfg.Signer},
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
