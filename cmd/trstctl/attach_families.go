// SPDX-License-Identifier: BUSL-1.1

package main

import (
	"context"
	"io/fs"
	"log/slog"
	"strings"
	"time"

	agentapi "trstctl.com/trstctl/internal/agentid/api"
	agentdelegation "trstctl.com/trstctl/internal/agentid/delegation"
	agentbrokerstore "trstctl.com/trstctl/internal/agentid/delegation/brokerstore"
	agentstore "trstctl.com/trstctl/internal/agentid/delegation/store"
	agentorch "trstctl.com/trstctl/internal/agentid/orchestrator"
	"trstctl.com/trstctl/internal/api"
	"trstctl.com/trstctl/internal/cbom"
	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/crypto"
	decommission "trstctl.com/trstctl/internal/decommission"
	decommissionstore "trstctl.com/trstctl/internal/decommission/store"
	"trstctl.com/trstctl/internal/editionseam"
	"trstctl.com/trstctl/internal/license"
	"trstctl.com/trstctl/internal/orchestrator"
	pqc "trstctl.com/trstctl/internal/pqc"
	pqccbom "trstctl.com/trstctl/internal/pqc/cbomposture"
	pqcmigration "trstctl.com/trstctl/internal/pqcmigration"
	pqcruntime "trstctl.com/trstctl/internal/pqcruntime"
	reconcile "trstctl.com/trstctl/internal/reconcile"
	reconcileapi "trstctl.com/trstctl/internal/reconcile/api"
	reconcileplanremediation "trstctl.com/trstctl/internal/reconcile/plan/remediation"
	"trstctl.com/trstctl/internal/reconcile/rounds"
	"trstctl.com/trstctl/internal/server"
	successionapi "trstctl.com/trstctl/internal/succession/api"
	successionbackground "trstctl.com/trstctl/internal/succession/background"
	successionorch "trstctl.com/trstctl/internal/succession/orchestrator"
	successionstore "trstctl.com/trstctl/internal/succession/store"
)

// attach_families.go is the core attach seam. The patent-pending families — PCAS
// (succession), AGID (agent delegation), XREC (reconcile), VDEC (verifiable
// decommission) — and PQC are part of the licensed work under the BSL, so they
// wire in every build: no license feature and no build tag switches them off.
// Until 2026-09-20 each sat behind one lic.Has(feature) block in ee_attach.go;
// the ee/ seam now carries only what a signed license adds.

// attachAll is the composition root handed to the server: the core families
// first, then whatever the signed license attaches through the tagged ee/ seam
// (attachEE), which the trstctl_core twin reduces to a no-op.
func attachAll(ctx context.Context, cfg *config.Config, log *slog.Logger, lic *license.Manager, deps *server.Deps) error {
	if err := attachFamilies(cfg, log, deps); err != nil {
		return err
	}
	return attachEE(ctx, cfg, log, lic, deps)
}

// attachFamilies wires the core families, one named stage each.
func attachFamilies(cfg *config.Config, log *slog.Logger, deps *server.Deps) error {
	attachPCAS(cfg, log, deps)
	attachAgentDelegation(cfg, log, deps)
	if err := attachReconcile(cfg, log, deps); err != nil {
		return err
	}
	if err := attachVerifiableDecommission(log, deps); err != nil {
		return err
	}
	attachPQC(log, deps)
	return nil
}

// attachPCAS is the Proof-Carrying Algorithm Succession stage (HARNESS §1.6.6).
// The succession API/orchestrator and the succession store migrations key off
// deps.EnablePCAS.
func attachPCAS(cfg *config.Config, log *slog.Logger, deps *server.Deps) {
	deps.EnablePCAS = true
	// Attach the PCAS external API (request-succession, chain fetch, RP acks)
	// through the feature-neutral route seam, composing with any other API routes
	// (e.g. PQC migration) already registered.
	// AUD-7: the pcas.{recovery,federation,kem}.outbox_topic keys were
	// validated, printed, and never read — enqueue and dispatch both used
	// hardcoded constants. Both sides now resolve the SAME operator
	// configuration; blanks keep the canonical defaults.
	pcasCfg := attachConfig(cfg).PCAS
	deps.LicensedAPIOptionsFactory = appendAPIFactory(deps.LicensedAPIOptionsFactory, successionapi.NewAPIOptionsFactory(
		successionapi.WithOutboxTopics(pcasCfg.Recovery.OutboxTopic, pcasCfg.Federation.OutboxTopic, pcasCfg.KEM.OutboxTopic)))
	// Register the PCAS succession worker on the server outbox dispatcher (INT-04),
	// composing with any other outbox handler: a pcas.succession-request message is
	// drained here and minted over the signer transport, then recorded + published;
	// pcas.rp-publish is acknowledged. This makes the succession worker a real
	// production caller — a POST to request-succession yields a record.
	deps.LicensedOutboxFactory = appendOutboxFactory(deps.LicensedOutboxFactory, successionorch.NewLicensedOutboxFactory(
		successionorch.WithBreadthTopics(pcasCfg.Recovery.OutboxTopic, pcasCfg.Federation.OutboxTopic, pcasCfg.KEM.OutboxTopic)))
	deps.LicensedBackgroundWorkers = append(deps.LicensedBackgroundWorkers, successionbackground.NewWorkers(successionbackground.Options{
		Store: deps.Store, Log: deps.Log, Signer: deps.Signer, PCAS: pcasCfg,
	})...)
	if log != nil {
		log.Info("PCAS attached")
	}
}

// attachAgentDelegation is the AGID stage of the core attach seam, a named
// stage so the seam stays readable (the startup-hotspot ratchet).
func attachAgentDelegation(cfg *config.Config, log *slog.Logger, deps *server.Deps) {
	{
		// Core activation point for Agent Identity Lifecycle Enforcement (AGID).
		// Every build attaches the feature-neutral chain-bound
		// broker issuance precondition (the internal/agentid delegation gate) via the core
		// broker.WithIssuancePrecondition seam. The broker consults it ONLY on its
		// chain-bound issuance path; the free single-hop attested-ephemeral badge
		// (broker.Issue) is never routed through it, so this attach neither gates, moves,
		// nor degrades the free badge (INV-A10 zero removal). This attaches the REAL
		// AGID-07b chain-verifying precondition (brokerstore.BrokerPrecondition) in its
		// fail-closed default form: it consults the AGID-04 in-signer gate, the S10.1
		// policy gate, the sub-hour TTL ceiling, and the attestation-replay defense before
		// any key op — but until AGID-INT-WIRE provisions those dependencies it refuses
		// every chain-bound request (never an unverified chain-bound credential, INV-A1).
		// deps.BrokerIssuancePrecondition is consumed by the feature-neutral broker
		// construction (internal/server), which passes it via broker.WithIssuancePrecondition.
		// Every build runs this block now that AGID ships in the core.
		deps.BrokerIssuancePrecondition = agentbrokerstore.NewFailClosedBrokerPrecondition()
		// B-7: the AGID-05 task-envelope gate for the broker's single-hop path.
		// Until now only the chain-bound path could bind a credential to one
		// authorized task; the broker could not carry an envelope at all. The
		// gate reuses the same in-signer verification the delegation gate runs
		// (requester signature over canonical bytes, resolved through an
		// operator-provisioned trust store the caller cannot inject into, plus
		// the expiry window) and returns the digest the credential binds.
		// Every build attaches this gate. An envelope must pass signature,
		// trust and expiry checks before the broker can issue a credential
		// bound to the authorized task.
		deps.BrokerTaskEnvelopeGate = agentdelegation.NewBrokerTaskEnvelopeGate(
			agentdelegation.NewDurableTaskEnvelopeTrustStore(cfg.Signer.KeyStoreDir).TrustLookup,
		)
		// AGID-INT-CALL: attach the AGID external API and outbox worker so the two
		// AGID user journeys are reachable from this control-plane binary and every internal/agentid
		// mechanism gains a PRODUCTION CALLER (the reachability bar), like the core PCAS
		// stage above. The API (request-issuance / request-revocation + read models) attaches
		// through the feature-neutral route seam; the worker registers on the outbox dispatcher
		// (INT-04). A POST to /api/v1/agent-delegation/issuances now enqueues an
		// agentid.issue-chain-bound message that the worker drains and drives through
		// reach.NewEngine + broker.IssueChainBound (the "chains of authority" feature); a POST to
		// /api/v1/agent-delegation/revocations enqueues an agentid.revoke-directive message the
		// worker drives through revoke.NewCascade -> NewExecutor -> NewTerminalTransition (the
		// "verifiable kill"). The chain-bound in-signer key op stays fail-closed until
		// AGID-INT-WIRE provisions the signer gate + anchors, but the call path to every
		// mechanism now exists. The single-hop broker.Issue path is untouched and ungated
		// (INV-A10 zero removal); this only adds seams, removes nothing.
		deps.LicensedAPIOptionsFactory = appendAPIFactory(deps.LicensedAPIOptionsFactory, agentapi.NewAPIOptionsFactory())
		deps.LicensedOutboxFactory = appendOutboxFactory(deps.LicensedOutboxFactory, agentorch.NewLicensedOutboxFactory())
		if log != nil {
			log.Info("agent delegation attached")
		}
	}
}

func attachReconcile(cfg *config.Config, log *slog.Logger, deps *server.Deps) error {
	// The XREC stage of the core attach seam; later XREC cards extend it here
	// rather than scattering wiring.
	runtime, err := reconcile.NewRuntime(reconcile.RuntimeConfig{
		Store: deps.Store,
		Log:   deps.Log,
		// C4: witness recording and quarantine admission are idempotent per
		// (round, authority pair); a replayed round re-derives the same keys
		// and no-ops (AN-5).
		Idempotency: orchestrator.NewIdempotency(deps.Store),
		Signer:      deps.Signer,
		Logger:      log,
		// AUD-1: this was the missing half. The rounds worker registered, hit a
		// len(Schedules)==0 guard on its first tick and blocked for the life of
		// the process — zero rounds, zero witnesses, and a served agreement
		// report answering "0 open witnesses" forever while a licensed operator
		// watched a healthy worker in the roster. There was no config key to
		// populate schedules; now there is, and an empty one still reports
		// collecting=false rather than letting silence read as agreement.
		Schedules: reconcileSchedulesFromConfig(reconcileConfigOf(cfg)),
	})
	if err != nil {
		return err
	}
	deps.IssuanceAdmission = runtime.IssuanceAdmission
	deps.LicensedProjectionOptions = append(deps.LicensedProjectionOptions, runtime.ProjectionOptions...)
	deps.LicensedBackgroundWorkers = append(deps.LicensedBackgroundWorkers, runtime.BackgroundWorkers...)
	deps.LicensedOutboxFactory = appendOutboxFactory(deps.LicensedOutboxFactory, runtime.RemediationOutboxFactory)
	deps.LicensedOutboxFactory = appendOutboxFactory(deps.LicensedOutboxFactory, runtime.QuarantineOutboxFactory)
	// C4: the agreement surface. Until this line the drift projection
	// accumulated every authority's divergence history and no route could read
	// it, so XREC could detect that two authorities disagreed and had no way to
	// tell anybody.
	deps.LicensedAPIOptionsFactory = appendAPIFactory(deps.LicensedAPIOptionsFactory,
		reconcileapi.NewAPIOptionsFactory(runtime.DriftProjection, runtime.RoundsScheduledByTenant))
	if log != nil {
		log.Info("XREC reconciliation attached")
	}
	return nil
}

// reconcileConfigOf tolerates a nil config so a caller that never loaded one
// schedules nothing rather than panicking — fail closed, not fail loud.
func reconcileConfigOf(cfg *config.Config) config.Reconcile {
	if cfg == nil {
		return config.Reconcile{}
	}
	return cfg.Reconcile
}

// reconcileSchedulesFromConfig maps operator config onto reconciliation rounds.
//
// A schedule with no authorities is DROPPED rather than scheduled: a round that
// compares one authority to nothing produces no witness and would inflate the
// served schedule count, making "collecting" true on a deployment that still
// compares nothing.
func reconcileSchedulesFromConfig(c config.Reconcile) []rounds.Config {
	var out []rounds.Config
	for _, s := range c.Schedules {
		if strings.TrimSpace(s.TenantID) == "" || len(s.Authorities) < 2 {
			continue
		}
		rc := rounds.Config{
			TenantID: strings.TrimSpace(s.TenantID),
			Cadence:  parseReconcileDuration(s.Cadence, time.Hour),
			Jitter:   parseReconcileDuration(s.Jitter, 5*time.Minute),
			Liveness: parseReconcileDuration(s.Liveness, 24*time.Hour),
		}
		for _, a := range s.Authorities {
			if strings.TrimSpace(a.AuthorityID) == "" {
				continue
			}
			rc.Planes = append(rc.Planes, rounds.PlaneConfig{
				AuthorityID: strings.TrimSpace(a.AuthorityID),
				Liveness:    parseReconcileDuration(a.Liveness, rc.Liveness),
			})
		}
		if len(rc.Planes) < 2 {
			// Fewer than two planes survived. Comparing an authority to itself
			// is not reconciliation.
			continue
		}
		out = append(out, rc)
	}
	return out
}

// parseReconcileDuration falls back to a sane default rather than zero: a zero
// cadence would busy-loop the scheduler, and a zero liveness would make every
// authority instantly stale.
func parseReconcileDuration(v string, fallback time.Duration) time.Duration {
	d, err := time.ParseDuration(strings.TrimSpace(v))
	if err != nil || d <= 0 {
		return fallback
	}
	return d
}

func attachVerifiableDecommission(log *slog.Logger, deps *server.Deps) error {
	// The VDEC stage of the core attach seam; later cards extend it here rather
	// than scattering wiring. Blunt-destroy / zeroize stays outside this path.
	runtime, err := decommission.NewRuntime(decommission.RuntimeConfig{
		Store: deps.Store,
		Log:   deps.Log,
	})
	if err != nil {
		return err
	}
	deps.LicensedOutboxFactory = appendOutboxFactory(deps.LicensedOutboxFactory, runtime.ReprotectionOutboxFactory)
	deps.LicensedOutboxFactory = appendOutboxFactory(deps.LicensedOutboxFactory, runtime.RetirementOutboxFactory)
	deps.LicensedProjectionOptions = append(deps.LicensedProjectionOptions, runtime.ProjectionOptions...)
	// The H4 surface: the retirement checklist source (without it the core route
	// answers 501 on every deployment, licensed included — AUD-3) and the
	// re-protection start route plus the signer-gated retirement producer. The
	// latter writes only an outbox intent; this process never owns the key handle.
	deps.LicensedAPIOptionsFactory = appendAPIFactory(deps.LicensedAPIOptionsFactory, runtime.APIOptionsFactory)
	if log != nil {
		log.Info("VDEC attached")
	}
	return nil
}

func attachPQC(log *slog.Logger, deps *server.Deps) {
	cryptoRuntime := pqcruntime.NewRuntime()
	migrationRuntime := pqcmigration.NewRuntime(deps.Store)
	deps.LicensedAPIOptionsFactory = appendAPIFactory(deps.LicensedAPIOptionsFactory, migrationRuntime.APIOptionsFactory)
	deps.LicensedOutboxFactory = appendOutboxFactory(deps.LicensedOutboxFactory, migrationRuntime.OutboxFactory)
	deps.LicensedProjectionOptions = append(deps.LicensedProjectionOptions, migrationRuntime.ProjectionOptions...)
	deps.LicensedLeafSigner = cryptoRuntime.LeafSigner
	deps.PreparedSubjectLeafSigner = cryptoRuntime.PreparedLeafSigner
	deps.LicensedCSRInspector = cryptoRuntime.CSRInspector
	deps.LicensedCSRParser = cryptoRuntime.CSRParser
	deps.LicensedSPIFFESVIDFactory = cryptoRuntime.SPIFFESVIDFactory
	// CBOM posture: name the FIPS-203/204/205 migration targets and recognize
	// post-quantum families so migration progress can count future-ready assets (A0.1).
	cbom.InstallLicensedPosture(pqccbom.CBOMTargetFor, pqccbom.CBOMClassifyKey)
	// Algorithm classifier: post-quantum and hybrid labels become valid
	// certificate-profile `allowed_key_algorithms` entries and inventory
	// classifications (A0.3b).
	crypto.InstallLicensedAlgorithmClassifier(pqc.ClassifyAlgorithm)
	if log != nil {
		log.Info("PQC attached")
	}
}

func attachConfig(cfg *config.Config) config.Config {
	if cfg == nil {
		return config.Config{}
	}
	return *cfg
}

// extraMigrationSources returns the core families' migration bundles. They
// apply through the feature-neutral core store seam in every build.
func extraMigrationSources() []fs.FS {
	return []fs.FS{
		successionstore.MigrationsFS(),
		agentstore.MigrationsFS(),
		reconcileplanremediation.MigrationsFS(),
		decommissionstore.MigrationsFS(),
	}
}

// appendAPIFactory composes API-option factories so core and commercial
// features can each contribute routes to the single deps.LicensedAPIOptionsFactory
// field, order-independently. A nil existing factory yields add alone.
func appendAPIFactory(existing, add editionseam.LicensedAPIOptionsFactory) editionseam.LicensedAPIOptionsFactory {
	if existing == nil {
		return add
	}
	return func(d editionseam.LicensedAPIOptionsDeps) ([]api.Option, error) {
		a, err := existing(d)
		if err != nil {
			return nil, err
		}
		b, err := add(d)
		if err != nil {
			return nil, err
		}
		return append(a, b...), nil
	}
}

// appendOutboxFactory composes outbox factories so core and commercial
// features can each contribute a handler to the single deps.LicensedOutboxFactory
// field, order-independently. The composed handler tries each in turn: the first that
// reports the message handled (or errors) wins. A nil existing factory yields add
// alone.
func appendOutboxFactory(existing, add editionseam.LicensedOutboxFactory) editionseam.LicensedOutboxFactory {
	if existing == nil {
		return add
	}
	return func(d editionseam.LicensedOutboxDeps) (editionseam.LicensedOutboxHandler, error) {
		a, err := existing(d)
		if err != nil {
			return nil, err
		}
		b, err := add(d)
		if err != nil {
			return nil, err
		}
		return chainedOutboxHandler{a, b}, nil
	}
}

type chainedOutboxHandler []editionseam.LicensedOutboxHandler

func (c chainedOutboxHandler) DeliverLicensed(ctx context.Context, m orchestrator.Message) (bool, error) {
	for _, h := range c {
		if h == nil {
			continue
		}
		if handled, err := h.DeliverLicensed(ctx, m); handled || err != nil {
			return handled, err
		}
	}
	return false, nil
}

func (c chainedOutboxHandler) DeliverLicensedTerminalFailure(ctx context.Context, m orchestrator.Message, cause error) (bool, error) {
	for _, h := range c {
		terminal, ok := h.(editionseam.LicensedOutboxTerminalFailureHandler)
		if !ok || terminal == nil {
			continue
		}
		if handled, err := terminal.DeliverLicensedTerminalFailure(ctx, m, cause); handled || err != nil {
			return handled, err
		}
	}
	return false, nil
}
