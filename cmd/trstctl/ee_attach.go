// SPDX-License-Identifier: MPL-2.0

//go:build !trstctl_core

package main

import (
	"context"
	"io/fs"
	"log/slog"

	_ "trstctl.com/trstctl/ee"
	eeagentapi "trstctl.com/trstctl/ee/agentid/api"
	eeagentdelegation "trstctl.com/trstctl/ee/agentid/delegation"
	eeagentbrokerstore "trstctl.com/trstctl/ee/agentid/delegation/brokerstore"
	eeagentstore "trstctl.com/trstctl/ee/agentid/delegation/store"
	eeagentorch "trstctl.com/trstctl/ee/agentid/orchestrator"
	eebilling "trstctl.com/trstctl/ee/billing"
	eedecommission "trstctl.com/trstctl/ee/decommission"
	eedecommissionstore "trstctl.com/trstctl/ee/decommission/store"
	eefederation "trstctl.com/trstctl/ee/federation"
	eegovernance "trstctl.com/trstctl/ee/governance"
	eekmip "trstctl.com/trstctl/ee/kmip"
	eemanagedkeys "trstctl.com/trstctl/ee/managedkeys"
	eepqc "trstctl.com/trstctl/ee/pqc"
	eepqcmigration "trstctl.com/trstctl/ee/pqcmigration"
	eepqcruntime "trstctl.com/trstctl/ee/pqcruntime"
	eeprovider "trstctl.com/trstctl/ee/provider"
	eereconcile "trstctl.com/trstctl/ee/reconcile"
	eereconcileplanremediation "trstctl.com/trstctl/ee/reconcile/plan/remediation"
	eesilo "trstctl.com/trstctl/ee/silo"
	eesuccessionapi "trstctl.com/trstctl/ee/succession/api"
	eesuccessionbackground "trstctl.com/trstctl/ee/succession/background"
	eesuccessionorch "trstctl.com/trstctl/ee/succession/orchestrator"
	eesuccessionstore "trstctl.com/trstctl/ee/succession/store"
	eewhitelabel "trstctl.com/trstctl/ee/whitelabel"
	"trstctl.com/trstctl/internal/api"
	"trstctl.com/trstctl/internal/cbom"
	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/editionseam"
	"trstctl.com/trstctl/internal/license"
	"trstctl.com/trstctl/internal/orchestrator"
	"trstctl.com/trstctl/internal/server"
)

// extraMigrationSources returns edition migration bundles for the full binary.
// They still apply through the feature-neutral core store seam; the core-only
// twin returns nil and links no ee/ packages.
func extraMigrationSources() []fs.FS {
	return []fs.FS{
		eesuccessionstore.MigrationsFS(),
		eeagentstore.MigrationsFS(),
		eereconcileplanremediation.MigrationsFS(),
		eedecommissionstore.MigrationsFS(),
	}
}

// appendAPIFactory composes two licensed-API-options factories so multiple gated
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

// appendOutboxFactory composes two licensed-outbox factories so multiple gated
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

// attachEE is the single sanctioned open-core seam. S-E0 attaches no features:
// the table is empty and behavior stays Community. Later cards add exactly one
// lic.Has(feature) block per gated capability here.
func attachEE(ctx context.Context, cfg *config.Config, log *slog.Logger, lic *license.Manager, deps *server.Deps) error {
	if lic != nil && lic.Has(license.FeatureRemediation) {
		attachRemediation(log, deps)
	}
	if lic != nil && lic.Has(license.FeaturePCAS) {
		// AN-9 activation point for Proof-Carrying Algorithm Succession (HARNESS
		// §1.6.6). This one block gates PCAS; later cards extend it (the succession
		// API/orchestrator and the ee/succession/store migrations key off
		// deps.EnablePCAS). Unlicensed or core-only deployments run zero PCAS jobs.
		deps.EnablePCAS = true
		// Attach the PCAS external API (request-succession, chain fetch, RP acks)
		// through the feature-neutral route seam, composing with any other licensed
		// API routes (e.g. PQC migration) already registered.
		deps.LicensedAPIOptionsFactory = appendAPIFactory(deps.LicensedAPIOptionsFactory, eesuccessionapi.NewAPIOptionsFactory())
		// Register the PCAS succession worker on the server outbox dispatcher (INT-04),
		// composing with any other licensed outbox handler: a pcas.succession-request
		// message is drained here and minted over the signer transport, then recorded +
		// published; pcas.rp-publish is acknowledged. This makes the succession worker a
		// real production caller — a POST to request-succession now yields a record.
		deps.LicensedOutboxFactory = appendOutboxFactory(deps.LicensedOutboxFactory, eesuccessionorch.NewLicensedOutboxFactory())
		deps.LicensedBackgroundWorkers = append(deps.LicensedBackgroundWorkers, eesuccessionbackground.NewWorkers(eesuccessionbackground.Options{
			Store: deps.Store, Log: deps.Log, Signer: deps.Signer, PCAS: attachConfig(cfg).PCAS,
		})...)
		if log != nil {
			log.Info("Enterprise PCAS attached", slog.String("feature", string(license.FeaturePCAS)))
		}
	}
	if lic != nil && lic.Has(license.FeatureAgentDelegation) {
		attachAgentDelegation(cfg, log, deps)
	}
	if lic != nil && lic.Has(license.FeatureReconcile) {
		if err := attachReconcile(log, deps); err != nil {
			return err
		}
	}
	if lic != nil && lic.Has(license.FeatureVerifiableDecommission) {
		if err := attachVerifiableDecommission(log, deps); err != nil {
			return err
		}
	}
	if lic != nil && lic.Has(license.FeaturePQC) {
		attachPQC(log, deps)
	}
	if lic != nil && lic.Has(license.FeatureHASupport) {
		if err := attachFederation(ctx, cfg, log, deps); err != nil {
			return err
		}
	}
	return attachEEProviderPlane(ctx, cfg, log, lic, deps)
}

// attachAgentDelegation is the AGID stage of the attach seam, lifted out of
// attachEE as a named stage so the seam stays readable as the feature list
// grows (the startup-hotspot ratchet).
func attachAgentDelegation(cfg *config.Config, log *slog.Logger, deps *server.Deps) {
	{
		// AN-9 activation point for Agent Identity Lifecycle Enforcement (AGID, HARNESS
		// §1.6). This one block gates AGID; it attaches the feature-neutral chain-bound
		// broker issuance precondition (the ee/agentid delegation gate) via the core
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
		// Unlicensed or core-only deployments skip this block, attach no precondition, and
		// run zero chain-bound issuance while the free badge is unaffected.
		deps.BrokerIssuancePrecondition = eeagentbrokerstore.NewFailClosedBrokerPrecondition()
		// B-7: the AGID-05 task-envelope gate for the broker's single-hop path.
		// Until now only the chain-bound path could bind a credential to one
		// authorized task; the broker could not carry an envelope at all. The
		// gate reuses the same in-signer verification the delegation gate runs
		// (requester signature over canonical bytes, resolved through an
		// operator-provisioned trust store the caller cannot inject into, plus
		// the expiry window) and returns the digest the credential binds.
		// Unlicensed builds attach no gate, and the core REFUSES an
		// envelope-bearing request rather than issuing an unscoped credential
		// in its place.
		deps.BrokerTaskEnvelopeGate = eeagentdelegation.NewBrokerTaskEnvelopeGate(
			eeagentdelegation.NewDurableTaskEnvelopeTrustStore(cfg.Signer.KeyStoreDir).TrustLookup,
		)
		// AGID-INT-CALL: attach the AGID external API + the licensed-outbox worker so the two
		// AGID user journeys are reachable from this control-plane binary and every ee/agentid
		// mechanism gains a PRODUCTION CALLER (the reachability bar), mirroring the FeaturePCAS
		// block above. The API (request-issuance / request-revocation + read models) attaches
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
		deps.LicensedAPIOptionsFactory = appendAPIFactory(deps.LicensedAPIOptionsFactory, eeagentapi.NewAPIOptionsFactory())
		deps.LicensedOutboxFactory = appendOutboxFactory(deps.LicensedOutboxFactory, eeagentorch.NewLicensedOutboxFactory())
		if log != nil {
			log.Info("Enterprise agent delegation attached", slog.String("feature", string(license.FeatureAgentDelegation)))
		}
	}
}

// attachEEProviderPlane is the second stage of the attach seam: the BYOK,
// governance, and multi-tenant provider features. Same one-block-per-feature
// shape as attachEE; split only to keep either function readable.
func attachEEProviderPlane(ctx context.Context, cfg *config.Config, log *slog.Logger, lic *license.Manager, deps *server.Deps) error {
	if lic != nil && lic.Has(license.FeatureBYOK) {
		managedKeysConfig := attachConfig(cfg).ManagedKeys
		if managedKeysConfig.Enabled {
			// The factory receives only provider identity + the event/store spine.
			// Provider constructors and credentials live in trstctl-signer; the
			// licensed outbox handler is the sole ManageKey RPC caller (AN-4/AN-6).
			deps.ManagedKeyFactory = eemanagedkeys.NewDurableFactory(managedKeysConfig.Provider)
			deps.LicensedOutboxFactory = appendOutboxFactory(deps.LicensedOutboxFactory, eemanagedkeys.NewDurableOutboxFactory())
		}
		deps.KMIPFactory = eekmip.NewFactory()
		if log != nil {
			log.Info("Enterprise BYOK support attached", slog.String("feature", string(license.FeatureBYOK)))
		}
	}
	if lic != nil && lic.Has(license.FeatureGovernance) {
		deps.GovernanceFactory = eegovernance.NewFactory()
		deps.GovernancePolicySource = eegovernance.NewPolicySource(nil)
		if log != nil {
			log.Info("Enterprise governance support attached", slog.String("feature", string(license.FeatureGovernance)))
		}
	}
	if lic != nil && lic.Has(license.FeatureSiloedIsolation) {
		eesilo.InstallInMemory()
		if log != nil {
			log.Info("Provider siloed isolation attached", slog.String("feature", string(license.FeatureSiloedIsolation)))
		}
	}
	if lic != nil && lic.Has(license.FeatureProviderPlane) {
		deps.ProviderHandler = eeprovider.NewHandler(eeprovider.Config{
			License: lic,
			Audit:   eeprovider.NewEventLogAuditSink(deps.Log),
		})
		if log != nil {
			log.Info("Provider plane attached", slog.String("feature", string(license.FeatureProviderPlane)))
		}
	}
	if lic != nil && lic.Has(license.FeatureMetering) {
		eebilling.InstallInMemory(ctx, log, nil)
		if log != nil {
			log.Info("Provider metering attached", slog.String("feature", string(license.FeatureMetering)))
		}
	}
	if lic != nil && lic.Has(license.FeatureWhiteLabel) {
		eewhitelabel.InstallInMemory()
		if log != nil {
			log.Info("Provider white-label branding attached", slog.String("feature", string(license.FeatureWhiteLabel)))
		}
	}
	return nil
}

func attachPQC(log *slog.Logger, deps *server.Deps) {
	cryptoRuntime := eepqcruntime.NewRuntime()
	migrationRuntime := eepqcmigration.NewRuntime(deps.Store)
	deps.LicensedAPIOptionsFactory = appendAPIFactory(deps.LicensedAPIOptionsFactory, migrationRuntime.APIOptionsFactory)
	deps.LicensedOutboxFactory = appendOutboxFactory(deps.LicensedOutboxFactory, migrationRuntime.OutboxFactory)
	deps.LicensedProjectionOptions = append(deps.LicensedProjectionOptions, migrationRuntime.ProjectionOptions...)
	deps.LicensedLeafSigner = cryptoRuntime.LeafSigner
	deps.LicensedCSRInspector = cryptoRuntime.CSRInspector
	deps.LicensedCSRParser = cryptoRuntime.CSRParser
	deps.LicensedSPIFFESVIDFactory = cryptoRuntime.SPIFFESVIDFactory
	// CBOM licensed posture: name the FIPS-203/204/205 migration targets and
	// recognize post-quantum families the MPL core deliberately does not know,
	// so migration progress can count future-ready assets (A0.1).
	cbom.InstallLicensedPosture(eepqc.CBOMTargetFor, eepqc.CBOMClassifyKey)
	// Licensed algorithm classifier: post-quantum and hybrid labels become
	// valid certificate-profile `allowed_key_algorithms` entries and inventory
	// classifications (A0.3b). Unlicensed builds keep failing closed on them.
	crypto.InstallLicensedAlgorithmClassifier(eepqc.ClassifyAlgorithm)
	if log != nil {
		log.Info("Enterprise PQC attached", slog.String("feature", string(license.FeaturePQC)))
	}
}

func attachRemediation(log *slog.Logger, deps *server.Deps) {
	server.EnableRemediationEdition(deps)
	if log != nil {
		log.Info("Enterprise remediation attached", slog.String("feature", string(license.FeatureRemediation)))
	}
}

func attachVerifiableDecommission(log *slog.Logger, deps *server.Deps) error {
	// AN-9 activation point for VDEC. This one helper is called by the single
	// lic.Has(FeatureVerifiableDecommission) block; later cards extend it instead of
	// scattering license checks. Free blunt-destroy / zeroize stays outside this path.
	runtime, err := eedecommission.NewRuntime(eedecommission.RuntimeConfig{
		Store: deps.Store,
	})
	if err != nil {
		return err
	}
	deps.LicensedOutboxFactory = appendOutboxFactory(deps.LicensedOutboxFactory, runtime.ReprotectionOutboxFactory)
	if log != nil {
		log.Info("Enterprise VDEC attached", slog.String("feature", string(license.FeatureVerifiableDecommission)))
	}
	return nil
}

func attachFederation(ctx context.Context, cfg *config.Config, log *slog.Logger, deps *server.Deps) error {
	fedCfg := config.Federation{}
	if cfg != nil {
		fedCfg = cfg.Federation
	}
	resolved, err := eefederation.ConfigFromConfig(ctx, fedCfg)
	if err != nil {
		return err
	}
	var factory server.FederationFactory
	if resolved.Enabled {
		factory = eefederation.NewFactory(resolved)
	}
	deps.FederationFactory = factory
	if factory != nil && log != nil {
		log.Info("Enterprise HA support attached", slog.String("feature", string(license.FeatureHASupport)))
	}
	return nil
}

func attachReconcile(log *slog.Logger, deps *server.Deps) error {
	// AN-9 activation point for XREC. This helper is called only by the single
	// FeatureReconcile block in attachEE; later XREC cards extend it instead of
	// scattering license checks. Community and core-only builds schedule zero XREC rounds.
	runtime, err := eereconcile.NewRuntime(eereconcile.RuntimeConfig{
		Store:  deps.Store,
		Log:    deps.Log,
		Signer: deps.Signer,
	})
	if err != nil {
		return err
	}
	deps.IssuanceAdmission = runtime.IssuanceAdmission
	deps.LicensedProjectionOptions = append(deps.LicensedProjectionOptions, runtime.ProjectionOptions...)
	deps.LicensedBackgroundWorkers = append(deps.LicensedBackgroundWorkers, runtime.BackgroundWorkers...)
	deps.LicensedOutboxFactory = appendOutboxFactory(deps.LicensedOutboxFactory, runtime.RemediationOutboxFactory)
	deps.LicensedOutboxFactory = appendOutboxFactory(deps.LicensedOutboxFactory, runtime.QuarantineOutboxFactory)
	if log != nil {
		log.Info("Enterprise XREC reconciliation attached", slog.String("feature", string(license.FeatureReconcile)))
	}
	return nil
}

func attachConfig(cfg *config.Config) config.Config {
	if cfg == nil {
		return config.Config{}
	}
	return *cfg
}
