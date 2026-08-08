// SPDX-License-Identifier: MPL-2.0

//go:build !trstctl_core

package main

import (
	"os"
	"strings"
	"time"

	"context"
	"fmt"
	"io"
	"io/fs"
	"log/slog"

	"trstctl.com/trstctl/internal/audit"

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
	eepqccbom "trstctl.com/trstctl/ee/pqc/cbomposture"
	eepqcmigration "trstctl.com/trstctl/ee/pqcmigration"
	eepqcruntime "trstctl.com/trstctl/ee/pqcruntime"
	eeprovider "trstctl.com/trstctl/ee/provider"
	eereconcile "trstctl.com/trstctl/ee/reconcile"
	eereconcileapi "trstctl.com/trstctl/ee/reconcile/api"
	eereconcileplanremediation "trstctl.com/trstctl/ee/reconcile/plan/remediation"
	"trstctl.com/trstctl/ee/reconcile/rounds"
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
	corestore "trstctl.com/trstctl/internal/store"
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
// eeLocalCommand dispatches EE-only local subcommands.
//
// `provider-grant` is the bootstrap path for delegation (L1). Without it the
// gate is unreachable in the other direction: the plane refuses every
// customer-scoped action until operators hold grants, and nothing could create
// one — a refusal nobody can lift is an outage, not a control.
//
// It is a LOCAL subcommand against the database, not a served route, because of
// the bootstrap problem: a route handing out provider authority must itself be
// authorised by somebody holding provider authority, and at install time no
// such operator exists. Requiring direct database access states the real trust
// level instead of inventing a self-referential API gate.
func eeLocalCommand(ctx context.Context, args []string, getenv func(string) string, stdout, stderr io.Writer) (bool, error) {
	if len(args) == 0 || args[0] != "provider-grant" {
		return false, nil
	}
	cfg, err := config.Load(getenv)
	if err != nil {
		return true, fmt.Errorf("configuration: %w", err)
	}
	return true, eeprovider.RunGrantCommand(ctx, cfg.Postgres.DSN, args[1:], stdout, stderr)
}

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
		if err := attachReconcile(cfg, log, deps); err != nil {
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
		// L4: durable silo placement. InstallInMemory reverted every tenant to
		// the shared isolation default on restart, SILENTLY — a customer who
		// bought hard isolation had it until the first deploy.
		eesilo.InstallDurable(deps.Store)
		if log != nil {
			log.Info("Provider siloed isolation attached", slog.String("feature", string(license.FeatureSiloedIsolation)))
		}
	}
	// L3/AUD-14: durable branding, installed BEFORE the provider block so the
	// provider console's brand-set route can write through the same store and
	// invalidate the same resolver. InstallDurable lost a provider's brand on
	// every deploy SILENTLY — their customers went back to seeing our product
	// name with nothing saying why.
	var brandInstall *eewhitelabel.Installation
	if lic != nil && lic.Has(license.FeatureWhiteLabel) {
		brandInstall = eewhitelabel.InstallDurable(deps.Store)
		if log != nil {
			log.Info("Provider white-label branding attached", slog.String("feature", string(license.FeatureWhiteLabel)))
		}
	}
	if lic != nil && lic.Has(license.FeatureProviderPlane) {
		// L1: the operator authenticator, federated to the provider's own IdP.
		// Unconfigured means NIL, and a nil authenticator REFUSES EVERY
		// REQUEST — closed-until-wired is the only safe state, and shipping a
		// placeholder verifier here is exactly how the original
		// accept-anything bypass came to exist. The JWKS is pinned OFFLINE:
		// this plane must not fetch keys from a URL the token's minter might
		// also control.
		var operatorAuth eeprovider.OperatorAuthenticator
		if cfg.Provider.OIDC.Configured() {
			jwksJSON := cfg.Provider.OIDC.JWKSJSON
			if path := strings.TrimSpace(cfg.Provider.OIDC.JWKSFile); path != "" {
				raw, readErr := os.ReadFile(path) // #nosec G304 -- operator-supplied path to their own IdP's JWKS (CWE-22)
				if readErr != nil {
					return fmt.Errorf("provider.oidc.jwks_file: %w", readErr)
				}
				jwksJSON = string(raw)
			}
			jwks, parseErr := crypto.ParseJWKS([]byte(jwksJSON))
			if parseErr != nil {
				return fmt.Errorf("provider.oidc jwks: %w", parseErr)
			}
			auth := eeprovider.NewOIDCAuthenticator(eeprovider.OIDCAuthenticatorConfig{
				Issuer:         cfg.Provider.OIDC.Issuer,
				Audience:       cfg.Provider.OIDC.Audience,
				JWKS:           jwks,
				RoleClaim:      cfg.Provider.OIDC.RoleClaim,
				AdminValues:    cfg.Provider.OIDC.AdminValues,
				OperatorValues: cfg.Provider.OIDC.OperatorValues,
				MFAClaim:       cfg.Provider.OIDC.MFAClaim,
				MFAValues:      cfg.Provider.OIDC.MFAValues,
			})
			if auth != nil {
				operatorAuth = auth
			}
		}
		// L1: the delegation source. Without it the rule in
		// ee/provider/delegation.go was a library nothing called, and every
		// served provider route still authorised any authenticated operator
		// against any customer. The constructor returns nil with no database,
		// and a nil source refuses every customer-scoped action — the same
		// closed-until-wired stance as the authenticator.
		delegations := eeprovider.NewPGDelegationSource(deps.Store)
		deps.ProviderHandler = eeprovider.NewHandler(eeprovider.Config{
			License: lic,
			// L3: durable tenant registry. Nil defaulted to MemStore, so the
			// provider's whole customer list vanished on every deploy — the
			// registry they run their business from, lost silently.
			Store:         eeprovider.NewPGStore(deps.Store),
			Audit:         eeprovider.NewEventLogAuditSink(deps.Log),
			Authenticator: operatorAuth,
			Delegations:   delegations,
			// L2: quota administration writes through the same durable store
			// the checker reads, behind the per-customer delegation gate. Nil
			// would refuse every quota write — correct, but only for a
			// deployment with no Postgres, which this branch has.
			Quotas: eebilling.NewPGStore(deps.Store),
			// L3: brand administration writes through the durable white-label
			// store and invalidates its resolver, behind the same delegation
			// gate. Nil when white-label is not licensed, which refuses every
			// brand write — a brand nobody can resolve is not white-label.
			Brands: providerBrandStore(brandInstall),
			// L3: the on-demand isolation drill runs the core store's real
			// cross-tenant read/write proof so a provider operator can attest,
			// at any moment, that tenant isolation holds.
			Drills: isolationDrillerAdapter{store: deps.Store},
		})
		if log != nil {
			// Says what an operator will actually observe. "Attached" alone
			// would read as working, and the first symptom would be 401s with
			// no explanation anywhere.
			if operatorAuth == nil {
				log.Warn("Provider plane attached but NO operator authenticator is configured; "+
					"/provider/ will refuse every request until provider.oidc is wired",
					slog.String("feature", string(license.FeatureProviderPlane)))
			} else {
				log.Info("Provider plane attached with OIDC operator federation",
					slog.String("issuer", cfg.Provider.OIDC.Issuer),
					slog.String("feature", string(license.FeatureProviderPlane)))
			}
			if delegations == nil {
				// Two separate silences to break. An operator who wires
				// authentication and still gets 403 needs to be told the second
				// gate exists, or they read a working plane as broken.
				log.Warn("Provider plane has NO delegation source; every customer-scoped action "+
					"will be refused until operators are granted customers",
					slog.String("feature", string(license.FeatureProviderPlane)))
			}
		}
	}
	if lic != nil && lic.Has(license.FeatureMetering) {
		// L2: durable metering. InstallInMemory lost usage on every restart
		// SILENTLY, so a provider invoiced from a figure that was quietly short.
		// The durable path records what it observed, which is what lets invoice
		// evidence be signed at all.
		// The counter makes quotas REAL: it answers "how many does this tenant
		// have right now", which is what a stored-resource cap compares
		// against. It was nil before, so AllowCreate compared every tenant
		// against a permanent zero and no cap could ever bind.
		billingInst := eebilling.InstallDurable(ctx, log, eebilling.StoreTenantCounter(deps.Store), deps.Store)
		// L2: the served evidence route. Without this the document builder and
		// the durable meters exist and no provider can ever pull an invoice —
		// the defect class this backlog keeps finding.
		//
		// Mounted unconditionally. On an in-memory fallback the MemStore reports
		// coverage as not durable, so the route answers with an UNSIGNABLE
		// document that says why — which is the fact an operator needs. Leaving
		// it unmounted would answer 404 and read as "no such feature" on a
		// deployment that is metering.
		var evidenceReader eebilling.EvidenceReader = billingInst.Store
		var reconciler eebilling.EvidenceReconciler
		if billingInst.PG != nil {
			evidenceReader = billingInst.PG
			// The reconciler recounts the period from identity_transitions —
			// the event log's projection — so the document can say the meter
			// and the log agree before anything is signed.
			reconciler = billingInst.PG
		}
		// The evidence signature uses the SAME audit-export key as every other
		// auditor-facing export (J1, the doctor receipt), so a finance team
		// verifies invoices and audit bundles against one public key.
		var evidenceSigner eebilling.EvidenceSigner
		if auditKey, keyErr := audit.LoadOrCreateSigningKey(cfg.Audit.SigningKeyFile, "audit-export"); keyErr != nil {
			if log != nil {
				log.Warn("invoice evidence will be served UNSIGNABLE: the audit signing key could not be loaded",
					slog.String("error", keyErr.Error()))
			}
		} else {
			evidenceSigner = &eebilling.AuditKeySigner{Key: auditKey}
		}
		deps.LicensedAPIOptionsFactory = appendAPIFactory(deps.LicensedAPIOptionsFactory,
			eebilling.NewAPIOptionsFactory(eebilling.EvidenceDeps{
				Reader: evidenceReader, Reconciler: reconciler, Signer: evidenceSigner,
			}))
		if log != nil {
			log.Info("Provider metering attached", slog.String("feature", string(license.FeatureMetering)))
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
	cbom.InstallLicensedPosture(eepqccbom.CBOMTargetFor, eepqccbom.CBOMClassifyKey)
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

func attachReconcile(cfg *config.Config, log *slog.Logger, deps *server.Deps) error {
	// AN-9 activation point for XREC. This helper is called only by the single
	// FeatureReconcile block in attachEE; later XREC cards extend it instead of
	// scattering license checks. Community and core-only builds schedule zero XREC rounds.
	runtime, err := eereconcile.NewRuntime(eereconcile.RuntimeConfig{
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
		eereconcileapi.NewAPIOptionsFactory(runtime.DriftProjection, runtime.RoundsScheduled))
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

// providerBrandStore adapts the durable white-label installation to the
// provider plane's BrandStore (L3). It lives in the attach seam because only
// here may both ee/provider and ee/whitelabel be imported without an edition
// cycle. A nil installation (white-label unlicensed) yields a nil store, and a
// nil BrandStore makes the provider's SetTenantBrand refuse — fail closed.
func providerBrandStore(inst *eewhitelabel.Installation) eeprovider.BrandStore {
	if inst == nil || inst.PG == nil {
		return nil
	}
	return brandStoreAdapter{inst: inst}
}

type brandStoreAdapter struct{ inst *eewhitelabel.Installation }

func (a brandStoreAdapter) SetTenantBrand(ctx context.Context, b eeprovider.TenantBrand) error {
	if err := a.inst.PG.SetTenantBrand(ctx, eewhitelabel.Record{
		TenantID:      b.TenantID,
		ProductName:   b.ProductName,
		LogoDataURI:   b.LogoDataURI,
		LoginMessage:  b.LoginMessage,
		EmailFromName: b.EmailFromName,
		EmailFooter:   b.EmailFooter,
		CustomDomain:  b.CustomDomain,
	}); err != nil {
		return err
	}
	// Invalidate the resolver cache so the new brand resolves immediately
	// rather than after the cache TTL — a provider who just set a customer's
	// brand expects to see it, not to wait a minute wondering if it took.
	if a.inst.Resolver != nil {
		a.inst.Resolver.Invalidate()
	}
	return nil
}

// isolationDrillerAdapter adapts the core store's isolation drill to the
// provider plane's IsolationDriller (L3), mapping the store's report type to the
// provider's so the plane holds no dependency on the store's internals. It lives
// in the attach seam for the same reason the brand adapter does: only here may
// both ee/provider and the core store be named without an edition cycle.
type isolationDrillerAdapter struct{ store *corestore.Store }

func (a isolationDrillerAdapter) RunIsolationDrill(ctx context.Context) (eeprovider.IsolationDrillReport, error) {
	r, err := a.store.RunIsolationDrill(ctx)
	if err != nil {
		return eeprovider.IsolationDrillReport{}, err
	}
	out := eeprovider.IsolationDrillReport{Passed: r.Passed}
	for _, c := range r.Checks {
		out.Checks = append(out.Checks, eeprovider.IsolationDrillCheck{Name: c.Name, Passed: c.Passed, Detail: c.Detail})
	}
	return out, nil
}
