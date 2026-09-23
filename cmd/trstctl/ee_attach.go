// SPDX-License-Identifier: BUSL-1.1

//go:build !trstctl_core

package main

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"strings"

	_ "trstctl.com/trstctl/ee"
	eebilling "trstctl.com/trstctl/ee/billing"
	eeenterpriseauth "trstctl.com/trstctl/ee/enterpriseauth"
	eefederation "trstctl.com/trstctl/ee/federation"
	eegovernance "trstctl.com/trstctl/ee/governance"
	eemanagedkeys "trstctl.com/trstctl/ee/managedkeys"
	eeprovider "trstctl.com/trstctl/ee/provider"
	eesilo "trstctl.com/trstctl/ee/silo"
	eewhitelabel "trstctl.com/trstctl/ee/whitelabel"
	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/crypto"
	cryptosamlsp "trstctl.com/trstctl/internal/crypto/samlsp"
	"trstctl.com/trstctl/internal/crypto/secret"
	"trstctl.com/trstctl/internal/crypto/secretfile"
	"trstctl.com/trstctl/internal/events"
	eekmip "trstctl.com/trstctl/internal/kmip"
	"trstctl.com/trstctl/internal/license"
	"trstctl.com/trstctl/internal/orchestrator"
	"trstctl.com/trstctl/internal/projections"
	"trstctl.com/trstctl/internal/server"
	corestore "trstctl.com/trstctl/internal/store"
)

// attachEE is the single sanctioned ee/ seam: one lic.Has(feature) block per
// licensed capability. The core families (PCAS, AGID, XREC, VDEC, PQC) are not
// here any more; attach_families.go wires them in every build.
// eeLocalCommand dispatches EE-only local subcommands.
//
// `provider-grant` is the bootstrap path for delegation (L1). Without it the
// gate is unreachable in the other direction: the plane refuses every
// customer-scoped action until operators hold grants, and nothing could create
// one — a refusal nobody can lift is an outage, not a control.
//
// It is a LOCAL subcommand against the database, not a served route, because of
// the bootstrap problem: a route handing out provider authority must itself be
// authorized by somebody holding provider authority, and at install time no
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
	return true, eeprovider.RunGrantCommand(ctx, cfg.Postgres.DSN, cfg.NATS, args[1:], stdout, stderr)
}

// attachEEProjectionOptions is the one-shot recovery twin of attachEE's
// projection wiring. It is passed only from the tagged composition root; core
// remains feature-neutral and the trstctl_core twin returns no options.
func attachEEProjectionOptions(
	ctx context.Context,
	_ *config.Config,
	lic *license.Manager,
	st *corestore.Store,
	log *events.Log,
) ([]projections.Option, error) {
	if lic == nil || !lic.Has(license.FeatureProviderPlane) {
		return nil, nil
	}
	if st == nil || log == nil {
		return nil, errors.New("provider recovery projection requires PostgreSQL and the event log")
	}
	runtime := eeprovider.NewAuthorityRuntime(st, log)
	if err := runtime.Bootstrap(ctx); err != nil {
		return nil, fmt.Errorf("bootstrap provider authority before recovery rebuild: %w", err)
	}
	return runtime.ProjectionOptions, nil
}

func attachEE(ctx context.Context, cfg *config.Config, log *slog.Logger, lic *license.Manager, deps *server.Deps) error {
	if lic != nil && lic.Has(license.FeatureEnterpriseSSO) {
		deps.TenantAuthFactory = eeenterpriseauth.Build
	}
	if err := requireTenantAuthAttachment(cfg, deps); err != nil {
		return err
	}

	if lic != nil && lic.Has(license.FeatureHASupport) {
		if err := attachFederation(ctx, cfg, log, deps); err != nil {
			return err
		}
	}
	return attachEEProviderPlane(ctx, cfg, log, lic, deps)
}

// attachEEProviderPlane is the second stage of the attach seam: the BYOK,
// governance, and multi-tenant provider features. Same one-block-per-feature
// shape as attachEE; split only to keep either function readable.
func attachEEProviderPlane(ctx context.Context, cfg *config.Config, log *slog.Logger, lic *license.Manager, deps *server.Deps) error {
	attachEEProviderBYOK(cfg, log, lic, deps)
	attachEEProviderGovernance(log, lic, deps)
	siloInstall := attachEEProviderSilo(log, lic, deps)
	brandInstall := attachEEProviderBrand(log, lic, deps)
	billingEvidence, err := attachEEProviderMetering(ctx, log, lic, deps)
	if err != nil {
		return err
	}
	if err := attachEEProviderAPI(ctx, cfg, log, lic, deps, siloInstall, brandInstall, billingEvidence); err != nil {
		return err
	}
	return nil
}

// Each helper below owns one license block. Keeping the blocks separate makes
// the edition boundary easy to audit while preserving attachEEProviderPlane's
// order: foundations first, metering authority second, Provider API consumer
// last. That lets both the tenant and Provider routes share one exact evidence
// dependency set instead of constructing signing truth twice.
func attachEEProviderBYOK(cfg *config.Config, log *slog.Logger, lic *license.Manager, deps *server.Deps) {
	if lic == nil || !lic.Has(license.FeatureBYOK) {
		return
	}
	managedKeysConfig := attachConfig(cfg).ManagedKeys
	if managedKeysConfig.Enabled {
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

func attachEEProviderGovernance(log *slog.Logger, lic *license.Manager, deps *server.Deps) {
	if lic == nil || !lic.Has(license.FeatureGovernance) {
		return
	}
	deps.GovernanceFactory = eegovernance.NewFactory()
	deps.GovernancePolicySource = eegovernance.NewPolicySource(nil)
	if log != nil {
		log.Info("Enterprise governance support attached", slog.String("feature", string(license.FeatureGovernance)))
	}
}

func attachEEProviderSilo(log *slog.Logger, lic *license.Manager, deps *server.Deps) *eesilo.Installation {
	// siloInstall is captured so the provider isolation drill can drive the
	// LIVE event-lane checks over the same registry and router the deployment
	// routes with. Nil when siloed isolation is not licensed — the drill then
	// runs the store dimensions only, claiming nothing about lanes that do not
	// exist.
	if lic == nil || !lic.Has(license.FeatureSiloedIsolation) {
		return nil
	}
	// InstallInMemory reverted every tenant to the shared isolation default on
	// restart. The durable installation keeps the operator's L4 placement.
	siloInstall := eesilo.InstallDurable(deps.Store)
	if log != nil {
		log.Info("Provider siloed isolation attached", slog.String("feature", string(license.FeatureSiloedIsolation)))
	}
	return siloInstall
}

func attachEEProviderBrand(log *slog.Logger, lic *license.Manager, deps *server.Deps) *eewhitelabel.Installation {
	// L3/AUD-14: durable branding, installed BEFORE the provider block so the
	// provider console's brand-set route can write through the same store and
	// invalidate the same resolver. InstallDurable lost a provider's brand on
	// every deploy SILENTLY — their customers went back to seeing our product
	// name with nothing saying why.
	if lic == nil || !lic.Has(license.FeatureWhiteLabel) {
		return nil
	}
	brandInstall := eewhitelabel.InstallDurable(deps.Store)
	if log != nil {
		log.Info("Provider white-label branding attached", slog.String("feature", string(license.FeatureWhiteLabel)))
	}
	return brandInstall
}

func attachEEProviderAPI(
	ctx context.Context,
	cfg *config.Config,
	log *slog.Logger,
	lic *license.Manager,
	deps *server.Deps,
	siloInstall *eesilo.Installation,
	brandInstall *eewhitelabel.Installation,
	billingEvidence providerBillingEvidence,
) error {
	if lic == nil || !lic.Has(license.FeatureProviderPlane) {
		return nil
	}
	// One event-projected directory is the request-time leaver gate for BOTH
	// cryptographic identity methods. Without SCIM, legacy OIDC remains usable;
	// when SCIM is enabled an absent/inactive row refuses even a valid token.
	deps.TenantServiceCheck = eeprovider.NewPGStore(deps.Store).RequireCustomerService
	access := eeprovider.NewPGAccessStore(deps.Store)
	operatorAuthenticators := eeprovider.AnyAuthenticator{}
	oidc, err := providerOIDCAuthenticator(cfg, access)
	if err != nil {
		return err
	}
	if oidc != nil {
		operatorAuthenticators = append(operatorAuthenticators, oidc)
	}
	// Delegations and durable stores fail closed when PostgreSQL is unavailable.
	delegations := eeprovider.NewPGDelegationSource(deps.Store)
	var authorityRuntime *eeprovider.AuthorityRuntime
	if deps.Store != nil && deps.Log != nil {
		authorityRuntime = eeprovider.NewAuthorityRuntime(deps.Store, deps.Log)
		if err := authorityRuntime.Bootstrap(ctx); err != nil {
			return fmt.Errorf("bootstrap provider authority event history: %w", err)
		}
		deps.LicensedProjectionOptions = append(deps.LicensedProjectionOptions, authorityRuntime.ProjectionOptions...)
	}
	var authorityMutations eeprovider.MutationSink
	var providerIdempotency *orchestrator.Idempotency
	if authorityRuntime != nil {
		authorityMutations = authorityRuntime.Mutations
		providerIdempotency = orchestrator.NewIdempotency(deps.Store,
			orchestrator.WithResultProtector(deps.IdempotencyResultProtector))
	}
	samlAuth, err := providerSAMLAuthenticator(cfg, access)
	if err != nil {
		return err
	}
	if samlAuth != nil {
		operatorAuthenticators = append(operatorAuthenticators, samlAuth)
	}
	var operatorAuth eeprovider.OperatorAuthenticator
	if len(operatorAuthenticators) > 0 {
		operatorAuth = operatorAuthenticators
	}
	providerSCIM, err := providerSCIMConfig(cfg)
	if err != nil {
		return err
	}
	if deps.RestoreDrill != nil {
		deps.RestoreDrill = server.RestoreDrillRunner(cfg, attachEEProjectionOptions)
	}
	deps.ProviderHandler = eeprovider.NewHandler(eeprovider.Config{
		License:                  lic,
		Store:                    eeprovider.NewPGStore(deps.Store),
		Audit:                    eeprovider.NewEventLogAuditSink(deps.Log),
		Mutations:                authorityMutations,
		Activity:                 eeprovider.NewEventLogActivitySource(deps.Log),
		Idempotency:              providerIdempotency,
		Authenticator:            operatorAuth,
		Delegations:              delegations,
		Access:                   access,
		SAML:                     samlAuth,
		SCIM:                     providerSCIM,
		Telemetry:                eeprovider.NewPGStore(deps.Store),
		Quotas:                   eebilling.NewPGStore(deps.Store),
		Evidence:                 billingEvidence.deps,
		EvidenceVerificationJWKS: billingEvidence.verificationJWKS,
		Brands:                   providerBrandStore(brandInstall),
		Drills:                   isolationDrillerAdapter{store: deps.Store, lanes: laneDrillFor(siloInstall, deps.Log)},
	})
	if log == nil {
		return nil
	}
	if operatorAuth == nil {
		log.Warn("Provider plane attached but NO operator authenticator is configured; "+
			"/provider/ will refuse every operator request until provider.oidc or provider.saml is wired",
			slog.String("feature", string(license.FeatureProviderPlane)))
	} else {
		log.Info("Provider plane attached with verified operator federation",
			slog.Bool("oidc", cfg.Provider.OIDC.Configured()), slog.Bool("saml", cfg.Provider.SAML.Enabled),
			slog.Bool("scim_lifecycle", cfg.Provider.SCIM.Enabled),
			slog.String("feature", string(license.FeatureProviderPlane)))
	}
	if delegations == nil {
		log.Warn("Provider plane has NO delegation source; every customer-scoped action "+
			"will be refused until operators are granted customers",
			slog.String("feature", string(license.FeatureProviderPlane)))
	}
	return nil
}

func providerOIDCAuthenticator(
	cfg *config.Config,
	directory eeprovider.OperatorDirectory,
) (*eeprovider.OIDCAuthenticator, error) {
	if !cfg.Provider.OIDC.Configured() {
		return nil, nil
	}
	jwksJSON := cfg.Provider.OIDC.JWKSJSON
	if path := strings.TrimSpace(cfg.Provider.OIDC.JWKSFile); path != "" {
		raw, err := os.ReadFile(path) // #nosec G304 -- operator-supplied path to their own IdP's JWKS (CWE-22)
		if err != nil {
			return nil, fmt.Errorf("provider.oidc.jwks_file: %w", err)
		}
		jwksJSON = string(raw)
	}
	jwks, err := crypto.ParseJWKS([]byte(jwksJSON))
	if err != nil {
		return nil, fmt.Errorf("provider.oidc jwks: %w", err)
	}
	return eeprovider.NewOIDCAuthenticator(eeprovider.OIDCAuthenticatorConfig{
		Issuer: cfg.Provider.OIDC.Issuer, Audience: cfg.Provider.OIDC.Audience, JWKS: jwks,
		RoleClaim: cfg.Provider.OIDC.RoleClaim, AdminValues: cfg.Provider.OIDC.AdminValues,
		OperatorValues: cfg.Provider.OIDC.OperatorValues, MFAClaim: cfg.Provider.OIDC.MFAClaim,
		MFAValues: cfg.Provider.OIDC.MFAValues, Directory: directory,
		RequireDirectory: cfg.Provider.SCIM.Enabled,
	}), nil
}

func providerSAMLAuthenticator(
	cfg *config.Config,
	directory eeprovider.OperatorDirectory,
) (*eeprovider.SAMLAuthenticator, error) {
	if !cfg.Provider.SAML.Enabled {
		return nil, nil
	}
	metadata := cfg.Provider.SAML.IDPMetadataXML
	if path := strings.TrimSpace(cfg.Provider.SAML.IDPMetadataFile); path != "" {
		raw, err := os.ReadFile(path) // #nosec G304 -- operator-pinned local IdP metadata, validated as configuration.
		if err != nil {
			return nil, fmt.Errorf("provider.saml.idp_metadata_file: %w", err)
		}
		metadata = string(raw)
	}
	sp, err := cryptosamlsp.NewServiceProvider(cryptosamlsp.Config{
		EntityID: cfg.Provider.SAML.EntityID, MetadataURL: cfg.Provider.SAML.MetadataURL,
		ACSURL: cfg.Provider.SAML.ACSURL, IDPMetadataXML: metadata, RequireRequestCorrelation: true,
	})
	if err != nil {
		return nil, fmt.Errorf("provider.saml: %w", err)
	}
	sessionSecret, err := secretfile.LoadOrCreate(cfg.Provider.SAML.SessionSecretFile, func() ([]byte, error) {
		return crypto.RandomBytes(32)
	})
	if err != nil {
		return nil, fmt.Errorf("provider.saml.session_secret_file: %w", err)
	}
	if len(sessionSecret) < 32 {
		secret.Wipe(sessionSecret)
		return nil, errors.New("provider.saml.session_secret_file must contain at least 32 bytes")
	}
	ttl, err := cfg.Provider.SAML.SessionTTLDuration()
	if err != nil {
		secret.Wipe(sessionSecret)
		return nil, fmt.Errorf("provider.saml.session_ttl: %w", err)
	}
	auth := eeprovider.NewSAMLAuthenticator(eeprovider.SAMLAuthenticatorConfig{
		Provider: sp, SubjectAttribute: cfg.Provider.SAML.SubjectAttribute,
		EmailAttribute: cfg.Provider.SAML.EmailAttribute, RoleAttribute: cfg.Provider.SAML.RoleAttribute,
		AdminValues: cfg.Provider.SAML.AdminValues, OperatorValues: cfg.Provider.SAML.OperatorValues,
		MFAAttribute: cfg.Provider.SAML.MFAAttribute, MFAValues: cfg.Provider.SAML.MFAValues,
		Directory: directory, RequireDirectory: cfg.Provider.SCIM.Enabled,
		SessionSecret: sessionSecret, SessionTTL: ttl, LoginRedirect: cfg.Provider.SAML.LoginRedirect,
		Secure: cfg.Server.TLS.Mode != config.TLSDisabled || strings.HasPrefix(strings.ToLower(cfg.Provider.SAML.ACSURL), "https://"),
	})
	if auth == nil {
		secret.Wipe(sessionSecret)
		return nil, errors.New("provider.saml configuration did not produce an authenticator")
	}
	// The authenticator owns sessionSecret for its lifetime; it is []byte and
	// never converted to or logged as an immutable string (AN-8).
	return auth, nil
}

func providerSCIMConfig(cfg *config.Config) (*eeprovider.SCIMConfig, error) {
	if !cfg.Provider.SCIM.Enabled {
		return nil, nil
	}
	result := &eeprovider.SCIMConfig{}
	seen := map[string]bool{}
	for index, token := range cfg.Provider.SCIM.Tokens {
		raw, err := secretfile.Load(token.TokenFile)
		if err != nil {
			return nil, fmt.Errorf("provider.scim.tokens[%d].token_file: %w", index, err)
		}
		trimmed := bytes.TrimSpace(raw)
		if len(trimmed) == 0 {
			secret.Wipe(raw)
			return nil, fmt.Errorf("provider.scim.tokens[%d].token_file is empty", index)
		}
		hash := crypto.SHA256Hex(trimmed)
		secret.Wipe(raw)
		if seen[hash] {
			return nil, fmt.Errorf("provider.scim.tokens[%d] duplicates another token", index)
		}
		seen[hash] = true
		result.Tokens = append(result.Tokens, eeprovider.SCIMToken{Name: token.Name, TokenHash: hash})
	}
	return result, nil
}

type providerBillingEvidence struct {
	deps             eebilling.EvidenceDeps
	verificationJWKS []byte
}

func attachEEProviderMetering(ctx context.Context, log *slog.Logger, lic *license.Manager, deps *server.Deps) (providerBillingEvidence, error) {
	if lic == nil || !lic.Has(license.FeatureMetering) {
		return providerBillingEvidence{}, nil
	}
	// The durable meter compares quotas against current tenant resources and
	// keeps invoice coverage through restarts.
	billingInst := eebilling.InstallDurable(ctx, log, eebilling.StoreTenantCounter(deps.Store), deps.Store)
	var evidenceReader eebilling.EvidenceReader = billingInst.Store
	var reconciler eebilling.EvidenceReconciler
	if billingInst.PG != nil {
		evidenceReader = billingInst.PG
		// Reconciliation recounts the period from the event-log projection, so
		// signed evidence can state that the meter and the log agree.
		reconciler = billingInst.PG
	}
	var evidenceSigner eebilling.EvidenceSigner
	var verificationJWKS []byte
	if deps.AuditSigningKey == nil {
		if log != nil {
			log.Warn("invoice evidence will be served UNSIGNABLE: the signer-bound audit evidence key is unavailable")
		}
	} else {
		evidenceSigner = &eebilling.AuditKeySigner{Key: deps.AuditSigningKey}
		var err error
		verificationJWKS, err = deps.AuditSigningKey.PublicJWKS()
		if err != nil {
			return providerBillingEvidence{}, fmt.Errorf("publish invoice evidence verification keys: %w", err)
		}
	}
	// All auditor-facing exports share the signer-bound audit-evidence key.
	evidenceDeps := eebilling.EvidenceDeps{
		Reader: evidenceReader, Reconciler: reconciler, Signer: evidenceSigner,
	}
	deps.LicensedAPIOptionsFactory = appendAPIFactory(deps.LicensedAPIOptionsFactory,
		eebilling.NewAPIOptionsFactory(evidenceDeps))
	if log != nil {
		log.Info("Provider metering attached", slog.String("feature", string(license.FeatureMetering)))
	}
	return providerBillingEvidence{deps: evidenceDeps, verificationJWKS: verificationJWKS}, nil
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

// providerBrandStore adapts the durable white-label installation's cache to
// the provider plane. The event projection owns PostgreSQL writes; this seam
// only makes a committed brand visible immediately.
func providerBrandStore(inst *eewhitelabel.Installation) eeprovider.BrandStore {
	if inst == nil || inst.PG == nil {
		return nil
	}
	return brandStoreAdapter{inst: inst}
}

type brandStoreAdapter struct{ inst *eewhitelabel.Installation }

func (a brandStoreAdapter) Invalidate() {
	if a.inst.Resolver != nil {
		a.inst.Resolver.Invalidate()
	}
}

// isolationDrillerAdapter adapts the core store's isolation drill to the
// provider plane's IsolationDriller (L3), mapping the store's report type to the
// provider's so the plane holds no dependency on the store's internals. It lives
// in the attach seam for the same reason the brand adapter does: only here may
// both ee/provider and the core store be named without an edition cycle.
type isolationDrillerAdapter struct {
	store *corestore.Store
	// lanes is the L4 live event-lane dimension; nil when siloed isolation is
	// not installed or no event log is up, in which case the drill truthfully
	// reports only the dimensions the deployment has.
	lanes *eesilo.LaneDrill
}

// laneDrillFor builds the event-lane drill only when its whole substrate
// exists: a DURABLE silo installation (lanes are a siloed-isolation concept)
// and the deployment's event log. Anything less returns nil rather than a
// drill that would fail on absence and read as a broken deployment.
func laneDrillFor(install *eesilo.Installation, log *events.Log) *eesilo.LaneDrill {
	if install == nil || !install.Durable || install.PG == nil || install.Router == nil || log == nil {
		return nil
	}
	return eesilo.NewLaneDrill(install.PG, install.Router, log)
}

func (a isolationDrillerAdapter) RunIsolationDrill(ctx context.Context) (eeprovider.IsolationDrillReport, error) {
	r, err := a.store.RunIsolationDrill(ctx)
	if err != nil {
		return eeprovider.IsolationDrillReport{}, err
	}
	if a.lanes != nil {
		// The lane checks join the same report: one drill, one attestation,
		// every dimension the deployment actually has (L4).
		laneChecks := a.lanes.Run(ctx)
		r.Checks = append(r.Checks, laneChecks...)
		for _, c := range laneChecks {
			if !c.Passed {
				r.Passed = false
			}
		}
	}
	out := eeprovider.IsolationDrillReport{Passed: r.Passed}
	for _, c := range r.Checks {
		out.Checks = append(out.Checks, eeprovider.IsolationDrillCheck{Name: c.Name, Passed: c.Passed, Detail: c.Detail})
	}
	return out, nil
}
