// SPDX-License-Identifier: MPL-2.0

//go:build !trstctl_core

package main

import (
	"context"
	"log/slog"

	_ "trstctl.com/trstctl/ee"
	eebilling "trstctl.com/trstctl/ee/billing"
	eefederation "trstctl.com/trstctl/ee/federation"
	eegovernance "trstctl.com/trstctl/ee/governance"
	eekmip "trstctl.com/trstctl/ee/kmip"
	eemanagedkeys "trstctl.com/trstctl/ee/managedkeys"
	eepqc "trstctl.com/trstctl/ee/pqc"
	eepqcmigration "trstctl.com/trstctl/ee/pqcmigration"
	eeprovider "trstctl.com/trstctl/ee/provider"
	eesilo "trstctl.com/trstctl/ee/silo"
	eesuccessionapi "trstctl.com/trstctl/ee/succession/api"
	eesuccessionorch "trstctl.com/trstctl/ee/succession/orchestrator"
	eewhitelabel "trstctl.com/trstctl/ee/whitelabel"
	"trstctl.com/trstctl/internal/api"
	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/editionseam"
	"trstctl.com/trstctl/internal/license"
	"trstctl.com/trstctl/internal/orchestrator"
	"trstctl.com/trstctl/internal/server"
)

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

// attachEE is the single sanctioned open-core seam. S-E0 attaches no features:
// the table is empty and behavior stays Community. Later cards add exactly one
// lic.Has(feature) block per gated capability here.
func attachEE(ctx context.Context, cfg *config.Config, log *slog.Logger, lic *license.Manager, deps *server.Deps) error {
	if lic != nil && lic.Has(license.FeatureRemediation) {
		deps.EnableRemediation = true
		if log != nil {
			log.Info("Enterprise remediation attached", slog.String("feature", string(license.FeatureRemediation)))
		}
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
		if log != nil {
			log.Info("Enterprise PCAS attached", slog.String("feature", string(license.FeaturePCAS)))
		}
	}
	if lic != nil && lic.Has(license.FeaturePQC) {
		deps.LicensedAPIOptionsFactory = appendAPIFactory(deps.LicensedAPIOptionsFactory, eepqcmigration.NewAPIOptionsFactory())
		deps.LicensedOutboxFactory = appendOutboxFactory(deps.LicensedOutboxFactory, eepqcmigration.NewOutboxFactory())
		deps.LicensedLeafSigner = eepqc.SignHybridLeafFromCSRWithProfile
		deps.LicensedCSRInspector = eepqc.InspectHybridCSR
		if log != nil {
			log.Info("Enterprise PQC attached", slog.String("feature", string(license.FeaturePQC)))
		}
	}
	if lic != nil && lic.Has(license.FeatureHASupport) {
		fedCfg := config.Federation{}
		if cfg != nil {
			fedCfg = cfg.Federation
		}
		factory, err := eefederation.FactoryFromConfig(ctx, fedCfg)
		if err != nil {
			return err
		}
		deps.FederationFactory = factory
		if factory != nil && log != nil {
			log.Info("Enterprise HA support attached", slog.String("feature", string(license.FeatureHASupport)))
		}
	}
	if lic != nil && lic.Has(license.FeatureBYOK) {
		managedKeyFactory, err := eemanagedkeys.FactoryFromConfig(ctx, attachConfig(cfg).ManagedKeys, deps.EgressGuard)
		if err != nil {
			return err
		}
		deps.ManagedKeyFactory = managedKeyFactory
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

func attachConfig(cfg *config.Config) config.Config {
	if cfg == nil {
		return config.Config{}
	}
	return *cfg
}
