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
	eeprovider "trstctl.com/trstctl/ee/provider"
	eewhitelabel "trstctl.com/trstctl/ee/whitelabel"
	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/license"
	"trstctl.com/trstctl/internal/server"
)

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
