//go:build !trstctl_core

package main

import (
	"context"
	"log/slog"

	_ "trstctl.com/trstctl/ee"
	eefederation "trstctl.com/trstctl/ee/federation"
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
	return nil
}
