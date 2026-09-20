// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"trstctl.com/trstctl/internal/api"
	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/profile"
	"trstctl.com/trstctl/internal/store"
)

// acmeOperatorPlan joins every server-owned prerequisite an operator otherwise
// has to infer from unrelated screens. It is deliberately a read: no probe is
// sent, no account/order is created, and no activation is performed here.
func (s *Server) acmeOperatorPlan(ctx context.Context, tenantID string) (api.ACMEOperatorPlan, error) {
	plan := api.ACMEOperatorPlan{
		DirectoryPath:          "/directory",
		ChallengeMethods:       []string{"http-01", "dns-01", "tls-alpn-01"},
		IssuingProfile:         s.defaultProfile,
		IssuingProfileReady:    s.defaultProfile == "",
		ActivationMode:         "startup_configuration",
		Blockers:               []string{},
		Warnings:               []string{},
		RecoverySteps:          []string{},
		PreviewWrites:          []string{},
		PreviewExternalEffects: []string{},
		GeneratedAt:            time.Now().UTC(),
	}

	sp := s.protocols
	if sp == nil || sp.acme == nil || sp.acmeTenant == "" || sp.acmeTenant != tenantID {
		plan.Blockers = append(plan.Blockers, "ACME is not served for this tenant. Bind and enable the ACME protocol in startup configuration, then restart the control plane.")
		plan.RecoverySteps = append(plan.RecoverySteps, "Check the ACME enable flag, tenant binding, issuing signer, and startup logs; correct configuration and restart.")
		plan.NextAction = api.ACMEOperatorAction{
			Kind: "repair_startup_configuration", Label: "Repair ACME startup configuration",
			Detail: "ACME is config-managed here. The console cannot silently open a public enrollment endpoint.",
		}
		return plan, nil
	}
	plan.TenantBound = true
	plan.Served = sp.activation == nil || sp.activation.Active()
	for _, activity := range sp.acme.DomainValidationActivities(12) {
		plan.ValidationActivity = append(plan.ValidationActivity, api.ACMEDomainValidationActivity{
			OrderID: activity.OrderID, Domain: activity.Domain,
			OrderStatus: activity.OrderStatus, AuthorizationStatus: activity.AuthorizationStatus,
			ChallengeMethods: append([]string(nil), activity.ChallengeMethods...),
			ValidatedMethod:  activity.ValidatedMethod, ValidationSkipped: activity.ValidationSkipped,
			CreatedAt: activity.CreatedAt,
		})
	}

	if sp.activation != nil {
		plan.ActivationMode = "eval_profile_event"
		plan.ActivationAvailable = true
		plan.ActivationRequired = !sp.activation.Active()
		if plan.ActivationRequired {
			plan.Blockers = append(plan.Blockers, "The evaluation protocol profile is assembled but not active for this tenant.")
			plan.RecoverySteps = append(plan.RecoverySteps, "Retry the tenant-bound activation action. Reusing the same idempotency key returns the original result instead of activating twice.")
		}
	}

	posture, err := s.acmeEABPosture(ctx, tenantID)
	if err != nil {
		return api.ACMEOperatorPlan{}, err
	}
	plan.EABRequired = posture.Required
	plan.EABConfigured = len(posture.Items)
	for _, credential := range posture.Items {
		if credential.State == "active" {
			plan.EABActive++
		}
	}
	if plan.EABRequired && plan.EABActive == 0 {
		plan.Blockers = append(plan.Blockers, "External Account Binding is required, but no credential can admit a new ACME account.")
		plan.RecoverySteps = append(plan.RecoverySteps, "Re-enable an operator-disabled EAB credential, or add a valid replacement credential through startup configuration. Existing certificates are not revoked by this repair.")
	} else if plan.EABRequired && plan.EABActive < plan.EABConfigured {
		plan.Warnings = append(plan.Warnings, "At least one EAB credential is disabled, expired, or exhausted. Active credentials can still admit scoped accounts.")
	}

	if s.store != nil {
		configs, err := s.store.ListACMEDNS01ProviderConfigs(ctx, tenantID)
		if err != nil {
			return api.ACMEOperatorPlan{}, err
		}
		plan.DNS01ProviderConfigs = len(configs)
	}
	if plan.DNS01ProviderConfigs == 0 {
		plan.Warnings = append(plan.Warnings, "No automated DNS-01 provider is configured. HTTP-01 and TLS-ALPN-01 remain available; wildcard certificates need DNS-01.")
		plan.RecoverySteps = append(plan.RecoverySteps, "For wildcard or private DNS names, add a least-privilege DNS-01 provider reference and run its preflight before retrying the ACME client.")
	}

	if s.defaultProfile != "" {
		if s.store == nil {
			plan.Blockers = append(plan.Blockers, "The named issuing profile cannot be checked because the profile store is unavailable.")
		} else if rec, err := s.store.GetActiveProfile(ctx, tenantID, s.defaultProfile); err != nil {
			if !store.IsNotFound(err) {
				return api.ACMEOperatorPlan{}, err
			}
			plan.Blockers = append(plan.Blockers, "The configured default issuing profile is not active for this tenant.")
			plan.RecoverySteps = append(plan.RecoverySteps, "Create or reactivate the named issuing profile, then retry the same ACME order. The responder fails closed while the profile is missing.")
		} else {
			var spec profile.CertificateProfile
			if err := json.Unmarshal(rec.Spec, &spec); err != nil {
				return api.ACMEOperatorPlan{}, fmt.Errorf("decode issuing profile %q: %w", s.defaultProfile, err)
			}
			maximum := time.Duration(spec.MaxValidity)
			if maximum > 0 && maximum <= crypto.IssuanceBackdateSkew() {
				plan.Blockers = append(plan.Blockers, fmt.Sprintf("The issuing profile's maximum validity %s leaves no usable lifetime after the %s NotBefore backdate.", maximum, crypto.IssuanceBackdateSkew()))
				plan.RecoverySteps = append(plan.RecoverySteps, "Choose an issuing profile whose maximum validity includes the clock-skew backdate and leaves enough time for deployment and automatic renewal. Then retry enrollment.")
			} else {
				plan.IssuingProfileReady = true
			}
		}
	}

	plan.Ready = plan.Served && plan.TenantBound && plan.IssuingProfileReady && (!plan.EABRequired || plan.EABActive > 0)
	switch {
	case plan.ActivationRequired:
		plan.NextAction = api.ACMEOperatorAction{
			Kind: "activate_eval_profile", Label: "Activate evaluation protocols",
			Detail: "This records one tenant-bound event, then opens the already-assembled protocol gate.",
			Method: "POST", Path: "/api/v1/setup/protocols/activate",
		}
	case plan.Ready:
		plan.NextAction = api.ACMEOperatorAction{
			Kind: "connect_acme_client", Label: "Connect an ACME client",
			Detail: "Point a stock ACME client at this directory. Account, order, challenge, issuance, renewal, and revocation remain protocol operations.",
			Method: "GET", Path: plan.DirectoryPath,
		}
	default:
		plan.NextAction = api.ACMEOperatorAction{
			Kind: "repair_prerequisites", Label: "Repair the blocked prerequisites",
			Detail: "Resolve every named blocker, then load this effect-free plan again before connecting a client.",
		}
	}
	plan.RecoverySteps = append(plan.RecoverySteps,
		"After a client failure, use Enrollment diagnostics to see the refused step and its safe retry guidance; do not weaken validation to make the order pass.")
	return plan, nil
}
