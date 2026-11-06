// SPDX-License-Identifier: BUSL-1.1
package server

import (
	"context"
	"encoding/json"
	"errors"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"time"
	"trstctl.com/trstctl/internal/cloudentitlements/assessment"
	"trstctl.com/trstctl/internal/cloudentitlements/awsiam"
	"trstctl.com/trstctl/internal/cloudentitlements/awspolicy"
	"trstctl.com/trstctl/internal/cloudentitlements/change"
	"trstctl.com/trstctl/internal/crypto/awssignin"
	"trstctl.com/trstctl/internal/crypto/secret"
	"trstctl.com/trstctl/internal/orchestrator"
	"trstctl.com/trstctl/internal/store"
)

func (d *issuanceDispatcher) replacementRoleReadback(ctx context.Context, tenantID string, intent change.Intent) error {
	finding, original, cfg, fingerprint, err := verifiedCloudFinding(ctx, d.store, tenantID, intent.ReplacementRoleFindingID)
	if err != nil {
		return err
	}
	if finding.SourceID != intent.ReplacementRoleSourceID || finding.Fingerprint != intent.ReplacementRoleFindingFingerprint || fingerprint != intent.ReplacementRoleSourceFingerprint || original.Identity.NativeID != intent.ReplacementRoleID {
		return errors.New("approved replacement role source drifted")
	}
	endpoint := cfg.Endpoint
	if endpoint == "" {
		endpoint = "https://iam.amazonaws.com"
	}
	if err := d.egress.CheckURL(endpoint); err != nil {
		return err
	}
	ref, ok := strings.CutPrefix(cfg.SessionFileRef, "env:")
	path, present := os.LookupEnv(ref)
	if !ok || !present || !filepath.IsAbs(path) {
		return errors.New("replacement role reader file is not configured")
	}
	prefixes := make([]netip.Prefix, 0, len(cfg.PrivateEgressCIDRs))
	for _, raw := range cfg.PrivateEgressCIDRs {
		prefix, err := netip.ParsePrefix(raw)
		if err != nil {
			return err
		}
		prefixes = append(prefixes, prefix)
	}
	reader, err := awsiam.New(awsiam.Config{Endpoint: endpoint, Region: cfg.Region, CAPEM: []byte(cfg.CAPEM), AllowInsecureLoopback: cfg.AllowPrivateEndpoint, PrivateEgressCIDRs: prefixes, UseCredentials: awsiam.SessionFile(path, nil)})
	if err != nil {
		return err
	}
	captured, err := reader.Collect(ctx, []awsiam.Selection{{Kind: awspolicy.IAMRole, Name: original.Identity.Name}})
	if err != nil || len(captured.Identities) != 1 {
		return errors.New("replacement role authority could not be read back")
	}
	current := captured.Identities[0]
	authority, err := assessment.AuthorityFingerprint(current)
	if err != nil || current.Principal.ARN != intent.ReplacementRoleARN || current.NativeID != intent.ReplacementRoleID || authority != intent.ReplacementRoleAuthorityFingerprint {
		return errors.New("approved native replacement role identity or policy changed")
	}
	return nil
}

func (d *issuanceDispatcher) verifyCloudReplacementLease(ctx context.Context, tenantID string, intent change.Intent, leaseID string, provider *configuredDynamicProvider) (time.Time, error) {
	record, err := d.store.GetDynamicSecretLease(ctx, tenantID, leaseID)
	if err != nil {
		return time.Time{}, err
	}
	if record.Provider != intent.ReplacementProviderID || record.Role != intent.ReplacementRole || record.State != store.DynamicSecretLeaseActive || !time.Now().Add(30*time.Second).Before(record.ExpiresAt) {
		return time.Time{}, errors.New("replacement lease is unavailable, expired or too close to expiry")
	}
	lifecycle, err := newDurableDynamicSecretLifecycle(tenantID, d.secretIntegrations.dynamicProvidersForTenant(tenantID), d.store, d.log, d.secretIntegrations.kek, d.outbox, func() {}, d.tenantCrypto)
	if err != nil {
		return time.Time{}, err
	}
	credential, err := lifecycle.openCredential(ctx, record)
	if err != nil {
		return time.Time{}, err
	}
	defer secret.Wipe(credential)
	endpoint := awsiam.STSEndpoint(provider.cfg.Region, provider.cfg.Endpoint)
	if err := d.egress.CheckURL(endpoint); err != nil {
		return time.Time{}, err
	}
	prefixes := make([]netip.Prefix, 0, len(provider.cfg.PrivateEgressCIDRs))
	for _, raw := range provider.cfg.PrivateEgressCIDRs {
		prefix, err := netip.ParsePrefix(raw)
		if err != nil {
			return time.Time{}, err
		}
		prefixes = append(prefixes, prefix)
	}
	identity, err := awsiam.VerifyAssumedRole(ctx, awsiam.Config{Endpoint: endpoint, Region: provider.cfg.Region, AllowInsecureLoopback: provider.cfg.AllowInsecureLoopback, PrivateEgressCIDRs: prefixes, UseCredentials: func(ctx context.Context, use func(awssignin.Credentials) error) error {
		if err := ctx.Err(); err != nil {
			return err
		}
		return awsiam.UseLeaseCredential(credential, time.Now(), use)
	}}, []string{intent.ReplacementRoleARN})
	if err != nil {
		return time.Time{}, err
	}
	nativeID, _, _ := strings.Cut(identity.UserID, ":")
	if nativeID != intent.ReplacementRoleID {
		return time.Time{}, errors.New("replacement session belongs to another immutable native role")
	}
	var native struct {
		Expiration time.Time `json:"expiration"`
	}
	if json.Unmarshal(credential, &native) != nil || native.Expiration.Before(record.ExpiresAt) {
		return time.Time{}, errors.New("replacement native expiration precedes its approved lease deadline")
	}
	return native.Expiration, nil
}

func (d *issuanceDispatcher) handleCloudReplacement(ctx context.Context, message orchestrator.Message, plan change.Record, phase string, writer *awsiam.ChangeClient) error {
	result := change.Result{CheckedAt: time.Now().UTC()}
	if plan.Result != nil {
		result = *plan.Result
		result.CheckedAt = time.Now().UTC()
	}
	fail := func(err error) error {
		result.Error = err.Error()
		result.CheckedAt = time.Now().UTC()
		return d.orch.RecordCloudMachineChangeResult(ctx, message.TenantID, plan.ID, change.Failed, result)
	}
	if d.secretIntegrations == nil || d.cloudReplacementPrepare == nil {
		return fail(errors.New("replacement publication worker is unavailable"))
	}
	provider, err := configuredReplacementProvider(d.secretIntegrations.dynamicProvidersForTenant(message.TenantID), plan.Intent.ReplacementProviderID, plan.Intent.ReplacementRole)
	if err != nil {
		return fail(err)
	}
	if provider.configurationRevision != plan.Intent.ReplacementProviderRevision || provider.cfg.RoleBindings[plan.Intent.ReplacementRole] != plan.Intent.ReplacementRoleARN {
		return fail(errors.New("approved replacement provider configuration changed"))
	}
	switch phase {
	case "":
		if plan.State != change.Queued {
			return nil
		}
		if err := d.replacementRoleReadback(ctx, message.TenantID, plan.Intent); err != nil {
			return fail(err)
		}
		prepared, err := d.cloudReplacementPrepare(ctx, message.TenantID, plan.ID)
		if err != nil {
			return fail(err)
		}
		result.ReplacementCommandID = prepared.CommandID
		result.PreparationPhase = prepared.Phase
		result.CheckedAt = time.Now().UTC()
		return d.orch.RecordCloudMachineReplacementPhase(ctx, message.TenantID, plan.ID, change.Preparing, result)
	case "prepare":
		if plan.State != change.Preparing {
			return nil
		}
		// This child-status read performs no receiver I/O. Pending publication alone
		// may defer; after native verification we commit the next phase and finish.
		prepared, err := d.cloudReplacementPrepare(ctx, message.TenantID, plan.ID)
		if err != nil {
			return fail(err)
		}
		result.ReplacementCommandID = prepared.CommandID
		result.ReplacementLeaseID = prepared.LeaseID
		result.PreparationPhase = prepared.Phase
		switch prepared.Phase {
		case store.SecretStaticRotationFailed, store.SecretStaticRotationRolledBack, store.SecretStaticRotationRollbackFailed, store.SecretStaticRotationRetirePending:
			return fail(errors.New("replacement publication failed; old-key retirement was not attempted"))
		case store.SecretStaticRotationCompleted:
		default:
			return orchestrator.DeferDeliveryUntil(errors.New("replacement publication is still pending"), time.Now().Add(2*time.Second))
		}
		if prepared.VerifyMode != "authenticated" || prepared.Version != plan.Intent.ReplacementExpectedVersion+1 {
			return fail(errors.New("replacement publication lacks the exact native authenticated version"))
		}
		if err := d.replacementRoleReadback(ctx, message.TenantID, plan.Intent); err != nil {
			return fail(err)
		}
		nativeExpiry, err := d.verifyCloudReplacementLease(ctx, message.TenantID, plan.Intent, prepared.LeaseID, provider)
		if err != nil {
			return fail(err)
		}
		result.ReplacementVersion = prepared.Version
		result.ReplacementExpiresAt = &nativeExpiry
		result.ReplacementNativeRoleID = plan.Intent.ReplacementRoleID
		result.CheckedAt = time.Now().UTC()
		return d.orch.RecordCloudMachineReplacementPhase(ctx, message.TenantID, plan.ID, change.WaitingAdoption, result)
	case "retire":
		if plan.State != change.WaitingAdoption {
			return nil
		}
		adoption := plan.Adoption
		if adoption == nil || adoption.Consumer != plan.Intent.Consumer || adoption.Subject != plan.Intent.ConsumerSubject || adoption.Name != plan.Intent.ReplacementRole || adoption.Version != plan.Intent.ReplacementExpectedVersion+1 || result.ReplacementVersion != adoption.Version {
			return fail(errors.New("replacement has no exact verified consumer receipt"))
		}
		current, err := d.store.GetSecret(ctx, message.TenantID, plan.Intent.ReplacementRole)
		if err != nil || current.Version != adoption.Version {
			return fail(errors.New("published replacement version drifted before retirement"))
		}
		if err := d.replacementRoleReadback(ctx, message.TenantID, plan.Intent); err != nil {
			return fail(err)
		}
		if _, err := d.verifyCloudReplacementLease(ctx, message.TenantID, plan.Intent, result.ReplacementLeaseID, provider); err != nil {
			return fail(err)
		}
		target := awsiam.ChangeTarget{ARN: plan.Intent.PrincipalARN, NativeID: plan.Intent.PrincipalID, Name: plan.Intent.PrincipalName, Kind: awspolicy.PrincipalKind(plan.Intent.PrincipalKind)}
		readback, err := writer.RevokeKey(ctx, target, plan.Intent.AccessKeyID)
		if err != nil {
			result.EffectUncertain = true
			return fail(err)
		}
		result.KeyAbsent = readback.KeyAbsent
		result.Postcondition = readback.Postcondition
		result.CheckedAt = readback.CheckedAt
		return d.orch.RecordCloudMachineChangeResult(ctx, message.TenantID, plan.ID, change.Verified, result)
	case "deadline":
		if plan.State != change.WaitingAdoption {
			return nil
		}
		if time.Now().Before(plan.ExpiresAt) {
			return orchestrator.DeferDeliveryUntil(errors.New("replacement adoption deadline has not arrived"), plan.ExpiresAt)
		}
		return fail(errors.New("replacement deadline expired before old-key retirement"))
	default:
		return orchestrator.DefiniteNoEffect(errors.New("unknown cloud replacement phase"))
	}
}
