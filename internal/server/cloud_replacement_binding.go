// SPDX-License-Identifier: BUSL-1.1
package server

import (
	"context"
	"errors"
	"time"
	"trstctl.com/trstctl/internal/api"
	"trstctl.com/trstctl/internal/cloudentitlements/assessment"
	"trstctl.com/trstctl/internal/cloudentitlements/awspolicy"
	"trstctl.com/trstctl/internal/cloudentitlements/change"
	"trstctl.com/trstctl/internal/dynsecret"
)

func configuredReplacementProvider(providers []dynsecret.Provider, id, role string) (*configuredDynamicProvider, error) {
	for _, candidate := range providers {
		if candidate == nil || candidate.Name() != id {
			continue
		}
		value, ok := candidate.(*configuredDynamicProvider)
		if !ok || value.cfg.Type != "aws-sts" || !value.allowedRoles[role] || value.cfg.RoleBindings[role] == "" {
			return nil, errors.New("replacement requires an operator-configured aws-sts provider and allowed role")
		}
		return value, nil
	}
	return nil, errors.New("replacement provider is not configured for this tenant")
}
func (s *Server) bindCloudReplacement(ctx context.Context, tenantID string, intent *change.Intent, user assessment.Assessment, req api.CloudMachineChangeRequest) error {
	if s.secretIntegrations == nil {
		return errors.New("replacement provider registry is unavailable")
	}
	provider, err := configuredReplacementProvider(s.secretIntegrations.dynamicProvidersForTenant(tenantID), req.ReplacementProviderID, req.ReplacementRole)
	if err != nil {
		return err
	}
	if req.TTLSeconds < 900 || time.Duration(req.TTLSeconds)*time.Second > provider.maxTTL {
		return errors.New("replacement TTL exceeds the configured temporary provider limit")
	}
	roleFinding, role, roleConfig, roleSourceFingerprint, err := s.verifiedCloudFinding(ctx, tenantID, req.ReplacementRoleFindingID)
	if err != nil {
		return err
	}
	if role.Identity.Principal.Kind != awspolicy.IAMRole || role.Identity.Principal.AccountID != user.Identity.Principal.AccountID || role.Identity.Principal.ARN != provider.cfg.RoleBindings[req.ReplacementRole] {
		return errors.New("replacement requires the exact configured native role in the key's AWS account")
	}
	authority, err := assessment.AuthorityFingerprint(role.Identity)
	if err != nil {
		return err
	}
	current, err := s.store.GetSecret(ctx, tenantID, req.ReplacementRole)
	if err != nil {
		return err
	}
	intent.ReplacementRoleAllowPrivate = roleConfig.AllowPrivateEndpoint
	intent.ReplacementProviderID = provider.id
	intent.ReplacementProviderRevision = provider.configurationRevision
	intent.ReplacementRole = req.ReplacementRole
	intent.ReplacementRoleARN = role.Identity.Principal.ARN
	intent.ReplacementRoleID = role.Identity.NativeID
	intent.ReplacementRoleFindingID = roleFinding.ID
	intent.ReplacementRoleFindingFingerprint = roleFinding.Fingerprint
	intent.ReplacementRoleSourceID = roleFinding.SourceID
	intent.ReplacementRoleSourceFingerprint = roleSourceFingerprint
	intent.ReplacementRoleAuthorityFingerprint = authority
	intent.ReplacementExpectedVersion = current.Version
	intent.ReplacementTTLSeconds = req.TTLSeconds
	intent.Consumer = req.Consumer
	intent.ConsumerSubject = req.ConsumerSubject
	return nil
}
