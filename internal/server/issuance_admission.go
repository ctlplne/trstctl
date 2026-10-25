// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"trstctl.com/trstctl/internal/orchestrator"
	"trstctl.com/trstctl/internal/profile"
	"trstctl.com/trstctl/internal/store"
)

// errServedDefaultProfileMissing: the configured default profile does not
// resolve for the tenant, which the mint refuses (fail closed).
var errServedDefaultProfileMissing = errors.New("server: served default profile not found")

// servedIssuanceProfile resolves the certificate profile the served mint
// applies: the issuance binding's pinned revision when one exists, else the
// configured default profile's active revision. found=false means the mint
// applies the built-in leaf profile and no certificate profile. The mint and
// the first-issuance admission check share it, so the two cannot disagree.
func servedIssuanceProfile(ctx context.Context, st *store.Store, defaultProfile, tenantID string, binding *store.OperationApprovalIssuanceBinding) (store.ProfileRecord, string, bool, error) {
	if binding != nil {
		name := strings.TrimSpace(binding.ProfileName)
		if name == "" {
			if defaultProfile == "" {
				return store.ProfileRecord{}, "", false, nil
			}
			return store.ProfileRecord{}, "", false, errors.New("server: approved issuance did not pin the configured profile revision")
		}
		if binding.ProfileID == "" || binding.ProfileVersion <= 0 || binding.ProfileSpecDigest == "" {
			return store.ProfileRecord{}, name, false, fmt.Errorf("server: approved profile %q has no immutable revision binding", name)
		}
		rec, err := st.GetProfileVersion(ctx, tenantID, name, binding.ProfileVersion)
		if err != nil {
			return store.ProfileRecord{}, name, false, fmt.Errorf("server: resolve approved profile %q version %d: %w", name, binding.ProfileVersion, err)
		}
		if rec.ID != binding.ProfileID || store.ProfileSpecDigest(rec.Spec) != binding.ProfileSpecDigest {
			return store.ProfileRecord{}, name, false, fmt.Errorf("server: approved profile %q revision evidence drifted", name)
		}
		return rec, name, true, nil
	}
	if defaultProfile == "" {
		return store.ProfileRecord{}, "", false, nil
	}
	rec, err := st.GetActiveProfile(ctx, tenantID, defaultProfile)
	if err != nil {
		if store.IsNotFound(err) {
			return store.ProfileRecord{}, defaultProfile, false, errServedDefaultProfileMissing
		}
		return store.ProfileRecord{}, defaultProfile, false, err
	}
	return rec, defaultProfile, true, nil
}

// issuanceAdmissionGuard runs, before a first issuance is recorded, the
// profile checks the mint would run that need no key: the enrollment protocol
// ("api") and the validity it would request. A profile that permits only
// ACME, say, refused every such issuance at the mint after the transition had
// been accepted; now the request is refused, naming the profile, before any
// event or outbox intent. Key strength, names and EKUs stay at the mint, where
// the CSR or the generated key exists. It reads the served mint's own store and
// default profile when it runs, so the two cannot disagree; without a served
// mint there is nothing to check.
func (s *Server) issuanceAdmissionGuard(ctx context.Context, tenantID string, _ store.Identity, binding *store.OperationApprovalIssuanceBinding) error {
	d, ok := s.obHandler.(*issuanceDispatcher)
	if !ok || d == nil {
		return nil
	}
	return issuanceAdmission(ctx, d.store, d.defaultProfile, tenantID, binding)
}

func issuanceAdmission(ctx context.Context, st *store.Store, defaultProfile, tenantID string, binding *store.OperationApprovalIssuanceBinding) error {
	if st == nil {
		return nil
	}
	rec, name, found, err := servedIssuanceProfile(ctx, st, defaultProfile, tenantID, binding)
	if errors.Is(err, errServedDefaultProfileMissing) {
		return orchestrator.IssuanceProfileRefused(fmt.Errorf("served default profile %q not found", name))
	}
	if err != nil || !found {
		return err
	}
	var prof profile.CertificateProfile
	if err := json.Unmarshal(rec.Spec, &prof); err != nil {
		return fmt.Errorf("server: decode profile %q: %w", name, err)
	}
	prof.Name, prof.Version = rec.Name, rec.Version
	var bindings []*store.OperationApprovalIssuanceBinding
	if binding != nil {
		bindings = append(bindings, binding)
	}
	ttl, _, err := approvedIssuanceTTL(bindings)
	if err != nil {
		return err
	}
	if verr := prof.ValidateRequestMetadata(profile.Request{Protocol: "api", TTL: ttl}); verr != nil {
		return orchestrator.IssuanceProfileRefused(verr)
	}
	return nil
}
