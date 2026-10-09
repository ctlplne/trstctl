// SPDX-License-Identifier: BUSL-1.1

package pqcmigration

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"trstctl.com/trstctl/internal/api"
	"trstctl.com/trstctl/internal/profile"
	"trstctl.com/trstctl/internal/store"
)

const migrationProtocolLeafTTL = 30 * 24 * time.Hour

// preflightPQCReissues uses the active served profile before Start writes an
// event or outbox intent. The issuer still rechecks the actual CSR at delivery:
// a policy edit between these steps must fail closed rather than bypass policy.
func (s *pqcMigrationService) preflightPQCReissues(ctx context.Context, tenantID string, plan Plan) error {
	if len(plan.Reissues) == 0 || s.defaultProfile == "" {
		return nil
	}
	rec, err := s.store.GetActiveProfile(ctx, tenantID, s.defaultProfile)
	if err != nil {
		if store.IsNotFound(err) {
			return api.ErrStatus(http.StatusConflict, fmt.Sprintf("PQC reissue cannot start: served default profile %q is not active", s.defaultProfile))
		}
		return err
	}
	var selected profile.CertificateProfile
	if err := json.Unmarshal(rec.Spec, &selected); err != nil {
		return fmt.Errorf("pqcmigration: decode active profile %q v%d: %w", rec.Name, rec.Version, err)
	}
	selected.Name, selected.Version = rec.Name, rec.Version
	for _, reissue := range plan.Reissues {
		if err := validatePQCReissueProfile(selected, reissue.Asset, reissue.Protocol); err != nil {
			return api.ErrStatus(http.StatusConflict, fmt.Sprintf("PQC reissue for asset %s cannot start under the served default profile: %v. Review the profile and observed endpoint name before starting", reissue.Asset.ID, err))
		}
	}
	return nil
}

// The reissue worker currently constructs an ECDSA P-256 hybrid CSR with the
// observed location as its DNS SAN. Keep this preview request in step with that
// exact CSR construction; the issuer is the final authority over the real CSR.
func validatePQCReissueProfile(selected profile.CertificateProfile, asset Asset, protocol string) error {
	ttl := migrationProtocolLeafTTL
	if selected.MaxValidity > 0 && ttl > time.Duration(selected.MaxValidity) {
		ttl = time.Duration(selected.MaxValidity)
	}
	return selected.Validate(profile.Request{
		KeyAlgorithm: "ECDSA", KeyBits: 256,
		RequestedEKUs: selected.AllowedEKUs,
		TTL:           ttl, DNSNames: []string{dnsNameFromLocation(asset.Location)}, Protocol: protocol,
	})
}
