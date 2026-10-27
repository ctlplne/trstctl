// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"context"
	"errors"
	"fmt"
	"math"
	"strings"
	"time"

	"trstctl.com/trstctl/internal/api"
	"trstctl.com/trstctl/internal/crypto"
)

// EvaluateLeaf decides a leaf request the way IssueLeaf would, without
// signing anything (A195): the same issuing authority (a superseded CA routes
// to its active successor), the same leaf profile clamped to the issuer, the
// recorded-compromised key refusal and the same CSR checks. A request the CA
// would refuse is answered Allowed=false with the reason; only a failure to
// decide is an error.
func (h *caHierarchyService) EvaluateLeaf(ctx context.Context, tenantID, caID string, req api.CAIssueLeafRequest) (api.CALeafEvaluation, error) {
	if len(req.CSRDER) == 0 {
		return api.CALeafEvaluation{}, fmt.Errorf("%w: CSR is required", api.ErrCAHierarchyInvalid)
	}
	if req.TTLSeconds <= 0 || req.TTLSeconds > math.MaxInt64/int64(time.Second) {
		return api.CALeafEvaluation{}, fmt.Errorf("%w: ttl_seconds must be a positive supported duration", api.ErrCAHierarchyInvalid)
	}
	out := api.CALeafEvaluation{CAID: caID}
	_, ca, err := h.issuingAuthority(ctx, tenantID, caID)
	if errors.Is(err, api.ErrCAHierarchyConflict) {
		out.Reason = strings.TrimPrefix(err.Error(), api.ErrCAHierarchyConflict.Error()+": ")
		return out, nil
	}
	if err != nil {
		return api.CALeafEvaluation{}, err
	}
	out.CAID = ca.ID
	caDER, err := firstCertDER(ca.CertificatePEM)
	if err != nil {
		return api.CALeafEvaluation{}, err
	}
	profile, err := h.leafProfileForAuthority(tenantID, ca, h.leafProfile)
	if err != nil {
		return api.CALeafEvaluation{}, err
	}
	profile.ClampTTLToIssuer = true
	if err := refuseCompromisedLeafKey(ctx, h.store, tenantID, req.CSRDER); err != nil {
		if !errors.Is(err, api.ErrCAHierarchyInvalid) {
			return api.CALeafEvaluation{}, err
		}
		out.Reason = strings.TrimPrefix(err.Error(), api.ErrCAHierarchyInvalid.Error()+": ")
		return out, nil
	}
	ttl := time.Duration(req.TTLSeconds) * time.Second
	info, pqc, err := inspectSubjectCSR(req.CSRDER, h.parseSubjectCSR, h.inspectHybridSubjectCSR)
	if err == nil {
		if pqc {
			if ttl, err = crypto.ClampLeafTTLToIssuer(caDER, ttl); err == nil {
				err = crypto.EnforceLeafProfileInfo(info, ttl, profile)
			}
		} else {
			ttl, err = crypto.EvaluateLeafRequest(caDER, req.CSRDER, ttl, profile)
		}
	}
	if err != nil {
		// Every refusal here is about the request, the profile or the issuer
		// certificate, and would refuse the same signing; the approver denies
		// with it.
		out.Reason = leafEvaluationReason(err)
		return out, nil
	}
	out.Allowed, out.EffectiveTTLSeconds = true, int64(ttl/time.Second)
	return out, nil
}

func leafEvaluationReason(err error) string {
	if detail := crypto.SubjectKeyRefusalDetail(err); detail != "" {
		return detail
	}
	return strings.TrimPrefix(err.Error(), "crypto: ")
}
