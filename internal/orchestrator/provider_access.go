// SPDX-License-Identifier: BUSL-1.1

package orchestrator

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"trstctl.com/trstctl/internal/projections"
)

// A95: the customer's side of Provider emergency access.

var (
	ErrProviderAccessDecided        = errors.New("orchestrator: this subject already decided on the grant")
	ErrProviderAccessClosed         = errors.New("orchestrator: the Provider request is unknown or has expired")
	ErrProviderAccessReasonRequired = errors.New("orchestrator: a denial needs a reason; the Provider reads it")
)

// SetProviderAccessPolicy records whether this tenant's own consent is
// required before a Provider emergency grant may be used, and how many
// distinct approvals it takes.
func (o *Orchestrator) SetProviderAccessPolicy(ctx context.Context, tenantID string, require bool, approvals int, by string) (projections.ProviderAccessPolicySet, error) {
	if strings.TrimSpace(by) == "" {
		return projections.ProviderAccessPolicySet{}, fmt.Errorf("orchestrator: a policy change needs the operator who made it")
	}
	if approvals <= 0 {
		approvals = 2
	}
	if approvals > 10 {
		return projections.ProviderAccessPolicySet{}, fmt.Errorf("orchestrator: approvals must be between 1 and 10")
	}
	payload := projections.ProviderAccessPolicySet{RequireTenantConsent: require, Approvals: approvals, SetBy: strings.TrimSpace(by), SetAt: time.Now().UTC()}
	raw, err := json.Marshal(payload)
	if err != nil {
		return projections.ProviderAccessPolicySet{}, err
	}
	_, err = o.emit(ctx, projections.EventProviderAccessPolicySet, tenantID, raw)
	return payload, err
}

// ConsentProviderAccess records one tenant subject's decision on a Provider
// grant. The grant must be a request this tenant has seen and that has not
// expired; a subject decides once.
func (o *Orchestrator) ConsentProviderAccess(ctx context.Context, tenantID, grantID, subject string, approve bool, reason string) (projections.ProviderAccessConsented, error) {
	grantID, subject = strings.TrimSpace(grantID), strings.TrimSpace(subject)
	if grantID == "" || subject == "" {
		return projections.ProviderAccessConsented{}, fmt.Errorf("orchestrator: a consent needs the grant id and the deciding subject")
	}
	if !approve && strings.TrimSpace(reason) == "" {
		return projections.ProviderAccessConsented{}, ErrProviderAccessReasonRequired
	}
	payload := projections.ProviderAccessConsented{GrantID: grantID, Subject: subject, Approve: approve, Reason: strings.TrimSpace(reason), DecidedAt: time.Now().UTC()}
	raw, err := json.Marshal(payload)
	if err != nil {
		return projections.ProviderAccessConsented{}, err
	}
	err = o.store.WithProjectionLock(ctx, func(locked context.Context) error {
		requests, err := o.store.ProviderAccessRequestsFor(locked, tenantID, time.Now().UTC())
		if err != nil {
			return err
		}
		known := false
		for _, r := range requests {
			if r.GrantID == grantID {
				known = true
				break
			}
		}
		if !known {
			return ErrProviderAccessClosed
		}
		consents, err := o.store.ProviderAccessConsentsFor(locked, tenantID, grantID)
		if err != nil {
			return err
		}
		for _, c := range consents {
			if c.Subject == subject {
				return ErrProviderAccessDecided
			}
		}
		_, err = o.emit(locked, projections.EventProviderAccessConsented, tenantID, raw)
		return err
	})
	return payload, err
}
