// SPDX-License-Identifier: BUSL-1.1

package api

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"time"

	"trstctl.com/trstctl/internal/authz"
	"trstctl.com/trstctl/internal/bulkhead"
	"trstctl.com/trstctl/internal/policy"
)

func (a *API) checkABAC(ctx context.Context, r *http.Request, principal authz.Principal, perm authz.Permission, target authz.Scope) error {
	if a.abac == nil {
		return nil
	}
	now := time.Now().UTC()
	if a.abacNow != nil {
		now = a.abacNow().UTC()
	}
	resource := map[string]string{
		"request.method": r.Method,
		"request.path":   r.URL.Path,
	}
	if target.Project != "" {
		resource["request.project"] = target.Project
		resource["project"] = target.Project
	}
	if target.Profile != "" {
		resource["request.profile"] = target.Profile
		resource["profile"] = target.Profile
	}
	if target.Issuer != "" {
		resource["request.issuer"] = target.Issuer
		resource["issuer"] = target.Issuer
	}
	in := policy.ABACInput{
		Permission: string(perm),
		TenantID:   principal.TenantID,
		Actor:      principal.Subject,
		ActorAttrs: map[string]string{
			"subject": principal.Subject,
			"roles":   strings.Join(principalRoles(principal), ","),
		},
		Resource:   resource,
		Env:        copyStringMap(a.abacEnvironment),
		Now:        now.Format(time.RFC3339),
		NowUnix:    now.Unix(),
		NowHourUTC: now.Hour(),
		NowWeekday: now.Weekday().String(),
	}
	d, err := a.abac.EvaluateDeny(ctx, in)
	switch {
	case errors.Is(err, bulkhead.ErrRejected):
		return errStatus(http.StatusServiceUnavailable, "ABAC engine busy; retry")
	case err != nil:
		return errStatus(http.StatusForbidden, "denied by ABAC (evaluation error)")
	case d.Deny:
		reason := d.Reason
		if reason == "" {
			reason = "denied by ABAC"
		}
		return errStatus(http.StatusForbidden, "denied by ABAC: "+reason)
	default:
		return nil
	}
}
