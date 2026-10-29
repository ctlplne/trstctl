// SPDX-License-Identifier: BUSL-1.1
package adcs

import (
	"encoding/json"
	"errors"
	"strings"
)

// EndpointProbeServiceCoverage identifies this service's place in the latest
// bounded page. It never claims that earlier pages were tested at this time.
type EndpointProbeServiceCoverage struct {
	PlanDigest    string `json:"plan_digest"`
	State         string `json:"state"`
	Reason        string `json:"reason,omitempty"`
	TotalTargets  int    `json:"total_targets"`
	Offset        int    `json:"offset"`
	NextOffset    int    `json:"next_offset"`
	TargetsOnPage int    `json:"targets_on_page"`
	Complete      bool   `json:"complete"`
}

func (p EndpointProbePage) ServiceCoverage(name string) *EndpointProbeServiceCoverage {
	c := &EndpointProbeServiceCoverage{PlanDigest: p.PlanDigest, State: "not_in_page", TotalTargets: p.TotalTargets, Offset: p.Offset, NextOffset: p.NextOffset, Complete: p.Complete}
	for _, target := range p.Targets {
		if target.EnrollmentService == name {
			c.TargetsOnPage++
		}
	}
	if c.TargetsOnPage > 0 {
		c.State = "in_page"
	}
	for _, issue := range p.HostIssues {
		if issue.EnrollmentService == name {
			c.State = "host_unassessed"
			c.Reason = issue.Reason
		}
	}
	return c
}

func probeJSONEqual(a, b any) bool {
	left, err := json.Marshal(a)
	if err != nil {
		return false
	}
	right, err := json.Marshal(b)
	return err == nil && string(left) == string(right)
}

func validateEndpointProbePage(intent InventoryIntent, inventory Inventory) error {
	if intent.EndpointProbe == nil {
		if inventory.EndpointProbePage != nil || intent.PreviousProbePage != nil {
			return errors.New("adcs: undeclared endpoint probe page")
		}
		return nil
	}
	options, err := normalizeEndpointProbeOptions(intent.EndpointProbe)
	if err != nil || options == nil || !probeJSONEqual(options, intent.EndpointProbe) {
		return errors.New("adcs: noncanonical endpoint probe grant")
	}
	want, err := PlanEnrollmentEndpointProbes(intent, inventory.EnrollmentServices)
	if err != nil {
		return err
	}
	if inventory.EndpointProbePage == nil || !probeJSONEqual(&want, inventory.EndpointProbePage) {
		return errors.New("adcs: reported endpoint page differs from scoped directory plan")
	}
	for _, service := range inventory.EnrollmentServices {
		if service.EndpointProbe == nil || !probeJSONEqual(want.ServiceCoverage(service.Name), service.EndpointProbe) {
			return errors.New("adcs: enrollment service omitted or altered endpoint coverage")
		}
	}
	return nil
}

func validateProbeEndpoint(e EnrollmentEndpoint, target EndpointProbeTarget) error {
	if e.Source != target.Source {
		return errors.New("adcs: endpoint provenance differs from planned target")
	}
	if e.ExtendedProtection != EvidenceUnobserved {
		return errors.New("adcs: HTTP probe cannot establish IIS extended protection")
	}
	if e.State == EndpointNotChecked {
		if e.NotCheckedReason != "deadline_or_cancellation" || e.HTTPStatus != 0 || len(e.Authentication) != 0 || e.TLSVerified {
			return errors.New("adcs: unattempted endpoint carries fabricated HTTP evidence")
		}
		return nil
	}
	if e.NotCheckedReason != "" {
		return errors.New("adcs: attempted endpoint carries an unattempted reason")
	}
	if e.State == EndpointUnreachable {
		if e.HTTPStatus != 0 || len(e.Authentication) != 0 || e.TLSVerified {
			return errors.New("adcs: unreachable endpoint carries HTTP evidence")
		}
		return nil
	}
	if e.TLSVerified != strings.HasPrefix(e.URL, "https://") {
		return errors.New("adcs: endpoint TLS fact differs from response transport")
	}
	want := EndpointReachableOther
	switch {
	case e.HTTPStatus >= 200 && e.HTTPStatus < 300:
		want = EndpointAnonymousAccess
	case e.HTTPStatus == 401 || e.HTTPStatus == 403:
		want = EndpointAuthenticationNeeded
	case e.HTTPStatus >= 300 && e.HTTPStatus < 400:
		want = EndpointRedirected
	case e.HTTPStatus == 404 || e.HTTPStatus == 410:
		want = EndpointNotFound
	}
	if e.HTTPStatus < 100 || e.HTTPStatus > 599 || e.State != want {
		return errors.New("adcs: endpoint state differs from HTTP status")
	}
	previous := ""
	for _, scheme := range e.Authentication {
		switch scheme {
		case "Basic", "Bearer", "Digest", "NTLM", "Negotiate":
		default:
			return errors.New("adcs: unknown authentication scheme")
		}
		if scheme <= previous {
			return errors.New("adcs: authentication schemes are not unique and sorted")
		}
		previous = scheme
	}
	return nil
}
