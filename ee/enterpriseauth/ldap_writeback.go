// SPDX-License-Identifier: LicenseRef-trstctl-EE

package enterpriseauth

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"sort"
	"strings"
	"time"

	ldap "github.com/go-ldap/ldap/v3"

	"trstctl.com/trstctl/internal/api"
	"trstctl.com/trstctl/internal/orchestrator"
	"trstctl.com/trstctl/internal/projections"
)

// ldapWritebackTarget is one tenant's directory: the service account that
// writes, and the role → group map.
type ldapWritebackTarget struct {
	URL          string
	BindDN       string
	BindPassword []byte
	Timeout      time.Duration
	RoleGroups   map[string]string
}

type ldapWriteback struct {
	deps    api.LDAPWritebackDeps
	targets map[string]ldapWritebackTarget
}

func newLDAPWriteback(deps api.LDAPWritebackDeps, targets map[string]ldapWritebackTarget) *ldapWriteback {
	return &ldapWriteback{deps: deps, targets: targets}
}

type ldapWritebackRefused struct{ detail string }

func (e ldapWritebackRefused) Error() string { return e.detail }

// Deliver applies one member's current roles to the directory's role groups:
// the member DN is added to every group its roles map to and removed from
// every mapped group its roles no longer cover (all of them when offboarded).
// Idempotent: a group already in the wanted state is left alone.
func (w *ldapWriteback) Deliver(ctx context.Context, m orchestrator.Message) error {
	var intent orchestrator.LDAPWritebackIntent
	if err := json.Unmarshal(m.Payload, &intent); err != nil || strings.TrimSpace(intent.Subject) == "" {
		return orchestrator.DefiniteNoEffect(errors.New("enterpriseauth: ldap.writeback row names no subject"))
	}
	target, ok := w.targets[m.TenantID]
	if !ok {
		return orchestrator.DefiniteNoEffect(errors.New("enterpriseauth: this tenant has no LDAP writeback"))
	}
	if w.deps.Store == nil || w.deps.Orchestrator == nil {
		return errors.New("enterpriseauth: LDAP writeback is not wired to the store")
	}
	member, err := w.deps.Store.GetTenantMember(ctx, m.TenantID, intent.Subject)
	if err != nil {
		return orchestrator.DefiniteNoEffect(fmt.Errorf("enterpriseauth: writeback member is not inventoried: %w", err))
	}
	recorded := projections.LDAPWritebackRecorded{
		Subject: member.Subject, Change: intent.Change, Active: member.Status == "active",
		Roles: append([]string(nil), member.Roles...), SourceEventID: intent.SourceEventID,
	}
	wanted := map[string]bool{}
	if recorded.Active {
		for _, role := range member.Roles {
			if dn, ok := target.RoleGroups[role]; ok {
				wanted[normalizeGroupDN(dn)] = true
			}
		}
	}
	added, removed, err := w.apply(ctx, target, member.Subject, wanted)
	recorded.GroupsAdded, recorded.GroupsRemoved = added, removed
	var refused ldapWritebackRefused
	switch {
	case err == nil:
		recorded.Status, recorded.Detail = "written", "directory role groups updated"
	case errors.As(err, &refused):
		recorded.Status, recorded.Detail = "refused", refused.detail
	default:
		return err
	}
	if err := w.deps.Orchestrator.RecordLDAPWriteback(ctx, m.TenantID, recorded); err != nil {
		return err
	}
	if recorded.Status == "refused" {
		return orchestrator.DefiniteNoEffect(errors.New("enterpriseauth: directory writeback refused: " + recorded.Detail))
	}
	return nil
}

func normalizeGroupDN(dn string) string {
	parts := strings.Split(strings.TrimSpace(dn), ",")
	for i := range parts {
		parts[i] = strings.TrimSpace(parts[i])
	}
	return strings.Join(parts, ",")
}

// apply reconciles the member DN against every mapped group.
func (w *ldapWriteback) apply(ctx context.Context, target ldapWritebackTarget, memberDN string, wanted map[string]bool) (added, removed []string, err error) {
	timeout := target.Timeout
	if timeout <= 0 {
		timeout = 5 * time.Second
	}
	conn, err := ldap.DialURL(target.URL, ldap.DialWithDialer(&net.Dialer{Timeout: timeout}))
	if err != nil {
		return nil, nil, fmt.Errorf("enterpriseauth: LDAP writeback dial: %w", err)
	}
	defer func() { _ = conn.Close() }()
	conn.SetTimeout(timeout)
	if ctx != nil && ctx.Err() != nil {
		return nil, nil, ctx.Err()
	}
	if err := conn.Bind(target.BindDN, string(target.BindPassword)); err != nil {
		return nil, nil, fmt.Errorf("enterpriseauth: LDAP writeback service bind: %w", err)
	}
	groups := make([]string, 0, len(target.RoleGroups))
	seen := map[string]bool{}
	for _, dn := range target.RoleGroups {
		dn = normalizeGroupDN(dn)
		if !seen[dn] {
			seen[dn] = true
			groups = append(groups, dn)
		}
	}
	sort.Strings(groups)
	memberKey := strings.ToLower(normalizeGroupDN(memberDN))
	for _, group := range groups {
		req := ldap.NewSearchRequest(group, ldap.ScopeBaseObject, ldap.NeverDerefAliases, 1, 5, false, "(objectClass=*)", []string{"member"}, nil)
		res, err := conn.Search(req)
		if err != nil {
			return added, removed, classifyWritebackError(err, "the role group "+group+" could not be read")
		}
		present := false
		if len(res.Entries) > 0 {
			for _, value := range res.Entries[0].GetAttributeValues("member") {
				if strings.ToLower(normalizeGroupDN(value)) == memberKey {
					present = true
					break
				}
			}
		}
		switch {
		case wanted[group] && !present:
			modify := ldap.NewModifyRequest(group, nil)
			modify.Add("member", []string{memberDN})
			if err := conn.Modify(modify); err != nil {
				return added, removed, classifyWritebackError(err, "the directory refused adding the member to "+group)
			}
			added = append(added, group)
		case !wanted[group] && present:
			modify := ldap.NewModifyRequest(group, nil)
			modify.Delete("member", []string{memberDN})
			if err := conn.Modify(modify); err != nil {
				return added, removed, classifyWritebackError(err, "the directory refused removing the member from "+group)
			}
			removed = append(removed, group)
		}
	}
	return added, removed, nil
}

// classifyWritebackError tells a directory refusal (recorded, not retried)
// from a transport failure (retried by the outbox).
func classifyWritebackError(err error, detail string) error {
	var ldapErr *ldap.Error
	if errors.As(err, &ldapErr) {
		switch ldapErr.ResultCode {
		case ldap.LDAPResultNoSuchObject, ldap.LDAPResultInsufficientAccessRights, ldap.LDAPResultUnwillingToPerform,
			ldap.LDAPResultConstraintViolation, ldap.LDAPResultObjectClassViolation, ldap.LDAPResultNotAllowedOnRDN,
			ldap.LDAPResultNoSuchAttribute, ldap.LDAPResultAttributeOrValueExists:
			return ldapWritebackRefused{detail: detail}
		}
	}
	return fmt.Errorf("enterpriseauth: LDAP writeback: %w", err)
}
