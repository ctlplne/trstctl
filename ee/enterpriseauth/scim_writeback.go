// SPDX-License-Identifier: LicenseRef-trstctl-EE

package enterpriseauth

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"

	"trstctl.com/trstctl/ee/enterpriseauth/scim"
	"trstctl.com/trstctl/internal/api"
	"trstctl.com/trstctl/internal/crypto/secret"
	"trstctl.com/trstctl/internal/netsec"
	"trstctl.com/trstctl/internal/orchestrator"
	"trstctl.com/trstctl/internal/projections"
	"trstctl.com/trstctl/internal/store"
)

// scimWritebackTarget is one tenant's directory: its SCIM endpoint, the
// attribute that names the login subject there, and the bearer in locked
// memory.
type scimWritebackTarget struct {
	TokenName        string
	Endpoint         string
	SubjectAttribute string
	bearer           *secret.Buffer
	// client is the SSRF-bounded outbound client for this endpoint: the
	// safe client for a real directory, the loopback client only for the
	// loopback endpoints configuration validation admits.
	client *http.Client
}

// scimWriteback delivers scim.writeback rows (A73): it reads the member's
// projected row, finds the directory's User by the same attribute the inbound
// token binds the login subject to, PATCHes active and the trstctl roles,
// reads the User back, and records the outcome as audit evidence. The
// directory's own words never enter the event log; a failure is a closed
// phrase and the outbox retries a transient one.
type scimWriteback struct {
	deps    api.SCIMWritebackDeps
	targets map[string]scimWritebackTarget
}

const (
	scimWritebackMaxResponse = 1 << 20
	scimWritebackTimeout     = 15 * time.Second
)

func newSCIMWriteback(deps api.SCIMWritebackDeps, targets map[string]scimWritebackTarget) *scimWriteback {
	for tenantID, target := range targets {
		switch {
		case deps.HTTPClient != nil:
			target.client = deps.HTTPClient
		case scimWritebackLoopback(target.Endpoint):
			target.client = netsec.InsecureLoopbackClient(scimWritebackTimeout)
		default:
			target.client = netsec.SafeClient(scimWritebackTimeout)
		}
		targets[tenantID] = target
	}
	return &scimWriteback{deps: deps, targets: targets}
}

func scimWritebackLoopback(endpoint string) bool {
	parsed, err := url.Parse(endpoint)
	if err != nil {
		return false
	}
	host := parsed.Hostname()
	if host == "localhost" {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

// scimWritebackRefused is a definite refusal: retrying would not change it.
type scimWritebackRefused struct{ detail string }

func (e scimWritebackRefused) Error() string { return e.detail }

func (w *scimWriteback) Deliver(ctx context.Context, m orchestrator.Message) error {
	var intent orchestrator.SCIMWritebackIntent
	if err := json.Unmarshal(m.Payload, &intent); err != nil || strings.TrimSpace(intent.Subject) == "" {
		return orchestrator.DefiniteNoEffect(errors.New("enterpriseauth: scim.writeback row names no subject"))
	}
	target, ok := w.targets[m.TenantID]
	if !ok {
		return orchestrator.DefiniteNoEffect(errors.New("enterpriseauth: this tenant's SCIM token names no writeback endpoint"))
	}
	if w.deps.Store == nil || w.deps.Orchestrator == nil {
		return errors.New("enterpriseauth: SCIM writeback is not wired to the store")
	}
	member, err := w.deps.Store.GetTenantMember(ctx, m.TenantID, intent.Subject)
	if err != nil {
		return orchestrator.DefiniteNoEffect(fmt.Errorf("enterpriseauth: writeback member is not inventoried: %w", err))
	}
	if member.SCIM == nil {
		return orchestrator.DefiniteNoEffect(errors.New("enterpriseauth: writeback member is not directory-owned"))
	}
	recorded := projections.SCIMWritebackRecorded{
		Subject: member.Subject, UserName: member.SCIM.UserName, Change: intent.Change,
		Active: member.Status == "active", Roles: append([]string(nil), member.Roles...), SourceEventID: intent.SourceEventID,
	}
	directoryID, err := w.writeUser(ctx, target, member.SCIM, recorded.Active, recorded.Roles)
	recorded.DirectoryUserID = directoryID
	var refused scimWritebackRefused
	switch {
	case err == nil:
		recorded.Status, recorded.Detail = "written", "directory user updated and read back"
	case errors.As(err, &refused):
		recorded.Status, recorded.Detail = "refused", refused.detail
	default:
		// Transient: nothing is recorded yet, the outbox retries.
		return err
	}
	if err := w.deps.Orchestrator.RecordSCIMWriteback(ctx, m.TenantID, recorded); err != nil {
		return err
	}
	if recorded.Status == "refused" {
		return orchestrator.DefiniteNoEffect(errors.New("enterpriseauth: directory writeback refused: " + recorded.Detail))
	}
	return nil
}

// writeUser finds the directory's User, patches it, and reads it back.
func (w *scimWriteback) writeUser(ctx context.Context, target scimWritebackTarget, identity *store.SCIMIdentity, active bool, roles []string) (string, error) {
	attribute, value := "userName", identity.UserName
	if target.SubjectAttribute == "externalId" {
		attribute, value = "externalId", identity.ExternalID
	}
	if strings.TrimSpace(value) == "" {
		return "", scimWritebackRefused{detail: "member has no " + attribute + " to find in the directory"}
	}
	filter := attribute + ` eq "` + strings.ReplaceAll(value, `"`, `\"`) + `"`
	var list scim.ListResponse
	if err := w.call(ctx, target, http.MethodGet, "/Users?filter="+url.QueryEscape(filter), nil, &list); err != nil {
		return "", err
	}
	if list.TotalResults != 1 || len(list.Resources) != 1 {
		return "", scimWritebackRefused{detail: fmt.Sprintf("directory returned %d users for the member's %s; exactly one is required", list.TotalResults, attribute)}
	}
	resource, _ := json.Marshal(list.Resources[0])
	var found struct {
		ID string `json:"id"`
	}
	if json.Unmarshal(resource, &found) != nil || strings.TrimSpace(found.ID) == "" {
		return "", scimWritebackRefused{detail: "directory user carries no id"}
	}
	roleValues := make([]map[string]any, 0, len(roles))
	for _, role := range roles {
		roleValues = append(roleValues, map[string]any{"value": role, "type": "trstctl"})
	}
	patch := map[string]any{
		"schemas": []string{scim.SchemaPatchOp},
		"Operations": []map[string]any{
			{"op": "replace", "path": "active", "value": active},
			{"op": "replace", "path": "roles", "value": roleValues},
		},
	}
	body, err := json.Marshal(patch)
	if err != nil {
		return found.ID, err
	}
	var patched directoryUser
	if err := w.call(ctx, target, http.MethodPatch, "/Users/"+url.PathEscape(found.ID), body, &patched); err != nil {
		return found.ID, err
	}
	var readback directoryUser
	if err := w.call(ctx, target, http.MethodGet, "/Users/"+url.PathEscape(found.ID), nil, &readback); err != nil {
		return found.ID, err
	}
	if readback.Active != active {
		return found.ID, scimWritebackRefused{detail: "directory read back a different active state than written"}
	}
	if !sameRoleSet(readback.Roles, roles) {
		return found.ID, scimWritebackRefused{detail: "directory read back different roles than written"}
	}
	return found.ID, nil
}

// directoryUser is the part of the directory's User the readback compares.
type directoryUser struct {
	Active bool `json:"active"`
	Roles  []struct {
		Value string `json:"value"`
	} `json:"roles,omitempty"`
}

func sameRoleSet(got []struct {
	Value string `json:"value"`
}, want []string) bool {
	have := make([]string, 0, len(got))
	for _, role := range got {
		have = append(have, role.Value)
	}
	expect := append([]string(nil), want...)
	sort.Strings(have)
	sort.Strings(expect)
	if len(have) != len(expect) {
		return false
	}
	for i := range have {
		if have[i] != expect[i] {
			return false
		}
	}
	return true
}

// call performs one SCIM request with the locked bearer. A non-2xx answer is
// a refusal with a closed phrase; a transport error is transient.
func (w *scimWriteback) call(ctx context.Context, target scimWritebackTarget, method, path string, body []byte, out any) error {
	var reader io.Reader
	if body != nil {
		reader = bytes.NewReader(body)
	}
	req, err := http.NewRequestWithContext(ctx, method, target.Endpoint+path, reader)
	if err != nil {
		return err
	}
	bearer := target.bearer.Bytes()
	req.Header.Set("Authorization", "Bearer "+string(bearer))
	req.Header.Set("Accept", scim.ContentType)
	if body != nil {
		req.Header.Set("Content-Type", scim.ContentType)
	}
	resp, err := target.client.Do(req)
	if err != nil {
		return fmt.Errorf("enterpriseauth: directory %s %s: transport failure", method, path)
	}
	defer func() { _ = resp.Body.Close() }()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, scimWritebackMaxResponse))
	if err != nil {
		return fmt.Errorf("enterpriseauth: directory %s %s: response could not be read", method, path)
	}
	switch {
	case resp.StatusCode >= 500 || resp.StatusCode == http.StatusTooManyRequests:
		return fmt.Errorf("enterpriseauth: directory %s %s answered %d", method, path, resp.StatusCode)
	case resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden:
		return scimWritebackRefused{detail: "directory refused the writeback bearer"}
	case resp.StatusCode == http.StatusNotFound:
		return scimWritebackRefused{detail: "directory has no such user"}
	case resp.StatusCode < 200 || resp.StatusCode >= 300:
		return scimWritebackRefused{detail: fmt.Sprintf("directory answered %d to %s", resp.StatusCode, method)}
	}
	if out != nil && len(bytes.TrimSpace(raw)) > 0 {
		if err := json.Unmarshal(raw, out); err != nil {
			return scimWritebackRefused{detail: "directory answer is not SCIM JSON"}
		}
	}
	return nil
}
