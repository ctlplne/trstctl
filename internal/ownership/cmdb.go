// SPDX-License-Identifier: MPL-2.0

package ownership

import (
	"encoding/json"
	"fmt"
	"io"
	"net/url"
	"strings"
)

// Reading ownership out of a ServiceNow CMDB (epic I2).
//
// This file only ever turns a cmdb_ci response into Records. It has no write
// path and cannot acquire one by accident: nothing here builds a request, and
// the ticket writer's table allow-list does not contain cmdb_ci. That is the
// acceptance criterion "no CMDB write unless explicitly configured" held as a
// structural property rather than a runtime flag somebody can flip.
//
// The mapping is the interesting part. A CMDB CI has several fields that could
// plausibly mean "owner" and they do not mean the same thing: assigned_to is a
// person currently responsible, owned_by is who the asset belongs to, and
// support_group is a rota. Picking one silently would make ownership look
// authoritative while encoding an arbitrary choice, so the preference order is
// written down and the field that supplied the answer travels with the record.

// CMDBRecord is one cmdb_ci row as ServiceNow returns it. Only the fields this
// mapping reads are declared; a real instance sends dozens more and they are
// ignored rather than stored, because storing a copy of the CMDB is what the
// epic says not to do — synchronize, do not duplicate.
type CMDBRecord struct {
	SysID           string `json:"sys_id"`
	Name            string `json:"name"`
	AssignedTo      string `json:"assigned_to"`
	OwnedBy         string `json:"owned_by"`
	SupportGroup    string `json:"support_group"`
	BusinessService string `json:"business_service"`
	UApplication    string `json:"u_application"`
	Environment     string `json:"used_for"`
	Company         string `json:"company"`
}

// cmdbResponse is the ServiceNow Table API envelope.
type cmdbResponse struct {
	Result []map[string]any `json:"result"`
}

// ParseCMDB maps a ServiceNow cmdb_ci Table API response into ownership records.
//
// Rows that name no owner are reported, not skipped: a CI whose ownership
// fields are all empty is a genuine finding — it is an asset nobody is
// accountable for — and silently dropping it would make the CMDB look better
// covered than it is.
func ParseCMDB(r io.Reader) (records []Record, unattributed []string, err error) {
	var resp cmdbResponse
	dec := json.NewDecoder(io.LimitReader(r, cmdbResponseLimit))
	if err := dec.Decode(&resp); err != nil {
		return nil, nil, fmt.Errorf("ownership: parse cmdb_ci response: %w", err)
	}
	for _, row := range resp.Result {
		rec := CMDBRecord{
			SysID:           cmdbField(row, "sys_id"),
			Name:            cmdbField(row, "name"),
			AssignedTo:      cmdbField(row, "assigned_to"),
			OwnedBy:         cmdbField(row, "owned_by"),
			SupportGroup:    cmdbField(row, "support_group"),
			BusinessService: cmdbField(row, "business_service"),
			UApplication:    cmdbField(row, "u_application"),
			Environment:     cmdbField(row, "used_for"),
			Company:         cmdbField(row, "company"),
		}
		owner, _ := cmdbOwner(rec)
		if owner == "" {
			// A CI with no ownership at all. Named so an operator can see the
			// gap; a count of "412 imported" that quietly excluded 38 of these
			// is how a CMDB reconciliation reports success on an estate it did
			// not actually cover.
			label := rec.Name
			if label == "" {
				label = rec.SysID
			}
			if label != "" {
				unattributed = append(unattributed, label)
			}
			continue
		}
		records = append(records, Record{
			OwnerName:     owner,
			ApplicationID: firstNonEmpty(rec.UApplication, rec.BusinessService),
			Service:       rec.BusinessService,
			BusinessUnit:  rec.Company,
			Environment:   rec.Environment,
			SourceRef:     rec.SysID,
		})
	}
	return records, unattributed, nil
}

// cmdbResponseLimit bounds a CMDB page. A ServiceNow instance answering with an
// unbounded body would otherwise be able to exhaust this process's memory
// through an integration the operator thinks of as read-only.
const cmdbResponseLimit = 8 << 20

// CMDBOwnerFields is the preference order for reading an owner off a CI, most
// specific first.
//
// owned_by before assigned_to before support_group: who the asset belongs to
// outranks who is currently handling it, which outranks a rota. Exported so the
// order is a stated product decision rather than a switch buried in a mapper —
// an operator who disagrees needs to be able to see what was chosen.
var CMDBOwnerFields = []string{"owned_by", "assigned_to", "support_group"}

// cmdbOwner returns the owner and the field it came from.
func cmdbOwner(rec CMDBRecord) (owner string, field string) {
	byField := map[string]string{
		"owned_by":      rec.OwnedBy,
		"assigned_to":   rec.AssignedTo,
		"support_group": rec.SupportGroup,
	}
	for _, f := range CMDBOwnerFields {
		if v := strings.TrimSpace(byField[f]); v != "" {
			return v, f
		}
	}
	return "", ""
}

// cmdbField reads a ServiceNow field, which is either a plain string or a
// reference object of the form {"value": "...", "display_value": "..."}.
//
// display_value wins when present: "Payments Platform" is the answer a human
// can act on, and a sys_id in an owner column is a value nobody can route a
// certificate expiry notice to.
func cmdbField(row map[string]any, key string) string {
	switch v := row[key].(type) {
	case string:
		return strings.TrimSpace(v)
	case map[string]any:
		if s, ok := v["display_value"].(string); ok && strings.TrimSpace(s) != "" {
			return strings.TrimSpace(s)
		}
		if s, ok := v["value"].(string); ok {
			return strings.TrimSpace(s)
		}
	}
	return ""
}

func firstNonEmpty(values ...string) string {
	for _, v := range values {
		if strings.TrimSpace(v) != "" {
			return strings.TrimSpace(v)
		}
	}
	return ""
}

// CMDBEndpoint builds the fixed read URL for one page of cmdb_ci.
//
// It lives beside ParseCMDB because BOTH vantages build it — the control
// plane's own fetch and the relay's (I2) — and two implementations of "which
// table may be read" is how one of them drifts onto sys_user_password. The
// path is fixed to cmdb_ci; a schedule cannot name an arbitrary table.
// display_value=all is requested because a reference field's raw value is a
// sys_id, and a sys_id in an owner column is a value nobody can act on.
func CMDBEndpoint(instanceURL, query string, limit int) (string, error) {
	base, err := url.Parse(strings.TrimSpace(instanceURL))
	if err != nil {
		return "", fmt.Errorf("ownership: parse ServiceNow instance URL: %w", err)
	}
	if base.Scheme == "" || base.Host == "" {
		return "", fmt.Errorf("ownership: ServiceNow instance URL must be absolute")
	}
	base.Path = strings.TrimRight(base.Path, "/") + "/api/now/table/cmdb_ci"
	q := url.Values{}
	q.Set("sysparm_display_value", "all")
	q.Set("sysparm_limit", fmt.Sprintf("%d", limit))
	if trimmed := strings.TrimSpace(query); trimmed != "" {
		q.Set("sysparm_query", trimmed)
	}
	base.RawQuery = q.Encode()
	base.Fragment = ""
	return base.String(), nil
}

// CMDBSyncIntent is the payload of one relay-executed cmdb.sync job (I2). It
// lives here, beside the parser and the endpoint builder, because both sides
// of the job decode it — the control plane enqueues it and the relay executes
// it, and a drift between those two shapes fails every sync while both halves
// pass their own tests.
//
// TokenRef is a secret:// REFERENCE; the relay redeems the value through the
// job-credential path for exactly one attempt. A token value here would be a
// token value on the queue, in every backup of it.
type CMDBSyncIntent struct {
	InstanceURL string `json:"instance_url"`
	CIQuery     string `json:"ci_query,omitempty"`
	TokenRef    string `json:"token_ref"`
	PageLimit   int    `json:"page_limit"`
}
