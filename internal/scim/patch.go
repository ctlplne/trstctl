// SPDX-License-Identifier: BUSL-1.1

package scim

import (
	"encoding/json"
	"fmt"
	"regexp"
	"strings"
)

type PatchOp struct {
	Schemas    []string         `json:"schemas"`
	Operations []PatchOperation `json:"Operations"`
}

type PatchOperation struct {
	Op    string          `json:"op"`
	Path  string          `json:"path,omitempty"`
	Value json.RawMessage `json:"value,omitempty"`
}

func ApplyUserPatch(u *User, ops []PatchOperation) error {
	for _, op := range ops {
		action := strings.ToLower(strings.TrimSpace(op.Op))
		if action == "remove" {
			switch strings.ToLower(strings.TrimSpace(op.Path)) {
			case "username":
				u.UserName = ""
			case "externalid":
				u.ExternalID = ""
			}
			continue
		}
		if action != "replace" && action != "add" {
			continue
		}
		switch strings.ToLower(strings.TrimSpace(op.Path)) {
		case "active":
			b, err := parseSCIMBool(op.Value)
			if err != nil {
				return err
			}
			u.Active = b
		case "username":
			u.UserName = jsonString(op.Value)
		case "externalid":
			u.ExternalID = jsonString(op.Value)
		case "displayname":
			u.DisplayName = jsonString(op.Value)
		case "name.formatted":
			if u.Name == nil {
				u.Name = &Name{}
			}
			u.Name.Formatted = jsonString(op.Value)
		case "":
			var m map[string]json.RawMessage
			if err := json.Unmarshal(op.Value, &m); err != nil {
				return fmt.Errorf("scim: patch value is not an object: %w", err)
			}
			if v, ok := m["active"]; ok {
				if b, err := parseSCIMBool(v); err == nil {
					u.Active = b
				}
			}
			if v, ok := m["externalId"]; ok {
				u.ExternalID = trimJSONString(v)
			}
			if v, ok := m["userName"]; ok {
				u.UserName = trimJSONString(v)
			}
			if v, ok := m["displayName"]; ok {
				u.DisplayName = trimJSONString(v)
			}
		}
	}
	return nil
}

type GroupPatch struct {
	Add         []string
	Remove      []string
	ReplaceAll  *[]string
	DisplayName *string
}

var memberFilterRe = regexp.MustCompile(`(?i)value\s+eq\s+"([^"]+)"`)

func ParseGroupPatch(ops []PatchOperation) GroupPatch {
	var gp GroupPatch
	for _, op := range ops {
		action := strings.ToLower(strings.TrimSpace(op.Op))
		path := strings.TrimSpace(op.Path)
		lpath := strings.ToLower(path)
		switch {
		case action == "remove" && strings.HasPrefix(lpath, "members"):
			if m := memberFilterRe.FindStringSubmatch(path); len(m) == 2 {
				gp.Remove = append(gp.Remove, m[1])
			} else {
				gp.Remove = append(gp.Remove, parseMembers(op.Value)...)
			}
		case action == "add" && lpath == "members":
			gp.Add = append(gp.Add, parseMembers(op.Value)...)
		case action == "replace" && lpath == "members":
			ms := parseMembers(op.Value)
			gp.ReplaceAll = &ms
		case (action == "replace" || action == "add") && lpath == "displayname":
			v := jsonString(op.Value)
			gp.DisplayName = &v
		case action == "replace" && lpath == "":
			var m map[string]json.RawMessage
			if err := json.Unmarshal(op.Value, &m); err == nil {
				if v, ok := m["displayName"]; ok {
					s := trimJSONString(v)
					gp.DisplayName = &s
				}
				if v, ok := m["members"]; ok {
					ms := parseMembers(v)
					gp.ReplaceAll = &ms
				}
			}
		}
	}
	return gp
}

func parseMembers(raw json.RawMessage) []string {
	var arr []Member
	if err := json.Unmarshal(raw, &arr); err == nil {
		out := make([]string, 0, len(arr))
		for _, m := range arr {
			if m.Value != "" {
				out = append(out, m.Value)
			}
		}
		return out
	}
	var one Member
	if err := json.Unmarshal(raw, &one); err == nil && one.Value != "" {
		return []string{one.Value}
	}
	return nil
}

func parseSCIMBool(raw json.RawMessage) (bool, error) {
	s := strings.ToLower(strings.Trim(strings.TrimSpace(string(raw)), `"`))
	switch s {
	case "true":
		return true, nil
	case "false":
		return false, nil
	}
	return false, fmt.Errorf("scim: invalid boolean value %q", string(raw))
}

func jsonString(raw json.RawMessage) string {
	var s string
	if err := json.Unmarshal(raw, &s); err == nil {
		return s
	}
	return trimJSONString(raw)
}

func trimJSONString(raw json.RawMessage) string {
	return strings.Trim(strings.TrimSpace(string(raw)), `"`)
}
