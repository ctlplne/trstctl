// SPDX-License-Identifier: BUSL-1.1
package awspolicy

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
	"unicode/utf8"
)

const maxPolicyBytes = 64 << 10
const maxStatements = 256
const maxSelectors = 128

type stringsValue []string

func (s *stringsValue) UnmarshalJSON(raw []byte) error {
	var one string
	if json.Unmarshal(raw, &one) == nil {
		*s = []string{one}
		return nil
	}
	var many []string
	if json.Unmarshal(raw, &many) != nil || len(many) == 0 || len(many) > maxSelectors {
		return errors.New("AWS selector needs a bounded string or string array")
	}
	*s = many
	return nil
}

type conditionValues []string

func (v *conditionValues) UnmarshalJSON(raw []byte) error {
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	var value any
	if dec.Decode(&value) != nil {
		return errors.New("invalid AWS condition value")
	}
	values, ok := value.([]any)
	if !ok {
		values = []any{value}
	}
	if len(values) == 0 || len(values) > 32 {
		return errors.New("AWS condition values exceed their bound")
	}
	for _, item := range values {
		var text string
		switch item := item.(type) {
		case string:
			text = item
		case bool:
			if item {
				text = "true"
			} else {
				text = "false"
			}
		case json.Number:
			text = item.String()
		default:
			return errors.New("AWS condition value must be scalar")
		}
		if len(text) > 2048 {
			return errors.New("AWS condition value exceeds its bound")
		}
		*v = append(*v, text)
	}
	return nil
}

type statement struct {
	Sid          string                                `json:"Sid,omitempty"`
	Effect       string                                `json:"Effect"`
	Action       stringsValue                          `json:"Action,omitempty"`
	NotAction    stringsValue                          `json:"NotAction,omitempty"`
	Resource     stringsValue                          `json:"Resource,omitempty"`
	NotResource  stringsValue                          `json:"NotResource,omitempty"`
	Principal    json.RawMessage                       `json:"Principal,omitempty"`
	NotPrincipal json.RawMessage                       `json:"NotPrincipal,omitempty"`
	Condition    map[string]map[string]conditionValues `json:"Condition,omitempty"`
}

func Parse(id string, raw []byte) (Document, error) {
	if id == "" || len(id) > 256 || strings.ContainsAny(id, "\x00\r\n") || len(raw) == 0 || len(raw) > maxPolicyBytes || !utf8.Valid(raw) {
		return Document{}, errors.New("AWS policy identity or body exceeds its bounds")
	}
	if err := strictJSON(raw); err != nil {
		return Document{}, err
	}
	var root struct {
		Version   string          `json:"Version"`
		ID        string          `json:"Id,omitempty"`
		Statement json.RawMessage `json:"Statement"`
	}
	if err := strictDecode(raw, &root); err != nil {
		return Document{}, errors.New("invalid AWS policy object")
	}
	if root.Version != "2012-10-17" && root.Version != "2008-10-17" {
		return Document{}, errors.New("AWS policy version is unsupported")
	}
	var entries []json.RawMessage
	if len(root.Statement) > 0 && root.Statement[0] == '{' {
		entries = []json.RawMessage{root.Statement}
	} else if json.Unmarshal(root.Statement, &entries) != nil {
		return Document{}, errors.New("AWS policy needs statements")
	}
	if len(entries) == 0 || len(entries) > maxStatements {
		return Document{}, errors.New("AWS statement count exceeds its bounds")
	}
	doc := Document{id: id, raw: append(json.RawMessage(nil), raw...)}
	for _, entry := range entries {
		var rule statement
		if strictDecode(entry, &rule) != nil {
			return Document{}, errors.New("invalid AWS statement")
		}
		var members map[string]json.RawMessage
		if json.Unmarshal(entry, &members) != nil {
			return Document{}, errors.New("invalid AWS statement object")
		}
		if _, present := members["Condition"]; present && len(rule.Condition) == 0 {
			return Document{}, errors.New("AWS Condition must be a nonempty object")
		}
		if rule.Effect != "Allow" && rule.Effect != "Deny" {
			return Document{}, errors.New("AWS statement effect must be Allow or Deny")
		}
		if (len(rule.Action) == 0) == (len(rule.NotAction) == 0) || (len(rule.Resource) == 0) == (len(rule.NotResource) == 0) {
			return Document{}, errors.New("AWS statement needs exactly one action selector and one resource selector")
		}
		if len(rule.Principal) > 0 && len(rule.NotPrincipal) > 0 {
			return Document{}, errors.New("AWS statement cannot mix Principal and NotPrincipal")
		}
		if len(rule.Sid) > 256 || strings.ContainsAny(rule.Sid, "\x00\r\n") {
			return Document{}, errors.New("invalid AWS statement identifier")
		}
		for _, selectors := range []stringsValue{rule.Action, rule.NotAction, rule.Resource, rule.NotResource} {
			for _, selector := range selectors {
				if len(selector) == 0 || len(selector) > 2048 || strings.ContainsAny(selector, "\x00\r\n") {
					return Document{}, errors.New("invalid AWS selector")
				}
			}
		}
		if len(rule.Condition) > 32 {
			return Document{}, errors.New("AWS condition operator count exceeds its bound")
		}
		for operator, keys := range rule.Condition {
			if len(operator) == 0 || len(operator) > 128 || len(keys) == 0 || len(keys) > 64 {
				return Document{}, errors.New("invalid AWS condition keys")
			}
			seen := map[string]bool{}
			for key := range keys {
				folded := strings.ToLower(key)
				if len(key) == 0 || len(key) > 256 || seen[folded] {
					return Document{}, errors.New("ambiguous or oversized AWS condition key")
				}
				seen[folded] = true
			}
		}
		for _, principal := range []json.RawMessage{rule.Principal, rule.NotPrincipal} {
			if len(principal) > 0 {
				if _, err := parsePrincipal(principal); err != nil {
					return Document{}, err
				}
			}
		}
		doc.statements = append(doc.statements, rule)
	}
	return doc, nil
}
func strictDecode(raw []byte, out any) error {
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	return d.Decode(out)
}

// strictJSON rejects duplicate object keys before encoding/json can silently
// replace one rule with another. Depth and token bounds apply to every value.
func strictJSON(raw []byte) error {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	tokens := 0
	var value func(int) error
	value = func(depth int) error {
		if depth > 24 || tokens > 16000 {
			return errors.New("AWS JSON complexity exceeds its bound")
		}
		tokens++
		token, err := decoder.Token()
		if err != nil {
			return errors.New("invalid AWS JSON")
		}
		delimiter, container := token.(json.Delim)
		if !container {
			return nil
		}
		switch delimiter {
		case '{':
			seen := map[string]bool{}
			for decoder.More() {
				keyToken, err := decoder.Token()
				if err != nil {
					return errors.New("invalid AWS JSON key")
				}
				key, ok := keyToken.(string)
				if !ok || seen[key] {
					return errors.New("duplicate AWS JSON key")
				}
				seen[key] = true
				if err = value(depth + 1); err != nil {
					return err
				}
			}
		case '[':
			for decoder.More() {
				if err = value(depth + 1); err != nil {
					return err
				}
			}
		default:
			return errors.New("invalid AWS JSON delimiter")
		}
		end, err := decoder.Token()
		if err != nil || (delimiter == '{' && end != json.Delim('}')) || (delimiter == '[' && end != json.Delim(']')) {
			return errors.New("unclosed AWS JSON value")
		}
		return nil
	}
	if err := value(0); err != nil {
		return err
	}
	if _, err := decoder.Token(); err != io.EOF {
		return errors.New("trailing AWS JSON value")
	}
	return nil
}

type principalSelector struct {
	all         bool
	aws         []string
	unsupported bool
}

func parsePrincipal(raw []byte) (principalSelector, error) {
	var wildcard string
	if json.Unmarshal(raw, &wildcard) == nil {
		if wildcard != "*" {
			return principalSelector{}, errors.New("AWS principal string must be a wildcard")
		}
		return principalSelector{all: true}, nil
	}
	var categories map[string]json.RawMessage
	if json.Unmarshal(raw, &categories) != nil || len(categories) == 0 || len(categories) > 4 {
		return principalSelector{}, errors.New("invalid AWS principal")
	}
	out := principalSelector{}
	for kind, value := range categories {
		var names stringsValue
		if names.UnmarshalJSON(value) != nil {
			return out, errors.New("invalid AWS principal values")
		}
		for _, name := range names {
			if len(name) == 0 || len(name) > 2048 {
				return out, errors.New("AWS principal exceeds its bound")
			}
		}
		if kind == "AWS" {
			out.aws = append(out.aws, names...)
		} else {
			out.unsupported = true
		}
	}
	return out, nil
}
func statementName(rule statement, index int) string {
	if rule.Sid != "" {
		return rule.Sid
	}
	return fmt.Sprintf("statement[%d]", index)
}
