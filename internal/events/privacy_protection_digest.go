// SPDX-License-Identifier: BUSL-1.1

package events

import (
	"bytes"
	"encoding/json"
	"errors"
	"sort"

	"trstctl.com/trstctl/internal/crypto"
)

// PrivacyEventPolicyDigest identifies the exact registered field classes and
// closed payload shape used by event protection. It contains no tenant data.
// Opaque means "do not inspect", not "public": the digest never authorizes
// leaving a field readable. Unknown type/version pairs have no fallback policy.
func PrivacyEventPolicyDigest(eventType string, schemaVersion int) (string, error) {
	policy, ok := registeredPrivacyEventPolicy(eventType, schemaVersion)
	if !ok {
		return "", errors.New("events: protection requires a registered privacy policy")
	}
	return protectionPolicyDigest(eventType, schemaVersion, policy)
}

type protectionShape struct {
	Kind     privacyPayloadShapeKind     `json:"kind"`
	Scalar   privacyPayloadScalarKind    `json:"scalar"`
	Nullable bool                        `json:"nullable"`
	Fields   map[string]*protectionShape `json:"fields,omitempty"`
	Required []string                    `json:"required,omitempty"`
	Element  *protectionShape            `json:"element,omitempty"`
}

func protectionPolicyDigest(eventType string, schemaVersion int, policy PrivacyEventPolicy) (string, error) {
	if eventType == "" || schemaVersion <= 0 {
		return "", errors.New("events: protection policy identity is incomplete")
	}
	rules := append([]PrivacyFieldRule(nil), policy.Rules...)
	sort.Slice(rules, func(i, j int) bool {
		if rules[i].Path == rules[j].Path {
			return rules[i].Mode < rules[j].Mode
		}
		return rules[i].Path < rules[j].Path
	})
	roots := privacyPayloadShapeRoots(policy.PayloadShape)
	shapes := make([]json.RawMessage, 0, len(roots))
	for _, root := range roots {
		encoded, err := json.Marshal(protectionShapeDeclaration(root))
		if err != nil {
			return "", err
		}
		shapes = append(shapes, encoded)
	}
	sort.Slice(shapes, func(i, j int) bool { return bytes.Compare(shapes[i], shapes[j]) < 0 })
	// Actor is an envelope field rather than a domain-payload field. Bind its
	// exact shape too, so adding attribution fields cannot retain an old digest.
	actorShape := PrivacyPayloadShapeOf[Actor]()
	encoded, err := json.Marshal(struct {
		Format            string             `json:"format"`
		EventType         string             `json:"event_type"`
		SchemaVersion     int                `json:"schema_version"`
		Rules             []PrivacyFieldRule `json:"rules"`
		RejectSubjectData bool               `json:"reject_subject_data"`
		Shapes            []json.RawMessage  `json:"shapes"`
		Actor             *protectionShape   `json:"actor"`
	}{"trstctl.event-protection-policy.v1", eventType, schemaVersion, rules, policy.RejectSubjectData, shapes, protectionShapeDeclaration(actorShape.root)})
	if err != nil {
		return "", err
	}
	return crypto.SHA256Hex(encoded), nil
}

func protectionShapeDeclaration(node *privacyPayloadShapeNode) *protectionShape {
	if node == nil {
		return nil
	}
	declaration := &protectionShape{
		Kind: node.kind, Scalar: node.scalar, Nullable: node.nullable,
		Element: protectionShapeDeclaration(node.element),
	}
	if len(node.fields) > 0 {
		declaration.Fields = make(map[string]*protectionShape, len(node.fields))
		for name, child := range node.fields {
			declaration.Fields[name] = protectionShapeDeclaration(child)
		}
	}
	for name := range node.requiredFields {
		declaration.Required = append(declaration.Required, name)
	}
	sort.Strings(declaration.Required)
	return declaration
}
