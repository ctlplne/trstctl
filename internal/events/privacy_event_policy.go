// SPDX-License-Identifier: MPL-2.0

package events

import (
	"bytes"
	"encoding"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"sync"
	"time"
	"unicode"
	"unicode/utf8"

	"trstctl.com/trstctl/internal/privacyref"
)

// PrivacyFieldMode says exactly how one declared JSON value may react to a
// subject erasure. A policy never infers privacy from a field's spelling: every
// path is registered for one exact event type and schema version.
type PrivacyFieldMode string

const (
	// PrivacyFieldIdentityExact rewrites only a value that is exactly the erased
	// identity. A short identity such as "a" therefore cannot corrupt "ca-a".
	PrivacyFieldIdentityExact PrivacyFieldMode = "identity_exact"
	// PrivacyFieldSubjectToken rewrites a complete token in structured text. It
	// accepts role-like forms such as delegate:<subject> and <subject>:release,
	// while leaving unrelated words such as admin byte-exact.
	PrivacyFieldSubjectToken PrivacyFieldMode = "subject_token"
	// PrivacyFieldFreeTextClear clears the complete selected value when it
	// contains the subject. It is for non-authoritative reason/evidence text; it
	// never edits security identities character by character.
	PrivacyFieldFreeTextClear PrivacyFieldMode = "free_text_clear"
	// PrivacyFieldJSONIdentityValues recursively rewrites only JSON string values
	// that exactly equal the erased identity. It is reserved for explicitly
	// cataloged schemaless metadata fields such as discovery config/metadata;
	// dynamic object keys remain closed and cannot carry personal data.
	PrivacyFieldJSONIdentityValues PrivacyFieldMode = "json_identity_values"
	// PrivacyFieldNestedJSONBytes rewrites one encoding/json []byte field whose
	// canonical base64 value contains a complete JSON command. It exists for
	// historical replayable envelopes such as lifecycle v3. Invalid base64,
	// non-canonical encoding, duplicate JSON keys, and non-JSON bytes fail closed.
	PrivacyFieldNestedJSONBytes PrivacyFieldMode = "nested_json_bytes"
	// PrivacyFieldOpaqueExact declares a digest, UUID, HMAC, ciphertext, DER, or
	// protocol value. The value and its complete subtree are never inspected or
	// rewritten, even when a short subject happens to occur in its encoding.
	PrivacyFieldOpaqueExact PrivacyFieldMode = "opaque_exact"
)

// PrivacyFieldRule is an RFC-6901-like path. A `*` segment matches one array
// element or object value. Object keys are closed too; a policy that genuinely
// permits personal data in a dynamic key must declare the synthetic `@key`
// segment explicitly.
type PrivacyFieldRule struct {
	Path string
	Mode PrivacyFieldMode
}

// PrivacyEventPolicy is the complete rewrite vocabulary for one event schema.
// Rules are copied at registration so later caller mutation cannot widen policy.
type PrivacyEventPolicy struct {
	Rules []PrivacyFieldRule
	// PayloadShape is the closed JSON shape accepted for this exact event type
	// and version. When it is empty, registration derives the shape from Rules:
	// explicit path segments are object fields and `*` is one array element.
	// Typed projector catalogs use PrivacyPayloadShapeOf when a schema has no
	// subject-bearing field but still needs same-version drift protection.
	PayloadShape PrivacyPayloadShape
	// RejectSubjectData explicitly records that this known schema has no
	// authorized subject-bearing payload path. It is different from a missing
	// registry entry, but both fail before staging when raw subject data appears.
	// Rules may still be present to close intentionally opaque/dynamic subtrees;
	// they do not authorize rewriting when RejectSubjectData is true.
	RejectSubjectData bool
}

// PrivacyPayloadShape is an immutable, reflection-derived JSON schema used only
// for validating that a producer did not add or reshape a field without bumping
// its event schema version. Its internals are deliberately private: callers can
// construct one only from a concrete Go payload type.
type PrivacyPayloadShape struct {
	root         *privacyPayloadShapeNode
	alternatives []*privacyPayloadShapeNode
}

type privacyPayloadShapeKind uint8

const (
	privacyPayloadShapeScalar privacyPayloadShapeKind = iota + 1
	privacyPayloadShapeObject
	privacyPayloadShapeArray
	privacyPayloadShapeMap
	privacyPayloadShapeOpen
)

type privacyPayloadShapeNode struct {
	kind           privacyPayloadShapeKind
	scalar         privacyPayloadScalarKind
	nullable       bool
	fields         map[string]*privacyPayloadShapeNode
	requiredFields map[string]struct{}
	element        *privacyPayloadShapeNode
}

type privacyPayloadScalarKind uint8

const (
	privacyPayloadScalarString privacyPayloadScalarKind = iota + 1
	privacyPayloadScalarNumber
	privacyPayloadScalarBoolean
)

var (
	jsonRawMessageType = reflect.TypeOf(json.RawMessage(nil))
	timeType           = reflect.TypeOf(time.Time{})
	jsonMarshalerType  = reflect.TypeOf((*json.Marshaler)(nil)).Elem()
	textMarshalerType  = reflect.TypeOf((*encoding.TextMarshaler)(nil)).Elem()
)

// PrivacyPayloadShapeOf returns the exact JSON field/container shape encoded by
// T. It is useful for schemas whose payload has no authorized personal-data
// path: the erasure policy can reject subject data while required append/import
// mode still refuses a new field smuggled under the same schema version.
func PrivacyPayloadShapeOf[T any]() PrivacyPayloadShape {
	return PrivacyPayloadShape{root: privacyPayloadShapeForType(reflect.TypeOf((*T)(nil)).Elem(), map[reflect.Type]bool{})}
}

// PrivacyPayloadShapeOneOf joins historical payloads that already share one
// immutable (event type, schema version) coordinate. It is intentionally not a
// loose union: registration accepts it only when every pair of closed object
// alternatives has a required field that the other alternative forbids. The
// append/import validator then requires exactly one matching alternative.
func PrivacyPayloadShapeOneOf(shapes ...PrivacyPayloadShape) PrivacyPayloadShape {
	roots := make([]*privacyPayloadShapeNode, 0, len(shapes))
	for _, shape := range shapes {
		for _, root := range privacyPayloadShapeRoots(shape) {
			roots = append(roots, clonePrivacyPayloadShapeNode(root))
		}
	}
	return PrivacyPayloadShape{alternatives: roots}
}

type privacyEventPolicyKey struct {
	eventType     string
	schemaVersion int
}

var privacyEventPolicies = struct {
	sync.RWMutex
	values map[privacyEventPolicyKey]PrivacyEventPolicy
}{values: make(map[privacyEventPolicyKey]PrivacyEventPolicy)}

// RegisterPrivacyEventPolicy installs one closed policy. Re-registering the
// byte-identical policy is harmless, which keeps package init and focused tests
// deterministic; a conflicting registration fails closed.
func RegisterPrivacyEventPolicy(eventType string, schemaVersion int, policy PrivacyEventPolicy) error {
	eventType = strings.TrimSpace(eventType)
	if eventType == "" || schemaVersion <= 0 {
		return errors.New("events: privacy event policy requires type and positive schema version")
	}
	seen := make(map[string]struct{}, len(policy.Rules))
	copyPolicy := PrivacyEventPolicy{
		Rules:             make([]PrivacyFieldRule, len(policy.Rules)),
		PayloadShape:      clonePrivacyPayloadShape(policy.PayloadShape),
		RejectSubjectData: policy.RejectSubjectData,
	}
	copy(copyPolicy.Rules, policy.Rules)
	if len(copyPolicy.Rules) == 0 && len(privacyPayloadShapeRoots(copyPolicy.PayloadShape)) == 0 {
		return errors.New("events: privacy event policy must declare a closed payload shape")
	}
	for _, rule := range copyPolicy.Rules {
		if rule.Path == "" || rule.Path[0] != '/' {
			return fmt.Errorf("events: privacy field path %q is not absolute", rule.Path)
		}
		switch rule.Mode {
		case PrivacyFieldIdentityExact, PrivacyFieldSubjectToken,
			PrivacyFieldFreeTextClear, PrivacyFieldJSONIdentityValues,
			PrivacyFieldNestedJSONBytes, PrivacyFieldOpaqueExact:
		default:
			return fmt.Errorf("events: privacy field path %q has unsupported mode %q", rule.Path, rule.Mode)
		}
		if _, duplicate := seen[rule.Path]; duplicate {
			return fmt.Errorf("events: privacy event policy repeats path %q", rule.Path)
		}
		seen[rule.Path] = struct{}{}
		for _, segment := range parsePrivacyPath(rule.Path) {
			if segment == "**" {
				return fmt.Errorf("events: privacy field path %q uses an unbounded wildcard", rule.Path)
			}
		}
	}
	for i := range copyPolicy.Rules {
		for j := i + 1; j < len(copyPolicy.Rules); j++ {
			if privacyRulePathsOverlap(
				parsePrivacyPath(copyPolicy.Rules[i].Path),
				parsePrivacyPath(copyPolicy.Rules[j].Path),
			) {
				return fmt.Errorf(
					"events: privacy field paths %q and %q overlap",
					copyPolicy.Rules[i].Path, copyPolicy.Rules[j].Path,
				)
			}
		}
	}
	if copyPolicy.PayloadShape.root == nil {
		if len(copyPolicy.PayloadShape.alternatives) == 0 {
			shape, err := privacyPayloadShapeFromRules(copyPolicy.Rules)
			if err != nil {
				return err
			}
			copyPolicy.PayloadShape = shape
		}
	}
	if err := validatePrivacyPayloadShapeAlternatives(copyPolicy.PayloadShape); err != nil {
		return fmt.Errorf("events: privacy payload shape alternatives: %w", err)
	}
	for _, rule := range copyPolicy.Rules {
		if err := validatePrivacyRulePayloadShape(rule, copyPolicy.PayloadShape); err != nil {
			return fmt.Errorf("events: privacy field path %q does not match its payload shape: %w", rule.Path, err)
		}
	}
	if err := validatePrivacyPayloadShapeClosed(copyPolicy.PayloadShape, copyPolicy.Rules); err != nil {
		return fmt.Errorf("events: privacy payload shape is not closed: %w", err)
	}
	key := privacyEventPolicyKey{eventType: eventType, schemaVersion: schemaVersion}
	privacyEventPolicies.Lock()
	defer privacyEventPolicies.Unlock()
	if existing, ok := privacyEventPolicies.values[key]; ok {
		if reflect.DeepEqual(existing, copyPolicy) {
			return nil
		}
		return fmt.Errorf("events: privacy event policy for %s v%d is already registered differently", eventType, schemaVersion)
	}
	privacyEventPolicies.values[key] = copyPolicy
	return nil
}

func privacyPayloadShapeRoots(shape PrivacyPayloadShape) []*privacyPayloadShapeNode {
	if shape.root != nil {
		return []*privacyPayloadShapeNode{shape.root}
	}
	return shape.alternatives
}

func validatePrivacyPayloadShapeAlternatives(shape PrivacyPayloadShape) error {
	roots := privacyPayloadShapeRoots(shape)
	if len(roots) == 0 {
		return errors.New("no payload shape is declared")
	}
	if shape.root != nil && len(shape.alternatives) != 0 {
		return errors.New("single-root and alternative payload shapes cannot be combined")
	}
	if len(roots) == 1 {
		return nil
	}
	for i, root := range roots {
		if root == nil || root.kind != privacyPayloadShapeObject {
			return fmt.Errorf("alternative %d is not a closed object", i+1)
		}
		if len(root.requiredFields) == 0 {
			return fmt.Errorf("alternative %d has no required discriminator field", i+1)
		}
	}
	for i := 0; i < len(roots); i++ {
		for j := i + 1; j < len(roots); j++ {
			if !privacyPayloadAlternativesHaveExclusiveRequiredField(roots[i], roots[j]) {
				return fmt.Errorf(
					"alternatives %d and %d have no mutually exclusive required field",
					i+1, j+1,
				)
			}
		}
	}
	return nil
}

func privacyPayloadAlternativesHaveExclusiveRequiredField(
	left, right *privacyPayloadShapeNode,
) bool {
	for field := range left.requiredFields {
		if _, allowed := right.fields[field]; !allowed {
			return true
		}
	}
	for field := range right.requiredFields {
		if _, allowed := left.fields[field]; !allowed {
			return true
		}
	}
	return false
}

func validatePrivacyPayloadShapeClosed(shape PrivacyPayloadShape, rules []PrivacyFieldRule) error {
	compiled := make([]compiledPrivacyFieldRule, len(rules))
	for i, rule := range rules {
		compiled[i] = compiledPrivacyFieldRule{segments: parsePrivacyPath(rule.Path), mode: rule.Mode}
	}
	for i, root := range privacyPayloadShapeRoots(shape) {
		if err := validatePrivacyPayloadShapeNodeClosed(root, nil, compiled); err != nil {
			return fmt.Errorf("alternative %d: %w", i+1, err)
		}
	}
	return nil
}

func validatePrivacyPayloadShapeNodeClosed(
	node *privacyPayloadShapeNode,
	path []string,
	rules []compiledPrivacyFieldRule,
) error {
	if _, closes := privacyRuleAt(rules, path); closes {
		return nil
	}
	if node == nil {
		return fmt.Errorf("path /%s is absent", strings.Join(path, "/"))
	}
	switch node.kind {
	case privacyPayloadShapeScalar:
		return nil
	case privacyPayloadShapeObject:
		for field, child := range node.fields {
			if err := validatePrivacyPayloadShapeNodeClosed(
				child, appendPrivacyPath(path, field), rules,
			); err != nil {
				return err
			}
		}
		return nil
	case privacyPayloadShapeArray:
		return validatePrivacyPayloadShapeNodeClosed(
			node.element, appendPrivacyPath(path, "*"), rules,
		)
	case privacyPayloadShapeMap:
		keyShape := &privacyPayloadShapeNode{
			kind: privacyPayloadShapeScalar, scalar: privacyPayloadScalarString,
		}
		if err := validatePrivacyPayloadShapeNodeClosed(
			keyShape, appendPrivacyPath(path, "@key"), rules,
		); err != nil {
			return err
		}
		return validatePrivacyPayloadShapeNodeClosed(
			node.element, appendPrivacyPath(path, "*"), rules,
		)
	case privacyPayloadShapeOpen:
		return fmt.Errorf(
			"open path /%s needs one explicit closing rule",
			strings.Join(path, "/"),
		)
	default:
		return fmt.Errorf("path /%s has no payload shape", strings.Join(path, "/"))
	}
}

func validatePrivacyRulePayloadShape(rule PrivacyFieldRule, shape PrivacyPayloadShape) error {
	matched := false
	for i, root := range privacyPayloadShapeRoots(shape) {
		node, present, err := privacyPayloadShapeNodeAt(root, parsePrivacyPath(rule.Path))
		if err != nil {
			return fmt.Errorf("alternative %d: %w", i+1, err)
		}
		if !present {
			continue
		}
		matched = true
		if err := validatePrivacyRuleNodeMode(rule.Mode, node); err != nil {
			return fmt.Errorf("alternative %d: %w", i+1, err)
		}
	}
	if !matched {
		return errors.New("path is absent from every alternative")
	}
	return nil
}

func privacyPayloadShapeNodeAt(
	root *privacyPayloadShapeNode,
	segments []string,
) (*privacyPayloadShapeNode, bool, error) {
	node := root
	for _, segment := range segments {
		if node == nil {
			return nil, false, nil
		}
		switch node.kind {
		case privacyPayloadShapeObject:
			if segment == "*" || segment == "@key" {
				return nil, false, nil
			}
			var ok bool
			node, ok = node.fields[segment]
			if !ok {
				return nil, false, nil
			}
		case privacyPayloadShapeArray:
			if segment != "*" {
				return nil, false, nil
			}
			node = node.element
		case privacyPayloadShapeMap:
			switch segment {
			case "*":
				node = node.element
			case "@key":
				node = &privacyPayloadShapeNode{
					kind: privacyPayloadShapeScalar, scalar: privacyPayloadScalarString,
				}
			default:
				return nil, false, nil
			}
		case privacyPayloadShapeOpen:
			return nil, false, errors.New("cannot select a descendant of an open subtree")
		default:
			return nil, false, nil
		}
	}
	if node == nil {
		return nil, false, nil
	}
	return node, true, nil
}

func validatePrivacyRuleNodeMode(mode PrivacyFieldMode, node *privacyPayloadShapeNode) error {
	switch mode {
	case PrivacyFieldIdentityExact, PrivacyFieldSubjectToken, PrivacyFieldNestedJSONBytes:
		if node.kind != privacyPayloadShapeOpen &&
			(node.kind != privacyPayloadShapeScalar || node.scalar != privacyPayloadScalarString) {
			return fmt.Errorf("%s requires a string leaf", mode)
		}
	case PrivacyFieldFreeTextClear:
		if !privacyPayloadShapeCanContainString(node, map[*privacyPayloadShapeNode]bool{}) {
			return errors.New("free-text clear requires a string-bearing scalar or container")
		}
	case PrivacyFieldJSONIdentityValues:
		if !privacyPayloadShapeCanContainString(node, map[*privacyPayloadShapeNode]bool{}) {
			return errors.New("JSON identity values require a string-bearing subtree")
		}
	case PrivacyFieldOpaqueExact:
		// Opaque declarations may close any concrete or intentionally open node.
	default:
		return fmt.Errorf("unsupported privacy mode %q", mode)
	}
	return nil
}

func privacyPayloadShapeCanContainString(node *privacyPayloadShapeNode, visiting map[*privacyPayloadShapeNode]bool) bool {
	if node == nil {
		return false
	}
	if visiting[node] {
		return false
	}
	visiting[node] = true
	defer delete(visiting, node)
	switch node.kind {
	case privacyPayloadShapeOpen:
		return true
	case privacyPayloadShapeScalar:
		return node.scalar == privacyPayloadScalarString
	case privacyPayloadShapeObject:
		for _, child := range node.fields {
			if privacyPayloadShapeCanContainString(child, visiting) {
				return true
			}
		}
		return false
	case privacyPayloadShapeArray, privacyPayloadShapeMap:
		return privacyPayloadShapeCanContainString(node.element, visiting)
	default:
		return false
	}
}

func clonePrivacyPayloadShape(shape PrivacyPayloadShape) PrivacyPayloadShape {
	cloned := PrivacyPayloadShape{root: clonePrivacyPayloadShapeNode(shape.root)}
	if shape.alternatives != nil {
		cloned.alternatives = make([]*privacyPayloadShapeNode, len(shape.alternatives))
		for i, root := range shape.alternatives {
			cloned.alternatives[i] = clonePrivacyPayloadShapeNode(root)
		}
	}
	return cloned
}

func clonePrivacyPayloadShapeNode(node *privacyPayloadShapeNode) *privacyPayloadShapeNode {
	if node == nil {
		return nil
	}
	cloned := &privacyPayloadShapeNode{
		kind: node.kind, scalar: node.scalar, nullable: node.nullable,
		element: clonePrivacyPayloadShapeNode(node.element),
	}
	if node.fields != nil {
		cloned.fields = make(map[string]*privacyPayloadShapeNode, len(node.fields))
		for name, child := range node.fields {
			cloned.fields[name] = clonePrivacyPayloadShapeNode(child)
		}
	}
	if node.requiredFields != nil {
		cloned.requiredFields = make(map[string]struct{}, len(node.requiredFields))
		for name := range node.requiredFields {
			cloned.requiredFields[name] = struct{}{}
		}
	}
	return cloned
}

func privacyPayloadShapeForType(typ reflect.Type, visiting map[reflect.Type]bool) *privacyPayloadShapeNode {
	nullable := false
	for typ.Kind() == reflect.Pointer {
		nullable = true
		typ = typ.Elem()
	}
	if typ == jsonRawMessageType || typ.Kind() == reflect.Interface {
		return &privacyPayloadShapeNode{kind: privacyPayloadShapeOpen, nullable: true}
	}
	if typ == timeType || implementsPrivacyScalarMarshaler(typ) {
		return &privacyPayloadShapeNode{
			kind: privacyPayloadShapeScalar, scalar: privacyPayloadScalarString, nullable: nullable,
		}
	}
	if visiting[typ] {
		// Recursive JSON payloads are intentionally open at the recursion edge.
		// A privacy rule must close the parent path before required-mode validation
		// will accept data there.
		return &privacyPayloadShapeNode{kind: privacyPayloadShapeOpen, nullable: nullable}
	}
	switch typ.Kind() {
	case reflect.Struct:
		visiting[typ] = true
		node := &privacyPayloadShapeNode{
			kind: privacyPayloadShapeObject, nullable: nullable,
			fields: make(map[string]*privacyPayloadShapeNode), requiredFields: make(map[string]struct{}),
		}
		for i := 0; i < typ.NumField(); i++ {
			field := typ.Field(i)
			if field.PkgPath != "" && !field.Anonymous {
				continue
			}
			name, include, flatten, omitEmpty := privacyJSONFieldName(field)
			if !include {
				continue
			}
			// encoding/json's omitempty option does not omit a non-pointer
			// struct, even when every field in that struct has its zero value.
			// Required-mode validation must mirror those wire semantics exactly:
			// treating such a field as optional would let an importer delete a
			// producer-required object or time value without changing the schema
			// version.
			if omitEmpty && !privacyJSONOmitEmptyCanOmit(field.Type) {
				omitEmpty = false
			}
			child := privacyPayloadShapeForType(field.Type, visiting)
			if flatten && child != nil && child.kind == privacyPayloadShapeObject {
				for childName, grandchild := range child.fields {
					node.fields[childName] = grandchild
				}
				if !omitEmpty && field.Type.Kind() != reflect.Pointer {
					for childName := range child.requiredFields {
						node.requiredFields[childName] = struct{}{}
					}
				}
				continue
			}
			node.fields[name] = child
			if !omitEmpty {
				node.requiredFields[name] = struct{}{}
			}
		}
		delete(visiting, typ)
		return node
	case reflect.Slice, reflect.Array:
		if typ.Elem().Kind() == reflect.Uint8 {
			return &privacyPayloadShapeNode{
				kind: privacyPayloadShapeScalar, scalar: privacyPayloadScalarString,
				nullable: nullable || typ.Kind() == reflect.Slice,
			}
		}
		return &privacyPayloadShapeNode{
			kind: privacyPayloadShapeArray, nullable: nullable || typ.Kind() == reflect.Slice,
			element: privacyPayloadShapeForType(typ.Elem(), visiting),
		}
	case reflect.Map:
		return &privacyPayloadShapeNode{
			kind: privacyPayloadShapeMap, nullable: true,
			element: privacyPayloadShapeForType(typ.Elem(), visiting),
		}
	default:
		return &privacyPayloadShapeNode{
			kind: privacyPayloadShapeScalar, scalar: privacyPayloadScalarForType(typ), nullable: nullable,
		}
	}
}

func privacyPayloadScalarForType(typ reflect.Type) privacyPayloadScalarKind {
	switch typ.Kind() {
	case reflect.Bool:
		return privacyPayloadScalarBoolean
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64,
		reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64,
		reflect.Float32, reflect.Float64:
		return privacyPayloadScalarNumber
	default:
		return privacyPayloadScalarString
	}
}

func implementsPrivacyScalarMarshaler(typ reflect.Type) bool {
	if typ.Implements(jsonMarshalerType) || typ.Implements(textMarshalerType) {
		return true
	}
	return typ.Kind() != reflect.Pointer &&
		(reflect.PointerTo(typ).Implements(jsonMarshalerType) || reflect.PointerTo(typ).Implements(textMarshalerType))
}

func privacyJSONFieldName(field reflect.StructField) (name string, include, flatten, omitEmpty bool) {
	tag := field.Tag.Get("json")
	if tag == "-" {
		return "", false, false, false
	}
	options := strings.Split(tag, ",")
	name = options[0]
	for _, option := range options[1:] {
		if option == "omitempty" {
			omitEmpty = true
		}
	}
	if name == "" {
		if field.Anonymous {
			return "", true, true, omitEmpty
		}
		name = field.Name
	}
	return name, true, false, omitEmpty
}

// privacyJSONOmitEmptyCanOmit reports whether a field of typ has any value that
// encoding/json's omitempty option considers empty. This is the type-level form
// of encoding/json.isEmptyValue. In particular, structs are never empty and a
// fixed array is empty only when its length is zero.
func privacyJSONOmitEmptyCanOmit(typ reflect.Type) bool {
	switch typ.Kind() {
	case reflect.Array:
		return typ.Len() == 0
	case reflect.Map, reflect.Slice, reflect.String,
		reflect.Bool,
		reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64,
		reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64, reflect.Uintptr,
		reflect.Float32, reflect.Float64,
		reflect.Interface, reflect.Pointer:
		return true
	default:
		return false
	}
}

func privacyPayloadShapeFromRules(rules []PrivacyFieldRule) (PrivacyPayloadShape, error) {
	root := &privacyPayloadShapeNode{kind: privacyPayloadShapeObject, fields: map[string]*privacyPayloadShapeNode{}}
	for _, rule := range rules {
		segments := parsePrivacyPath(rule.Path)
		if len(segments) == 0 {
			return PrivacyPayloadShape{}, fmt.Errorf("events: privacy field path %q has no segments", rule.Path)
		}
		node := root
		for i, segment := range segments {
			last := i == len(segments)-1
			if segment == "@key" {
				return PrivacyPayloadShape{}, fmt.Errorf(
					"events: privacy field path %q needs an explicit typed payload shape for dynamic keys", rule.Path)
			}
			if segment == "*" {
				if node.kind != privacyPayloadShapeArray {
					return PrivacyPayloadShape{}, fmt.Errorf("events: privacy field path %q has an array element under a non-array", rule.Path)
				}
				if last {
					node.element = &privacyPayloadShapeNode{kind: privacyPayloadShapeOpen, nullable: true}
					break
				}
				if node.element == nil {
					nextKind := privacyPayloadShapeObject
					if segments[i+1] == "*" {
						nextKind = privacyPayloadShapeArray
					}
					node.element = &privacyPayloadShapeNode{kind: nextKind}
					if nextKind == privacyPayloadShapeObject {
						node.element.fields = map[string]*privacyPayloadShapeNode{}
					}
				}
				node = node.element
				continue
			}
			if node.kind != privacyPayloadShapeObject {
				return PrivacyPayloadShape{}, fmt.Errorf("events: privacy field path %q has an object field under a non-object", rule.Path)
			}
			if node.fields == nil {
				node.fields = map[string]*privacyPayloadShapeNode{}
			}
			if last {
				node.fields[segment] = &privacyPayloadShapeNode{kind: privacyPayloadShapeOpen, nullable: true}
				break
			}
			child := node.fields[segment]
			if child == nil {
				nextKind := privacyPayloadShapeObject
				if segments[i+1] == "*" {
					nextKind = privacyPayloadShapeArray
				}
				child = &privacyPayloadShapeNode{kind: nextKind}
				if nextKind == privacyPayloadShapeObject {
					child.fields = map[string]*privacyPayloadShapeNode{}
				}
				node.fields[segment] = child
			}
			node = child
		}
	}
	return PrivacyPayloadShape{root: root}, nil
}

// HasPrivacyEventPolicy lets the projector's schema-completeness guard prove
// that adding a decoder cannot silently add an unrewritable history shape.
func HasPrivacyEventPolicy(eventType string, schemaVersion int) bool {
	privacyEventPolicies.RLock()
	_, ok := privacyEventPolicies.values[privacyEventPolicyKey{
		eventType: eventType, schemaVersion: schemaVersion,
	}]
	privacyEventPolicies.RUnlock()
	return ok
}

func registeredPrivacyEventPolicy(eventType string, schemaVersion int) (PrivacyEventPolicy, bool) {
	privacyEventPolicies.RLock()
	policy, ok := privacyEventPolicies.values[privacyEventPolicyKey{
		eventType: eventType, schemaVersion: schemaVersion,
	}]
	privacyEventPolicies.RUnlock()
	return policy, ok
}

// ValidatePrivacyEventPolicySubjectFixtures mechanically exercises every
// subject-bearing rule registered for one exact event schema. Each fixture is a
// complete payload built from the independently declared shape, carries the raw
// subject at exactly one declared path, must rewrite it, must retain the closed
// payload shape, and must contain no raw subject afterward. CI catalogs use the
// returned count as their denominator instead of maintaining a second hand-made
// list that can forget a newly added personal-data path.
func ValidatePrivacyEventPolicySubjectFixtures(eventType string, schemaVersion int) (int, error) {
	if schemaVersion == 0 {
		schemaVersion = DefaultSchemaVersion
	}
	policy, ok := registeredPrivacyEventPolicy(eventType, schemaVersion)
	if !ok {
		return 0, fmt.Errorf("events: no privacy policy for %s v%d", eventType, schemaVersion)
	}
	if policy.RejectSubjectData {
		return 0, nil
	}
	const (
		tenantID = "privacy-fixture-tenant"
		subject  = "privacy-fixture-subject@example.test"
	)
	covered := 0
	for _, rule := range policy.Rules {
		if rule.Mode == PrivacyFieldOpaqueExact {
			continue
		}
		root, err := privacyPayloadShapeRootForRule(policy.PayloadShape, rule)
		if err != nil {
			return covered, fmt.Errorf("events: select %s v%d fixture alternative for %s: %w",
				eventType, schemaVersion, rule.Path, err)
		}
		document, err := privacyPayloadFixtureValue(root)
		if err != nil {
			return covered, fmt.Errorf("events: build %s v%d fixture for %s: %w",
				eventType, schemaVersion, rule.Path, err)
		}
		for _, declared := range policy.Rules {
			if declared.Mode != PrivacyFieldNestedJSONBytes {
				continue
			}
			if _, present, pathErr := privacyPayloadShapeNodeAt(root, parsePrivacyPath(declared.Path)); pathErr != nil {
				return covered, fmt.Errorf("events: locate %s v%d nested fixture for %s: %w",
					eventType, schemaVersion, declared.Path, pathErr)
			} else if !present {
				continue
			}
			if err := setPrivacyPayloadFixtureSubject(
				&document, root, parsePrivacyPath(declared.Path), declared.Mode, "fixture-safe-nested-json",
			); err != nil {
				return covered, fmt.Errorf("events: seed %s v%d nested fixture for %s: %w",
					eventType, schemaVersion, declared.Path, err)
			}
		}
		if err := setPrivacyPayloadFixtureSubject(
			&document, root, parsePrivacyPath(rule.Path), rule.Mode, subject,
		); err != nil {
			return covered, fmt.Errorf("events: seed %s v%d fixture for %s: %w",
				eventType, schemaVersion, rule.Path, err)
		}
		raw, err := json.Marshal(document)
		if err != nil {
			return covered, fmt.Errorf("events: encode %s v%d fixture for %s: %w",
				eventType, schemaVersion, rule.Path, err)
		}
		if err := validateRegisteredPrivacyEventPayload(raw, eventType, schemaVersion); err != nil {
			return covered, fmt.Errorf("events: validate %s v%d fixture for %s: %w",
				eventType, schemaVersion, rule.Path, err)
		}
		rewritten, changed, err := applyRegisteredPrivacyEventPolicy(
			raw, tenantID, subject, eventType, schemaVersion,
		)
		if err != nil {
			return covered, fmt.Errorf("events: rewrite %s v%d fixture for %s: %w",
				eventType, schemaVersion, rule.Path, err)
		}
		if !changed {
			return covered, fmt.Errorf("events: %s v%d fixture for %s did not rewrite", eventType, schemaVersion, rule.Path)
		}
		if bytes.Contains(rewritten, []byte(subject)) {
			return covered, fmt.Errorf("events: %s v%d fixture for %s retained the raw subject",
				eventType, schemaVersion, rule.Path)
		}
		if err := validateRegisteredPrivacyEventPayload(rewritten, eventType, schemaVersion); err != nil {
			return covered, fmt.Errorf("events: rewritten %s v%d fixture for %s changed shape: %w",
				eventType, schemaVersion, rule.Path, err)
		}
		covered++
	}
	return covered, nil
}

func privacyPayloadShapeRootForRule(
	shape PrivacyPayloadShape,
	rule PrivacyFieldRule,
) (*privacyPayloadShapeNode, error) {
	for _, root := range privacyPayloadShapeRoots(shape) {
		node, present, err := privacyPayloadShapeNodeAt(root, parsePrivacyPath(rule.Path))
		if err != nil {
			return nil, err
		}
		if !present {
			continue
		}
		if err := validatePrivacyRuleNodeMode(rule.Mode, node); err != nil {
			return nil, err
		}
		return root, nil
	}
	return nil, errors.New("rule is absent from every alternative")
}

func privacyPayloadFixtureValue(node *privacyPayloadShapeNode) (any, error) {
	if node == nil {
		return nil, errors.New("payload shape is absent")
	}
	switch node.kind {
	case privacyPayloadShapeScalar:
		switch node.scalar {
		case privacyPayloadScalarString:
			return "fixture-safe", nil
		case privacyPayloadScalarNumber:
			return json.Number("1"), nil
		case privacyPayloadScalarBoolean:
			return true, nil
		default:
			return nil, errors.New("scalar kind is absent")
		}
	case privacyPayloadShapeObject:
		value := make(map[string]any, len(node.fields))
		for field, child := range node.fields {
			childValue, err := privacyPayloadFixtureValue(child)
			if err != nil {
				return nil, fmt.Errorf("field %q: %w", field, err)
			}
			value[field] = childValue
		}
		return value, nil
	case privacyPayloadShapeArray:
		child, err := privacyPayloadFixtureValue(node.element)
		if err != nil {
			return nil, err
		}
		return []any{child}, nil
	case privacyPayloadShapeMap:
		child, err := privacyPayloadFixtureValue(node.element)
		if err != nil {
			return nil, err
		}
		return map[string]any{"fixture-key": child}, nil
	case privacyPayloadShapeOpen:
		return "fixture-safe", nil
	default:
		return nil, errors.New("payload shape kind is absent")
	}
}

func setPrivacyPayloadFixtureSubject(
	value *any,
	shape *privacyPayloadShapeNode,
	segments []string,
	mode PrivacyFieldMode,
	subject string,
) error {
	if len(segments) == 0 {
		next, err := privacyPayloadSubjectFixtureValue(shape, mode, subject)
		if err != nil {
			return err
		}
		*value = next
		return nil
	}
	if shape == nil {
		return errors.New("path is absent")
	}
	segment := segments[0]
	switch shape.kind {
	case privacyPayloadShapeObject:
		object, ok := (*value).(map[string]any)
		if !ok {
			return errors.New("fixture object changed shape")
		}
		childShape, ok := shape.fields[segment]
		if !ok {
			return fmt.Errorf("field %q is absent", segment)
		}
		child := object[segment]
		if err := setPrivacyPayloadFixtureSubject(&child, childShape, segments[1:], mode, subject); err != nil {
			return err
		}
		object[segment] = child
		return nil
	case privacyPayloadShapeArray:
		if segment != "*" {
			return fmt.Errorf("array segment is %q, want '*'", segment)
		}
		array, ok := (*value).([]any)
		if !ok || len(array) != 1 {
			return errors.New("fixture array has no representative element")
		}
		child := array[0]
		if err := setPrivacyPayloadFixtureSubject(&child, shape.element, segments[1:], mode, subject); err != nil {
			return err
		}
		array[0] = child
		return nil
	case privacyPayloadShapeMap:
		object, ok := (*value).(map[string]any)
		if !ok || len(object) != 1 {
			return errors.New("fixture dynamic object has no representative value")
		}
		if segment == "@key" {
			if len(segments) != 1 {
				return errors.New("dynamic object key cannot have descendants")
			}
			for key, child := range object {
				delete(object, key)
				object[subject] = child
				return nil
			}
		}
		if segment != "*" {
			return fmt.Errorf("dynamic object segment is %q, want '*' or '@key'", segment)
		}
		for key, child := range object {
			if err := setPrivacyPayloadFixtureSubject(&child, shape.element, segments[1:], mode, subject); err != nil {
				return err
			}
			object[key] = child
			return nil
		}
		return errors.New("fixture dynamic object is empty")
	default:
		return fmt.Errorf("segment %q descends through a scalar or open value", segment)
	}
}

func privacyPayloadSubjectFixtureValue(
	shape *privacyPayloadShapeNode,
	mode PrivacyFieldMode,
	subject string,
) (any, error) {
	switch mode {
	case PrivacyFieldIdentityExact:
		return subject, nil
	case PrivacyFieldSubjectToken:
		return "fixture/" + subject + "/member", nil
	case PrivacyFieldFreeTextClear, PrivacyFieldJSONIdentityValues:
		value, err := privacyPayloadFixtureValue(shape)
		if err != nil {
			return nil, err
		}
		if !seedPrivacyPayloadFixtureString(&value, shape, subject) {
			return nil, errors.New("declared subtree has no string value")
		}
		return value, nil
	case PrivacyFieldNestedJSONBytes:
		return canonicalNestedJSONFixture(subject)
	case PrivacyFieldOpaqueExact:
		return nil, errors.New("opaque paths are not subject-bearing fixtures")
	default:
		return nil, fmt.Errorf("unsupported privacy mode %q", mode)
	}
}

func seedPrivacyPayloadFixtureString(value *any, shape *privacyPayloadShapeNode, subject string) bool {
	if shape == nil {
		return false
	}
	switch shape.kind {
	case privacyPayloadShapeOpen:
		*value = subject
		return true
	case privacyPayloadShapeScalar:
		if shape.scalar != privacyPayloadScalarString {
			return false
		}
		*value = "fixture evidence for " + subject
		return true
	case privacyPayloadShapeObject:
		object, ok := (*value).(map[string]any)
		if !ok {
			return false
		}
		for field, childShape := range shape.fields {
			child := object[field]
			if seedPrivacyPayloadFixtureString(&child, childShape, subject) {
				object[field] = child
				return true
			}
		}
	case privacyPayloadShapeArray:
		array, ok := (*value).([]any)
		if !ok || len(array) == 0 {
			return false
		}
		child := array[0]
		if seedPrivacyPayloadFixtureString(&child, shape.element, subject) {
			array[0] = child
			return true
		}
	case privacyPayloadShapeMap:
		object, ok := (*value).(map[string]any)
		if !ok {
			return false
		}
		for key, child := range object {
			if seedPrivacyPayloadFixtureString(&child, shape.element, subject) {
				object[key] = child
				return true
			}
		}
	}
	return false
}

// validateRegisteredPrivacyEventPayload is the production append/import
// vocabulary gate. It runs without an erasure subject: a producer cannot smuggle
// a new path or container shape under an already-registered schema version and
// leave recovery to discover the drift years later.
func validateRegisteredPrivacyEventPayload(data []byte, eventType string, schemaVersion int) error {
	if schemaVersion == 0 {
		schemaVersion = DefaultSchemaVersion
	}
	policy, ok := registeredPrivacyEventPolicy(eventType, schemaVersion)
	if !ok {
		return fmt.Errorf("events: append %s v%d has no registered privacy policy", eventType, schemaVersion)
	}
	if len(data) == 0 || !json.Valid(data) {
		return fmt.Errorf("events: %s v%d payload is not valid JSON", eventType, schemaVersion)
	}
	if err := validatePrivacyJSONUniqueKeys(data); err != nil {
		return fmt.Errorf("events: %s v%d payload: %w", eventType, schemaVersion, err)
	}
	var document any
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.UseNumber()
	if err := decoder.Decode(&document); err != nil {
		return fmt.Errorf("events: decode %s v%d privacy payload: %w", eventType, schemaVersion, err)
	}
	rules := make([]compiledPrivacyFieldRule, len(policy.Rules))
	for i, rule := range policy.Rules {
		rules[i] = compiledPrivacyFieldRule{segments: parsePrivacyPath(rule.Path), mode: rule.Mode}
	}
	matched := 0
	var mismatch []string
	for i, root := range privacyPayloadShapeRoots(policy.PayloadShape) {
		if err := validatePrivacyPayloadValue(document, nil, root, rules); err != nil {
			mismatch = append(mismatch, fmt.Sprintf("alternative %d: %v", i+1, err))
			continue
		}
		matched++
	}
	if matched != 1 {
		if matched > 1 {
			return fmt.Errorf("events: %s v%d payload matches %d privacy shape alternatives, want exactly one",
				eventType, schemaVersion, matched)
		}
		return fmt.Errorf("events: %s v%d payload violates every closed privacy shape alternative: %s",
			eventType, schemaVersion, strings.Join(mismatch, "; "))
	}
	return nil
}

func validatePrivacyPayloadValue(
	value any,
	path []string,
	shape *privacyPayloadShapeNode,
	rules []compiledPrivacyFieldRule,
) error {
	if mode, declared := privacyRuleAt(rules, path); declared {
		null, err := validatePrivacyClosingNodeShape(value, path, shape)
		if err != nil || null {
			return err
		}
		return validatePrivacyClosingModeShape(value, path, mode)
	}
	if shape == nil {
		return fmt.Errorf("undeclared path /%s", strings.Join(path, "/"))
	}
	if value == nil {
		if shape.nullable {
			return nil
		}
		return fmt.Errorf("non-null path /%s changed to null", strings.Join(path, "/"))
	}
	switch shape.kind {
	case privacyPayloadShapeScalar:
		valid := false
		switch shape.scalar {
		case privacyPayloadScalarString:
			_, valid = value.(string)
		case privacyPayloadScalarNumber:
			_, valid = value.(json.Number)
		case privacyPayloadScalarBoolean:
			_, valid = value.(bool)
		}
		if !valid {
			return fmt.Errorf("scalar path /%s changed scalar or container shape", strings.Join(path, "/"))
		}
		return nil
	case privacyPayloadShapeObject:
		object, ok := value.(map[string]any)
		if !ok {
			return fmt.Errorf("object path /%s changed shape", strings.Join(path, "/"))
		}
		for key, child := range object {
			childShape, declared := shape.fields[key]
			if !declared {
				return fmt.Errorf("undeclared object field /%s", strings.Join(appendPrivacyPath(path, key), "/"))
			}
			if err := validatePrivacyPayloadValue(child, appendPrivacyPath(path, key), childShape, rules); err != nil {
				return err
			}
		}
		for required := range shape.requiredFields {
			if _, present := object[required]; !present {
				return fmt.Errorf("required object field /%s is missing", strings.Join(appendPrivacyPath(path, required), "/"))
			}
		}
		return nil
	case privacyPayloadShapeArray:
		array, ok := value.([]any)
		if !ok {
			return fmt.Errorf("array path /%s changed shape", strings.Join(path, "/"))
		}
		if shape.element == nil {
			return fmt.Errorf("array path /%s has no declared element shape", strings.Join(path, "/"))
		}
		for _, child := range array {
			if err := validatePrivacyPayloadValue(child, appendPrivacyPath(path, "*"), shape.element, rules); err != nil {
				return err
			}
		}
		return nil
	case privacyPayloadShapeMap:
		object, ok := value.(map[string]any)
		if !ok {
			return fmt.Errorf("dynamic object path /%s changed shape", strings.Join(path, "/"))
		}
		if shape.element == nil {
			return fmt.Errorf("dynamic object path /%s has no declared value shape", strings.Join(path, "/"))
		}
		keyShape := &privacyPayloadShapeNode{
			kind: privacyPayloadShapeScalar, scalar: privacyPayloadScalarString,
		}
		for key, child := range object {
			if err := validatePrivacyPayloadValue(
				key, appendPrivacyPath(path, "@key"), keyShape, rules,
			); err != nil {
				return err
			}
			if err := validatePrivacyPayloadValue(
				child, appendPrivacyPath(path, "*"), shape.element, rules,
			); err != nil {
				return err
			}
		}
		return nil
	case privacyPayloadShapeOpen:
		return fmt.Errorf("open path /%s lacks an explicit opaque/free-text/JSON-identity rule", strings.Join(path, "/"))
	default:
		return fmt.Errorf("path /%s has no payload shape", strings.Join(path, "/"))
	}
}

// validatePrivacyClosingNodeShape preserves the part of the typed schema that
// remains observable at a rule which deliberately closes an entire subtree.
// The rule owns descendant semantics, but it cannot turn a registered string
// into an object, an object into a scalar, or a required value into null.
func validatePrivacyClosingNodeShape(value any, path []string, shape *privacyPayloadShapeNode) (bool, error) {
	if shape == nil {
		return false, fmt.Errorf("undeclared path /%s", strings.Join(path, "/"))
	}
	if value == nil {
		if shape.nullable {
			return true, nil
		}
		return false, fmt.Errorf("non-null path /%s changed to null", strings.Join(path, "/"))
	}
	switch shape.kind {
	case privacyPayloadShapeScalar:
		valid := false
		switch shape.scalar {
		case privacyPayloadScalarString:
			_, valid = value.(string)
		case privacyPayloadScalarNumber:
			_, valid = value.(json.Number)
		case privacyPayloadScalarBoolean:
			_, valid = value.(bool)
		}
		if !valid {
			return false, fmt.Errorf("scalar path /%s changed scalar or container shape", strings.Join(path, "/"))
		}
	case privacyPayloadShapeObject, privacyPayloadShapeMap:
		if _, ok := value.(map[string]any); !ok {
			return false, fmt.Errorf("object path /%s changed shape", strings.Join(path, "/"))
		}
	case privacyPayloadShapeArray:
		if _, ok := value.([]any); !ok {
			return false, fmt.Errorf("array path /%s changed shape", strings.Join(path, "/"))
		}
	case privacyPayloadShapeOpen:
		// Raw JSON, interface values, recursive edges, and rule-derived leaves
		// deliberately have no stronger kind to preserve.
	default:
		return false, fmt.Errorf("path /%s has no payload shape", strings.Join(path, "/"))
	}
	return false, nil
}

func validatePrivacyClosingModeShape(value any, path []string, mode PrivacyFieldMode) error {
	switch mode {
	case PrivacyFieldIdentityExact, PrivacyFieldSubjectToken, PrivacyFieldNestedJSONBytes:
		if _, ok := value.(string); !ok {
			return fmt.Errorf("%s path /%s is not a string", mode, strings.Join(path, "/"))
		}
	case PrivacyFieldFreeTextClear:
		switch value.(type) {
		case string, []any, map[string]any:
		default:
			return fmt.Errorf("free-text path /%s has non-text shape", strings.Join(path, "/"))
		}
	case PrivacyFieldJSONIdentityValues, PrivacyFieldOpaqueExact:
		// These modes deliberately close the complete selected subtree. The
		// catalog author owns that decision; no descendant path is inferred.
	default:
		return fmt.Errorf("path /%s has unsupported privacy mode %q", strings.Join(path, "/"), mode)
	}
	return nil
}

func applyRegisteredPrivacyEventPolicy(
	data []byte,
	tenantID, subject, eventType string,
	schemaVersion int,
) ([]byte, bool, error) {
	if len(data) == 0 || subject == "" {
		return data, false, nil
	}
	if schemaVersion == 0 {
		schemaVersion = DefaultSchemaVersion
	}
	if !json.Valid(data) {
		if bytes.Contains(data, []byte(subject)) {
			return nil, false, errors.New("events: event payload containing erased subject is not valid JSON")
		}
		return data, false, nil
	}
	if err := validatePrivacyJSONUniqueKeys(data); err != nil {
		return nil, false, err
	}
	var document any
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.UseNumber()
	if err := decoder.Decode(&document); err != nil {
		if bytes.Contains(data, []byte(subject)) {
			return nil, false, errors.New("events: event payload containing erased subject is not valid JSON")
		}
		return data, false, nil
	}
	policy, ok := registeredPrivacyEventPolicy(eventType, schemaVersion)
	if !ok {
		if !privacyJSONContainsSubject(document, subject) {
			return data, false, nil
		}
		return nil, false, fmt.Errorf(
			"events: no privacy policy for subject-bearing event %s v%d",
			eventType, schemaVersion,
		)
	}
	if !privacyJSONContainsSubject(document, subject) && !privacyPolicyHasNestedJSONBytes(policy) {
		return data, false, nil
	}
	// A rewrite policy is meaningful only for the exact payload vocabulary it
	// was registered against. Validate the complete closed/OneOf shape before a
	// rule can select fields; otherwise a mixed historical variant, a deleted
	// required field, or an added sibling could ride through erasure merely
	// because the rule walker never visits it.
	if err := validateRegisteredPrivacyEventPayload(data, eventType, schemaVersion); err != nil {
		return nil, false, fmt.Errorf(
			"events: %s v%d privacy pre-rewrite payload: %w",
			eventType, schemaVersion, err,
		)
	}
	if policy.RejectSubjectData {
		return nil, false, fmt.Errorf(
			"events: privacy policy for %s v%d rejects subject-bearing payload data",
			eventType, schemaVersion,
		)
	}
	rules := make([]compiledPrivacyFieldRule, len(policy.Rules))
	for i, rule := range policy.Rules {
		rules[i] = compiledPrivacyFieldRule{
			segments: parsePrivacyPath(rule.Path), mode: rule.Mode,
		}
	}
	placeholder := subjectPrivacyPlaceholder(tenantID, subject)
	rewritten, changed, err := rewritePrivacyJSONValue(document, nil, rules, subject, placeholder)
	if err != nil {
		return nil, false, fmt.Errorf("events: %s v%d privacy policy: %w", eventType, schemaVersion, err)
	}
	if !changed {
		return data, false, nil
	}
	encoded, err := json.Marshal(rewritten)
	if err != nil {
		return nil, false, fmt.Errorf("events: encode policy-rewritten %s v%d: %w", eventType, schemaVersion, err)
	}
	if err := validateRegisteredPrivacyEventPayload(encoded, eventType, schemaVersion); err != nil {
		return nil, false, fmt.Errorf(
			"events: %s v%d privacy post-rewrite payload: %w",
			eventType, schemaVersion, err,
		)
	}
	return encoded, true, nil
}

func privacyPolicyHasNestedJSONBytes(policy PrivacyEventPolicy) bool {
	for _, rule := range policy.Rules {
		if rule.Mode == PrivacyFieldNestedJSONBytes {
			return true
		}
	}
	return false
}

func validatePrivacyJSONUniqueKeys(data []byte) error {
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.UseNumber()
	if err := validatePrivacyJSONValueTokens(decoder); err != nil {
		return fmt.Errorf("events: privacy JSON duplicate-key preflight: %w", err)
	}
	return nil
}

func validatePrivacyJSONValueTokens(decoder *json.Decoder) error {
	token, err := decoder.Token()
	if err != nil {
		return err
	}
	delim, structured := token.(json.Delim)
	if !structured {
		return nil
	}
	switch delim {
	case '{':
		seen := map[string]struct{}{}
		for decoder.More() {
			keyToken, err := decoder.Token()
			if err != nil {
				return err
			}
			key, ok := keyToken.(string)
			if !ok {
				return errors.New("object key is not a string")
			}
			if _, duplicate := seen[key]; duplicate {
				return fmt.Errorf("duplicate object key %q", key)
			}
			seen[key] = struct{}{}
			if err := validatePrivacyJSONValueTokens(decoder); err != nil {
				return err
			}
		}
		closing, err := decoder.Token()
		if err != nil || closing != json.Delim('}') {
			return errors.New("object did not end cleanly")
		}
	case '[':
		for decoder.More() {
			if err := validatePrivacyJSONValueTokens(decoder); err != nil {
				return err
			}
		}
		closing, err := decoder.Token()
		if err != nil || closing != json.Delim(']') {
			return errors.New("array did not end cleanly")
		}
	default:
		return fmt.Errorf("unexpected JSON delimiter %q", delim)
	}
	return nil
}

type compiledPrivacyFieldRule struct {
	segments []string
	mode     PrivacyFieldMode
}

func parsePrivacyPath(path string) []string {
	parts := strings.Split(strings.TrimPrefix(path, "/"), "/")
	for i := range parts {
		parts[i] = strings.ReplaceAll(strings.ReplaceAll(parts[i], "~1", "/"), "~0", "~")
	}
	return parts
}

func privacyRuleAt(rules []compiledPrivacyFieldRule, path []string) (PrivacyFieldMode, bool) {
	for _, rule := range rules {
		if privacyPathMatches(rule.segments, path) {
			return rule.mode, true
		}
	}
	return "", false
}

func privacyPathMatches(rule, path []string) bool {
	if len(rule) != len(path) {
		return false
	}
	for i := range rule {
		if !privacyPathSegmentMatches(rule[i], path[i]) {
			return false
		}
	}
	return true
}

func privacyPathSegmentMatches(rule, path string) bool {
	// @key is a synthetic map-key coordinate, never an object/array value.
	// Keeping it disjoint from * lets one closed typed map declare different
	// handling for arbitrary keys and arbitrary values without rule shadowing.
	if rule == "@key" || path == "@key" {
		return rule == path
	}
	return rule == "*" || rule == path
}

func privacyPathSegmentsOverlap(left, right string) bool {
	if left == "@key" || right == "@key" {
		return left == right
	}
	return left == right || left == "*" || right == "*"
}

func privacyRulePathsOverlap(left, right []string) bool {
	shared := len(left)
	if len(right) < shared {
		shared = len(right)
	}
	for i := 0; i < shared; i++ {
		if !privacyPathSegmentsOverlap(left[i], right[i]) {
			return false
		}
	}
	// Equal paths overlap, and a compatible shorter path shadows every longer
	// descendant at runtime. Registration rejects both declaration orders so an
	// opaque/clear parent cannot silently bypass a more specific child rule.
	return true
}

func rewritePrivacyJSONValue(
	value any,
	path []string,
	rules []compiledPrivacyFieldRule,
	subject, placeholder string,
) (any, bool, error) {
	if mode, declared := privacyRuleAt(rules, path); declared {
		switch mode {
		case PrivacyFieldOpaqueExact:
			return value, false, nil
		case PrivacyFieldIdentityExact:
			text, ok := value.(string)
			if !ok {
				return nil, false, fmt.Errorf("identity path /%s is not a string", strings.Join(path, "/"))
			}
			if text == subject && !isExactExistingPrivacyPlaceholder(text) {
				return placeholder, true, nil
			}
			if stringContainsUnprotectedSubjectToken(text, subject) {
				return nil, false, fmt.Errorf(
					"identity path /%s contains the subject in a non-exact value",
					strings.Join(path, "/"),
				)
			}
			return value, false, nil
		case PrivacyFieldSubjectToken:
			text, ok := value.(string)
			if !ok {
				return nil, false, fmt.Errorf("subject-token path /%s is not a string", strings.Join(path, "/"))
			}
			rewritten, changed := replaceSubjectTokens(text, subject, placeholder)
			return rewritten, changed, nil
		case PrivacyFieldJSONIdentityValues:
			return rewritePrivacyJSONIdentityValues(value, subject, placeholder)
		case PrivacyFieldNestedJSONBytes:
			return rewritePrivacyNestedJSONBytes(value, subject, placeholder)
		case PrivacyFieldFreeTextClear:
			if !privacyJSONContainsSubject(value, subject) {
				switch value.(type) {
				case string, []any, map[string]any:
					return value, false, nil
				default:
					return nil, false, fmt.Errorf("free-text path /%s has non-text shape", strings.Join(path, "/"))
				}
			}
			switch value.(type) {
			case string:
				return "", true, nil
			case []any:
				return []any{}, true, nil
			case map[string]any:
				return map[string]any{}, true, nil
			default:
				return nil, false, fmt.Errorf("free-text path /%s has non-text shape", strings.Join(path, "/"))
			}
		}
	}

	switch typed := value.(type) {
	case map[string]any:
		changed := false
		out := make(map[string]any, len(typed))
		destinations := make(map[string]string, len(typed))
		for key := range typed {
			keyPath := appendPrivacyPath(path, "@key")
			nextKey := key
			if stringContainsUnprotectedSubjectToken(key, subject) {
				mode, declared := privacyRuleAt(rules, keyPath)
				if !declared {
					return nil, false, fmt.Errorf("raw subject appears in undeclared object key at /%s", strings.Join(path, "/"))
				}
				switch mode {
				case PrivacyFieldIdentityExact:
					if key == subject {
						nextKey = placeholder
					}
				case PrivacyFieldSubjectToken:
					nextKey, _ = replaceSubjectTokens(key, subject, placeholder)
				case PrivacyFieldOpaqueExact, PrivacyFieldJSONIdentityValues, PrivacyFieldNestedJSONBytes:
				case PrivacyFieldFreeTextClear:
					return nil, false, errors.New("free-text object keys cannot be cleared")
				}
			}
			if prior, collision := destinations[nextKey]; collision && prior != key {
				return nil, false, fmt.Errorf(
					"privacy object-key rewrite collides at /%s between %q and %q",
					strings.Join(path, "/"), prior, key,
				)
			}
			destinations[nextKey] = key
		}
		for key, child := range typed {
			keyPath := appendPrivacyPath(path, "@key")
			nextKey := key
			if stringContainsUnprotectedSubjectToken(key, subject) {
				mode, declared := privacyRuleAt(rules, keyPath)
				if !declared {
					return nil, false, fmt.Errorf("raw subject appears in undeclared object key at /%s", strings.Join(path, "/"))
				}
				switch mode {
				case PrivacyFieldIdentityExact:
					if key == subject {
						nextKey = placeholder
						changed = true
					}
				case PrivacyFieldSubjectToken:
					var keyChanged bool
					nextKey, keyChanged = replaceSubjectTokens(key, subject, placeholder)
					changed = changed || keyChanged
				case PrivacyFieldOpaqueExact, PrivacyFieldJSONIdentityValues, PrivacyFieldNestedJSONBytes:
				case PrivacyFieldFreeTextClear:
					return nil, false, errors.New("free-text object keys cannot be cleared")
				}
			}
			next, childChanged, err := rewritePrivacyJSONValue(
				child, appendPrivacyPath(path, key), rules, subject, placeholder,
			)
			if err != nil {
				return nil, false, err
			}
			out[nextKey] = next
			changed = changed || childChanged
		}
		return out, changed, nil
	case []any:
		changed := false
		out := make([]any, len(typed))
		for i, child := range typed {
			next, childChanged, err := rewritePrivacyJSONValue(
				child, appendPrivacyPath(path, "*"), rules, subject, placeholder,
			)
			if err != nil {
				return nil, false, err
			}
			out[i] = next
			changed = changed || childChanged
		}
		return out, changed, nil
	case string:
		if stringContainsUnprotectedSubjectToken(typed, subject) {
			return nil, false, fmt.Errorf("raw subject appears at undeclared path /%s", strings.Join(path, "/"))
		}
	}
	return value, false, nil
}

func rewritePrivacyJSONIdentityValues(value any, subject, placeholder string) (any, bool, error) {
	switch typed := value.(type) {
	case string:
		if typed == subject && !isExactExistingPrivacyPlaceholder(typed) {
			return placeholder, true, nil
		}
		if stringContainsUnprotectedSubjectToken(typed, subject) {
			return nil, false, errors.New("JSON identity value contains the subject in a non-exact value")
		}
		return typed, false, nil
	case []any:
		out := make([]any, len(typed))
		changed := false
		for i, child := range typed {
			next, childChanged, err := rewritePrivacyJSONIdentityValues(child, subject, placeholder)
			if err != nil {
				return nil, false, err
			}
			out[i] = next
			changed = changed || childChanged
		}
		return out, changed, nil
	case map[string]any:
		out := make(map[string]any, len(typed))
		changed := false
		for key, child := range typed {
			if stringContainsUnprotectedSubjectToken(key, subject) {
				return nil, false, fmt.Errorf("raw subject appears in dynamic JSON object key %q", key)
			}
			next, childChanged, err := rewritePrivacyJSONIdentityValues(child, subject, placeholder)
			if err != nil {
				return nil, false, err
			}
			out[key] = next
			changed = changed || childChanged
		}
		return out, changed, nil
	default:
		return value, false, nil
	}
}

func appendPrivacyPath(path []string, segment string) []string {
	out := make([]string, len(path)+1)
	copy(out, path)
	out[len(path)] = segment
	return out
}

func privacyJSONContainsSubject(value any, subject string) bool {
	if subject == "" {
		return false
	}
	switch typed := value.(type) {
	case string:
		return stringContainsUnprotectedSubjectToken(typed, subject)
	case []any:
		for _, child := range typed {
			if privacyJSONContainsSubject(child, subject) {
				return true
			}
		}
	case map[string]any:
		for key, child := range typed {
			if stringContainsUnprotectedSubjectToken(key, subject) || privacyJSONContainsSubject(child, subject) {
				return true
			}
		}
	}
	return false
}

func subjectPrivacyPlaceholder(tenantID, subject string) string {
	return privacyref.Placeholder(privacyref.SubjectRef(tenantID, subject))
}

// replaceSubjectTokens replaces only occurrences bounded by structured
// delimiters. Letters, digits, underscore, hyphen, dot, and at-sign continue an
// identity token. This keeps short-subject erasure from changing admin, data,
// UUIDs, host names, email addresses, hashes, or algorithms by coincidence.
func replaceSubjectTokens(value, subject, placeholder string) (string, bool) {
	if subject == "" || !strings.Contains(value, subject) {
		return value, false
	}
	var out strings.Builder
	cursor := 0
	changed := false
	for cursor < len(value) {
		relative := strings.Index(value[cursor:], subject)
		if relative < 0 {
			break
		}
		start := cursor + relative
		end := start + len(subject)
		if placeholderEnd := existingPrivacyPlaceholderContaining(value, start, end); placeholderEnd > start {
			out.WriteString(value[cursor:placeholderEnd])
			cursor = placeholderEnd
			continue
		}
		if subjectTokenBoundaryBefore(value, start) && subjectTokenBoundaryAfter(value, end) {
			out.WriteString(value[cursor:start])
			out.WriteString(placeholder)
			cursor = end
			changed = true
			continue
		}
		out.WriteString(value[cursor:end])
		cursor = end
	}
	if !changed {
		return value, false
	}
	out.WriteString(value[cursor:])
	return out.String(), true
}

func existingPrivacyPlaceholderEnd(value string, start int) int {
	const (
		prefix    = "erased:"
		digestLen = 12
	)
	if start < 0 || start+len(prefix)+digestLen > len(value) ||
		!strings.HasPrefix(value[start:], prefix) {
		return 0
	}
	end := start + len(prefix) + digestLen
	for _, digit := range value[start+len(prefix) : end] {
		if (digit < '0' || digit > '9') && (digit < 'a' || digit > 'f') {
			return 0
		}
	}
	return end
}

func existingPrivacyPlaceholderContaining(value string, start, end int) int {
	const maxPlaceholderLen = len("erased:") + 12
	first := start - maxPlaceholderLen + 1
	if first < 0 {
		first = 0
	}
	for candidate := first; candidate <= start; candidate++ {
		placeholderEnd := existingPrivacyPlaceholderEnd(value, candidate)
		if placeholderEnd >= end {
			return placeholderEnd
		}
	}
	return 0
}

func isExactExistingPrivacyPlaceholder(value string) bool {
	return existingPrivacyPlaceholderEnd(value, 0) == len(value)
}

func stringContainsUnprotectedSubjectToken(value, subject string) bool {
	if subject == "" {
		return false
	}
	for cursor := 0; cursor < len(value); {
		relative := strings.Index(value[cursor:], subject)
		if relative < 0 {
			return false
		}
		start := cursor + relative
		end := start + len(subject)
		if placeholderEnd := existingPrivacyPlaceholderContaining(value, start, end); placeholderEnd > start {
			cursor = placeholderEnd
			continue
		}
		if subjectTokenBoundaryBefore(value, start) && subjectTokenBoundaryAfter(value, end) {
			return true
		}
		cursor = end
	}
	return false
}

func subjectTokenBoundaryBefore(value string, index int) bool {
	if index == 0 {
		return true
	}
	r, _ := utf8.DecodeLastRuneInString(value[:index])
	return !isSubjectTokenRune(r)
}

func subjectTokenBoundaryAfter(value string, index int) bool {
	if index == len(value) {
		return true
	}
	r, _ := utf8.DecodeRuneInString(value[index:])
	return !isSubjectTokenRune(r)
}

func isSubjectTokenRune(r rune) bool {
	return unicode.IsLetter(r) || unicode.IsNumber(r) || r == '_' || r == '-' || r == '.' || r == '@'
}
