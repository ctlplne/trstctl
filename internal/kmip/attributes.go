// SPDX-License-Identifier: BUSL-1.1

package kmip

import (
	"context"
	"encoding/binary"
	"fmt"
	"strings"
	"time"

	"trstctl.com/trstctl/internal/auditsink"
)

// Attribute operations (A197): Get Attributes, Get Attribute List, Add,
// Modify and Delete Attribute. A client sets names, contact information,
// x- custom attributes with text values, and may make a key unextractable;
// everything else is the server's and read-only.

const (
	attrUniqueIdentifier       = "Unique Identifier"
	attrObjectType             = "Object Type"
	attrCryptographicAlgorithm = "Cryptographic Algorithm"
	attrCryptographicLength    = "Cryptographic Length"
	attrCryptographicUsageMask = "Cryptographic Usage Mask"
	attrState                  = "State"
	attrInitialDate            = "Initial Date"
	attrActivationDate         = "Activation Date"
	attrLastChangeDate         = "Last Change Date"
	attrName                   = "Name"
	attrLink                   = "Link"
	attrContactInformation     = "Contact Information"
	attrSensitive              = "Sensitive"
	attrAlwaysSensitive        = "Always Sensitive"
	attrExtractable            = "Extractable"
	attrNeverExtractable       = "Never Extractable"
)

// Bounds on what a client stores, so one object's attributes stay small.
const (
	maxObjectNames      = 16
	maxCustomAttributes = 32
	maxAttributeText    = 1024
	maxCustomNameLength = 128
)

// attributeInstance is one encoded attribute value of an object.
type attributeInstance struct {
	name  string
	index int32
	value []byte // encoded with TagAttributeValue
}

func (a attributeInstance) encode() []byte {
	children := [][]byte{encodeText(TagAttributeName, a.name)}
	if a.index > 0 {
		children = append(children, encodeInteger(TagAttributeIndex, a.index))
	}
	return encodeStructure(TagAttribute, append(children, a.value)...)
}

// requestedAttribute is an attribute a client sent: its name, index and value.
type requestedAttribute struct {
	name  string
	index int32
	value TTLV
}

func sameAttribute(a, b string) bool {
	if strings.HasPrefix(a, "x-") || strings.HasPrefix(b, "x-") {
		return a == b
	}
	return normalizedAttributeName(a) == normalizedAttributeName(b)
}

func objectTypeEnum(t ObjectType) int32 {
	switch t {
	case ObjectPublicKey:
		return objectTypePublicKey
	case ObjectPrivateKey:
		return objectTypePrivateKey
	default:
		return objectTypeSymmetricKey
	}
}

func algorithmEnum(algorithm string) int32 {
	switch algorithm {
	case "RSA":
		return cryptographicAlgorithmRSA
	case "ECDSA":
		return cryptographicAlgorithmECDSA
	default:
		return cryptographicAlgorithmAES
	}
}

func stateEnum(state ObjectState) int32 {
	switch state {
	case StatePreActive:
		return stateEnumPreActive
	case StateRevoked:
		return stateEnumDeactivated
	case StateCompromised:
		return stateEnumCompromised
	case StateDestroyed:
		return stateEnumDestroyed
	default:
		return stateEnumActive
	}
}

func encodeBoolean(tag uint32, value bool) []byte {
	var buf [8]byte
	if value {
		buf[7] = 1
	}
	return encodeItem(tag, TTLVBoolean, buf[:])
}

// attributesOf lists an object's attributes in Get Attribute List order.
func attributesOf(obj *ManagedObject) []attributeInstance {
	out := []attributeInstance{
		{name: attrUniqueIdentifier, value: encodeText(TagAttributeValue, obj.ID)},
		{name: attrObjectType, value: encodeEnumeration(TagAttributeValue, objectTypeEnum(obj.Type))},
		{name: attrCryptographicAlgorithm, value: encodeEnumeration(TagAttributeValue, algorithmEnum(obj.Algorithm))},
	}
	if length, err := wireInt32From(obj.Length); err == nil && length > 0 {
		out = append(out, attributeInstance{name: attrCryptographicLength, value: encodeInteger(TagAttributeValue, length)})
	}
	if obj.UsageMask != 0 {
		out = append(out, attributeInstance{name: attrCryptographicUsageMask, value: encodeInteger(TagAttributeValue, obj.UsageMask)})
	}
	out = append(out, attributeInstance{name: attrState, value: encodeEnumeration(TagAttributeValue, stateEnum(obj.State))})
	for _, date := range []struct {
		name string
		at   time.Time
	}{{attrInitialDate, obj.Initial}, {attrActivationDate, obj.Activated}, {attrLastChangeDate, obj.LastChange}} {
		if !date.at.IsZero() {
			out = append(out, attributeInstance{name: date.name, value: encodeDateTime(TagAttributeValue, date.at)})
		}
	}
	for i, name := range obj.Names {
		index, _ := wireInt32From(i)
		out = append(out, attributeInstance{name: attrName, index: index, value: encodeStructure(TagAttributeValue,
			encodeText(TagNameValue, name), encodeEnumeration(TagNameType, nameTypeUninterpretedText))})
	}
	if obj.Link != "" {
		linkType := linkTypePrivateKey
		if obj.Type == ObjectPrivateKey {
			linkType = linkTypePublicKey
		}
		out = append(out, attributeInstance{name: attrLink, value: encodeStructure(TagAttributeValue,
			encodeEnumeration(TagLinkType, linkType), encodeText(TagLinkedObjectIdentifier, obj.Link))})
	}
	if obj.Contact != "" {
		out = append(out, attributeInstance{name: attrContactInformation, value: encodeText(TagAttributeValue, obj.Contact)})
	}
	out = append(out,
		attributeInstance{name: attrSensitive, value: encodeBoolean(TagAttributeValue, false)},
		attributeInstance{name: attrAlwaysSensitive, value: encodeBoolean(TagAttributeValue, false)},
		attributeInstance{name: attrExtractable, value: encodeBoolean(TagAttributeValue, obj.Extractable)},
		attributeInstance{name: attrNeverExtractable, value: encodeBoolean(TagAttributeValue, obj.NeverExtractable)},
	)
	for _, custom := range obj.Custom {
		out = append(out, attributeInstance{name: custom.Name, value: encodeText(TagAttributeValue, custom.Value)})
	}
	return out
}

// GetAttributes returns the named attributes of an object, every instance of
// each, or all of them when no name is given. A name the object has no value
// for is left out.
func (s *Server) GetAttributes(ctx context.Context, clientCertDER []byte, id string, names []string) ([]attributeInstance, error) {
	if _, err := s.authClient(ctx, "get_attributes", clientCertDER); err != nil {
		return nil, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	obj, ok := s.objects[id]
	if !ok {
		return nil, fmt.Errorf("kmip: object %q not found", id)
	}
	all := attributesOf(obj)
	if len(names) == 0 {
		return all, nil
	}
	var out []attributeInstance
	for _, want := range names {
		for _, attr := range all {
			if sameAttribute(attr.name, want) {
				out = append(out, attr)
			}
		}
	}
	return out, nil
}

// GetAttributeList returns the names of an object's attributes.
func (s *Server) GetAttributeList(ctx context.Context, clientCertDER []byte, id string) ([]string, error) {
	attrs, err := s.GetAttributes(ctx, clientCertDER, id, nil)
	if err != nil {
		return nil, err
	}
	var names []string
	for _, attr := range attrs {
		if len(names) == 0 || names[len(names)-1] != attr.name {
			names = append(names, attr.name)
		}
	}
	return names, nil
}

// readOnlyAttribute reports whether a client may never set an attribute.
func readOnlyAttribute(name string) bool {
	for _, server := range []string{attrUniqueIdentifier, attrObjectType, attrCryptographicAlgorithm, attrCryptographicLength,
		attrCryptographicUsageMask, attrState, attrInitialDate, attrActivationDate, attrLastChangeDate, attrLink,
		attrAlwaysSensitive, attrNeverExtractable} {
		if sameAttribute(name, server) {
			return true
		}
	}
	return strings.HasPrefix(name, "y-")
}

func textValue(attr requestedAttribute) (string, error) {
	if attr.value.Type != TTLVTextString {
		return "", wireError{reason: resultReasonInvalidField, message: attr.name + " takes a text value"}
	}
	value := string(attr.value.Value)
	if strings.TrimSpace(value) == "" || len(value) > maxAttributeText {
		return "", wireError{reason: resultReasonInvalidField, message: fmt.Sprintf("%s must be 1 to %d bytes", attr.name, maxAttributeText)}
	}
	return value, nil
}

func nameValue(attr requestedAttribute) (string, error) {
	if attr.value.Type != TTLVStructure {
		return "", wireError{reason: resultReasonInvalidField, message: "Name takes a Name Value and Name Type structure"}
	}
	node, ok := attr.value.FirstChild(TagNameValue)
	if !ok {
		return "", wireError{reason: resultReasonInvalidField, message: "Name Value is required"}
	}
	return textValue(requestedAttribute{name: attrName, value: node})
}

func booleanValue(attr requestedAttribute) (bool, error) {
	if attr.value.Type != TTLVBoolean || len(attr.value.Value) != 8 {
		return false, wireError{reason: resultReasonInvalidField, message: attr.name + " takes a boolean"}
	}
	return binary.BigEndian.Uint64(attr.value.Value) != 0, nil
}

func customIndex(obj *ManagedObject, name string) int {
	for i, custom := range obj.Custom {
		if custom.Name == name {
			return i
		}
	}
	return -1
}

// changeAttribute applies one Add, Modify or Delete Attribute to an object it
// holds locked, and returns the instance the response carries.
func changeAttribute(obj *ManagedObject, op Operation, attr requestedAttribute) (attributeInstance, error) {
	name := attr.name
	switch {
	case readOnlyAttribute(name):
		return attributeInstance{}, wireError{reason: resultReasonPermissionDenied, message: name + " is set by the server"}
	case sameAttribute(name, attrName):
		return changeName(obj, op, attr)
	case sameAttribute(name, attrContactInformation):
		return changeContact(obj, op, attr)
	case sameAttribute(name, attrExtractable):
		return changeExtractable(obj, op, attr)
	case sameAttribute(name, attrSensitive):
		return attributeInstance{}, wireError{reason: resultReasonFeatureNotSupported, message: "Sensitive objects are not served; Sensitive stays false"}
	case strings.HasPrefix(name, "x-"):
		return changeCustom(obj, op, attr)
	}
	return attributeInstance{}, wireError{reason: resultReasonFeatureNotSupported, message: "attribute " + name + " is not served"}
}

func changeName(obj *ManagedObject, op Operation, attr requestedAttribute) (attributeInstance, error) {
	index := int(attr.index)
	if op != OperationAddAttribute && (index < 0 || index >= len(obj.Names)) {
		return attributeInstance{}, wireError{reason: resultReasonIndexOutOfBounds, message: fmt.Sprintf("the object has no Name at index %d", index)}
	}
	switch op {
	case OperationAddAttribute:
		if len(obj.Names) >= maxObjectNames {
			return attributeInstance{}, wireError{reason: resultReasonPermissionDenied, message: fmt.Sprintf("an object holds at most %d names", maxObjectNames)}
		}
		value, err := nameValue(attr)
		if err != nil {
			return attributeInstance{}, err
		}
		obj.Names = append(obj.Names, value)
		index = len(obj.Names) - 1
	case OperationModifyAttribute:
		value, err := nameValue(attr)
		if err != nil {
			return attributeInstance{}, err
		}
		obj.Names[index] = value
	default:
		removed := obj.Names[index]
		obj.Names = append(obj.Names[:index:index], obj.Names[index+1:]...)
		return nameInstance(removed, index), nil
	}
	return nameInstance(obj.Names[index], index), nil
}

func nameInstance(value string, index int) attributeInstance {
	i, _ := wireInt32From(index)
	return attributeInstance{name: attrName, index: i, value: encodeStructure(TagAttributeValue,
		encodeText(TagNameValue, value), encodeEnumeration(TagNameType, nameTypeUninterpretedText))}
}

func changeContact(obj *ManagedObject, op Operation, attr requestedAttribute) (attributeInstance, error) {
	if op == OperationAddAttribute && obj.Contact != "" {
		return attributeInstance{}, wireError{reason: resultReasonIllegalOperation, message: "Contact Information has a value; use Modify Attribute"}
	}
	if op != OperationAddAttribute && obj.Contact == "" {
		return attributeInstance{}, wireError{reason: resultReasonItemNotFound, message: "the object has no Contact Information"}
	}
	if op == OperationDeleteAttribute {
		removed := obj.Contact
		obj.Contact = ""
		return attributeInstance{name: attrContactInformation, value: encodeText(TagAttributeValue, removed)}, nil
	}
	value, err := textValue(attr)
	if err != nil {
		return attributeInstance{}, err
	}
	obj.Contact = value
	return attributeInstance{name: attrContactInformation, value: encodeText(TagAttributeValue, value)}, nil
}

// changeExtractable lets a client make a key unextractable, never the reverse:
// a key that has been unextractable stays inside the server.
func changeExtractable(obj *ManagedObject, op Operation, attr requestedAttribute) (attributeInstance, error) {
	if op != OperationModifyAttribute {
		return attributeInstance{}, wireError{reason: resultReasonPermissionDenied, message: "Extractable always has a value; use Modify Attribute"}
	}
	value, err := booleanValue(attr)
	if err != nil {
		return attributeInstance{}, err
	}
	if value && !obj.Extractable {
		return attributeInstance{}, wireError{reason: resultReasonPermissionDenied, message: "an unextractable key stays unextractable"}
	}
	obj.Extractable = value
	return attributeInstance{name: attrExtractable, value: encodeBoolean(TagAttributeValue, value)}, nil
}

func changeCustom(obj *ManagedObject, op Operation, attr requestedAttribute) (attributeInstance, error) {
	if len(attr.name) > maxCustomNameLength {
		return attributeInstance{}, wireError{reason: resultReasonInvalidField, message: fmt.Sprintf("custom attribute names are at most %d bytes", maxCustomNameLength)}
	}
	at := customIndex(obj, attr.name)
	switch {
	case op == OperationAddAttribute && at >= 0:
		return attributeInstance{}, wireError{reason: resultReasonIllegalOperation, message: attr.name + " has a value; use Modify Attribute"}
	case op == OperationAddAttribute && len(obj.Custom) >= maxCustomAttributes:
		return attributeInstance{}, wireError{reason: resultReasonPermissionDenied, message: fmt.Sprintf("an object holds at most %d custom attributes", maxCustomAttributes)}
	case op != OperationAddAttribute && (at < 0 || attr.index != 0):
		return attributeInstance{}, wireError{reason: resultReasonItemNotFound, message: "the object has no " + attr.name + " at that index"}
	}
	if op == OperationDeleteAttribute {
		removed := obj.Custom[at]
		obj.Custom = append(obj.Custom[:at:at], obj.Custom[at+1:]...)
		return attributeInstance{name: removed.Name, value: encodeText(TagAttributeValue, removed.Value)}, nil
	}
	value, err := textValue(attr)
	if err != nil {
		return attributeInstance{}, wireError{reason: resultReasonFeatureNotSupported, message: "custom attributes are served with text values of up to 1024 bytes"}
	}
	if at < 0 {
		obj.Custom = append(obj.Custom, CustomAttribute{Name: attr.name, Value: value})
	} else {
		obj.Custom[at].Value = value
	}
	return attributeInstance{name: attr.name, value: encodeText(TagAttributeValue, value)}, nil
}

// ChangeAttribute runs Add, Modify or Delete Attribute and records the
// object's client attributes afterwards. A destroyed object's attributes do
// not change.
func (s *Server) ChangeAttribute(ctx context.Context, clientCertDER []byte, op Operation, id string, attr requestedAttribute) (attributeInstance, error) {
	if _, err := s.authClient(ctx, "change_attribute", clientCertDER); err != nil {
		return attributeInstance{}, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	obj, ok := s.objects[id]
	if !ok {
		return attributeInstance{}, fmt.Errorf("kmip: object %q not found", id)
	}
	if obj.State == StateDestroyed {
		return attributeInstance{}, wireError{reason: resultReasonPermissionDenied, message: "a destroyed object's attributes do not change"}
	}
	// Work on a copy, so a refused or unrecorded change leaves the object as
	// it was.
	changed := *obj
	changed.Names = append([]string(nil), obj.Names...)
	changed.Custom = append([]CustomAttribute(nil), obj.Custom...)
	instance, err := changeAttribute(&changed, op, attr)
	if err != nil {
		return attributeInstance{}, err
	}
	if err := s.persistAttributes(ctx, &changed); err != nil {
		return attributeInstance{}, err
	}
	obj.Names, obj.Contact, obj.Custom, obj.Extractable = changed.Names, changed.Contact, changed.Custom, changed.Extractable
	obj.LastChange = time.Now().UTC()
	_ = auditsink.Emit(ctx, s.audit, nil, "kmip.object.attributes_changed", s.tenantID, []byte(fmt.Sprintf(`{"id":%q}`, id)))
	return instance, nil
}

// persistAttributes records an object's client attributes.
func (s *Server) persistAttributes(ctx context.Context, obj *ManagedObject) error {
	extractable := obj.Extractable
	return s.persistState(ctx, kmipStateAttributesEventType, kmipAttributesEvent{
		ID: obj.ID, Names: obj.Names, Contact: obj.Contact, Custom: obj.Custom, Extractable: &extractable,
	})
}

// applyAttributes replays an attributes event. Erasure clears client text, so
// a cleared name or custom attribute is dropped rather than served empty.
func applyAttributes(obj *ManagedObject, p kmipAttributesEvent) {
	obj.Names = obj.Names[:0:0]
	for _, name := range p.Names {
		if name != "" {
			obj.Names = append(obj.Names, name)
		}
	}
	obj.Contact = p.Contact
	obj.Custom = obj.Custom[:0:0]
	for _, custom := range p.Custom {
		if strings.HasPrefix(custom.Name, "x-") && custom.Value != "" {
			obj.Custom = append(obj.Custom, custom)
		}
	}
	if p.Extractable != nil {
		obj.Extractable = *p.Extractable
	}
}
