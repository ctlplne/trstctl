// SPDX-License-Identifier: LicenseRef-trstctl-EE

package kmip

import (
	"encoding/binary"
	"fmt"
	"strings"
	"time"

	servedkmip "trstctl.com/trstctl/ee/kmip"
)

func DecodeSnapshotTTLV(frame []byte) (Snapshot, error) {
	root, err := servedkmip.ParseTTLV(frame)
	if err != nil {
		return Snapshot{}, err
	}
	var objects []ManagedObject
	for _, payload := range collectNodes(root, servedkmip.TagResponsePayload) {
		for _, node := range payload.Children {
			if node.Tag != TagManagedObject || node.Type != servedkmip.TTLVStructure {
				continue
			}
			obj, err := parseManagedObject(node)
			if err != nil {
				return Snapshot{}, err
			}
			objects = append(objects, obj)
		}
	}
	if len(objects) == 0 && root.Tag == TagManagedObject && root.Type == servedkmip.TTLVStructure {
		obj, err := parseManagedObject(root)
		if err != nil {
			return Snapshot{}, err
		}
		objects = append(objects, obj)
	}
	return Snapshot{Objects: objects}, nil
}

func parseManagedObject(node servedkmip.TTLV) (ManagedObject, error) {
	var out ManagedObject
	if uid, ok := textChild(node, servedkmip.TagUniqueIdentifier); ok {
		out.UniqueIdentifier = uid
	}
	if objectType, ok := textChild(node, servedkmip.TagObjectType); ok {
		out.ObjectType = ObjectType(objectType)
	}
	for _, attr := range node.ChildrenByTag(servedkmip.TagAttribute) {
		name, value, ok := parseAttribute(attr)
		if !ok {
			continue
		}
		switch normalizeAttrName(name) {
		case "cryptographic_algorithm":
			out.Algorithm = valueString(value)
		case "cryptographic_length":
			out.LengthBits = valueInt(value)
		case "state":
			out.State = State(valueString(value))
		case "initial_date":
			out.InitialDate = valueTime(value)
		case "activation_date":
			out.ActivationDate = valueTime(value)
		case "deactivation_date":
			out.DeactivationDate = valueTime(value)
		case "issuer_der":
			out.IssuerNameDER = valueBytes(value)
		case "serial_number":
			out.SerialHex = valueString(value)
		case "subject_dn":
			out.SubjectDN = valueString(value)
		case "subject_public_key_info", "spki":
			out.SPKI = valueBytes(value)
		case "object_type":
			out.ObjectType = ObjectType(valueString(value))
		}
	}
	if out.UniqueIdentifier == "" {
		return ManagedObject{}, fmt.Errorf("xrec kmip: managed object missing Unique Identifier")
	}
	if out.ObjectType == "" {
		return ManagedObject{}, fmt.Errorf("xrec kmip: managed object %q missing Object Type", out.UniqueIdentifier)
	}
	return out, nil
}

func collectNodes(root servedkmip.TTLV, tag uint32) []servedkmip.TTLV {
	var out []servedkmip.TTLV
	var walk func(servedkmip.TTLV)
	walk = func(node servedkmip.TTLV) {
		if node.Tag == tag {
			out = append(out, node)
		}
		for _, child := range node.Children {
			walk(child)
		}
	}
	walk(root)
	return out
}

func parseAttribute(attr servedkmip.TTLV) (string, servedkmip.TTLV, bool) {
	nameNode, ok := attr.FirstChild(servedkmip.TagAttributeName)
	if !ok || nameNode.Type != servedkmip.TTLVTextString {
		return "", servedkmip.TTLV{}, false
	}
	valueNode, ok := attr.FirstChild(servedkmip.TagAttributeValue)
	if !ok {
		return "", servedkmip.TTLV{}, false
	}
	return string(nameNode.Value), valueNode, true
}

func normalizeAttrName(name string) string {
	return strings.ToLower(strings.NewReplacer(" ", "_", "-", "_", ".", "_").Replace(strings.TrimSpace(name)))
}

func textChild(node servedkmip.TTLV, tag uint32) (string, bool) {
	child, ok := node.FirstChild(tag)
	if !ok || child.Type != servedkmip.TTLVTextString {
		return "", false
	}
	return string(child.Value), true
}

func valueString(v servedkmip.TTLV) string {
	switch v.Type {
	case servedkmip.TTLVTextString:
		return string(v.Value)
	case servedkmip.TTLVEnumeration, servedkmip.TTLVInteger:
		return fmt.Sprint(valueInt(v))
	default:
		return ""
	}
}

func valueInt(v servedkmip.TTLV) int {
	if len(v.Value) != 4 {
		return 0
	}
	return int(int32(binary.BigEndian.Uint32(v.Value)))
}

func valueBytes(v servedkmip.TTLV) []byte {
	if v.Type != servedkmip.TTLVByteString {
		return nil
	}
	return append([]byte(nil), v.Value...)
}

func valueTime(v servedkmip.TTLV) time.Time {
	if v.Type != servedkmip.TTLVDateTime || len(v.Value) != 8 {
		return time.Time{}
	}
	return time.Unix(int64(binary.BigEndian.Uint64(v.Value)), 0).UTC()
}
