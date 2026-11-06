//go:build windows

// SPDX-License-Identifier: BUSL-1.1
package windependents

import (
	"encoding/binary"
	"errors"
	"strings"
)

func iisProperty(element *automationObject, name string) (*automationObject, error) {
	key, err := newAutomationPublicString(name)
	if err != nil {
		return nil, err
	}
	defer func() { _ = key.destroy() }()
	return element.object("GetPropertyByName", 1, key.variant())
}
func iisPublicProperty(element *automationObject, name string) (string, error) {
	property, err := iisProperty(element, name)
	if err != nil {
		return "", err
	}
	defer property.destroy()
	return property.publicText("Value")
}
func iisIntegerProperty(element *automationObject, name string) (int64, error) {
	property, err := iisProperty(element, name)
	if err != nil {
		return 0, err
	}
	defer property.destroy()
	return property.integer("Value")
}
func iisChild(element *automationObject, name string) (*automationObject, error) {
	children, err := element.object("ChildElements", 2)
	if err != nil {
		return nil, err
	}
	defer children.destroy()
	key, err := newAutomationPublicString(name)
	if err != nil {
		return nil, err
	}
	defer func() { _ = key.destroy() }()
	return children.object("Item", 2, key.variant())
}
func iisMetadata(property *automationObject, name string) (automationVariant, error) {
	key, err := newAutomationPublicString(name)
	if err != nil {
		return automationVariant{}, err
	}
	defer func() { _ = key.destroy() }()
	return property.call("GetMetadata", 1, key.variant())
}
func iisPublicMetadata(property *automationObject, name string) (string, error) {
	value, err := iisMetadata(property, name)
	if err != nil {
		return "", err
	}
	if value.VT != 8 {
		value.destroy()
		return "", errors.New("windows pool: unexpected native encryption metadata type")
	}
	text, err := takeAutomationBSTR(value.Value, false)
	if err != nil {
		return "", err
	}
	defer func() { _ = text.destroy() }()
	return text.publicText()
}
func hashIISValue(buffer *poolHashBuffer, value *automationVariant) error {
	var kind [2]byte
	binary.LittleEndian.PutUint16(kind[:], value.VT)
	if err := buffer.field(kind[:]); err != nil {
		return err
	}
	switch value.VT {
	case 0, 1:
		return buffer.field(nil)
	case 2, 3, 11, 16, 17, 18, 19, 20, 21, 22, 23:
		var data [8]byte
		bits := value.scalarBits64()
		if value.VT == 16 || value.VT == 17 {
			bits &= 0xff
		} else if value.VT == 2 || value.VT == 11 || value.VT == 18 {
			bits &= 0xffff
		} else if value.VT != 20 && value.VT != 21 {
			bits &= 0xffffffff
		}
		binary.LittleEndian.PutUint64(data[:], bits)
		return buffer.field(data[:])
	case 8:
		text, err := takeAutomationBSTR(value.Value, true)
		if err != nil {
			*value = automationVariant{}
			return err
		}
		*value = automationVariant{}
		var hashErr error
		if len(text.raw) == 0 {
			hashErr = buffer.field(nil)
		} else {
			hashErr = buffer.field(text.raw[:len(text.raw)-2])
		}
		closeErr := text.destroy()
		if hashErr != nil {
			return hashErr
		}
		return closeErr
	default:
		return errors.New("windows pool: unsupported native configuration value type")
	}
}

type nativePoolHashBuffer struct {
	*poolHashBuffer
	elements, properties int
}

func hashIISElement(buffer *nativePoolHashBuffer, element *automationObject, depth int) error {
	buffer.elements++
	if depth > 12 || buffer.elements > 1024 {
		return errors.New("windows pool: native element tree exceeds bound")
	}
	name, err := element.publicText("Name")
	if err != nil {
		return err
	}
	if err := buffer.field([]byte(name)); err != nil {
		return err
	}
	properties, err := element.object("Properties", 2)
	if err != nil {
		return err
	}
	defer properties.destroy()
	count, err := properties.integer("Count")
	if err != nil || count < 0 || count > 256 {
		return errors.New("windows pool: native property count exceeds bound")
	}
	for i := uint32(0); i < uint32(count&0xffffffff); i++ {
		buffer.properties++
		if buffer.properties > 4096 {
			return errors.New("windows pool: native configuration property census exceeds bound")
		}
		property, err := properties.object("Item", 2, automationInteger(i))
		if err != nil {
			return err
		}
		key, err := property.publicText("Name")
		if err != nil {
			property.destroy()
			return err
		}
		if strings.EqualFold(key, "password") || (depth == 0 && strings.EqualFold(key, "state")) {
			property.destroy()
			// Never retrieve a saved password. Runtime state is not persistent config.
			continue
		}
		if err := buffer.field([]byte(key)); err != nil {
			property.destroy()
			return err
		}
		value, err := property.call("Value", 2)
		if err == nil {
			err = hashIISValue(buffer.poolHashBuffer, &value)
		}
		value.destroy()
		property.destroy()
		if err != nil {
			return err
		}
	}
	children, err := element.optionalObject("ChildElements", 2)
	if err != nil {
		return err
	}
	if children != nil {
		defer children.destroy()
		count, err := children.integer("Count")
		if err != nil || count < 0 || count > 256 {
			return errors.New("windows pool: native child count exceeds bound")
		}
		for i := uint32(0); i < uint32(count&0xffffffff); i++ {
			child, err := children.object("Item", 2, automationInteger(i))
			if err != nil {
				return err
			}
			err = hashIISElement(buffer, child, depth+1)
			child.destroy()
			if err != nil {
				return err
			}
		}
	}
	collection, err := element.optionalObject("Collection", 2)
	if err != nil {
		return err
	}
	if collection != nil {
		defer collection.destroy()
		count, err := collection.integer("Count")
		if err != nil || count < 0 || count > 1024 {
			return errors.New("windows pool: native collection count exceeds bound")
		}
		for i := uint32(0); i < uint32(count&0xffffffff); i++ {
			child, err := collection.object("Item", 2, automationInteger(i))
			if err != nil {
				return err
			}
			err = hashIISElement(buffer, child, depth+1)
			child.destroy()
			if err != nil {
				return err
			}
		}
	}
	return nil
}
func nativePoolConfigurationHash(pool Pool, element *automationObject) (string, error) {
	buffer, err := newPoolHashBuffer()
	if err != nil {
		return "", err
	}
	defer buffer.destroy()
	for _, value := range []string{"trstctl/windows-iis-pool/config/v1", pool.Name, pool.AccountSID, pool.EncryptionProvider} {
		if err := buffer.field([]byte(value)); err != nil {
			return "", err
		}
	}
	if err := hashIISElement(&nativePoolHashBuffer{poolHashBuffer: buffer}, element, 0); err != nil {
		return "", err
	}
	return buffer.digest(), nil
}
