// SPDX-License-Identifier: BUSL-1.1
package awsiam

import (
	"bytes"
	"encoding/xml"
	"errors"
	"io"
	"strings"
)

type element struct {
	name     string
	text     strings.Builder
	children []*element
}

func (e *element) child(name string) (*element, error) {
	var found *element
	for _, c := range e.children {
		if c.name == name {
			if found != nil {
				return nil, errors.New("duplicate XML field")
			}
			found = c
		}
	}
	if found == nil {
		return nil, errors.New("missing XML field")
	}
	return found, nil
}
func (e *element) optional(name string) (*element, error) {
	var found *element
	for _, c := range e.children {
		if c.name == name {
			if found != nil {
				return nil, errors.New("duplicate XML field")
			}
			found = c
		}
	}
	return found, nil
}
func (e *element) value(name string) (string, error) {
	v, err := e.child(name)
	if err != nil {
		return "", err
	}
	if len(v.children) > 0 {
		return "", errors.New("XML scalar contains children")
	}
	return v.text.String(), nil
}
func (e *element) optionalValue(name string) (string, error) {
	v, err := e.optional(name)
	if err != nil || v == nil {
		return "", err
	}
	if len(v.children) > 0 {
		return "", errors.New("XML scalar contains children")
	}
	return v.text.String(), nil
}
func parseResponse(raw []byte, action string) (*element, error) {
	if len(raw) > maxResponse {
		return nil, errors.New("XML byte bound")
	}
	decoder := xml.NewDecoder(bytes.NewReader(raw))
	var stack []*element
	var root *element
	for tokens := 0; ; tokens++ {
		if tokens > 100000 {
			return nil, errors.New("XML token bound")
		}
		token, err := decoder.Token()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, errors.New("invalid XML")
		}
		switch v := token.(type) {
		case xml.StartElement:
			if len(stack) >= 24 || len(v.Attr) > 32 || len(v.Name.Local) > 128 {
				return nil, errors.New("XML structural bound")
			}
			n := &element{name: v.Name.Local}
			if len(stack) == 0 {
				if root != nil {
					return nil, errors.New("multiple XML roots")
				}
				root = n
			} else {
				parent := stack[len(stack)-1]
				parent.children = append(parent.children, n)
			}
			stack = append(stack, n)
		case xml.EndElement:
			if len(stack) == 0 {
				return nil, errors.New("invalid XML end")
			}
			stack = stack[:len(stack)-1]
		case xml.CharData:
			if len(stack) == 0 {
				if len(bytes.TrimSpace(v)) > 0 {
					return nil, errors.New("text outside XML root")
				}
			} else {
				stack[len(stack)-1].text.Write(v)
			}
		case xml.Directive:
			return nil, errors.New("XML directives are not accepted")
		}
	}
	if len(stack) != 0 || root == nil || root.name != action+"Response" {
		return nil, errors.New("unexpected XML response root")
	}
	return root.child(action + "Result")
}
