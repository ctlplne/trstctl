// SPDX-License-Identifier: BUSL-1.1

package sourcecatalog

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"strings"
)

// ValidateControlFieldCase protects every discovery source kind, including
// sources stored before an API upgrade. Go's struct decoder accepts folded
// spellings that raw JSON grant checks do not. Credential references,
// destinations and private-egress controls must use one exact spelling.
func ValidateControlFieldCase(raw []byte) error {
	dec := json.NewDecoder(bytes.NewReader(raw))
	if err := scanControlFieldCase(dec); err != nil {
		return err
	}
	if _, err := dec.Token(); err != io.EOF {
		return fmt.Errorf("config contains trailing JSON data")
	}
	return nil
}

func scanControlFieldCase(dec *json.Decoder) error {
	token, err := dec.Token()
	if err != nil {
		return err
	}
	switch token {
	case json.Delim('{'):
		seen := make(map[string]bool)
		for dec.More() {
			field, err := dec.Token()
			if err != nil {
				return err
			}
			name, ok := field.(string)
			if !ok {
				return fmt.Errorf("config has an invalid field name")
			}
			canonical := strings.ToLower(name)
			controlled := strings.HasSuffix(canonical, "_ref") || DiscoveryEndpointKey(canonical) || canonical == "allow_private_endpoint" || canonical == "private_egress_cidrs"
			if controlled && (name != canonical || seen[canonical]) {
				return fmt.Errorf("config has mis-cased or duplicate control field %q", name)
			}
			if controlled {
				seen[canonical] = true
			}
			if err := scanControlFieldCase(dec); err != nil {
				return err
			}
		}
		closing, err := dec.Token()
		if err != nil || closing != json.Delim('}') {
			return fmt.Errorf("config has an incomplete object")
		}
	case json.Delim('['):
		for dec.More() {
			if err := scanControlFieldCase(dec); err != nil {
				return err
			}
		}
		closing, err := dec.Token()
		if err != nil || closing != json.Delim(']') {
			return fmt.Errorf("config has an incomplete array")
		}
	}
	return nil
}

// DiscoveryEndpointKey names endpoint fields that travel beside a credential
// reference and therefore participate in its destination-bound grant.
func DiscoveryEndpointKey(key string) bool {
	return key == "endpoint" || key == "url" || strings.HasSuffix(key, "_endpoint") || strings.HasSuffix(key, "_url")
}
