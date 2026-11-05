// SPDX-License-Identifier: BUSL-1.1

package store

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"

	"trstctl.com/trstctl/internal/accessrules"
)

func encodePAMCommandPolicy(p *accessrules.Policy, target string) ([]byte, error) {
	if p == nil {
		return []byte(`{}`), nil
	}
	if err := accessrules.ValidatePolicy(p, target); err != nil {
		return nil, err
	}
	return json.Marshal(p)
}

func decodePAMCommandPolicy(raw []byte, target string) (*accessrules.Policy, error) {
	raw = bytes.TrimSpace(raw)
	if len(raw) == 0 || bytes.Equal(raw, []byte(`{}`)) {
		return nil, nil
	}
	if len(raw) > 128<<10 {
		return nil, errors.New("store: command policy exceeds its bound")
	}
	var p accessrules.Policy
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&p); err != nil {
		return nil, errors.New("store: invalid command policy")
	}
	var extra any
	if decoder.Decode(&extra) != io.EOF {
		return nil, errors.New("store: trailing command policy data")
	}
	if err := accessrules.ValidatePolicy(&p, target); err != nil {
		return nil, err
	}
	return &p, nil
}
