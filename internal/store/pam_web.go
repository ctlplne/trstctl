// SPDX-License-Identifier: BUSL-1.1

package store

import (
	"encoding/json"
	"fmt"

	"trstctl.com/trstctl/internal/accessweb"
)

// A273: a web console target's route and a template's or session's web
// sign-in are stored as JSON objects; none is the empty object.

func encodeWebJSON[T any](v *T) ([]byte, error) {
	if v == nil {
		return []byte(`{}`), nil
	}
	return json.Marshal(v)
}

func decodeWebRoute(raw []byte) (*accessweb.Route, error) {
	if len(raw) == 0 || string(raw) == "{}" {
		return nil, nil
	}
	var r accessweb.Route
	if err := json.Unmarshal(raw, &r); err != nil {
		return nil, fmt.Errorf("store: decode web console route: %w", err)
	}
	return &r, nil
}

func decodeWebSignIn(raw []byte) (*accessweb.SignIn, error) {
	if len(raw) == 0 || string(raw) == "{}" {
		return nil, nil
	}
	var s accessweb.SignIn
	if err := json.Unmarshal(raw, &s); err != nil {
		return nil, fmt.Errorf("store: decode web sign-in: %w", err)
	}
	return &s, nil
}
