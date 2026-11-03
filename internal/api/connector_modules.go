// SPDX-License-Identifier: BUSL-1.1

package api

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"regexp"
	"strings"

	"trstctl.com/trstctl/internal/plugincensus"
)

// Connector modules in the served API (A242): the relay census rows the
// catalog returns, and the check of a module destination's configuration
// against the setup inputs its signed manifest declares.

// relayPluginResponseEntries preserves the array shapes promised by OpenAPI.
// A stored signed census may contain nil slices because nil and empty have the
// same signing meaning. JSON clients must still receive [] rather than null.
func relayPluginResponseEntries(entries []plugincensus.Entry) []plugincensus.Entry {
	out := make([]plugincensus.Entry, len(entries))
	for i, entry := range entries {
		out[i] = entry
		out[i].Grants = make([]plugincensus.Grant, len(entry.Grants))
		for j, grant := range entry.Grants {
			out[i].Grants[j] = grant
			out[i].Grants[j].Constraints = append([]string{}, grant.Constraints...)
		}
		if entry.Module != nil {
			module := *entry.Module
			module.Actions = append([]string{}, entry.Module.Actions...)
			module.Credentials = append([]string{}, entry.Module.Credentials...)
			module.Inputs = append([]plugincensus.ModuleInput{}, entry.Module.Inputs...)
			module.PendingPermissions = append([]string{}, entry.Module.PendingPermissions...)
			out[i].Module = &module
		}
	}
	return out
}

// requireModuleInputs checks a module connector's target configuration
// against the setup inputs its relay reports (A242): every required input is
// present, each has its declared type, and a secret input holds a reference
// (scheme://name), never the secret itself. A connector no relay reports
// module metadata for is not checked.
func (a *API) requireModuleInputs(ctx context.Context, tenantID, connectorName string, config json.RawMessage) error {
	if servedConnectorName(connectorName) || a.store == nil {
		return nil
	}
	inputs, found, err := a.store.TenantRelayModuleInputs(ctx, tenantID, connectorName)
	if err != nil || !found {
		return err
	}
	if err := validateModuleTargetConfig(inputs, config); err != nil {
		return errStatus(http.StatusUnprocessableEntity, "connector module "+connectorName+": "+err.Error())
	}
	return nil
}

var secretReference = regexp.MustCompile(`^[a-z][a-z0-9+.-]*://\S+$`)

// validateModuleTargetConfig checks config against a module's setup inputs.
func validateModuleTargetConfig(inputs []plugincensus.ModuleInput, config json.RawMessage) error {
	values := map[string]json.RawMessage{}
	if trimmed := bytes.TrimSpace(config); len(trimmed) > 0 && !bytes.Equal(trimmed, []byte("null")) {
		if err := json.Unmarshal(trimmed, &values); err != nil {
			return errors.New("configuration must be a JSON object")
		}
	}
	for _, in := range inputs {
		raw, present := values[in.Name]
		if !present || bytes.Equal(bytes.TrimSpace(raw), []byte("null")) {
			if in.Required {
				return fmt.Errorf("setup input %s is required", in.Name)
			}
			continue
		}
		switch in.Type {
		case "string":
			var v string
			if json.Unmarshal(raw, &v) != nil || (in.Required && strings.TrimSpace(v) == "") {
				return fmt.Errorf("setup input %s must be a non-empty string", in.Name)
			}
			if in.Secret && !secretReference.MatchString(v) {
				return fmt.Errorf("setup input %s is a secret: give a reference (scheme://name), never the value", in.Name)
			}
		case "integer":
			// Decoded into any, so a quoted "443" stays a string rather than
			// being accepted as a number.
			var v any
			dec := json.NewDecoder(bytes.NewReader(raw))
			dec.UseNumber()
			_ = dec.Decode(&v) // a failed decode leaves v nil: not a number
			n, isNumber := v.(json.Number)
			if !isNumber || strings.ContainsAny(n.String(), ".eE") {
				return fmt.Errorf("setup input %s must be an integer", in.Name)
			}
		case "boolean":
			var v bool
			if json.Unmarshal(raw, &v) != nil {
				return fmt.Errorf("setup input %s must be true or false", in.Name)
			}
		}
	}
	return nil
}
