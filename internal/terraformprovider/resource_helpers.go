package terraformprovider

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/hashicorp/terraform-plugin-framework/types"
)

func requiredString(v types.String, name string) (string, error) {
	if v.IsNull() || v.IsUnknown() || strings.TrimSpace(v.ValueString()) == "" {
		return "", fmt.Errorf("%s is required", name)
	}
	return v.ValueString(), nil
}

func optionalString(v types.String) string {
	if v.IsNull() || v.IsUnknown() {
		return ""
	}
	return v.ValueString()
}

func idempotencySeed(v types.String, parts ...string) string {
	if seed := strings.TrimSpace(optionalString(v)); seed != "" {
		return seed
	}
	return stableIdempotencyKey(append([]string{"seed"}, parts...)...)
}

func parseRawJSON(s string) (json.RawMessage, error) {
	raw := json.RawMessage(strings.TrimSpace(s))
	if len(raw) == 0 {
		return nil, fmt.Errorf("JSON body is required")
	}
	if !json.Valid(raw) {
		return nil, fmt.Errorf("value must be valid JSON")
	}
	return raw, nil
}

func maybeNotFound(err error) bool {
	apiErr, ok := err.(*Error)
	return ok && apiErr.StatusCode == 404
}
