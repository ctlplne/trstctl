// SPDX-License-Identifier: LicenseRef-trstctl-EE

package api

import (
	"strings"
)

// OpenAPISpec renders the AGID API as a standalone OpenAPI 3.1 document from the same
// Routes() + schemas() metadata the served document is generated from (the PCAS
// precedent), so a checked-in golden cannot drift from the routes. Every mutating
// operation documents the required Idempotency-Key header (AN-5), which the idempotency
// linter and the release conformance gate check.
func OpenAPISpec() map[string]any {
	paths := map[string]any{}
	for _, rt := range Routes(nil) {
		op := map[string]any{
			"operationId": rt.OperationID,
			"summary":     rt.Summary,
			"responses": map[string]any{
				rt.SuccessCode: map[string]any{"description": "success"},
			},
		}
		params := []any{}
		for _, p := range rt.PathParams {
			params = append(params, map[string]any{
				"name": p.Name, "in": "path", "required": true,
				"description": p.Description,
				"schema":      map[string]any{"type": "string"},
			})
		}
		for _, p := range rt.Query {
			params = append(params, map[string]any{
				"name": p.Name, "in": "query", "required": true,
				"description": p.Description,
				"schema":      map[string]any{"type": "string"},
			})
		}
		if rt.Mutation {
			params = append(params, map[string]any{
				"name": "Idempotency-Key", "in": "header", "required": true,
				"description": "AN-5 idempotency key; replaying it returns the original result",
				"schema":      map[string]any{"type": "string"},
			})
		}
		if len(params) > 0 {
			op["parameters"] = params
		}
		if rt.RequestSchema != "" {
			op["requestBody"] = map[string]any{
				"required": true,
				"content": map[string]any{
					"application/json": map[string]any{
						"schema": map[string]any{"$ref": "#/components/schemas/" + rt.RequestSchema},
					},
				},
			}
		}
		entry, _ := paths[rt.Path].(map[string]any)
		if entry == nil {
			entry = map[string]any{}
		}
		entry[strings.ToLower(rt.Method)] = op
		paths[rt.Path] = entry
	}
	return map[string]any{
		"openapi": "3.1.0",
		"info": map[string]any{
			"title":       "trstctl AGID API",
			"version":     "v1",
			"description": "Agent Identity Lifecycle Enforcement external surface: chain-bound issuance + cascaded revocation (ee/, LicenseRef-trstctl-EE).",
		},
		"paths":      paths,
		"components": map[string]any{"schemas": schemas()},
	}
}
