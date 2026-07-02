package api

import "strings"

// VaultCompatContract returns the machine-readable OpenAPI 3.1 fragment for the
// Vault/OpenBao-compatible /v1 shim. It is intentionally separate from the native
// /api/v1 contract because these paths mimic Vault wire shapes for migration tools,
// not trstctl's resource-oriented API.
func VaultCompatContract() *Document {
	doc := &Document{
		OpenAPI: "3.1.0",
		Info: Info{
			Title:       "trstctl Vault/OpenBao Compatibility API",
			Version:     "v1",
			Description: "Compatibility subset for stock Vault/OpenBao migration clients. The native /api/v1 OpenAPI document remains the complete trstctl API contract.",
		},
		Paths: map[string]PathItem{},
		Components: Components{
			Schemas: vaultCompatSchemas(),
			SecuritySchemes: map[string]SecurityScheme{
				"VaultToken": {
					Type:        "apiKey",
					Name:        "X-Vault-Token",
					In:          "header",
					Description: "A normal trstctl tenant API token carried in the header used by the stock Vault CLI.",
				},
			},
		},
	}
	for _, rt := range vaultCompatRoutes {
		item := doc.Paths[rt.contractPath]
		if item == nil {
			item = PathItem{}
			doc.Paths[rt.contractPath] = item
		}
		item[strings.ToLower(rt.method)] = vaultCompatOperation(rt)
	}
	return doc
}

func vaultCompatOperation(rt vaultCompatRoute) *Operation {
	op := &Operation{
		OperationID:        rt.operationID,
		Summary:            rt.summary,
		Parameters:         vaultCompatParameters(rt),
		Responses:          vaultCompatResponses(rt),
		XPermission:        string(rt.permission),
		XSensitiveResponse: rt.sensitiveResponse,
	}
	if rt.tokenRequired {
		op.Security = []map[string][]string{{"VaultToken": {}}}
	}
	if rt.requestSchema != "" {
		op.RequestBody = &RequestBody{
			Required: true,
			Content: map[string]MediaType{
				"application/json": {Schema: ref(rt.requestSchema)},
			},
		}
	}
	return op
}

func vaultCompatParameters(rt vaultCompatRoute) []Parameter {
	var out []Parameter
	switch rt.contractPath {
	case "/v1/sys/internal/ui/mounts/{path}":
		out = append(out, Parameter{
			Name:        "path",
			In:          "path",
			Required:    true,
			Description: "Vault mount-relative path, for example secret/data/payments/db or pki/issue/default.",
			Schema:      str(),
		})
	case "/v1/secret/data/{name}":
		out = append(out, Parameter{
			Name:        "name",
			In:          "path",
			Required:    true,
			Description: "Vault KV v2 secret path below the secret/ mount.",
			Schema:      str(),
		})
	case "/v1/pki/issue/{role}":
		out = append(out, Parameter{
			Name:        "role",
			In:          "path",
			Required:    true,
			Description: "Vault PKI role label accepted for CLI compatibility; trstctl maps issuance to the requested common name.",
			Schema:      str(),
		})
	}
	if rt.mutation {
		out = append(out, Parameter{
			Name:        "Idempotency-Key",
			In:          "header",
			Description: "Optional for stock Vault/OpenBao clients. When omitted, trstctl derives a deterministic key from method, path, and body so retries do not duplicate mutations.",
			Schema:      str(),
		})
	}
	return out
}

func vaultCompatResponses(rt vaultCompatRoute) map[string]Response {
	responses := map[string]Response{
		rt.successCode: {
			Description: "Vault/OpenBao-compatible success response.",
			Content: map[string]MediaType{
				"application/json": {Schema: ref(rt.responseSchema)},
			},
		},
	}
	for _, code := range vaultCompatErrorCodes(rt) {
		responses[code] = Response{
			Description: "Vault/OpenBao-compatible error envelope.",
			Content: map[string]MediaType{
				"application/json": {Schema: ref("VaultErrorResponse")},
			},
		}
	}
	return responses
}

func vaultCompatErrorCodes(rt vaultCompatRoute) []string {
	switch {
	case rt.contractPath == "/v1/sys/health":
		return nil
	case rt.contractPath == "/v1/sys/internal/ui/mounts/{path}":
		return []string{"403", "404", "429", "500"}
	case rt.contractPath == "/v1/secret/data/{name}" && rt.mutation:
		return []string{"400", "403", "404", "409", "413", "429", "500"}
	case rt.contractPath == "/v1/secret/data/{name}":
		return []string{"400", "403", "404", "429", "500"}
	case rt.contractPath == "/v1/pki/issue/{role}":
		return []string{"400", "403", "413", "422", "429", "503"}
	default:
		return []string{"403", "429", "500"}
	}
}

func vaultCompatSchemas() map[string]*Schema {
	anySchema := &Schema{}
	boolSchema := &Schema{Type: "boolean"}
	intSchema := &Schema{Type: "integer"}
	stringArray := &Schema{Type: "array", Items: str()}

	return map[string]*Schema{
		"VaultHealthResponse": object(map[string]*Schema{
			"initialized": boolSchema,
			"sealed":      boolSchema,
			"standby":     boolSchema,
			"version":     str(),
		}, "initialized", "sealed", "standby", "version"),
		"VaultErrorResponse": object(map[string]*Schema{
			"errors": stringArray,
		}, "errors"),
		"VaultMountInfo": object(map[string]*Schema{
			"path":    str(),
			"type":    {Type: "string", Enum: []string{"kv", "pki"}},
			"options": object(map[string]*Schema{"version": str()}),
		}, "path", "type"),
		"VaultTokenLookupSelf": object(map[string]*Schema{
			"id":           str(),
			"accessor":     str(),
			"display_name": str(),
			"entity_id":    str(),
			"meta":         object(map[string]*Schema{"tenant_id": str()}, "tenant_id"),
			"num_uses":     intSchema,
			"orphan":       boolSchema,
			"path":         str(),
			"policies":     stringArray,
			"renewable":    boolSchema,
			"ttl":          intSchema,
		}, "id", "accessor", "display_name", "entity_id", "meta", "num_uses", "orphan", "path", "policies", "renewable", "ttl"),
		"VaultKVWriteRequest": object(map[string]*Schema{
			"data":    object(map[string]*Schema{}),
			"options": object(map[string]*Schema{}),
		}, "data"),
		"VaultKVMetadata": object(map[string]*Schema{
			"created_time":    timestamp(),
			"deletion_time":   str(),
			"destroyed":       boolSchema,
			"version":         intSchema,
			"custom_metadata": object(map[string]*Schema{}),
		}, "created_time", "deletion_time", "destroyed", "version", "custom_metadata"),
		"VaultKVReadData": object(map[string]*Schema{
			"data":     object(map[string]*Schema{}),
			"metadata": ref("VaultKVMetadata"),
		}, "data", "metadata"),
		"VaultPKIIssueRequest": object(map[string]*Schema{
			"common_name": str(),
			"ttl":         str(),
			"ttl_seconds": intSchema,
		}, "common_name"),
		"VaultPKIIssueData": object(map[string]*Schema{
			"serial_number": str(),
			"certificate":   str(),
			"private_key":   str(),
		}, "serial_number", "certificate", "private_key"),
		"VaultMountInfoResponse":       vaultCompatEnvelope("VaultMountInfo", anySchema),
		"VaultTokenLookupSelfResponse": vaultCompatEnvelope("VaultTokenLookupSelf", anySchema),
		"VaultKVWriteResponse":         vaultCompatEnvelope("VaultKVMetadata", anySchema),
		"VaultKVReadResponse":          vaultCompatEnvelope("VaultKVReadData", anySchema),
		"VaultPKIIssueResponse":        vaultCompatEnvelope("VaultPKIIssueData", anySchema),
	}
}

func vaultCompatEnvelope(dataSchema string, warnings *Schema) *Schema {
	return object(map[string]*Schema{
		"request_id":     str(),
		"lease_id":       str(),
		"renewable":      {Type: "boolean"},
		"lease_duration": {Type: "integer"},
		"data":           ref(dataSchema),
		"warnings":       warnings,
	}, "request_id", "lease_id", "renewable", "lease_duration", "data", "warnings")
}
