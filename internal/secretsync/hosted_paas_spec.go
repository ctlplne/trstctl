// SPDX-License-Identifier: BUSL-1.1

package secretsync

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"unicode/utf8"

	"trstctl.com/trstctl/internal/crypto/secret"
)

// Railway variables (public GraphQL API): variableUpsert and variableDelete,
// and the variables query returns each value. Writes skip the redeploy; the
// next deploy picks them up.
const (
	railwayUpsert    = `mutation($input: VariableUpsertInput!) { variableUpsert(input: $input) }`
	railwayDelete    = `mutation($input: VariableDeleteInput!) { variableDelete(input: $input) }`
	railwayVariables = `query($projectId: String!, $environmentId: String!, $serviceId: String) { variables(projectId: $projectId, environmentId: $environmentId, serviceId: $serviceId, unrendered: true) }`
)

var railwayVendor = &hostedVendor{
	name:         "Railway",
	deliveryMode: "public GraphQL API variableUpsert and variableDelete over HTTPS (skipDeploys: applied on the next deploy)",
	authMode:     "Bearer account or workspace token supplied by operator config",
	wireFormat:   "GraphQL input {projectId, environmentId, serviceId, name, value}",
	readBack:     ReadBackValue,
	proof:        ProofStandIn,
	headers:      bearerHeaders,
	put: func(ctx context.Context, p *HostedSyncPusher, key string, value []byte) error {
		if !utf8.Valid(value) {
			return errHostedValueNotText
		}
		body := railwayRequest(p, railwayUpsert, key, value)
		defer secret.Wipe(body)
		return hostedError(p, "set variable", railwayCall(ctx, p, body, nil))
	},
	list: func(ctx context.Context, p *HostedSyncPusher) ([]string, error) {
		vars, err := railwayVars(ctx, p)
		if err != nil {
			return nil, err
		}
		defer wipeJSONMap(vars)
		names := make([]string, 0, len(vars))
		for name := range vars {
			names = append(names, name)
		}
		return names, nil
	},
	read: func(ctx context.Context, p *HostedSyncPusher, key string) (bool, []byte, error) {
		vars, err := railwayVars(ctx, p)
		if err != nil {
			return false, nil, err
		}
		defer wipeJSONMap(vars)
		value, ok := vars[key]
		if !ok {
			return false, nil, nil
		}
		return true, append([]byte(nil), value...), nil
	},
	remove: func(ctx context.Context, p *HostedSyncPusher, key string) error {
		vars, err := railwayVars(ctx, p)
		if err != nil {
			return err
		}
		_, exists := vars[key]
		wipeJSONMap(vars)
		if !exists {
			return nil
		}
		return hostedError(p, "delete variable", railwayCall(ctx, p, railwayRequest(p, railwayDelete, key, nil), nil))
	},
}

// railwayRequest is the GraphQL request body: a mutation's input carries the
// name and, for an upsert, the value; the query takes the scope alone.
func railwayRequest(p *HostedSyncPusher, query, key string, value []byte) []byte {
	body := []byte(`{"query":`)
	body = appendJSONValueBytes(body, []byte(query))
	body = append(body, `,"variables":{`...)
	if key != "" {
		body = append(body, `"input":{`...)
	}
	body = append(body, `"projectId":`...)
	body = appendJSONValueBytes(body, []byte(p.binding["project"]))
	body = append(body, `,"environmentId":`...)
	body = appendJSONValueBytes(body, []byte(p.binding["environment"]))
	if service := p.binding["service"]; service != "" {
		body = append(body, `,"serviceId":`...)
		body = appendJSONValueBytes(body, []byte(service))
	}
	if key != "" {
		body = append(body, `,"name":`...)
		body = appendJSONValueBytes(body, []byte(key))
		if value != nil {
			body = append(body, `,"value":`...)
			body = appendJSONValueBytes(body, value)
			body = append(body, `,"skipDeploys":true`...)
		}
		body = append(body, '}')
	}
	return append(body, `}}`...)
}

// railwayCall posts one GraphQL request; a GraphQL error is a failure whose
// message is not kept (it may quote the request).
func railwayCall(ctx context.Context, p *HostedSyncPusher, body []byte, data any) error {
	var got struct {
		Data   json.RawMessage `json:"data"`
		Errors []struct{}      `json:"errors"`
	}
	if err := p.send(ctx, http.MethodPost, "", body, &got); err != nil {
		return err
	}
	defer secret.Wipe(got.Data)
	if len(got.Errors) > 0 {
		return errors.New("the GraphQL API answered with an error")
	}
	if data == nil || len(got.Data) == 0 {
		return nil
	}
	return json.Unmarshal(got.Data, data)
}

func railwayVars(ctx context.Context, p *HostedSyncPusher) (map[string]secret.JSONBytes, error) {
	body := railwayRequest(p, railwayVariables, "", nil)
	var data struct {
		Variables map[string]secret.JSONBytes `json:"variables"`
	}
	if err := railwayCall(ctx, p, body, &data); err != nil {
		wipeJSONMap(data.Variables)
		return nil, hostedError(p, "read variables", err)
	}
	if data.Variables == nil {
		return map[string]secret.JSONBytes{}, nil
	}
	return data.Variables, nil
}

// DigitalOcean App Platform: variables live in the app spec (the app's
// envs, or one component's). A change reads the spec, edits that envs list
// and puts the whole spec back; everything else in it is sent unchanged. A
// SECRET env reads back as ciphertext, so the target is receipt-only.
var digitalOceanVendor = &hostedVendor{
	name:         "DigitalOcean App Platform",
	deliveryMode: "app spec read, then PUT of the whole spec with the variable set or removed, over HTTPS",
	authMode:     "Bearer API token (app:read, app:update) supplied by operator config",
	wireFormat:   "app spec envs entry {key, value, type: SECRET, scope: RUN_AND_BUILD_TIME}",
	readBack:     ReadBackReceiptOnly,
	proof:        ProofStandIn,
	headers:      bearerHeaders,
	put: func(ctx context.Context, p *HostedSyncPusher, key string, value []byte) error {
		if !utf8.Valid(value) {
			return errHostedValueNotText
		}
		return doEditEnvs(ctx, p, func(envs []map[string]json.RawMessage) ([]map[string]json.RawMessage, bool, error) {
			encoded := appendJSONValueBytes(nil, value)
			for _, env := range envs {
				if doEnvKey(env) == key {
					secret.Wipe(env["value"])
					env["value"], env["type"] = encoded, json.RawMessage(`"SECRET"`)
					return envs, true, nil
				}
			}
			name, _ := json.Marshal(key)
			return append(envs, map[string]json.RawMessage{
				"key": name, "value": encoded, "type": json.RawMessage(`"SECRET"`), "scope": json.RawMessage(`"RUN_AND_BUILD_TIME"`),
			}), true, nil
		})
	},
	list: func(ctx context.Context, p *HostedSyncPusher) ([]string, error) {
		var names []string
		err := doEditEnvs(ctx, p, func(envs []map[string]json.RawMessage) ([]map[string]json.RawMessage, bool, error) {
			for _, env := range envs {
				names = append(names, doEnvKey(env))
			}
			return envs, false, nil
		})
		return names, err
	},
	remove: func(ctx context.Context, p *HostedSyncPusher, key string) error {
		return doEditEnvs(ctx, p, func(envs []map[string]json.RawMessage) ([]map[string]json.RawMessage, bool, error) {
			kept := envs[:0]
			removed := false
			for _, env := range envs {
				if doEnvKey(env) == key {
					wipeRawMap(env)
					removed = true
					continue
				}
				kept = append(kept, env)
			}
			return kept, removed, nil
		})
	},
}

var doComponentKinds = []string{"services", "workers", "jobs", "static_sites", "functions"}

func doEnvKey(env map[string]json.RawMessage) string {
	var key string
	_ = json.Unmarshal(env["key"], &key)
	return key
}

// doEditEnvs reads the app's spec, hands the bound envs list to edit and,
// when edit reports a change, puts the whole spec back. Every decoded part
// of the spec, which holds other variables' values, is wiped.
func doEditEnvs(ctx context.Context, p *HostedSyncPusher, edit func([]map[string]json.RawMessage) ([]map[string]json.RawMessage, bool, error)) error {
	var got struct {
		App struct {
			Spec json.RawMessage `json:"spec"`
		} `json:"app"`
	}
	path := "/v2/apps/" + pathEscape(p.binding["app"])
	if err := p.send(ctx, http.MethodGet, path, nil, &got); err != nil {
		return hostedError(p, "read app spec", err)
	}
	defer secret.Wipe(got.App.Spec)
	var spec map[string]json.RawMessage
	if err := json.Unmarshal(got.App.Spec, &spec); err != nil {
		return hostedError(p, "decode app spec", err)
	}
	defer wipeRawMap(spec)
	// envsAt is the envs list's holder: the spec itself, or the component.
	holder, kind, index, components := spec, "", -1, []map[string]json.RawMessage(nil)
	if component := p.binding["component"]; component != "" {
		for _, k := range doComponentKinds {
			var list []map[string]json.RawMessage
			if len(spec[k]) == 0 || json.Unmarshal(spec[k], &list) != nil {
				continue
			}
			for i, c := range list {
				var name string
				if json.Unmarshal(c["name"], &name) == nil && name == component {
					holder, kind, index, components = c, k, i, list
				}
			}
			if index >= 0 {
				break
			}
			for _, c := range list {
				wipeRawMap(c)
			}
		}
		if index < 0 {
			return hostedError(p, "find component", errors.New("the app spec has no component of that name"))
		}
		defer func() {
			for _, c := range components {
				wipeRawMap(c)
			}
		}()
	}
	var envs []map[string]json.RawMessage
	if len(holder["envs"]) > 0 {
		if err := json.Unmarshal(holder["envs"], &envs); err != nil {
			return hostedError(p, "decode envs", err)
		}
	}
	defer func() {
		for _, env := range envs {
			wipeRawMap(env)
		}
	}()
	edited, changed, err := edit(envs)
	envs = edited
	if err != nil || !changed {
		return err
	}
	encodedEnvs, err := json.Marshal(envs)
	if err != nil {
		return err
	}
	secret.Wipe(holder["envs"])
	holder["envs"] = encodedEnvs
	if index >= 0 {
		encoded, err := json.Marshal(components)
		if err != nil {
			return err
		}
		secret.Wipe(spec[kind])
		spec[kind] = encoded
	}
	encodedSpec, err := json.Marshal(spec)
	if err != nil {
		return err
	}
	defer secret.Wipe(encodedSpec)
	body := append([]byte(`{"spec":`), encodedSpec...)
	body = append(body, '}')
	defer secret.Wipe(body)
	return hostedError(p, "update app spec", p.send(ctx, http.MethodPut, path, body, nil))
}

// wipeRawMap wipes every value of a decoded JSON object.
func wipeRawMap(m map[string]json.RawMessage) {
	for name, value := range m {
		secret.Wipe(value)
		delete(m, name)
	}
}

// Laravel Forge site environment: the site's .env file is read and written
// whole (the write is asynchronous). A variable is one KEY='value' line, or
// KEY="value" with escapes when the value holds a single quote.
var forgeVendor = &hostedVendor{
	name:         "Laravel Forge",
	deliveryMode: "site environment file read, then PUT of the whole file with the variable set or removed, over HTTPS (applied asynchronously)",
	authMode:     "Bearer API token supplied by operator config",
	wireFormat:   `.env line KEY='value', or KEY="value" with \\ and \" escapes when the value holds a single quote`,
	readBack:     ReadBackValue,
	proof:        ProofStandIn,
	headers:      bearerHeaders,
	put: func(ctx context.Context, p *HostedSyncPusher, key string, value []byte) error {
		line, err := dotenvLine(key, value)
		if err != nil {
			return hostedError(p, "set variable", err)
		}
		defer secret.Wipe(line)
		return forgeEdit(ctx, p, key, line)
	},
	list: func(ctx context.Context, p *HostedSyncPusher) ([]string, error) {
		content, err := forgeFile(ctx, p)
		if err != nil {
			return nil, err
		}
		defer secret.Wipe(content)
		var names []string
		for _, line := range bytes.Split(content, []byte{'\n'}) {
			if key, _ := dotenvSplit(line); key != "" {
				names = append(names, key)
			}
		}
		return names, nil
	},
	read: func(ctx context.Context, p *HostedSyncPusher, key string) (bool, []byte, error) {
		content, err := forgeFile(ctx, p)
		if err != nil {
			return false, nil, err
		}
		defer secret.Wipe(content)
		for _, line := range bytes.Split(content, []byte{'\n'}) {
			if name, raw := dotenvSplit(line); name == key {
				return true, dotenvValue(raw), nil
			}
		}
		return false, nil, nil
	},
	remove: func(ctx context.Context, p *HostedSyncPusher, key string) error {
		return forgeEdit(ctx, p, key, nil)
	},
}

func forgePath(p *HostedSyncPusher) string {
	return "/orgs/" + pathEscape(p.binding["org"]) + "/servers/" + pathEscape(p.binding["server"]) +
		"/sites/" + pathEscape(p.binding["site"]) + "/environment"
}

func forgeFile(ctx context.Context, p *HostedSyncPusher) ([]byte, error) {
	var got struct {
		Data struct {
			Attributes struct {
				Content secret.JSONBytes `json:"content"`
			} `json:"attributes"`
		} `json:"data"`
	}
	if err := p.send(ctx, http.MethodGet, forgePath(p), nil, &got); err != nil {
		return nil, hostedError(p, "read environment file", err)
	}
	return got.Data.Attributes.Content, nil
}

// forgeEdit replaces key's line with line (or removes it when line is nil)
// and writes the file back; a file that already says so is left alone.
func forgeEdit(ctx context.Context, p *HostedSyncPusher, key string, line []byte) error {
	content, err := forgeFile(ctx, p)
	if err != nil {
		return err
	}
	defer secret.Wipe(content)
	var out []byte
	defer func() { secret.Wipe(out) }()
	found, changed := false, false
	lines := bytes.Split(content, []byte{'\n'})
	for i, current := range lines {
		name, _ := dotenvSplit(current)
		switch {
		case name != key:
			out = append(out, current...)
		case line == nil || found:
			changed = true
			continue
		default:
			found = true
			changed = changed || !bytes.Equal(current, line)
			out = append(out, line...)
		}
		if i < len(lines)-1 {
			out = append(out, '\n')
		}
	}
	if line != nil && !found {
		if len(out) > 0 && out[len(out)-1] != '\n' {
			out = append(out, '\n')
		}
		out = append(out, line...)
		out = append(out, '\n')
		changed = true
	}
	if !changed {
		return nil
	}
	body := append([]byte(`{"environment":`), appendJSONValueBytes(nil, out)...)
	body = append(body, '}')
	defer secret.Wipe(body)
	return hostedError(p, "write environment file", p.send(ctx, http.MethodPut, forgePath(p), body, nil))
}

// dotenvLine is KEY='value', or KEY="value" with \\ and \" escaped when the
// value holds a single quote. A line break or "${" (interpolation) can't be
// written safely.
func dotenvLine(key string, value []byte) ([]byte, error) {
	if !utf8.Valid(value) {
		return nil, errHostedValueNotText
	}
	if bytes.ContainsAny(value, "\r\n") {
		return nil, errors.New("a .env variable can't hold a line break")
	}
	line := append([]byte(key), '=')
	if !bytes.ContainsAny(value, `'\`) {
		line = append(line, '\'')
		line = append(line, value...)
		return append(line, '\''), nil
	}
	if bytes.Contains(value, []byte("${")) {
		return nil, errors.New(`a .env value holding both a single quote and "${" can't be written without interpolation`)
	}
	line = append(line, '"')
	for _, c := range value {
		if c == '"' || c == '\\' {
			line = append(line, '\\')
		}
		line = append(line, c)
	}
	return append(line, '"'), nil
}

// dotenvSplit returns a line's key and raw value; comments and blank lines
// have no key.
func dotenvSplit(line []byte) (string, []byte) {
	trimmed := bytes.TrimSpace(line)
	trimmed = bytes.TrimPrefix(trimmed, []byte("export "))
	if len(trimmed) == 0 || trimmed[0] == '#' {
		return "", nil
	}
	eq := bytes.IndexByte(trimmed, '=')
	if eq <= 0 {
		return "", nil
	}
	return string(bytes.TrimSpace(trimmed[:eq])), bytes.TrimSpace(trimmed[eq+1:])
}

// dotenvValue decodes a raw value: single-quoted literally, double-quoted
// with backslash escapes, unquoted up to an inline " #" comment.
func dotenvValue(raw []byte) []byte {
	switch {
	case len(raw) >= 2 && raw[0] == '\'' && raw[len(raw)-1] == '\'':
		return append([]byte(nil), raw[1:len(raw)-1]...)
	case len(raw) >= 2 && raw[0] == '"' && raw[len(raw)-1] == '"':
		out := make([]byte, 0, len(raw))
		for i := 1; i < len(raw)-1; i++ {
			c := raw[i]
			if c == '\\' && i+1 < len(raw)-1 {
				i++
				switch raw[i] {
				case 'n':
					c = '\n'
				case 't':
					c = '\t'
				case 'r':
					c = '\r'
				default:
					c = raw[i]
				}
			}
			out = append(out, c)
		}
		return out
	default:
		if comment := bytes.Index(raw, []byte(" #")); comment >= 0 {
			raw = raw[:comment]
		}
		return append([]byte(nil), bytes.TrimSpace(raw)...)
	}
}
