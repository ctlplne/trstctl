// SPDX-License-Identifier: BUSL-1.1

package secretsync

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"unicode/utf8"

	"trstctl.com/trstctl/internal/crypto/secret"
	"trstctl.com/trstctl/internal/secrettext"
)

// Developer and operations platforms (A241).

// Windmill workspace variables: secret variables at paths (u/<user>/... or
// f/<folder>/...). Create and update are separate calls; get_value returns
// the decrypted value.
var windmillVendor = &hostedVendor{
	name:         "Windmill",
	deliveryMode: "workspace variable create or update, and delete, over HTTPS",
	authMode:     "Bearer token supplied by operator config",
	wireFormat:   "JSON {path, value, is_secret: true, description}",
	readBack:     ReadBackValue,
	proof:        ProofStandIn,
	headers:      bearerHeaders,
	put: func(ctx context.Context, p *HostedSyncPusher, key string, value []byte) error {
		if !utf8.Valid(value) {
			return errHostedValueNotText
		}
		err := p.send(ctx, http.MethodGet, windmillPath(p, "get/"+windmillVar(key))+"?decrypt_secret=false", nil, nil)
		if err != nil && !notFound(err) {
			return hostedError(p, "read variable", err)
		}
		if err == nil {
			body := jsonValueBody("value", value)
			defer secret.Wipe(body)
			return hostedError(p, "update variable", p.send(ctx, http.MethodPost, windmillPath(p, "update/"+windmillVar(key)), body, nil))
		}
		body := append([]byte(`{"path":`), appendJSONValueBytes(nil, []byte(key))...)
		body = append(body, `,"value":`...)
		body = appendJSONValueBytes(body, value)
		body = append(body, `,"is_secret":true,"description":"managed by trstctl"}`...)
		defer secret.Wipe(body)
		return hostedError(p, "create variable", p.send(ctx, http.MethodPost, windmillPath(p, "create"), body, nil))
	},
	list: func(ctx context.Context, p *HostedSyncPusher) ([]string, error) {
		var names []string
		for page := 1; page <= hostedPageLimit; page++ {
			var got []struct {
				Path string `json:"path"`
			}
			if err := p.send(ctx, http.MethodGet, windmillPath(p, "list")+"?per_page=100&page="+strconv.Itoa(page), nil, &got); err != nil {
				return nil, hostedError(p, "list variables", err)
			}
			for _, item := range got {
				names = append(names, item.Path)
			}
			if len(got) < 100 {
				return names, nil
			}
		}
		return nil, ErrScopedListLimit
	},
	read: func(ctx context.Context, p *HostedSyncPusher, key string) (bool, []byte, error) {
		var value secret.JSONBytes
		err := p.send(ctx, http.MethodGet, windmillPath(p, "get_value/"+windmillVar(key)), nil, &value)
		if notFound(err) {
			return false, nil, nil
		}
		if err != nil {
			return false, nil, hostedError(p, "read variable", err)
		}
		return true, value, nil
	},
	remove: func(ctx context.Context, p *HostedSyncPusher, key string) error {
		return hostedError(p, "delete variable", ignoreNotFound(p.send(ctx, http.MethodDelete, windmillPath(p, "delete/"+windmillVar(key)), nil, nil)))
	},
}

func windmillPath(p *HostedSyncPusher, rest string) string {
	return "/w/" + pathEscape(p.binding["workspace"]) + "/variables/" + rest
}

// windmillVar escapes each segment of a variable path, keeping its slashes.
func windmillVar(key string) string {
	parts := strings.Split(key, "/")
	for i, part := range parts {
		parts[i] = pathEscape(part)
	}
	return strings.Join(parts, "/")
}

// Zabbix user macros (JSON-RPC): secret-text macros {$NAME}, global or on
// one host. Create and update are separate methods; a secret macro's value
// is never returned. The key is the macro's name without {$ }.
var zabbixVendor = &hostedVendor{
	name:         "Zabbix",
	deliveryMode: "JSON-RPC usermacro create, update and delete (global or host macros) over HTTPS",
	authMode:     "Bearer API token supplied by operator config",
	wireFormat:   "secret-text user macro {macro: \"{$NAME}\", value, type: 1}",
	readBack:     ReadBackReceiptOnly,
	proof:        ProofStandIn,
	headers:      bearerHeaders,
	put: func(ctx context.Context, p *HostedSyncPusher, key string, value []byte) error {
		if !utf8.Valid(value) {
			return errHostedValueNotText
		}
		ids, err := zabbixMacros(ctx, p)
		if err != nil {
			return err
		}
		host := p.binding["host"]
		params := []byte(`{`)
		method := "usermacro.createglobal"
		if id, ok := ids[key]; ok {
			method = "usermacro.updateglobal"
			field := "globalmacroid"
			if host != "" {
				method, field = "usermacro.update", "hostmacroid"
			}
			params = append(params, `"`+field+`":`...)
			params = appendJSONValueBytes(params, []byte(id))
		} else {
			if host != "" {
				method = "usermacro.create"
				params = append(params, `"hostid":`...)
				params = appendJSONValueBytes(params, []byte(host))
				params = append(params, ',')
			}
			params = append(params, `"macro":`...)
			params = appendJSONValueBytes(params, []byte(zabbixMacro(key)))
			params = append(params, `,"description":"managed by trstctl"`...)
		}
		params = append(params, `,"type":1,"value":`...)
		params = appendJSONValueBytes(params, value)
		params = append(params, '}')
		defer secret.Wipe(params)
		return hostedError(p, "set macro", zabbixCall(ctx, p, method, params, nil))
	},
	list: func(ctx context.Context, p *HostedSyncPusher) ([]string, error) {
		ids, err := zabbixMacros(ctx, p)
		if err != nil {
			return nil, err
		}
		return mapKeys(ids), nil
	},
	remove: func(ctx context.Context, p *HostedSyncPusher, key string) error {
		ids, err := zabbixMacros(ctx, p)
		if err != nil {
			return err
		}
		id, ok := ids[key]
		if !ok {
			return nil
		}
		method := "usermacro.deleteglobal"
		if p.binding["host"] != "" {
			method = "usermacro.delete"
		}
		params := appendJSONValueBytes([]byte(`[`), []byte(id))
		params = append(params, ']')
		return hostedError(p, "delete macro", zabbixCall(ctx, p, method, params, nil))
	},
}

func zabbixMacro(key string) string { return "{$" + key + "}" }

// zabbixMacros maps each of this target's macro names (without {$ }) to its
// ID: the global macros, or the bound host's own macros.
func zabbixMacros(ctx context.Context, p *HostedSyncPusher) (map[string]string, error) {
	params := []byte(`{"output":["globalmacroid","hostmacroid","macro"],"globalmacro":true}`)
	if host := p.binding["host"]; host != "" {
		params = append([]byte(`{"output":["hostmacroid","macro"],"hostids":[`), appendJSONValueBytes(nil, []byte(host))...)
		params = append(params, `]}`...)
	}
	var got []struct {
		GlobalMacroID string `json:"globalmacroid"`
		HostMacroID   string `json:"hostmacroid"`
		Macro         string `json:"macro"`
	}
	if err := zabbixCall(ctx, p, "usermacro.get", params, &got); err != nil {
		return nil, hostedError(p, "list macros", err)
	}
	ids := map[string]string{}
	for _, item := range got {
		name, ok := strings.CutPrefix(item.Macro, "{$")
		name, closed := strings.CutSuffix(name, "}")
		if !ok || !closed {
			continue
		}
		if p.binding["host"] != "" {
			ids[name] = item.HostMacroID
		} else {
			ids[name] = item.GlobalMacroID
		}
	}
	return ids, nil
}

// zabbixCall posts one JSON-RPC 2.0 request; an error object fails without
// keeping its text.
func zabbixCall(ctx context.Context, p *HostedSyncPusher, method string, params []byte, result any) error {
	body := append([]byte(`{"jsonrpc":"2.0","method":`), appendJSONValueBytes(nil, []byte(method))...)
	body = append(body, `,"params":`...)
	body = append(body, params...)
	body = append(body, `,"id":1}`...)
	defer secret.Wipe(body)
	req, err := p.request(ctx, http.MethodPost, "", body, "application/json-rpc")
	if err != nil {
		return err
	}
	var got struct {
		Result json.RawMessage `json:"result"`
		Error  *struct{}       `json:"error"`
	}
	if err := readJSON2xx(p.doer, req, &got); err != nil {
		return err
	}
	defer secret.Wipe(got.Result)
	if got.Error != nil {
		return errors.New("the JSON-RPC API answered with an error")
	}
	if result == nil {
		return nil
	}
	return json.Unmarshal(got.Result, result)
}

// Portainer stack environment variables: a change reads the stack and its
// compose file and puts both back with the variable set or removed; the
// stack redeploys. GET returns each value.
var portainerVendor = &hostedVendor{
	name:         "Portainer",
	deliveryMode: "stack read, then PUT of its compose file and whole Env list (the stack redeploys), over HTTPS",
	authMode:     "X-API-Key access token supplied by operator config",
	wireFormat:   "stack Env entry {name, value}",
	readBack:     ReadBackValue,
	proof:        ProofStandIn,
	headers: func(p *HostedSyncPusher, req *http.Request) {
		req.Header.Set("X-API-Key", secrettext.String(p.token.Bytes()))
	},
	put: func(ctx context.Context, p *HostedSyncPusher, key string, value []byte) error {
		if !utf8.Valid(value) {
			return errHostedValueNotText
		}
		return portainerEdit(ctx, p, key, value)
	},
	list: func(ctx context.Context, p *HostedSyncPusher) ([]string, error) {
		env, err := portainerEnv(ctx, p)
		if err != nil {
			return nil, err
		}
		defer wipePortainerEnv(env)
		names := make([]string, 0, len(env))
		for _, item := range env {
			names = append(names, item.Name)
		}
		return names, nil
	},
	read: func(ctx context.Context, p *HostedSyncPusher, key string) (bool, []byte, error) {
		env, err := portainerEnv(ctx, p)
		if err != nil {
			return false, nil, err
		}
		defer wipePortainerEnv(env)
		for _, item := range env {
			if item.Name == key {
				return true, append([]byte(nil), item.Value...), nil
			}
		}
		return false, nil, nil
	},
	remove: func(ctx context.Context, p *HostedSyncPusher, key string) error {
		return portainerEdit(ctx, p, key, nil)
	},
}

type portainerVar struct {
	Name  string           `json:"name"`
	Value secret.JSONBytes `json:"value"`
}

func wipePortainerEnv(env []portainerVar) {
	for _, item := range env {
		secret.Wipe(item.Value)
	}
}

func portainerStackPath(p *HostedSyncPusher) string {
	return "/api/stacks/" + pathEscape(p.binding["stack"])
}

func portainerEnv(ctx context.Context, p *HostedSyncPusher) ([]portainerVar, error) {
	var got struct {
		Env []portainerVar `json:"Env"`
	}
	if err := p.send(ctx, http.MethodGet, portainerStackPath(p), nil, &got); err != nil {
		return nil, hostedError(p, "read stack", err)
	}
	return got.Env, nil
}

// portainerEdit sets key to value (removes it when value is nil) and puts
// the stack back with its own compose file; no change sends nothing.
func portainerEdit(ctx context.Context, p *HostedSyncPusher, key string, value []byte) error {
	env, err := portainerEnv(ctx, p)
	if err != nil {
		return err
	}
	defer wipePortainerEnv(env)
	out := env[:0]
	found, changed := false, false
	for _, item := range env {
		if item.Name != key {
			out = append(out, item)
			continue
		}
		found = true
		if value == nil {
			secret.Wipe(item.Value)
			changed = true
			continue
		}
		if string(item.Value) != string(value) {
			secret.Wipe(item.Value)
			item.Value = append(secret.JSONBytes(nil), value...)
			changed = true
		}
		out = append(out, item)
	}
	if value != nil && !found {
		out = append(out, portainerVar{Name: key, Value: append(secret.JSONBytes(nil), value...)})
		changed = true
	}
	env = out
	if !changed {
		return nil
	}
	var file struct {
		StackFileContent secret.JSONBytes `json:"StackFileContent"`
	}
	if err := p.send(ctx, http.MethodGet, portainerStackPath(p)+"/file", nil, &file); err != nil {
		return hostedError(p, "read stack file", err)
	}
	defer secret.Wipe(file.StackFileContent)
	body := append([]byte(`{"StackFileContent":`), appendJSONValueBytes(nil, file.StackFileContent)...)
	body = append(body, `,"Prune":false,"Env":[`...)
	for i, item := range env {
		if i > 0 {
			body = append(body, ',')
		}
		body = append(body, `{"name":`...)
		body = appendJSONValueBytes(body, []byte(item.Name))
		body = append(body, `,"value":`...)
		body = appendJSONValueBytes(body, item.Value)
		body = append(body, '}')
	}
	body = append(body, `]}`...)
	defer secret.Wipe(body)
	path := portainerStackPath(p) + "?endpointId=" + url.QueryEscape(p.binding["environment"])
	return hostedError(p, "update stack", p.send(ctx, http.MethodPut, path, body, nil))
}

// Devin organization secrets (API v3): no update, so a change deletes the
// key's secret and creates it again; values are never returned.
var devinVendor = &hostedVendor{
	name:         "Devin",
	deliveryMode: "organization secret delete-and-create over HTTPS (API v3)",
	authMode:     "Bearer service-user API key supplied by operator config",
	wireFormat:   `JSON {type: "key-value", key, value, is_sensitive: true}`,
	readBack:     ReadBackReceiptOnly,
	proof:        ProofStandIn,
	headers:      bearerHeaders,
	put: func(ctx context.Context, p *HostedSyncPusher, key string, value []byte) error {
		if !utf8.Valid(value) {
			return errHostedValueNotText
		}
		ids, err := devinSecrets(ctx, p)
		if err != nil {
			return err
		}
		for _, id := range ids[key] {
			if err := p.send(ctx, http.MethodDelete, devinPath(p, id), nil, nil); ignoreNotFound(err) != nil {
				return hostedError(p, "replace secret", err)
			}
		}
		body := append([]byte(`{"type":"key-value","key":`), appendJSONValueBytes(nil, []byte(key))...)
		body = append(body, `,"value":`...)
		body = appendJSONValueBytes(body, value)
		body = append(body, `,"is_sensitive":true,"note":"managed by trstctl"}`...)
		defer secret.Wipe(body)
		return hostedError(p, "create secret", p.send(ctx, http.MethodPost, devinPath(p, ""), body, nil))
	},
	list: func(ctx context.Context, p *HostedSyncPusher) ([]string, error) {
		ids, err := devinSecrets(ctx, p)
		if err != nil {
			return nil, err
		}
		names := make([]string, 0, len(ids))
		for name := range ids {
			names = append(names, name)
		}
		return names, nil
	},
	remove: func(ctx context.Context, p *HostedSyncPusher, key string) error {
		ids, err := devinSecrets(ctx, p)
		if err != nil {
			return err
		}
		for _, id := range ids[key] {
			if err := p.send(ctx, http.MethodDelete, devinPath(p, id), nil, nil); ignoreNotFound(err) != nil {
				return hostedError(p, "delete secret", err)
			}
		}
		return nil
	},
}

func devinPath(p *HostedSyncPusher, id string) string {
	path := "/v3/organizations/" + pathEscape(p.binding["org"]) + "/secrets"
	if id != "" {
		path += "/" + pathEscape(id)
	}
	return path
}

// devinSecrets maps each key to its secret IDs (a key may repeat), every
// page.
func devinSecrets(ctx context.Context, p *HostedSyncPusher) (map[string][]string, error) {
	ids := map[string][]string{}
	after := ""
	for range hostedPageLimit {
		path := devinPath(p, "") + "?first=200"
		if after != "" {
			path += "&after=" + url.QueryEscape(after)
		}
		var got struct {
			Items []struct {
				SecretID string `json:"secret_id"`
				Key      string `json:"key"`
			} `json:"items"`
			HasNextPage bool   `json:"has_next_page"`
			EndCursor   string `json:"end_cursor"`
		}
		if err := p.send(ctx, http.MethodGet, path, nil, &got); err != nil {
			return nil, hostedError(p, "list secrets", err)
		}
		for _, item := range got.Items {
			ids[item.Key] = append(ids[item.Key], item.SecretID)
		}
		if !got.HasNextPage || got.EndCursor == "" {
			return ids, nil
		}
		after = got.EndCursor
	}
	return nil, ErrScopedListLimit
}

// Daytona organization secrets: create by name, update the value by ID,
// delete by ID; values are never returned after creation.
var daytonaVendor = &hostedVendor{
	name:         "Daytona",
	deliveryMode: "organization secret POST, PATCH and DELETE over HTTPS",
	authMode:     "Bearer API key supplied by operator config",
	wireFormat:   "JSON {name, value, description}",
	readBack:     ReadBackReceiptOnly,
	proof:        ProofStandIn,
	headers: func(p *HostedSyncPusher, req *http.Request) {
		bearerHeaders(p, req)
		if org := p.binding["organization"]; org != "" {
			req.Header.Set("X-Daytona-Organization-ID", org)
		}
	},
	put: func(ctx context.Context, p *HostedSyncPusher, key string, value []byte) error {
		if !utf8.Valid(value) {
			return errHostedValueNotText
		}
		ids, err := daytonaSecrets(ctx, p)
		if err != nil {
			return err
		}
		if id, ok := ids[key]; ok {
			body := jsonValueBody("value", value)
			defer secret.Wipe(body)
			return hostedError(p, "update secret", p.send(ctx, http.MethodPatch, "/secret/"+pathEscape(id), body, nil))
		}
		body := append([]byte(`{"name":`), appendJSONValueBytes(nil, []byte(key))...)
		body = append(body, `,"value":`...)
		body = appendJSONValueBytes(body, value)
		body = append(body, `,"description":"managed by trstctl"}`...)
		defer secret.Wipe(body)
		return hostedError(p, "create secret", p.send(ctx, http.MethodPost, "/secret", body, nil))
	},
	list: func(ctx context.Context, p *HostedSyncPusher) ([]string, error) {
		ids, err := daytonaSecrets(ctx, p)
		if err != nil {
			return nil, err
		}
		return mapKeys(ids), nil
	},
	remove: func(ctx context.Context, p *HostedSyncPusher, key string) error {
		ids, err := daytonaSecrets(ctx, p)
		if err != nil {
			return err
		}
		id, ok := ids[key]
		if !ok {
			return nil
		}
		return hostedError(p, "delete secret", ignoreNotFound(p.send(ctx, http.MethodDelete, "/secret/"+pathEscape(id), nil, nil)))
	},
}

func daytonaSecrets(ctx context.Context, p *HostedSyncPusher) (map[string]string, error) {
	ids := map[string]string{}
	cursor := ""
	for range hostedPageLimit {
		path := "/secret/paginated?limit=200"
		if cursor != "" {
			path += "&cursor=" + url.QueryEscape(cursor)
		}
		var got struct {
			Items []struct {
				ID   string `json:"id"`
				Name string `json:"name"`
			} `json:"items"`
			NextCursor string `json:"nextCursor"`
		}
		if err := p.send(ctx, http.MethodGet, path, nil, &got); err != nil {
			return nil, hostedError(p, "list secrets", err)
		}
		for _, item := range got.Items {
			ids[item.Name] = item.ID
		}
		if got.NextCursor == "" {
			return ids, nil
		}
		cursor = got.NextCursor
	}
	return nil, ErrScopedListLimit
}

// Ona (formerly Gitpod) secrets (Connect RPC): environment-variable secrets
// at an organization, project or user scope. Create, update the value by
// ID, delete by ID; a management token can't read values back.
var onaVendor = &hostedVendor{
	name:         "Ona",
	deliveryMode: "SecretService CreateSecret, UpdateSecretValue and DeleteSecret over HTTPS (Connect RPC)",
	authMode:     "Bearer personal access or service-account token supplied by operator config",
	wireFormat:   "JSON {name, value, scope, environmentVariable: true}",
	readBack:     ReadBackReceiptOnly,
	proof:        ProofStandIn,
	headers:      bearerHeaders,
	put: func(ctx context.Context, p *HostedSyncPusher, key string, value []byte) error {
		if !utf8.Valid(value) {
			return errHostedValueNotText
		}
		ids, err := onaSecrets(ctx, p)
		if err != nil {
			return err
		}
		if id, ok := ids[key]; ok {
			body := append([]byte(`{"secretId":`), appendJSONValueBytes(nil, []byte(id))...)
			body = append(body, `,"value":`...)
			body = appendJSONValueBytes(body, value)
			body = append(body, '}')
			defer secret.Wipe(body)
			return hostedError(p, "update secret", p.send(ctx, http.MethodPost, onaMethod("UpdateSecretValue"), body, nil))
		}
		body := append([]byte(`{"name":`), appendJSONValueBytes(nil, []byte(key))...)
		body = append(body, `,"value":`...)
		body = appendJSONValueBytes(body, value)
		body = append(body, `,"scope":`...)
		body = append(body, onaScope(p)...)
		body = append(body, `,"environmentVariable":true}`...)
		defer secret.Wipe(body)
		return hostedError(p, "create secret", p.send(ctx, http.MethodPost, onaMethod("CreateSecret"), body, nil))
	},
	list: func(ctx context.Context, p *HostedSyncPusher) ([]string, error) {
		ids, err := onaSecrets(ctx, p)
		if err != nil {
			return nil, err
		}
		return mapKeys(ids), nil
	},
	remove: func(ctx context.Context, p *HostedSyncPusher, key string) error {
		ids, err := onaSecrets(ctx, p)
		if err != nil {
			return err
		}
		id, ok := ids[key]
		if !ok {
			return nil
		}
		body := append([]byte(`{"secretId":`), appendJSONValueBytes(nil, []byte(id))...)
		body = append(body, '}')
		return hostedError(p, "delete secret", ignoreNotFound(p.send(ctx, http.MethodPost, onaMethod("DeleteSecret"), body, nil)))
	},
}

func onaMethod(name string) string { return "/gitpod.v1.SecretService/" + name }

// onaScope is the scope object: {"organizationId": …}, {"projectId": …} or
// {"userId": …}.
func onaScope(p *HostedSyncPusher) []byte {
	field := map[string]string{"organization": "organizationId", "project": "projectId", "user": "userId"}[p.binding["scope"]]
	out := append([]byte(`{"`), field...)
	out = append(out, `":`...)
	out = appendJSONValueBytes(out, []byte(p.binding["id"]))
	return append(out, '}')
}

func onaSecrets(ctx context.Context, p *HostedSyncPusher) (map[string]string, error) {
	ids := map[string]string{}
	token := ""
	for range hostedPageLimit {
		body := append([]byte(`{"filter":{"scope":`), onaScope(p)...)
		body = append(body, `},"pagination":{"pageSize":100`...)
		if token != "" {
			body = append(body, `,"token":`...)
			body = appendJSONValueBytes(body, []byte(token))
		}
		body = append(body, `}}`...)
		var got struct {
			Secrets []struct {
				ID   string `json:"id"`
				Name string `json:"name"`
			} `json:"secrets"`
			Pagination struct {
				NextToken string `json:"nextToken"`
			} `json:"pagination"`
		}
		if err := p.send(ctx, http.MethodPost, onaMethod("ListSecrets"), body, &got); err != nil {
			return nil, hostedError(p, "list secrets", err)
		}
		for _, item := range got.Secrets {
			ids[item.Name] = item.ID
		}
		if got.Pagination.NextToken == "" {
			return ids, nil
		}
		token = got.Pagination.NextToken
	}
	return nil, ErrScopedListLimit
}

// Trigger.dev environment variables: the import endpoint with override
// upserts one, DELETE removes it, and GET returns each value.
var triggerVendor = &hostedVendor{
	name:         "Trigger.dev",
	deliveryMode: "environment variable import (override) and DELETE over HTTPS",
	authMode:     "Bearer personal access token or environment secret key supplied by operator config",
	wireFormat:   "JSON {variables: [{name, value}], override: true}",
	readBack:     ReadBackValue,
	proof:        ProofStandIn,
	headers:      bearerHeaders,
	put: func(ctx context.Context, p *HostedSyncPusher, key string, value []byte) error {
		if !utf8.Valid(value) {
			return errHostedValueNotText
		}
		body := append([]byte(`{"variables":[{"name":`), appendJSONValueBytes(nil, []byte(key))...)
		body = append(body, `,"value":`...)
		body = appendJSONValueBytes(body, value)
		body = append(body, `}],"override":true}`...)
		defer secret.Wipe(body)
		return hostedError(p, "set variable", p.send(ctx, http.MethodPost, triggerPath(p, "import"), body, nil))
	},
	list: func(ctx context.Context, p *HostedSyncPusher) ([]string, error) {
		var got []struct {
			Name string `json:"name"`
		}
		if err := p.send(ctx, http.MethodGet, triggerPath(p, ""), nil, &got); err != nil {
			return nil, hostedError(p, "list variables", err)
		}
		names := make([]string, 0, len(got))
		for _, item := range got {
			names = append(names, item.Name)
		}
		return names, nil
	},
	read: func(ctx context.Context, p *HostedSyncPusher, key string) (bool, []byte, error) {
		var got struct {
			Value secret.JSONBytes `json:"value"`
		}
		err := p.send(ctx, http.MethodGet, triggerPath(p, pathEscape(key)), nil, &got)
		if notFound(err) {
			return false, nil, nil
		}
		if err != nil {
			return false, nil, hostedError(p, "read variable", err)
		}
		return true, got.Value, nil
	},
	remove: func(ctx context.Context, p *HostedSyncPusher, key string) error {
		return hostedError(p, "delete variable", ignoreNotFound(p.send(ctx, http.MethodDelete, triggerPath(p, pathEscape(key)), nil, nil)))
	},
}

func triggerPath(p *HostedSyncPusher, rest string) string {
	path := "/api/v1/projects/" + pathEscape(p.binding["project"]) + "/envvars/" + pathEscape(p.binding["env"])
	if rest != "" {
		path += "/" + rest
	}
	return path
}
