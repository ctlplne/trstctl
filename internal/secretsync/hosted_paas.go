// SPDX-License-Identifier: BUSL-1.1

package secretsync

import (
	"context"
	"net/http"
	"net/url"
	"slices"
	"strconv"
	"unicode/utf8"

	"trstctl.com/trstctl/internal/crypto/secret"
	"trstctl.com/trstctl/internal/secrettext"
)

// Hosted application platforms (A241): each holds a service's or app's
// environment variables. Values are text.

// jsonValueBody is {"<field>":<value>} with the value escaped in place; the
// caller wipes it.
func jsonValueBody(field string, value []byte) []byte {
	body := append([]byte(`{"`), field...)
	body = append(body, `":`...)
	body = appendJSONValueBytes(body, value)
	return append(body, '}')
}

// ignoreNotFound treats a 404 answer to a delete as already done.
func ignoreNotFound(err error) error {
	if notFound(err) {
		return nil
	}
	return err
}

// Render service environment variables: PUT sets one, DELETE removes it, GET
// reads its value.
var renderVendor = &hostedVendor{
	name:         "Render",
	deliveryMode: "service env-var PUT and DELETE over HTTPS",
	authMode:     "Bearer API key supplied by operator config",
	wireFormat:   "JSON {value} per variable",
	readBack:     ReadBackValue,
	proof:        ProofStandIn,
	headers:      bearerHeaders,
	put: func(ctx context.Context, p *HostedSyncPusher, key string, value []byte) error {
		if !utf8.Valid(value) {
			return errHostedValueNotText
		}
		body := jsonValueBody("value", value)
		defer secret.Wipe(body)
		return hostedError(p, "set env var", p.send(ctx, http.MethodPut, renderPath(p, key), body, nil))
	},
	list: func(ctx context.Context, p *HostedSyncPusher) ([]string, error) {
		var names []string
		cursor := ""
		for range hostedPageLimit {
			query := "?limit=100"
			if cursor != "" {
				query += "&cursor=" + url.QueryEscape(cursor)
			}
			var page []struct {
				EnvVar struct {
					Key string `json:"key"`
				} `json:"envVar"`
				Cursor string `json:"cursor"`
			}
			if err := p.send(ctx, http.MethodGet, renderPath(p, "")+query, nil, &page); err != nil {
				return nil, hostedError(p, "list env vars", err)
			}
			for _, item := range page {
				names = append(names, item.EnvVar.Key)
			}
			if len(page) < 100 {
				return names, nil
			}
			cursor = page[len(page)-1].Cursor
		}
		return nil, ErrScopedListLimit
	},
	read: func(ctx context.Context, p *HostedSyncPusher, key string) (bool, []byte, error) {
		var got struct {
			Value secret.JSONBytes `json:"value"`
		}
		err := p.send(ctx, http.MethodGet, renderPath(p, key), nil, &got)
		if notFound(err) {
			return false, nil, nil
		}
		if err != nil {
			return false, nil, hostedError(p, "read env var", err)
		}
		return true, got.Value, nil
	},
	remove: func(ctx context.Context, p *HostedSyncPusher, key string) error {
		return hostedError(p, "delete env var", ignoreNotFound(p.send(ctx, http.MethodDelete, renderPath(p, key), nil, nil)))
	},
}

func renderPath(p *HostedSyncPusher, key string) string {
	path := "/services/" + pathEscape(p.binding["service"]) + "/env-vars"
	if key != "" {
		path += "/" + pathEscape(key)
	}
	return path
}

// hostedPageLimit bounds a paginated listing; a destination with more pages
// is ErrScopedListLimit.
const hostedPageLimit = 50

// Fly.io app secrets (Machines API): POST sets one, DELETE removes it, the
// list names them. Fly returns a digest it keys itself, which can't be
// recomputed, so the target is receipt-only.
var flyVendor = &hostedVendor{
	name:         "Fly.io",
	deliveryMode: "Machines API app secret POST and DELETE over HTTPS",
	authMode:     "Bearer Fly API token supplied by operator config",
	wireFormat:   "JSON {value} per secret; Machines read it when created or updated at the returned secrets version",
	readBack:     ReadBackReceiptOnly,
	proof:        ProofStandIn,
	headers:      bearerHeaders,
	put: func(ctx context.Context, p *HostedSyncPusher, key string, value []byte) error {
		if !utf8.Valid(value) {
			return errHostedValueNotText
		}
		body := jsonValueBody("value", value)
		defer secret.Wipe(body)
		return hostedError(p, "set secret", p.send(ctx, http.MethodPost, flyPath(p, key), body, nil))
	},
	list: func(ctx context.Context, p *HostedSyncPusher) ([]string, error) {
		var got struct {
			Secrets []struct {
				Name string `json:"name"`
			} `json:"secrets"`
		}
		if err := p.send(ctx, http.MethodGet, flyPath(p, ""), nil, &got); err != nil {
			return nil, hostedError(p, "list secrets", err)
		}
		names := make([]string, 0, len(got.Secrets))
		for _, item := range got.Secrets {
			names = append(names, item.Name)
		}
		return names, nil
	},
	remove: func(ctx context.Context, p *HostedSyncPusher, key string) error {
		return hostedError(p, "delete secret", ignoreNotFound(p.send(ctx, http.MethodDelete, flyPath(p, key), nil, nil)))
	},
}

func flyPath(p *HostedSyncPusher, key string) string {
	path := "/v1/apps/" + pathEscape(p.binding["app"]) + "/secrets"
	if key != "" {
		path += "/" + pathEscape(key)
	}
	return path
}

// Cloud 66 stack environment variables: POST creates, PUT updates, DELETE
// removes; the stack's list carries each value.
var cloud66Vendor = &hostedVendor{
	name:         "Cloud 66",
	deliveryMode: "stack environment-variable POST, PUT and DELETE over HTTPS (applied on the next deploy)",
	authMode:     "Bearer OAuth token (admin scope) supplied by operator config",
	wireFormat:   "JSON {key, value}",
	readBack:     ReadBackValue,
	proof:        ProofStandIn,
	headers:      bearerHeaders,
	put: func(ctx context.Context, p *HostedSyncPusher, key string, value []byte) error {
		if !utf8.Valid(value) {
			return errHostedValueNotText
		}
		vars, err := cloud66Vars(ctx, p)
		if err != nil {
			return err
		}
		_, exists := vars[key]
		wipeJSONMap(vars)
		if exists {
			body := jsonValueBody("value", value)
			defer secret.Wipe(body)
			return hostedError(p, "update env var", p.send(ctx, http.MethodPut, cloud66Path(p, key), body, nil))
		}
		body := append([]byte(`{"key":`), appendJSONValueBytes(nil, []byte(key))...)
		body = append(body, `,"value":`...)
		body = appendJSONValueBytes(body, value)
		body = append(body, '}')
		defer secret.Wipe(body)
		return hostedError(p, "create env var", p.send(ctx, http.MethodPost, cloud66Path(p, ""), body, nil))
	},
	list: func(ctx context.Context, p *HostedSyncPusher) ([]string, error) {
		vars, err := cloud66Vars(ctx, p)
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
		vars, err := cloud66Vars(ctx, p)
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
		return hostedError(p, "delete env var", ignoreNotFound(p.send(ctx, http.MethodDelete, cloud66Path(p, key), nil, nil)))
	},
}

func cloud66Path(p *HostedSyncPusher, key string) string {
	path := "/stacks/" + pathEscape(p.binding["stack"]) + "/environments"
	if key != "" {
		path += "/" + pathEscape(key)
	}
	return path
}

// cloud66Vars reads every page of the stack's variables.
func cloud66Vars(ctx context.Context, p *HostedSyncPusher) (map[string]secret.JSONBytes, error) {
	vars := map[string]secret.JSONBytes{}
	for page := 1; page <= hostedPageLimit; page++ {
		var got struct {
			Response []struct {
				Key   string           `json:"key"`
				Value secret.JSONBytes `json:"value"`
			} `json:"response"`
			Pagination struct {
				Next *int `json:"next"`
			} `json:"pagination"`
		}
		if err := p.send(ctx, http.MethodGet, cloud66Path(p, "")+"?page="+strconv.Itoa(page), nil, &got); err != nil {
			wipeJSONMap(vars)
			return nil, hostedError(p, "list env vars", err)
		}
		for _, item := range got.Response {
			vars[item.Key] = item.Value
		}
		if got.Pagination.Next == nil || *got.Pagination.Next <= page {
			return vars, nil
		}
	}
	wipeJSONMap(vars)
	return nil, ErrScopedListLimit
}

// Northflank secret groups: the group's variables are one map; a change reads
// the map, edits it and writes it whole (PATCH replaces the variables).
var northflankVendor = &hostedVendor{
	name:         "Northflank",
	deliveryMode: "secret group read, then PATCH of its whole variable map, over HTTPS",
	authMode:     "Bearer API token supplied by operator config",
	wireFormat:   "JSON {secrets: {variables: {...}}}",
	readBack:     ReadBackValue,
	proof:        ProofStandIn,
	headers:      bearerHeaders,
	put: func(ctx context.Context, p *HostedSyncPusher, key string, value []byte) error {
		if !utf8.Valid(value) {
			return errHostedValueNotText
		}
		vars, err := northflankVars(ctx, p)
		if err != nil {
			return err
		}
		defer wipeJSONMap(vars)
		secret.Wipe(vars[key])
		vars[key] = append(secret.JSONBytes(nil), value...)
		return northflankWrite(ctx, p, vars)
	},
	list: func(ctx context.Context, p *HostedSyncPusher) ([]string, error) {
		vars, err := northflankVars(ctx, p)
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
		vars, err := northflankVars(ctx, p)
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
		vars, err := northflankVars(ctx, p)
		if err != nil {
			return err
		}
		defer wipeJSONMap(vars)
		if _, ok := vars[key]; !ok {
			return nil
		}
		secret.Wipe(vars[key])
		delete(vars, key)
		return northflankWrite(ctx, p, vars)
	},
}

func northflankPath(p *HostedSyncPusher) string {
	return "/projects/" + pathEscape(p.binding["project"]) + "/secrets/" + pathEscape(p.binding["secret-group"])
}

func northflankVars(ctx context.Context, p *HostedSyncPusher) (map[string]secret.JSONBytes, error) {
	var got struct {
		Data struct {
			Secrets struct {
				Variables map[string]secret.JSONBytes `json:"variables"`
			} `json:"secrets"`
		} `json:"data"`
	}
	if err := p.send(ctx, http.MethodGet, northflankPath(p), nil, &got); err != nil {
		return nil, hostedError(p, "read secret group", err)
	}
	if got.Data.Secrets.Variables == nil {
		return map[string]secret.JSONBytes{}, nil
	}
	return got.Data.Secrets.Variables, nil
}

func northflankWrite(ctx context.Context, p *HostedSyncPusher, vars map[string]secret.JSONBytes) error {
	body := append([]byte(`{"secrets":{"variables":`), appendJSONObject(nil, vars)...)
	body = append(body, `}}`...)
	defer secret.Wipe(body)
	return hostedError(p, "write secret group", p.send(ctx, http.MethodPatch, northflankPath(p), body, nil))
}

// appendJSONObject writes vars as a JSON object of strings, in name order,
// without a Go string of any value.
func appendJSONObject(dst []byte, vars map[string]secret.JSONBytes) []byte {
	names := make([]string, 0, len(vars))
	for name := range vars {
		names = append(names, name)
	}
	slices.Sort(names)
	dst = append(dst, '{')
	for i, name := range names {
		if i > 0 {
			dst = append(dst, ',')
		}
		dst = appendJSONValueBytes(dst, []byte(name))
		dst = append(dst, ':')
		dst = appendJSONValueBytes(dst, vars[name])
	}
	return append(dst, '}')
}

// Qovery variables: one call creates (POST /variable) and another updates by
// ID (PUT); a secret's value never comes back, so the target is receipt-only.
var qoveryVendor = &hostedVendor{
	name:         "Qovery",
	deliveryMode: "variable POST, PUT and DELETE over HTTPS (applied on the next deploy)",
	authMode:     "API token (Authorization: Token) supplied by operator config",
	wireFormat:   "JSON {key, value, is_secret, variable_scope, variable_parent_id}",
	readBack:     ReadBackReceiptOnly,
	proof:        ProofStandIn,
	headers: func(p *HostedSyncPusher, req *http.Request) {
		req.Header.Set("Authorization", secrettext.Prefixed("Token ", p.token.Bytes()))
	},
	put: func(ctx context.Context, p *HostedSyncPusher, key string, value []byte) error {
		if !utf8.Valid(value) {
			return errHostedValueNotText
		}
		ids, err := qoveryVariables(ctx, p)
		if err != nil {
			return err
		}
		body := append([]byte(`{"key":`), appendJSONValueBytes(nil, []byte(key))...)
		body = append(body, `,"value":`...)
		body = appendJSONValueBytes(body, value)
		if id, ok := ids[key]; ok {
			body = append(body, '}')
			defer secret.Wipe(body)
			return hostedError(p, "update variable", p.send(ctx, http.MethodPut, "/variable/"+pathEscape(id), body, nil))
		}
		body = append(body, `,"is_secret":true,"variable_scope":`...)
		body = appendJSONValueBytes(body, []byte(p.binding["scope"]))
		body = append(body, `,"variable_parent_id":`...)
		body = appendJSONValueBytes(body, []byte(p.binding["parent"]))
		body = append(body, '}')
		defer secret.Wipe(body)
		return hostedError(p, "create variable", p.send(ctx, http.MethodPost, "/variable", body, nil))
	},
	list: func(ctx context.Context, p *HostedSyncPusher) ([]string, error) {
		ids, err := qoveryVariables(ctx, p)
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
		ids, err := qoveryVariables(ctx, p)
		if err != nil {
			return err
		}
		id, ok := ids[key]
		if !ok {
			return nil
		}
		return hostedError(p, "delete variable", ignoreNotFound(p.send(ctx, http.MethodDelete, "/variable/"+pathEscape(id), nil, nil)))
	},
}

// qoveryVariables maps each key defined at the bound scope to its ID;
// inherited and built-in variables of other scopes are not this target's.
func qoveryVariables(ctx context.Context, p *HostedSyncPusher) (map[string]string, error) {
	var got struct {
		Results []struct {
			ID    string `json:"id"`
			Key   string `json:"key"`
			Scope string `json:"scope"`
		} `json:"results"`
	}
	query := "?parent_id=" + url.QueryEscape(p.binding["parent"]) + "&scope=" + url.QueryEscape(p.binding["scope"])
	if err := p.send(ctx, http.MethodGet, "/variable"+query, nil, &got); err != nil {
		return nil, hostedError(p, "list variables", err)
	}
	ids := map[string]string{}
	for _, item := range got.Results {
		if item.Scope == p.binding["scope"] {
			ids[item.Key] = item.ID
		}
	}
	return ids, nil
}
