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

// CI/CD and operations platforms (A241). None of them returns a secret's
// value, so every one is receipt-only.

// CircleCI: project variables (POST creates; a change is delete then
// create, as CircleCI documents) or context variables (PUT upserts). The
// project listing masks values; contexts never return them.
var circleCIVendor = &hostedVendor{
	name:         "CircleCI",
	deliveryMode: "project variable delete-and-create, or context variable PUT, over HTTPS",
	authMode:     "Circle-Token personal API token supplied by operator config",
	wireFormat:   "JSON {name, value} (project) or {value} (context)",
	readBack:     ReadBackReceiptOnly,
	proof:        ProofStandIn,
	headers: func(p *HostedSyncPusher, req *http.Request) {
		req.Header.Set("Circle-Token", secrettext.String(p.token.Bytes()))
	},
	put: func(ctx context.Context, p *HostedSyncPusher, key string, value []byte) error {
		if !utf8.Valid(value) {
			return errHostedValueNotText
		}
		if context := p.binding["context"]; context != "" {
			body := jsonValueBody("value", value)
			defer secret.Wipe(body)
			return hostedError(p, "set context variable", p.send(ctx, http.MethodPut, circleCIContextPath(p, key), body, nil))
		}
		names, err := p.vendor.list(ctx, p)
		if err != nil {
			return err
		}
		for _, name := range names {
			if name == key {
				if err := p.send(ctx, http.MethodDelete, circleCIProjectPath(p, key), nil, nil); ignoreNotFound(err) != nil {
					return hostedError(p, "replace project variable", err)
				}
			}
		}
		body := append([]byte(`{"name":`), appendJSONValueBytes(nil, []byte(key))...)
		body = append(body, `,"value":`...)
		body = appendJSONValueBytes(body, value)
		body = append(body, '}')
		defer secret.Wipe(body)
		return hostedError(p, "create project variable", p.send(ctx, http.MethodPost, circleCIProjectPath(p, ""), body, nil))
	},
	list: func(ctx context.Context, p *HostedSyncPusher) ([]string, error) {
		var names []string
		token := ""
		for range hostedPageLimit {
			var page struct {
				Items []struct {
					Name     string `json:"name"`
					Variable string `json:"variable"`
				} `json:"items"`
				NextPageToken string `json:"next_page_token"`
			}
			path := circleCIProjectPath(p, "")
			if p.binding["context"] != "" {
				path = circleCIContextPath(p, "")
			}
			if token != "" {
				path += "?page-token=" + url.QueryEscape(token)
			}
			if err := p.send(ctx, http.MethodGet, path, nil, &page); err != nil {
				return nil, hostedError(p, "list variables", err)
			}
			for _, item := range page.Items {
				if item.Variable != "" {
					names = append(names, item.Variable)
				} else {
					names = append(names, item.Name)
				}
			}
			if page.NextPageToken == "" {
				return names, nil
			}
			token = page.NextPageToken
		}
		return nil, ErrScopedListLimit
	},
	remove: func(ctx context.Context, p *HostedSyncPusher, key string) error {
		path := circleCIProjectPath(p, key)
		if p.binding["context"] != "" {
			path = circleCIContextPath(p, key)
		}
		return hostedError(p, "delete variable", ignoreNotFound(p.send(ctx, http.MethodDelete, path, nil, nil)))
	},
}

// circleCIProjectPath keeps the project slug's slashes: CircleCI addresses
// a project as vcs/org/repo.
func circleCIProjectPath(p *HostedSyncPusher, key string) string {
	path := "/project/" + p.binding["project"] + "/envvar"
	if key != "" {
		path += "/" + pathEscape(key)
	}
	return path
}

func circleCIContextPath(p *HostedSyncPusher, key string) string {
	path := "/context/" + pathEscape(p.binding["context"]) + "/environment-variable"
	if key != "" {
		path += "/" + pathEscape(key)
	}
	return path
}

// Travis CI repository variables (API v3): create, update by ID, delete by
// ID; a private variable's value is not returned.
var travisVendor = &hostedVendor{
	name:         "Travis CI",
	deliveryMode: "repository env_var POST, PATCH and DELETE over HTTPS (API v3)",
	authMode:     "API token (Authorization: token) supplied by operator config",
	wireFormat:   `JSON {"env_var.name", "env_var.value", "env_var.public": false}`,
	readBack:     ReadBackReceiptOnly,
	proof:        ProofStandIn,
	headers: func(p *HostedSyncPusher, req *http.Request) {
		req.Header.Set("Authorization", secrettext.Prefixed("token ", p.token.Bytes()))
		req.Header.Set("Travis-API-Version", "3")
	},
	put: func(ctx context.Context, p *HostedSyncPusher, key string, value []byte) error {
		if !utf8.Valid(value) {
			return errHostedValueNotText
		}
		ids, err := travisVars(ctx, p)
		if err != nil {
			return err
		}
		if id, ok := ids[key]; ok {
			body := jsonValueBody("env_var.value", value)
			defer secret.Wipe(body)
			return hostedError(p, "update variable", p.send(ctx, http.MethodPatch, travisPath(p)+"/env_var/"+pathEscape(id), body, nil))
		}
		body := append([]byte(`{"env_var.name":`), appendJSONValueBytes(nil, []byte(key))...)
		body = append(body, `,"env_var.value":`...)
		body = appendJSONValueBytes(body, value)
		body = append(body, `,"env_var.public":false}`...)
		defer secret.Wipe(body)
		return hostedError(p, "create variable", p.send(ctx, http.MethodPost, travisPath(p)+"/env_vars", body, nil))
	},
	list: func(ctx context.Context, p *HostedSyncPusher) ([]string, error) {
		ids, err := travisVars(ctx, p)
		if err != nil {
			return nil, err
		}
		return mapKeys(ids), nil
	},
	remove: func(ctx context.Context, p *HostedSyncPusher, key string) error {
		ids, err := travisVars(ctx, p)
		if err != nil {
			return err
		}
		id, ok := ids[key]
		if !ok {
			return nil
		}
		return hostedError(p, "delete variable", ignoreNotFound(p.send(ctx, http.MethodDelete, travisPath(p)+"/env_var/"+pathEscape(id), nil, nil)))
	},
}

// travisPath escapes the repository slug's slash (owner%2Frepo).
func travisPath(p *HostedSyncPusher) string { return "/repo/" + url.PathEscape(p.binding["repo"]) }

func travisVars(ctx context.Context, p *HostedSyncPusher) (map[string]string, error) {
	var got struct {
		EnvVars []struct {
			ID   string `json:"id"`
			Name string `json:"name"`
		} `json:"env_vars"`
	}
	if err := p.send(ctx, http.MethodGet, travisPath(p)+"/env_vars", nil, &got); err != nil {
		return nil, hostedError(p, "list variables", err)
	}
	ids := map[string]string{}
	for _, item := range got.EnvVars {
		ids[item.Name] = item.ID
	}
	return ids, nil
}

func mapKeys(m map[string]string) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}

// Bitbucket Cloud repository Pipelines variables: create (409 if present),
// update and delete by UUID; a secured variable's value comes back empty.
var bitbucketVendor = &hostedVendor{
	name:         "Bitbucket Pipelines",
	deliveryMode: "repository pipelines_config variable POST, PUT and DELETE over HTTPS",
	authMode:     "Bearer repository, project or workspace access token supplied by operator config",
	wireFormat:   "JSON {key, value, secured: true}",
	readBack:     ReadBackReceiptOnly,
	proof:        ProofStandIn,
	headers:      bearerHeaders,
	put: func(ctx context.Context, p *HostedSyncPusher, key string, value []byte) error {
		if !utf8.Valid(value) {
			return errHostedValueNotText
		}
		ids, err := bitbucketVars(ctx, p)
		if err != nil {
			return err
		}
		body := append([]byte(`{"key":`), appendJSONValueBytes(nil, []byte(key))...)
		body = append(body, `,"value":`...)
		body = appendJSONValueBytes(body, value)
		body = append(body, `,"secured":true}`...)
		defer secret.Wipe(body)
		if id, ok := ids[key]; ok {
			return hostedError(p, "update variable", p.send(ctx, http.MethodPut, bitbucketPath(p)+"/"+url.PathEscape(id), body, nil))
		}
		return hostedError(p, "create variable", p.send(ctx, http.MethodPost, bitbucketPath(p), body, nil))
	},
	list: func(ctx context.Context, p *HostedSyncPusher) ([]string, error) {
		ids, err := bitbucketVars(ctx, p)
		if err != nil {
			return nil, err
		}
		return mapKeys(ids), nil
	},
	remove: func(ctx context.Context, p *HostedSyncPusher, key string) error {
		ids, err := bitbucketVars(ctx, p)
		if err != nil {
			return err
		}
		id, ok := ids[key]
		if !ok {
			return nil
		}
		return hostedError(p, "delete variable", ignoreNotFound(p.send(ctx, http.MethodDelete, bitbucketPath(p)+"/"+url.PathEscape(id), nil, nil)))
	},
}

func bitbucketPath(p *HostedSyncPusher) string {
	return "/repositories/" + pathEscape(p.binding["workspace"]) + "/" + pathEscape(p.binding["repository"]) + "/pipelines_config/variables"
}

// bitbucketVars reads every page (100 a page) of the repository's
// variables; the next page is named by the next link's page number.
func bitbucketVars(ctx context.Context, p *HostedSyncPusher) (map[string]string, error) {
	ids := map[string]string{}
	page := 1
	for range hostedPageLimit {
		var got struct {
			Values []struct {
				UUID string `json:"uuid"`
				Key  string `json:"key"`
			} `json:"values"`
			Next string `json:"next"`
		}
		if err := p.send(ctx, http.MethodGet, bitbucketPath(p)+"?pagelen=100&page="+strconv.Itoa(page), nil, &got); err != nil {
			return nil, hostedError(p, "list variables", err)
		}
		for _, item := range got.Values {
			ids[item.Key] = item.UUID
		}
		if got.Next == "" {
			return ids, nil
		}
		next, err := url.Parse(got.Next)
		if err != nil {
			return nil, hostedError(p, "list variables", err)
		}
		n, err := strconv.Atoi(next.Query().Get("page"))
		if err != nil || n <= page {
			return nil, hostedError(p, "list variables", errors.New("the next page link has no later page number"))
		}
		page = n
	}
	return nil, ErrScopedListLimit
}

// TeamCity project parameters of type password: PUT creates or updates one,
// DELETE removes it; a password's value is never returned. Inherited
// parameters are the parent project's, not this target's.
var teamCityVendor = &hostedVendor{
	name:         "TeamCity",
	deliveryMode: "project parameter PUT and DELETE over HTTPS (REST API)",
	authMode:     "Bearer access token supplied by operator config",
	wireFormat:   `JSON {name, value, type: {rawValue: "password"}}`,
	readBack:     ReadBackReceiptOnly,
	proof:        ProofStandIn,
	headers:      bearerHeaders,
	put: func(ctx context.Context, p *HostedSyncPusher, key string, value []byte) error {
		if !utf8.Valid(value) {
			return errHostedValueNotText
		}
		body := append([]byte(`{"name":`), appendJSONValueBytes(nil, []byte(key))...)
		body = append(body, `,"value":`...)
		body = appendJSONValueBytes(body, value)
		body = append(body, `,"type":{"rawValue":"password"}}`...)
		defer secret.Wipe(body)
		return hostedError(p, "set parameter", p.send(ctx, http.MethodPut, teamCityPath(p, key), body, nil))
	},
	list: func(ctx context.Context, p *HostedSyncPusher) ([]string, error) {
		var got struct {
			Property []struct {
				Name      string `json:"name"`
				Inherited bool   `json:"inherited"`
			} `json:"property"`
		}
		if err := p.send(ctx, http.MethodGet, teamCityPath(p, ""), nil, &got); err != nil {
			return nil, hostedError(p, "list parameters", err)
		}
		var names []string
		for _, item := range got.Property {
			if !item.Inherited {
				names = append(names, item.Name)
			}
		}
		return names, nil
	},
	remove: func(ctx context.Context, p *HostedSyncPusher, key string) error {
		return hostedError(p, "delete parameter", ignoreNotFound(p.send(ctx, http.MethodDelete, teamCityPath(p, key), nil, nil)))
	},
}

func teamCityPath(p *HostedSyncPusher, key string) string {
	path := "/app/rest/projects/" + pathEscape("id:"+p.binding["project"]) + "/parameters"
	if key != "" {
		path += "/" + pathEscape(key)
	}
	return path
}

// Humanitec shared app values: create (409 if present), update by key,
// delete by key; a secret's value is always empty. The value-less DELETE of
// the collection, which removes every value, is never sent.
var humanitecVendor = &hostedVendor{
	name:         "Humanitec",
	deliveryMode: "shared app value POST, PUT and DELETE over HTTPS",
	authMode:     "Bearer service-user token supplied by operator config",
	wireFormat:   "JSON {key, value, description, is_secret: true}",
	readBack:     ReadBackReceiptOnly,
	proof:        ProofStandIn,
	headers:      bearerHeaders,
	put: func(ctx context.Context, p *HostedSyncPusher, key string, value []byte) error {
		if !utf8.Valid(value) {
			return errHostedValueNotText
		}
		names, err := p.vendor.list(ctx, p)
		if err != nil {
			return err
		}
		exists := false
		for _, name := range names {
			exists = exists || name == key
		}
		if exists {
			body := append([]byte(`{"value":`), appendJSONValueBytes(nil, value)...)
			body = append(body, `,"description":"managed by trstctl"}`...)
			defer secret.Wipe(body)
			return hostedError(p, "update value", p.send(ctx, http.MethodPut, humanitecPath(p, key), body, nil))
		}
		body := append([]byte(`{"key":`), appendJSONValueBytes(nil, []byte(key))...)
		body = append(body, `,"value":`...)
		body = appendJSONValueBytes(body, value)
		body = append(body, `,"description":"managed by trstctl","is_secret":true}`...)
		defer secret.Wipe(body)
		return hostedError(p, "create value", p.send(ctx, http.MethodPost, humanitecPath(p, ""), body, nil))
	},
	list: func(ctx context.Context, p *HostedSyncPusher) ([]string, error) {
		var got []struct {
			Key string `json:"key"`
		}
		if err := p.send(ctx, http.MethodGet, humanitecPath(p, ""), nil, &got); err != nil {
			return nil, hostedError(p, "list values", err)
		}
		names := make([]string, 0, len(got))
		for _, item := range got {
			names = append(names, item.Key)
		}
		return names, nil
	},
	remove: func(ctx context.Context, p *HostedSyncPusher, key string) error {
		if key == "" {
			return errors.New("secretsync: Humanitec delete needs a key")
		}
		return hostedError(p, "delete value", ignoreNotFound(p.send(ctx, http.MethodDelete, humanitecPath(p, key), nil, nil)))
	},
}

func humanitecPath(p *HostedSyncPusher, key string) string {
	path := "/orgs/" + pathEscape(p.binding["org"]) + "/apps/" + pathEscape(p.binding["app"]) + "/values"
	if key != "" {
		path += "/" + pathEscape(key)
	}
	return path
}

// Checkly environment variables: create (409 if present), update by key,
// delete by key; a secret variable's value is always null. Every request
// names the account.
var checklyVendor = &hostedVendor{
	name:         "Checkly",
	deliveryMode: "environment variable POST, PUT and DELETE over HTTPS",
	authMode:     "Bearer API key and X-Checkly-Account supplied by operator config",
	wireFormat:   "JSON {key, value, secret: true}",
	readBack:     ReadBackReceiptOnly,
	proof:        ProofStandIn,
	headers: func(p *HostedSyncPusher, req *http.Request) {
		bearerHeaders(p, req)
		req.Header.Set("X-Checkly-Account", p.binding["account"])
	},
	put: func(ctx context.Context, p *HostedSyncPusher, key string, value []byte) error {
		if !utf8.Valid(value) {
			return errHostedValueNotText
		}
		body := append([]byte(`{"key":`), appendJSONValueBytes(nil, []byte(key))...)
		body = append(body, `,"value":`...)
		body = appendJSONValueBytes(body, value)
		body = append(body, `,"secret":true}`...)
		defer secret.Wipe(body)
		err := p.send(ctx, http.MethodPost, "/v1/variables", body, nil)
		if statusCode(err) != http.StatusConflict {
			return hostedError(p, "create variable", err)
		}
		update := append([]byte(`{"value":`), appendJSONValueBytes(nil, value)...)
		update = append(update, `,"secret":true}`...)
		defer secret.Wipe(update)
		return hostedError(p, "update variable", p.send(ctx, http.MethodPut, "/v1/variables/"+pathEscape(key), update, nil))
	},
	list: func(ctx context.Context, p *HostedSyncPusher) ([]string, error) {
		var names []string
		for page := 1; page <= hostedPageLimit; page++ {
			var got []struct {
				Key string `json:"key"`
			}
			if err := p.send(ctx, http.MethodGet, "/v1/variables?limit=100&page="+strconv.Itoa(page), nil, &got); err != nil {
				return nil, hostedError(p, "list variables", err)
			}
			for _, item := range got {
				names = append(names, item.Key)
			}
			if len(got) < 100 {
				return names, nil
			}
		}
		return nil, ErrScopedListLimit
	},
	remove: func(ctx context.Context, p *HostedSyncPusher, key string) error {
		return hostedError(p, "delete variable", ignoreNotFound(p.send(ctx, http.MethodDelete, "/v1/variables/"+pathEscape(key), nil, nil)))
	},
}

// Rundeck Key Storage password keys: PUT modifies one, POST creates it
// (Content-Type application/x-rundeck-data-password, the value as the
// body), DELETE removes it; password contents are never returned. Keys are
// paths under the bound folder.
var rundeckVendor = &hostedVendor{
	name:         "Rundeck",
	deliveryMode: "Key Storage password PUT or POST and DELETE over HTTPS",
	authMode:     "X-Rundeck-Auth-Token API token supplied by operator config",
	wireFormat:   "raw value, Content-Type application/x-rundeck-data-password",
	readBack:     ReadBackReceiptOnly,
	proof:        ProofStandIn,
	headers: func(p *HostedSyncPusher, req *http.Request) {
		req.Header.Set("X-Rundeck-Auth-Token", secrettext.String(p.token.Bytes()))
	},
	put: func(ctx context.Context, p *HostedSyncPusher, key string, value []byte) error {
		path := rundeckPath(p, key)
		err := rundeckWrite(ctx, p, http.MethodPut, path, value)
		if notFound(err) {
			err = rundeckWrite(ctx, p, http.MethodPost, path, value)
		}
		return hostedError(p, "store password", err)
	},
	list: func(ctx context.Context, p *HostedSyncPusher) ([]string, error) {
		return rundeckWalk(ctx, p, "", 0)
	},
	remove: func(ctx context.Context, p *HostedSyncPusher, key string) error {
		return hostedError(p, "delete password", ignoreNotFound(p.send(ctx, http.MethodDelete, rundeckPath(p, key), nil, nil)))
	},
}

const rundeckAPI = "/api/41/storage/"

func rundeckPath(p *HostedSyncPusher, key string) string {
	parts := strings.Split(strings.Trim(p.binding["folder"]+"/"+key, "/"), "/")
	for i, part := range parts {
		parts[i] = pathEscape(part)
	}
	return rundeckAPI + strings.Join(parts, "/")
}

func rundeckWrite(ctx context.Context, p *HostedSyncPusher, method, path string, value []byte) error {
	req, err := p.request(ctx, method, path, value, "application/x-rundeck-data-password")
	if err != nil {
		return err
	}
	return expect2xx(p.doer, req)
}

// rundeckWalk lists the password keys under the bound folder, depth-first,
// as paths relative to it.
func rundeckWalk(ctx context.Context, p *HostedSyncPusher, rel string, depth int) ([]string, error) {
	if depth > 8 {
		return nil, ErrScopedListLimit
	}
	var dir struct {
		Resources []struct {
			Name string `json:"name"`
			Type string `json:"type"`
			Meta struct {
				KeyType string `json:"Rundeck-key-type"`
			} `json:"meta"`
		} `json:"resources"`
	}
	err := p.send(ctx, http.MethodGet, rundeckPath(p, rel)+"/", nil, &dir)
	if notFound(err) && rel == "" {
		return nil, nil
	}
	if err != nil {
		return nil, hostedError(p, "list keys", err)
	}
	var names []string
	for _, item := range dir.Resources {
		name := strings.TrimPrefix(rel+"/"+item.Name, "/")
		switch item.Type {
		case "directory":
			nested, err := rundeckWalk(ctx, p, name, depth+1)
			if err != nil {
				return nil, err
			}
			names = append(names, nested...)
		case "file":
			if item.Meta.KeyType == "" || item.Meta.KeyType == "password" {
				names = append(names, name)
			}
		}
	}
	return names, nil
}

// Spacelift context configuration (GraphQL): an environment variable is a
// write-only config element; a change deletes and re-adds it, as Spacelift's
// own provider does. Requests carry a JWT the API key exchanges for.
const (
	spaceliftLogin  = `mutation($id: ID!, $secret: String!) { apiKeyUser(id: $id, secret: $secret) { jwt } }`
	spaceliftAdd    = `mutation($context: ID!, $config: ConfigInput!) { contextConfigAdd(context: $context, config: $config) { id } }`
	spaceliftDelete = `mutation($context: ID!, $id: ID!) { contextConfigDelete(context: $context, id: $id) { id } }`
	spaceliftList   = `query($id: ID!) { context(id: $id) { config { id type } } }`
)

var spaceliftVendor = &hostedVendor{
	name:         "Spacelift",
	deliveryMode: "GraphQL contextConfigAdd (write-only) and contextConfigDelete over HTTPS",
	authMode:     "API key ID (username) and secret (token_ref) exchanged for a short-lived JWT per operation",
	wireFormat:   "GraphQL ConfigInput {id, type: ENVIRONMENT_VARIABLE, value, writeOnly: true}",
	readBack:     ReadBackReceiptOnly,
	proof:        ProofStandIn,
	headers:      func(*HostedSyncPusher, *http.Request) {},
	put: func(ctx context.Context, p *HostedSyncPusher, key string, value []byte) error {
		if !utf8.Valid(value) {
			return errHostedValueNotText
		}
		jwt, err := spaceliftJWT(ctx, p)
		if err != nil {
			return err
		}
		defer secret.Wipe(jwt)
		names, err := spaceliftNames(ctx, p, jwt)
		if err != nil {
			return err
		}
		for _, name := range names {
			if name == key {
				if err := spaceliftCall(ctx, p, jwt, spaceliftRequest(spaceliftDelete, p, key, nil), nil); err != nil {
					return hostedError(p, "replace variable", err)
				}
			}
		}
		body := spaceliftRequest(spaceliftAdd, p, key, value)
		defer secret.Wipe(body)
		return hostedError(p, "add variable", spaceliftCall(ctx, p, jwt, body, nil))
	},
	list: func(ctx context.Context, p *HostedSyncPusher) ([]string, error) {
		jwt, err := spaceliftJWT(ctx, p)
		if err != nil {
			return nil, err
		}
		defer secret.Wipe(jwt)
		return spaceliftNames(ctx, p, jwt)
	},
	remove: func(ctx context.Context, p *HostedSyncPusher, key string) error {
		jwt, err := spaceliftJWT(ctx, p)
		if err != nil {
			return err
		}
		defer secret.Wipe(jwt)
		names, err := spaceliftNames(ctx, p, jwt)
		if err != nil {
			return err
		}
		for _, name := range names {
			if name == key {
				return hostedError(p, "delete variable", spaceliftCall(ctx, p, jwt, spaceliftRequest(spaceliftDelete, p, key, nil), nil))
			}
		}
		return nil
	},
}

// spaceliftRequest builds a GraphQL body: the context and element ID, and
// for an add the write-only environment variable with its value.
func spaceliftRequest(query string, p *HostedSyncPusher, key string, value []byte) []byte {
	body := []byte(`{"query":`)
	body = appendJSONValueBytes(body, []byte(query))
	body = append(body, `,"variables":{"context":`...)
	body = appendJSONValueBytes(body, []byte(p.binding["context"]))
	if value == nil {
		body = append(body, `,"id":`...)
		body = appendJSONValueBytes(body, []byte(key))
		return append(body, `}}`...)
	}
	body = append(body, `,"config":{"id":`...)
	body = appendJSONValueBytes(body, []byte(key))
	body = append(body, `,"type":"ENVIRONMENT_VARIABLE","writeOnly":true,"value":`...)
	body = appendJSONValueBytes(body, value)
	return append(body, `}}}`...)
}

// spaceliftJWT exchanges the API key for a JWT, held only for this
// operation.
func spaceliftJWT(ctx context.Context, p *HostedSyncPusher) ([]byte, error) {
	body := []byte(`{"query":`)
	body = appendJSONValueBytes(body, []byte(spaceliftLogin))
	body = append(body, `,"variables":{"id":`...)
	body = appendJSONValueBytes(body, []byte(p.username))
	body = append(body, `,"secret":`...)
	body = appendJSONValueBytes(body, p.token.Bytes())
	body = append(body, `}}`...)
	defer secret.Wipe(body)
	var data struct {
		APIKeyUser struct {
			JWT secret.JSONBytes `json:"jwt"`
		} `json:"apiKeyUser"`
	}
	if err := spaceliftCall(ctx, p, nil, body, &data); err != nil || len(data.APIKeyUser.JWT) == 0 {
		secret.Wipe(data.APIKeyUser.JWT)
		if err == nil {
			err = errors.New("no token in the answer")
		}
		return nil, hostedError(p, "exchange the API key", err)
	}
	return data.APIKeyUser.JWT, nil
}

func spaceliftNames(ctx context.Context, p *HostedSyncPusher, jwt []byte) ([]string, error) {
	body := []byte(`{"query":`)
	body = appendJSONValueBytes(body, []byte(spaceliftList))
	body = append(body, `,"variables":{"id":`...)
	body = appendJSONValueBytes(body, []byte(p.binding["context"]))
	body = append(body, `}}`...)
	var data struct {
		Context *struct {
			Config []struct {
				ID   string `json:"id"`
				Type string `json:"type"`
			} `json:"config"`
		} `json:"context"`
	}
	if err := spaceliftCall(ctx, p, jwt, body, &data); err != nil {
		return nil, hostedError(p, "list context", err)
	}
	if data.Context == nil {
		return nil, hostedError(p, "list context", errors.New("no context of that ID"))
	}
	var names []string
	for _, item := range data.Context.Config {
		if item.Type == "ENVIRONMENT_VARIABLE" {
			names = append(names, item.ID)
		}
	}
	return names, nil
}

// spaceliftCall posts one GraphQL request with the JWT (none for the
// exchange); a GraphQL error fails without keeping its message.
func spaceliftCall(ctx context.Context, p *HostedSyncPusher, jwt, body []byte, data any) error {
	req, err := p.request(ctx, http.MethodPost, "", body, "application/json")
	if err != nil {
		return err
	}
	if jwt != nil {
		req.Header.Set("Authorization", secrettext.Prefixed("Bearer ", jwt))
	}
	var got struct {
		Data   json.RawMessage `json:"data"`
		Errors []struct{}      `json:"errors"`
	}
	if err := readJSON2xx(p.doer, req, &got); err != nil {
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
