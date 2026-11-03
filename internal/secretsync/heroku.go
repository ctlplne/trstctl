// SPDX-License-Identifier: BUSL-1.1

package secretsync

import (
	"context"
	"net/http"
	"unicode/utf8"

	"trstctl.com/trstctl/internal/crypto/secret"
)

// Heroku config vars (A241): one PATCH sets a var (a null deletes it); GET
// returns every var with its value.
var herokuVendor = &hostedVendor{
	name:         "Heroku",
	deliveryMode: "app config-vars PATCH over HTTPS (a null value deletes)",
	authMode:     "Bearer API token supplied by operator config",
	wireFormat:   "JSON object of config var names and string values",
	readBack:     ReadBackValue,
	proof:        ProofStandIn,
	headers: func(p *HostedSyncPusher, req *http.Request) {
		bearerHeaders(p, req)
		req.Header.Set("Accept", "application/vnd.heroku+json; version=3")
	},
	put: func(ctx context.Context, p *HostedSyncPusher, key string, value []byte) error {
		if !utf8.Valid(value) {
			return errHostedValueNotText
		}
		body := append([]byte(`{`), appendJSONValueBytes(nil, []byte(key))...)
		body = append(body, ':')
		body = appendJSONValueBytes(body, value)
		body = append(body, '}')
		defer secret.Wipe(body)
		return hostedError(p, "set config var", p.send(ctx, http.MethodPatch, herokuPath(p), body, nil))
	},
	list: func(ctx context.Context, p *HostedSyncPusher) ([]string, error) {
		vars, err := herokuVars(ctx, p)
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
		vars, err := herokuVars(ctx, p)
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
		body := append([]byte(`{`), appendJSONValueBytes(nil, []byte(key))...)
		body = append(body, `:null}`...)
		return hostedError(p, "delete config var", p.send(ctx, http.MethodPatch, herokuPath(p), body, nil))
	},
}

func herokuPath(p *HostedSyncPusher) string {
	return "/apps/" + pathEscape(p.binding["app"]) + "/config-vars"
}

func herokuVars(ctx context.Context, p *HostedSyncPusher) (map[string]secret.JSONBytes, error) {
	var vars map[string]secret.JSONBytes
	if err := p.send(ctx, http.MethodGet, herokuPath(p), nil, &vars); err != nil {
		return nil, hostedError(p, "read config vars", err)
	}
	return vars, nil
}

// wipeJSONMap wipes every value of a decoded map.
func wipeJSONMap(m map[string]secret.JSONBytes) {
	for name, value := range m {
		secret.Wipe(value)
		delete(m, name)
	}
}
