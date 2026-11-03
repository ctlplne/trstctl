// SPDX-License-Identifier: BUSL-1.1

package secretsync

import (
	"context"
	"encoding/base64"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/crypto/secret"
)

// Chef Infra Server data bag items (A241): each key is an item {"id", "value"}
// in the bound data bag; POST creates one, PUT replaces it, DELETE removes
// it, and GET reads the value back. Every request is signed with the
// client's key (X-Ops authentication protocol 1.3, SHA-256). The endpoint is
// the organization's URL, https://<server>/organizations/<org>.
var chefVendor = &hostedVendor{
	name:         "Chef Infra Server",
	deliveryMode: "data bag item POST, PUT and DELETE over HTTPS (X-Ops request signing, protocol 1.3)",
	authMode:     "client name (username) and its PEM private key (token_ref), each request signed",
	wireFormat:   `JSON data bag item {"id": <key>, "value": <the secret>}`,
	readBack:     ReadBackValue,
	proof:        ProofStandIn,
	headers:      func(*HostedSyncPusher, *http.Request) {},
	sign:         signChefRequest,
	put: func(ctx context.Context, p *HostedSyncPusher, key string, value []byte) error {
		if !utf8.Valid(value) {
			return errHostedValueNotText
		}
		body := append([]byte(`{"id":`), appendJSONValueBytes(nil, []byte(key))...)
		body = append(body, `,"value":`...)
		body = appendJSONValueBytes(body, value)
		body = append(body, '}')
		defer secret.Wipe(body)
		err := p.send(ctx, http.MethodPut, chefPath(p, key), body, nil)
		if notFound(err) {
			err = p.send(ctx, http.MethodPost, chefPath(p, ""), body, nil)
		}
		return hostedError(p, "store data bag item", err)
	},
	list: func(ctx context.Context, p *HostedSyncPusher) ([]string, error) {
		var items map[string]string
		if err := p.send(ctx, http.MethodGet, chefPath(p, ""), nil, &items); err != nil {
			return nil, hostedError(p, "list data bag", err)
		}
		return mapKeys(items), nil
	},
	read: func(ctx context.Context, p *HostedSyncPusher, key string) (bool, []byte, error) {
		var item struct {
			Value secret.JSONBytes `json:"value"`
		}
		err := p.send(ctx, http.MethodGet, chefPath(p, key), nil, &item)
		if notFound(err) {
			return false, nil, nil
		}
		if err != nil {
			return false, nil, hostedError(p, "read data bag item", err)
		}
		return true, item.Value, nil
	},
	remove: func(ctx context.Context, p *HostedSyncPusher, key string) error {
		return hostedError(p, "delete data bag item", ignoreNotFound(p.send(ctx, http.MethodDelete, chefPath(p, key), nil, nil)))
	},
}

func chefPath(p *HostedSyncPusher, key string) string {
	path := "/data/" + pathEscape(p.binding["data-bag"])
	if key != "" {
		path += "/" + pathEscape(key)
	}
	return path
}

var chefSlashes = regexp.MustCompile(`/+`)

// signChefRequest adds the X-Ops 1.3 headers: the body's SHA-256, the
// timestamp, the client name and API version, and the RSA-SHA256 signature
// of the canonical request split into 60-character X-Ops-Authorization-N
// headers.
func signChefRequest(p *HostedSyncPusher, req *http.Request, body []byte) error {
	if body == nil {
		body = []byte{}
	}
	timestamp := time.Now().UTC().Format("2006-01-02T15:04:05Z")
	hash := base64.StdEncoding.EncodeToString(crypto.SHA256Sum(body))
	path := chefSlashes.ReplaceAllString(req.URL.EscapedPath(), "/")
	if len(path) > 1 {
		path = strings.TrimSuffix(path, "/")
	}
	canonical := "Method:" + req.Method + "\nPath:" + path + "\nX-Ops-Content-Hash:" + hash +
		"\nX-Ops-Sign:version=1.3\nX-Ops-Timestamp:" + timestamp + "\nX-Ops-UserId:" + p.username +
		"\nX-Ops-Server-API-Version:1"
	signature, err := crypto.SignRSASHA256WithPEMKey(p.token.Bytes(), []byte(canonical))
	if err != nil {
		return err
	}
	req.Header.Set("X-Ops-Sign", "algorithm=sha256;version=1.3")
	req.Header.Set("X-Ops-Userid", p.username)
	req.Header.Set("X-Ops-Timestamp", timestamp)
	req.Header.Set("X-Ops-Content-Hash", hash)
	req.Header.Set("X-Ops-Server-API-Version", "1")
	req.Header.Set("X-Chef-Version", "18.0.0")
	encoded := base64.StdEncoding.EncodeToString(signature)
	for i := 0; len(encoded) > 0; i++ {
		n := min(60, len(encoded))
		req.Header.Set("X-Ops-Authorization-"+strconv.Itoa(i+1), encoded[:n])
		encoded = encoded[n:]
	}
	return nil
}
