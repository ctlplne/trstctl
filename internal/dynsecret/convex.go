// SPDX-License-Identifier: BUSL-1.1

package dynsecret

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"strings"

	"trstctl.com/trstctl/internal/crypto/secret"
)

// convexVendor creates deploy keys of the bound deployment through the
// Platform API ("<deployment>" or "<deployment>:<action>,<action>") and
// deletes them by their unique name, which serves as the key's ID (A240). A
// deploy key is checked only by the deployment itself, not the Platform API,
// so verification reports not available.
type convexVendor struct {
	token *secret.Buffer
}

func convexDeploymentOf(binding string) (string, []string) {
	deployment, actions, ok := strings.Cut(binding, ":")
	if !ok {
		return deployment, nil
	}
	return deployment, strings.Split(actions, ",")
}

func (c convexVendor) mint(ctx context.Context, api hostedAPI, binding, name string) (string, []byte, error) {
	deployment, actions := convexDeploymentOf(binding)
	request := map[string]any{"name": name}
	if len(actions) > 0 {
		request["allowedActions"] = actions
	}
	var created struct {
		DeployKey secret.JSONBytes `json:"deployKey"`
	}
	path := "/deployments/" + url.PathEscape(deployment) + "/create_deploy_key"
	if _, err := hostedJSON(ctx, api, http.MethodPost, path, request, bearerFrom(c.token), &created); err != nil {
		return "", nil, err
	}
	defer secret.Wipe(created.DeployKey)
	if len(created.DeployKey) == 0 {
		return "", nil, errors.New("dynsecret convex: the create response carries no deploy key")
	}
	credential, err := json.Marshal(map[string]any{ // #nosec G117 -- the new key is this provider's output: the outbox seals it and only its readers open it (CWE-200)
		"deploy_key": created.DeployKey, "deployment": deployment, "key_name": name,
	})
	if err != nil {
		return "", nil, err
	}
	return name, credential, nil
}

// named lists the deployment's deploy keys; a key's unique name is its ID
// here, as the delete operation takes it.
func (c convexVendor) named(ctx context.Context, api hostedAPI, binding, name string) ([]string, error) {
	deployment, _ := convexDeploymentOf(binding)
	var keys []struct {
		Name string `json:"name"`
	}
	path := "/deployments/" + url.PathEscape(deployment) + "/list_deploy_keys"
	if _, err := hostedJSON(ctx, api, http.MethodGet, path, nil, bearerFrom(c.token), &keys); err != nil {
		return nil, err
	}
	for _, key := range keys {
		if key.Name == name {
			return []string{name}, nil
		}
	}
	return nil, nil
}

func (c convexVendor) nameOf(ctx context.Context, api hostedAPI, binding, id string) (string, bool, error) {
	found, err := c.named(ctx, api, binding, id)
	if err != nil || len(found) == 0 {
		return "", false, err
	}
	return id, true, nil
}

// remove deletes the key by name after checking it is still there: the
// Platform API documents no answer for a key already gone.
func (c convexVendor) remove(ctx context.Context, api hostedAPI, binding, id string) error {
	if found, err := c.named(ctx, api, binding, id); err != nil || len(found) == 0 {
		return err
	}
	deployment, _ := convexDeploymentOf(binding)
	path := "/deployments/" + url.PathEscape(deployment) + "/delete_deploy_key"
	_, err := hostedJSON(ctx, api, http.MethodPost, path, map[string]string{"id": id}, bearerFrom(c.token), nil, http.StatusNotFound)
	return err
}

// verify: only the deployment checks a deploy key; the Platform API offers
// no side-effect-free check of one.
func (convexVendor) verify(context.Context, hostedAPI, []byte) error {
	return ErrNoSelfProof
}
