// SPDX-License-Identifier: BUSL-1.1

package relay

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/textproto"
	"strings"

	"trstctl.com/trstctl/internal/pluginhost"
)

// A193: what a third-party connector receives for one deploy or test, and the
// HTTP calls the relay makes on its behalf.
//
// The guest reads public inputs only: the certificate chain it deploys, the
// fingerprint, the target name and the target's configuration (which names
// credential references, never their values). It sends the private key and
// calls the appliance as its administrator by asking the relay: a request
// names the key by reference ({"$input": "private_key_pem"} in a JSON body, or
// body_input) and asks for "basic", "bearer" or "header" auth, and the relay
// adds the redeemed credential, sends the request through the agent's egress
// policy, and removes every redeemed value from the response before the guest
// reads it.

// maxPluginResponseBody bounds an appliance response the relay reads for a guest.
const maxPluginResponseBody = 256 << 10

// pluginReadableInputs are the inputs a guest may read; pluginSplicedInputs
// may only be named in a request body, never read.
var (
	pluginReadableInputs = map[string]string{
		"certificate_pem": "credential.cert_pem",
	}
	pluginSplicedInputs = map[string]string{
		"certificate_pem": "credential.cert_pem",
		"private_key_pem": "credential.key_pem",
	}
)

// pluginTargetConfig is the part of a target's configuration the relay reads to
// add a plugin request's credential.
type pluginTargetConfig struct {
	Username    string `json:"username"`
	PasswordRef string `json:"password_ref"`
	TokenRef    string `json:"token_ref"`
}

// pluginInvocation assembles one call's inputs and HTTP service.
func pluginInvocation(client *http.Client, intent DeployIntent, material Material, readOnly bool) pluginhost.Invocation {
	inputs := map[string][]byte{
		"fingerprint": []byte(intent.Fingerprint),
		"target":      []byte(intent.Target),
	}
	if len(intent.TargetConfig) > 0 {
		inputs["target_config"] = append([]byte(nil), intent.TargetConfig...)
	}
	for name, key := range pluginReadableInputs {
		if value := material[key]; len(value) > 0 {
			inputs[name] = append([]byte(nil), value...)
		}
	}
	return pluginhost.Invocation{Inputs: inputs, HTTP: pluginHTTPDoer(client, intent, material), ReadOnly: readOnly}
}

// pluginHTTPDoer makes a guest's request with the target's credential added.
func pluginHTTPDoer(client *http.Client, intent DeployIntent, material Material) pluginhost.HTTPDoer {
	return func(ctx context.Context, req pluginhost.HTTPRequest) (pluginhost.HTTPResponse, error) {
		body, err := pluginRequestBody(req, material)
		if err != nil {
			return pluginhost.HTTPResponse{}, err
		}
		r, err := http.NewRequestWithContext(ctx, req.Method, req.URL, bytes.NewReader(body))
		if err != nil {
			return pluginhost.HTTPResponse{}, fmt.Errorf("relay: plugin request: %w", err)
		}
		for name, value := range req.Headers {
			canonical := textproto.CanonicalMIMEHeaderKey(strings.TrimSpace(name))
			if canonical == "Authorization" || canonical == "Proxy-Authorization" || canonical == "Cookie" ||
				(req.Auth == "header" && strings.EqualFold(canonical, req.AuthHeader)) {
				return pluginhost.HTTPResponse{}, fmt.Errorf("relay: a plugin may not set the %s header; the relay adds the credential", canonical)
			}
			r.Header.Set(canonical, value)
		}
		if err := addPluginAuth(r, req, intent, material); err != nil {
			return pluginhost.HTTPResponse{}, err
		}
		resp, err := client.Do(r)
		if err != nil {
			return pluginhost.HTTPResponse{}, fmt.Errorf("relay: plugin request to %s failed", r.URL.Host)
		}
		defer func() { _ = resp.Body.Close() }()
		data, err := io.ReadAll(io.LimitReader(resp.Body, maxPluginResponseBody+1))
		if err != nil {
			return pluginhost.HTTPResponse{}, fmt.Errorf("relay: read plugin response: %w", err)
		}
		truncated := len(data) > maxPluginResponseBody
		if truncated {
			data = data[:maxPluginResponseBody]
		}
		out := pluginhost.HTTPResponse{Status: resp.StatusCode, Truncated: truncated, Headers: map[string]string{}}
		for _, name := range []string{"Content-Type", "Location", "Etag", "Retry-After"} {
			if value := resp.Header.Get(name); value != "" {
				out.Headers[name] = redactRedeemed(value, material)
			}
		}
		out.Body = redactRedeemed(string(data), material)
		return out, nil
	}
}

// pluginRequestBody builds the body a guest asked for, splicing in the inputs it
// named by reference.
func pluginRequestBody(req pluginhost.HTTPRequest, material Material) ([]byte, error) {
	set := 0
	for _, used := range []bool{req.Body != "", req.BodyInput != "", len(req.JSON) > 0} {
		if used {
			set++
		}
	}
	if set > 1 {
		return nil, errors.New("relay: a plugin request names more than one body")
	}
	switch {
	case req.BodyInput != "":
		return splicedInput(req.BodyInput, material)
	case len(req.JSON) > 0:
		var doc any
		if err := json.Unmarshal(req.JSON, &doc); err != nil {
			return nil, fmt.Errorf("relay: plugin JSON body: %w", err)
		}
		resolved, err := spliceJSONInputs(doc, material)
		if err != nil {
			return nil, err
		}
		return json.Marshal(resolved)
	default:
		return []byte(req.Body), nil
	}
}

func splicedInput(name string, material Material) ([]byte, error) {
	key, ok := pluginSplicedInputs[name]
	if !ok {
		return nil, fmt.Errorf("relay: a plugin request names unknown input %q", name)
	}
	value := material[key]
	if len(value) == 0 {
		return nil, fmt.Errorf("relay: input %q is not available for this deploy", name)
	}
	return value, nil
}

// spliceJSONInputs replaces each {"$input": "<name>"} object with that input's
// text.
func spliceJSONInputs(node any, material Material) (any, error) {
	switch v := node.(type) {
	case map[string]any:
		if name, ok := v["$input"].(string); ok && len(v) == 1 {
			value, err := splicedInput(name, material)
			if err != nil {
				return nil, err
			}
			return string(value), nil
		}
		for key, child := range v {
			resolved, err := spliceJSONInputs(child, material)
			if err != nil {
				return nil, err
			}
			v[key] = resolved
		}
		return v, nil
	case []any:
		for i, child := range v {
			resolved, err := spliceJSONInputs(child, material)
			if err != nil {
				return nil, err
			}
			v[i] = resolved
		}
		return v, nil
	default:
		return v, nil
	}
}

// addPluginAuth adds the target's credential to r as the request asked.
func addPluginAuth(r *http.Request, req pluginhost.HTTPRequest, intent DeployIntent, material Material) error {
	if req.Auth == "" {
		return nil
	}
	var cfg pluginTargetConfig
	if len(intent.TargetConfig) > 0 {
		if err := json.Unmarshal(intent.TargetConfig, &cfg); err != nil {
			return errors.New("relay: target configuration is not JSON")
		}
	}
	redeemed := func(ref string) ([]byte, error) {
		value := material[strings.TrimSpace(ref)]
		if strings.TrimSpace(ref) == "" || len(value) == 0 {
			return nil, fmt.Errorf("relay: %s auth needs a credential reference this deploy redeemed", req.Auth)
		}
		return value, nil
	}
	switch req.Auth {
	case "basic":
		password, err := redeemed(cfg.PasswordRef)
		if err != nil {
			return err
		}
		pair := append(append([]byte(cfg.Username), ':'), password...)
		r.Header.Set("Authorization", "Basic "+base64.StdEncoding.EncodeToString(pair))
		clear(pair)
	case "bearer":
		token, err := redeemed(cfg.TokenRef)
		if err != nil {
			return err
		}
		r.Header.Set("Authorization", "Bearer "+string(token))
	case "header":
		name := textproto.CanonicalMIMEHeaderKey(strings.TrimSpace(req.AuthHeader))
		if name == "" || name == "Host" {
			return errors.New("relay: header auth needs a header name")
		}
		token, err := redeemed(cfg.TokenRef)
		if err != nil {
			return err
		}
		r.Header.Set(name, string(token))
	default:
		return fmt.Errorf("relay: unknown plugin auth %q; expected basic, bearer or header", req.Auth)
	}
	return nil
}

// runPluginTest runs a verified plugin's test entry point for connector.test
// (A193). A module without one is refused before anything is redeemed; one
// with one runs read-only with the attempt's credentials added to its requests.
func runPluginTest(ctx context.Context, ch Channel, client *http.Client, plugins *PluginRuntime, job Job, intent DeployIntent) bool {
	plan := Plan{Connector: intent.Connector, Target: intent.Target}
	if !plugins.HasTest(intent.Connector) {
		plan.Steps = []PlanStep{{
			Name: "connector", Status: StepFailed,
			Detail: "this verified plugin has no test entry point; no credential was redeemed and the plugin was not invoked",
		}}
		return reportConnectorTestPlan(ctx, ch, job, plan)
	}
	items, err := ch.RedeemJobCredential(ctx, job.JobID, job.Attempt)
	if err != nil {
		return reportConnectorTestPlan(ctx, ch, job, blockedConnectorTestPlan(intent,
			"credentials", "credential redemption was not granted for this test attempt"))
	}
	material, destroy, err := AdoptMaterial(items)
	if err != nil {
		return reportConnectorTestPlan(ctx, ch, job, blockedConnectorTestPlan(intent,
			"credentials", "redeemed material could not be protected in locked memory"))
	}
	defer destroy()
	if err := plugins.Test(ctx, intent.Connector, PluginCall{Intent: intent, Material: material, Client: client}); err != nil {
		// The module's own words stay on this host, as a deploy's do.
		log.Printf("trstctl-agent: job %d: plugin %s test failed: %s", job.JobID, intent.Connector, scrubFailure(err.Error(), material))
		plan.Steps = []PlanStep{{
			Name: "connector", Status: StepFailed,
			Detail: "the plugin's read-only test failed or tried to change the target; nothing was written",
		}}
		return reportConnectorTestPlan(ctx, ch, job, plan)
	}
	plan.Steps = []PlanStep{{Name: "connector", Status: StepOK, Detail: "the plugin's read-only test passed; nothing was written"}}
	plan.Ready = true
	return reportConnectorTestPlan(ctx, ch, job, plan)
}
