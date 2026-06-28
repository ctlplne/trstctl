package main

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	internalcrypto "trstctl.com/trstctl/internal/crypto"
)

var connectorHTTPClient = http.DefaultClient

type connectorCLIConfig struct {
	baseURL string
	token   string
	tenant  string
}

func runConnector(ctx context.Context, args []string, getenv func(string) string, stdout, stderr io.Writer) error {
	if len(args) < 1 || args[0] != "target" {
		return errors.New("usage: trstctl connector target <list|get|create|update|delete|bind|test|deploy|rollback>")
	}
	return runConnectorTarget(ctx, args[1:], getenv, stdout, stderr)
}

func runConnectorTarget(ctx context.Context, args []string, getenv func(string) string, stdout, stderr io.Writer) error {
	if len(args) < 1 {
		return errors.New("usage: trstctl connector target <list|get|create|update|delete|bind|test|deploy|rollback>")
	}
	cfg, err := connectorCLIConfigFromEnv(getenv)
	if err != nil {
		return err
	}
	switch args[0] {
	case "list":
		return connectorCLIRequest(ctx, stdout, cfg, http.MethodGet, "/api/v1/connectors/targets", nil, false)
	case "get":
		fs := flag.NewFlagSet("trstctl connector target get", flag.ContinueOnError)
		fs.SetOutput(stderr)
		targetID := fs.String("target", "", "deployment target id")
		if err := fs.Parse(args[1:]); err != nil {
			return err
		}
		if strings.TrimSpace(*targetID) == "" {
			return errors.New("connector target get: --target is required")
		}
		return connectorCLIRequest(ctx, stdout, cfg, http.MethodGet, "/api/v1/connectors/targets/"+url.PathEscape(*targetID), nil, false)
	case "create":
		return runConnectorTargetUpsert(ctx, stdout, stderr, cfg, args[1:], "")
	case "update":
		fs := flag.NewFlagSet("trstctl connector target update", flag.ContinueOnError)
		fs.SetOutput(stderr)
		targetID := fs.String("target", "", "deployment target id")
		name := fs.String("name", "", "target display/route name")
		connector := fs.String("connector", "", "served connector name")
		configJSON := fs.String("config-json", "{}", "non-secret connector config JSON")
		if err := fs.Parse(args[1:]); err != nil {
			return err
		}
		if strings.TrimSpace(*targetID) == "" {
			return errors.New("connector target update: --target is required")
		}
		return connectorTargetUpsert(ctx, stdout, cfg, *targetID, *name, *connector, *configJSON)
	case "delete":
		fs := flag.NewFlagSet("trstctl connector target delete", flag.ContinueOnError)
		fs.SetOutput(stderr)
		targetID := fs.String("target", "", "deployment target id")
		if err := fs.Parse(args[1:]); err != nil {
			return err
		}
		if strings.TrimSpace(*targetID) == "" {
			return errors.New("connector target delete: --target is required")
		}
		return connectorCLIRequest(ctx, stdout, cfg, http.MethodDelete, "/api/v1/connectors/targets/"+url.PathEscape(*targetID), nil, true)
	case "bind":
		fs := flag.NewFlagSet("trstctl connector target bind", flag.ContinueOnError)
		fs.SetOutput(stderr)
		identityID := fs.String("identity", "", "identity id")
		targetID := fs.String("target", "", "deployment target id")
		if err := fs.Parse(args[1:]); err != nil {
			return err
		}
		if strings.TrimSpace(*identityID) == "" || strings.TrimSpace(*targetID) == "" {
			return errors.New("connector target bind: --identity and --target are required")
		}
		return connectorCLIRequest(ctx, stdout, cfg, http.MethodPost, "/api/v1/identities/"+url.PathEscape(*identityID)+"/connector-target", map[string]string{"target_id": *targetID}, true)
	case "test", "deploy", "rollback":
		return runConnectorTargetAction(ctx, stdout, stderr, cfg, args[0], args[1:])
	default:
		return fmt.Errorf("unknown connector target command %q", args[0])
	}
}

func runConnectorTargetUpsert(ctx context.Context, stdout, stderr io.Writer, cfg connectorCLIConfig, args []string, targetID string) error {
	fs := flag.NewFlagSet("trstctl connector target create", flag.ContinueOnError)
	fs.SetOutput(stderr)
	name := fs.String("name", "", "target display/route name")
	connector := fs.String("connector", "", "served connector name")
	configJSON := fs.String("config-json", "{}", "non-secret connector config JSON")
	if err := fs.Parse(args); err != nil {
		return err
	}
	return connectorTargetUpsert(ctx, stdout, cfg, targetID, *name, *connector, *configJSON)
}

func connectorTargetUpsert(ctx context.Context, stdout io.Writer, cfg connectorCLIConfig, targetID, name, connectorName, configJSON string) error {
	name = strings.TrimSpace(name)
	connectorName = strings.TrimSpace(connectorName)
	if name == "" || connectorName == "" {
		return errors.New("connector target create/update: --name and --connector are required")
	}
	var config map[string]any
	if err := json.Unmarshal([]byte(configJSON), &config); err != nil || config == nil {
		return errors.New("connector target create/update: --config-json must be a JSON object")
	}
	body := map[string]any{"name": name, "connector": connectorName, "config": config}
	method, path := http.MethodPost, "/api/v1/connectors/targets"
	if targetID != "" {
		method, path = http.MethodPut, "/api/v1/connectors/targets/"+url.PathEscape(targetID)
	}
	return connectorCLIRequest(ctx, stdout, cfg, method, path, body, true)
}

func runConnectorTargetAction(ctx context.Context, stdout, stderr io.Writer, cfg connectorCLIConfig, action string, args []string) error {
	fs := flag.NewFlagSet("trstctl connector target "+action, flag.ContinueOnError)
	fs.SetOutput(stderr)
	targetID := fs.String("target", "", "deployment target id")
	identityID := fs.String("identity", "", "identity id")
	reason := fs.String("reason", "", "operator reason")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if strings.TrimSpace(*targetID) == "" {
		return fmt.Errorf("connector target %s: --target is required", action)
	}
	body := map[string]string{}
	if strings.TrimSpace(*identityID) != "" {
		body["identity_id"] = strings.TrimSpace(*identityID)
	}
	if strings.TrimSpace(*reason) != "" {
		body["reason"] = strings.TrimSpace(*reason)
	}
	if action == "deploy" && body["identity_id"] == "" {
		return errors.New("connector target deploy: --identity is required")
	}
	return connectorCLIRequest(ctx, stdout, cfg, http.MethodPost, "/api/v1/connectors/targets/"+url.PathEscape(*targetID)+"/"+action, body, true)
}

func connectorCLIConfigFromEnv(getenv func(string) string) (connectorCLIConfig, error) {
	baseURL := strings.TrimRight(strings.TrimSpace(firstEnv(getenv, "TRSTCTL_URL", "TRSTCTL_API_URL")), "/")
	token := strings.TrimSpace(firstEnv(getenv, "TRSTCTL_TOKEN", "TRSTCTL_API_TOKEN"))
	tenant := strings.TrimSpace(getenv("TRSTCTL_TENANT"))
	if baseURL == "" || token == "" || tenant == "" {
		return connectorCLIConfig{}, errors.New("connector CLI requires TRSTCTL_URL, TRSTCTL_TOKEN, and TRSTCTL_TENANT")
	}
	return connectorCLIConfig{baseURL: baseURL, token: token, tenant: tenant}, nil
}

func firstEnv(getenv func(string) string, keys ...string) string {
	for _, key := range keys {
		if v := getenv(key); strings.TrimSpace(v) != "" {
			return v
		}
	}
	return ""
}

func connectorCLIRequest(ctx context.Context, stdout io.Writer, cfg connectorCLIConfig, method, path string, body any, mutation bool) error {
	var rdr io.Reader
	if body != nil {
		raw, err := json.Marshal(body)
		if err != nil {
			return err
		}
		rdr = bytes.NewReader(raw)
	}
	req, err := http.NewRequestWithContext(ctx, method, cfg.baseURL+path, rdr)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+cfg.token)
	req.Header.Set("X-Tenant-ID", cfg.tenant)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if mutation {
		req.Header.Set("Idempotency-Key", "cli-"+time.Now().UTC().Format("20060102T150405Z")+"-"+randomHex8())
	}
	resp, err := connectorHTTPClient.Do(req)
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 2<<20))
	if err != nil {
		return err
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("connector API %s %s returned %d: %s", method, path, resp.StatusCode, strings.TrimSpace(string(raw)))
	}
	if resp.StatusCode != http.StatusNoContent {
		_, _ = stdout.Write(raw)
		if len(raw) == 0 || raw[len(raw)-1] != '\n' {
			_, _ = io.WriteString(stdout, "\n")
		}
	}
	return nil
}

func randomHex8() string {
	b, err := internalcrypto.RandomBytes(4)
	if err != nil {
		return "00000000"
	}
	return hex.EncodeToString(b)
}
