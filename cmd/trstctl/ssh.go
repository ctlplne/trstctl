// SPDX-License-Identifier: MPL-2.0

package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
)

func runSSH(ctx context.Context, args []string, getenv func(string) string, stdout, stderr io.Writer) error {
	if len(args) < 1 {
		return errors.New("usage: trstctl ssh <status|fleet|trust-rollout|preview|issue|issue-attested-user|revoke|retire-host>")
	}
	cfg, err := connectorCLIConfigFromEnv(getenv)
	if err != nil {
		return err
	}
	switch args[0] {
	case "status":
		return connectorCLIRequest(ctx, stdout, cfg, http.MethodGet, "/api/v1/ssh/status", nil, false)
	case "fleet":
		return connectorCLIRequest(ctx, stdout, cfg, http.MethodGet, "/api/v1/ssh/fleet", nil, false)
	case "trust-rollout":
		fs := flag.NewFlagSet("trstctl ssh trust-rollout", flag.ContinueOnError)
		fs.SetOutput(stderr)
		sourceID := fs.String("source", "", "discovery source id")
		hosts := fs.String("hosts", "", "comma-separated target hosts")
		fingerprint := fs.String("ca-fingerprint", "", "candidate SSH CA fingerprint")
		reload := fs.String("reload-cmd", "", "sshd reload command")
		health := fs.String("health-cmd", "", "post-reload health command")
		rollback := fs.String("rollback-plan", "", "rollback plan")
		status := fs.String("status", "health_passed", "rollout status")
		confirm := fs.Bool("confirm", false, "confirm high-blast-radius trust rollout evidence")
		if err := fs.Parse(args[1:]); err != nil {
			return err
		}
		body := map[string]any{
			"source_id": *sourceID, "target_hosts": splitCSV(*hosts), "candidate_ca_fingerprint": *fingerprint,
			"reload_command": *reload, "health_command": *health, "rollback_plan": *rollback,
			"status": *status, "confirmed": *confirm,
		}
		return connectorCLIRequest(ctx, stdout, cfg, http.MethodPost, "/api/v1/ssh/trust-rollouts", body, true)
	case "preview", "issue":
		command := args[0]
		fs := flag.NewFlagSet("trstctl ssh "+command, flag.ContinueOnError)
		fs.SetOutput(stderr)
		certificateType := fs.String("type", "host", "certificate type: host or user")
		publicKey := fs.String("public-key", "", "subject SSH public key in authorized_keys form")
		keyID := fs.String("key-id", "", "certificate name recorded in audit and KRL evidence")
		principals := fs.String("principals", "", "comma-separated allowed hostnames or users")
		ttl := fs.Int64("ttl-seconds", 0, "requested lifetime in seconds; defaults to 3600 and is capped at 86400")
		sourceAddresses := fs.String("source-addresses", "", "user certificates only: comma-separated allowed source CIDRs")
		forceCommand := fs.String("force-command", "", "user certificates only: command the SSH server must run")
		extensions := fs.String("extensions", "", "user certificates only: comma-separated OpenSSH extension names")
		if err := fs.Parse(args[1:]); err != nil {
			return err
		}
		criticalOptions := map[string]string{}
		if values := splitCSV(*sourceAddresses); len(values) > 0 {
			criticalOptions["source-address"] = strings.Join(values, ",")
		}
		if value := strings.TrimSpace(*forceCommand); value != "" {
			criticalOptions["force-command"] = value
		}
		extensionMap := map[string]string{}
		for _, name := range splitCSV(*extensions) {
			extensionMap[name] = ""
		}
		body := map[string]any{
			"certificate_type": strings.TrimSpace(*certificateType),
			"public_key":       strings.TrimSpace(*publicKey),
			"key_id":           strings.TrimSpace(*keyID),
			"principals":       splitCSV(*principals),
			"ttl_seconds":      *ttl,
			"critical_options": criticalOptions,
			"extensions":       extensionMap,
		}
		path := "/api/v1/ssh/certificates"
		mutation := true
		if command == "preview" {
			path += "/preview"
			mutation = false
		}
		return connectorCLIRequest(ctx, stdout, cfg, http.MethodPost, path, body, mutation)
	case "issue-attested-user":
		fs := flag.NewFlagSet("trstctl ssh issue-attested-user", flag.ContinueOnError)
		fs.SetOutput(stderr)
		method := fs.String("method", "", "attestation method")
		payload := fs.String("payload-base64", "", "attestation payload as standard base64")
		publicKey := fs.String("public-key", "", "subject SSH public key in authorized_keys form")
		keyID := fs.String("key-id", "", "SSH certificate key id")
		ttl := fs.Int64("ttl-seconds", 0, "requested TTL in seconds")
		if err := fs.Parse(args[1:]); err != nil {
			return err
		}
		body := map[string]any{"method": *method, "payload_base64": *payload, "public_key": *publicKey, "key_id": *keyID, "ttl_seconds": *ttl}
		return connectorCLIRequest(ctx, stdout, cfg, http.MethodPost, "/api/v1/ssh/attested-user-certs", body, true)
	case "revoke":
		fs := flag.NewFlagSet("trstctl ssh revoke", flag.ContinueOnError)
		fs.SetOutput(stderr)
		serial := fs.String("serial", "", "SSH cert serial")
		keyID := fs.String("key-id", "", "SSH cert key id")
		reason := fs.String("reason", "", "revocation reason")
		if err := fs.Parse(args[1:]); err != nil {
			return err
		}
		body := map[string]any{"key_id": *keyID, "reason": *reason}
		if strings.TrimSpace(*serial) != "" {
			n, err := strconv.ParseUint(strings.TrimSpace(*serial), 10, 64)
			if err != nil {
				return fmt.Errorf("ssh revoke: --serial must be an unsigned integer: %w", err)
			}
			body["serial"] = n
		}
		return connectorCLIRequest(ctx, stdout, cfg, http.MethodPost, "/api/v1/ssh/certificates/revoke", body, true)
	case "retire-host":
		fs := flag.NewFlagSet("trstctl ssh retire-host", flag.ContinueOnError)
		fs.SetOutput(stderr)
		host := fs.String("host", "", "host name")
		sourceID := fs.String("source", "", "discovery source id")
		runID := fs.String("run", "", "discovery run id")
		identityID := fs.String("identity", "", "identity id")
		reason := fs.String("reason", "", "retirement reason")
		if err := fs.Parse(args[1:]); err != nil {
			return err
		}
		body := map[string]any{"host": *host, "source_id": *sourceID, "run_id": *runID, "identity_id": *identityID, "reason": *reason}
		return connectorCLIRequest(ctx, stdout, cfg, http.MethodPost, "/api/v1/ssh/hosts/retire", body, true)
	default:
		return fmt.Errorf("unknown ssh command %q", args[0])
	}
}

func splitCSV(s string) []string {
	parts := strings.Split(s, ",")
	out := make([]string, 0, len(parts))
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part != "" {
			out = append(out, part)
		}
	}
	return out
}
