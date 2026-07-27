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
		return errors.New("usage: trstctl ssh <status|fleet|trust-rollout|issue-attested-user|revoke|retire-host>")
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
