// SPDX-License-Identifier: BUSL-1.1

package cli

import (
	"bytes"
	"context"
	"encoding/hex"
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"

	"github.com/google/uuid"

	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/crypto/secret"
)

// secrets scans hooks test sends one delivery to a native scan webhook (P6)
// exactly as GitHub would: signed with the hook's secret from a local file
// (X-Hub-Signature-256), with a fresh X-GitHub-Delivery. With no payload it
// sends a ping; with --push-file it sends that push payload. It checks a hook's
// configuration end to end; the secret never leaves this machine.

func secretScanHookTestUsage(w io.Writer) {
	_, _ = fmt.Fprintln(w, "Usage: trstctl secrets scans hooks test --hook <id> --secret-file <path> [--push-file <payload.json>]")
	_, _ = fmt.Fprintln(w, "\nSends a signed ping (or the push payload) to POST /api/v1/secrets/scans/hooks/{id}, as GitHub would.")
	_, _ = fmt.Fprintln(w, "\nExample: trstctl secrets scans hooks test --hook gh-payments --secret-file ./hook-secret")
}

func runSecretScanHookTest(ctx context.Context, args []string, env Env, stdout, stderr io.Writer, server, caFile string) int {
	fs := flag.NewFlagSet("secrets scans hooks test", flag.ContinueOnError)
	fs.SetOutput(stderr)
	hook := fs.String("hook", "", "the secrets.scan_webhooks id")
	secretFile := fs.String("secret-file", "", "file holding the webhook's signing secret")
	pushFile := fs.String("push-file", "", "a GitHub push payload to deliver (default: a ping)")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if *hook == "" || *secretFile == "" || server == "" {
		secretScanHookTestUsage(stderr)
		return 2
	}
	key, err := os.ReadFile(*secretFile) // #nosec G304 -- the operator names their own secret file (CWE-22)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "read the secret file: %v\n", err)
		return 1
	}
	defer secret.Wipe(key)
	key = bytes.TrimRight(key, "\r\n")
	event, body := "ping", []byte(`{"zen":"trstctl hook test"}`)
	if *pushFile != "" {
		if body, err = os.ReadFile(*pushFile); err != nil { // #nosec G304 -- the operator names their own payload file (CWE-22)
			_, _ = fmt.Fprintf(stderr, "read the push payload: %v\n", err)
			return 1
		}
		event = "push"
	}
	client, err := httpClientForEnv(env, caFile)
	if err != nil {
		_, _ = fmt.Fprintln(stderr, err)
		return 1
	}
	endpoint := strings.TrimRight(server, "/") + "/api/v1/secrets/scans/hooks/" + url.PathEscape(*hook)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(body))
	if err != nil {
		_, _ = fmt.Fprintln(stderr, err)
		return 1
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-GitHub-Event", event)
	req.Header.Set("X-GitHub-Delivery", uuid.NewString())
	req.Header.Set("X-Hub-Signature-256", "sha256="+hex.EncodeToString(crypto.HMACSHA256(key, body)))
	resp, err := client.Do(req)
	if err != nil {
		_, _ = fmt.Fprintln(stderr, err)
		return 1
	}
	defer func() { _ = resp.Body.Close() }()
	out, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	_, _ = fmt.Fprintln(stdout, strings.TrimSpace(string(out)))
	if resp.StatusCode >= 300 {
		_, _ = fmt.Fprintf(stderr, "HTTP %d\n", resp.StatusCode)
		return 1
	}
	return 0
}
