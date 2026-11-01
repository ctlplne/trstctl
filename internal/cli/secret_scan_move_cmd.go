// SPDX-License-Identifier: BUSL-1.1

package cli

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"

	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/crypto/secret"
	"trstctl.com/trstctl/internal/secretjson"
	"trstctl.com/trstctl/internal/secretscan"
)

// secrets scans move moves a leaked secret a scan found into the native store
// (P6). It reads the finding (rule, file and line; never a value), re-finds the
// value in the operator's own checkout with the pinned gitleaks — its report
// read from a pipe, never written to disk — stores it as a native secret, links
// the finding to that secret version together with the history commits that
// still hold the value, and prints the reference to use instead. The value is
// wiped and never printed.

func secretScanMoveUsage(w io.Writer) {
	_, _ = fmt.Fprintln(w, "Usage: trstctl secrets scans move <finding-id> --repo <checkout> --name <secret-name> [--gitleaks-bin path]")
	_, _ = fmt.Fprintln(w, "\nRe-finds a leaked-secret finding's value in your checkout of the scanned repository, stores it as a native secret and links the finding to it. The value goes only to the secret store and is never printed.")
	_, _ = fmt.Fprintln(w, "\nExample: trstctl secrets scans move 3f2a9c1e-0000-4000-8000-000000000000 --repo ./payments --name payments/slack-bot-token")
}

type movedFinding struct {
	ID       string `json:"id"`
	Kind     string `json:"kind"`
	Metadata struct {
		RuleID string `json:"rule_id"`
		File   string `json:"file"`
		Line   int    `json:"line"`
	} `json:"metadata"`
}

func runSecretScanMove(ctx context.Context, args []string, env Env, stdout, stderr io.Writer, server, token, tenant, caFile string) int {
	if len(args) == 0 || strings.HasPrefix(args[0], "-") || server == "" {
		secretScanMoveUsage(stderr)
		return 2
	}
	findingID := args[0]
	fs := flag.NewFlagSet("secrets scans move", flag.ContinueOnError)
	fs.SetOutput(stderr)
	repo := fs.String("repo", "", "your checkout of the scanned repository (its top-level directory)")
	name := fs.String("name", "", "the native secret to create, for example payments/slack-bot-token")
	gitleaksBin := fs.String("gitleaks-bin", "", "the pinned gitleaks binary (default: TRSTCTL_GITLEAKS_BIN, tools/bin/gitleaks, PATH)")
	if err := fs.Parse(args[1:]); err != nil {
		return 2
	}
	if *repo == "" || strings.TrimSpace(*name) == "" {
		secretScanMoveUsage(stderr)
		return 2
	}
	fail := func(format string, a ...any) int {
		_, _ = fmt.Fprintf(stderr, format+"\n", a...)
		return 1
	}
	client, err := httpClientForEnv(env, caFile)
	if err != nil {
		return fail("%v", err)
	}
	finding, err := readMovedFinding(ctx, client, server, token, tenant, findingID)
	if err != nil {
		return fail("%v", err)
	}
	runner := secretscan.NewGitleaksRunner(*gitleaksBin)
	runner.AllowedRoots = []string{*repo}
	value, residue, err := runner.LocateSecretForMove(ctx, *repo, secretscan.SecretLocation{
		RuleID: finding.Metadata.RuleID, File: finding.Metadata.File, Line: finding.Metadata.Line,
	})
	if err != nil {
		if errors.Is(err, secretscan.ErrSecretNotLocated) {
			return fail("%s:%d holds no %s value in %s: check out the commit the scan saw", finding.Metadata.File, finding.Metadata.Line, finding.Metadata.RuleID, *repo)
		}
		return fail("%v", err)
	}
	defer secret.Wipe(value)
	version, err := storeMovedSecret(ctx, client, server, token, tenant, findingID, *name, value)
	if err != nil {
		return fail("%v", err)
	}
	link, err := json.Marshal(map[string]any{"secret_name": *name, "secret_version": version, "history_residue": historyResidue(residue)})
	if err != nil {
		return fail("%v", err)
	}
	status, body, err := do(ctx, client, server, http.MethodPost, "/api/v1/discovery/findings/"+url.PathEscape(findingID)+"/secret-move",
		nil, link, token, tenant, "secret-move-link:"+findingID+":"+crypto.SHA256Hex([]byte(*name)), "")
	if err != nil {
		return fail("link the finding: %v", err)
	}
	if status/100 != 2 {
		return fail("link the finding: HTTP %d %s", status, strings.TrimSpace(string(body)))
	}
	_, _ = fmt.Fprintf(stdout, "moved finding %s into %s (version %d)\n", findingID, *name, version)
	_, _ = fmt.Fprintf(stdout, "reference: ${secret.%s}\n", *name)
	_, _ = fmt.Fprintf(stdout, "use it:    trstctl run --secret ENV_NAME=%s -- <command>\n", *name)
	if len(residue) > 0 {
		_, _ = fmt.Fprintf(stdout, "history:   %d commit(s) still hold the value; cleaning the file does not end the exposure, rotating does\n", len(residue))
	}
	_, _ = fmt.Fprintf(stdout, "next:      rotate the value at its issuer, store the new one (trstctl secrets store update %s -f new.json), remove it from %s and commit; the finding closes when a consumer reads the new version and a scan no longer sees the leak\n", *name, finding.Metadata.File)
	return 0
}

func readMovedFinding(ctx context.Context, client *http.Client, server, token, tenant, findingID string) (movedFinding, error) {
	status, body, err := do(ctx, client, server, http.MethodGet, "/api/v1/discovery/findings", url.Values{"id": {findingID}}, nil, token, tenant, "", "")
	if err != nil {
		return movedFinding{}, fmt.Errorf("read the finding: %w", err)
	}
	if status != http.StatusOK {
		return movedFinding{}, fmt.Errorf("read the finding: HTTP %d %s", status, strings.TrimSpace(string(body)))
	}
	var page struct {
		Items []movedFinding `json:"items"`
	}
	if err := json.Unmarshal(body, &page); err != nil {
		return movedFinding{}, fmt.Errorf("read the finding: %w", err)
	}
	if len(page.Items) != 1 || page.Items[0].ID != findingID {
		return movedFinding{}, fmt.Errorf("no finding %s in this tenant", findingID)
	}
	f := page.Items[0]
	if f.Kind != "leaked_secret" || f.Metadata.RuleID == "" || f.Metadata.File == "" || f.Metadata.Line < 1 {
		return movedFinding{}, fmt.Errorf("finding %s is not a leaked secret with a rule, file and line", findingID)
	}
	return f, nil
}

// storeMovedSecret creates the native secret holding value and returns its
// version. The request body is built from bytes and wiped after the call.
func storeMovedSecret(ctx context.Context, client *http.Client, server, token, tenant, findingID, name string, value []byte) (int, error) {
	quotedName, err := json.Marshal(name)
	if err != nil {
		return 0, err
	}
	quotedValue := secretjson.QuoteBytes(value)
	defer secret.Wipe(quotedValue)
	body := make([]byte, 0, len(quotedName)+len(quotedValue)+20)
	body = append(append(append(append(append(body, `{"name":`...), quotedName...), `,"value":`...), quotedValue...), '}')
	defer secret.Wipe(body)
	status, resp, err := do(ctx, client, server, http.MethodPost, "/api/v1/secrets/store", nil, body, token, tenant,
		"secret-move:"+findingID+":"+crypto.SHA256Hex([]byte(name)), "")
	if err != nil {
		return 0, fmt.Errorf("store the secret: %w", err)
	}
	if status == http.StatusConflict {
		return 0, fmt.Errorf("store the secret: a secret named %s already exists; choose a new name", name)
	}
	if status/100 != 2 {
		return 0, fmt.Errorf("store the secret: HTTP %d %s", status, strings.TrimSpace(string(resp)))
	}
	var meta struct {
		Version int `json:"version"`
	}
	if err := json.Unmarshal(resp, &meta); err != nil || meta.Version < 1 {
		return 0, fmt.Errorf("store the secret: no version in the reply")
	}
	return meta.Version, nil
}

func historyResidue(locations []secretscan.SecretLocation) []secretscan.SecretLocation {
	if locations == nil {
		return []secretscan.SecretLocation{}
	}
	return locations
}
