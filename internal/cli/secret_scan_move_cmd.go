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
	"os"
	"path/filepath"
	"slices"
	"strings"

	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/crypto/secret"
	"trstctl.com/trstctl/internal/secretjson"
	"trstctl.com/trstctl/internal/secretscan"
)

// secrets scans move moves a leaked secret a scan found into the native store
// (P6). It reads the finding (rule, file and line; never a value), re-finds the
// value with the pinned gitleaks — its report read from a pipe, never written
// to disk — in the operator's own checkout of a scanned repository, or in its
// own copy of a scanned third-party export (P6-L7: a Slack or Jira export, a
// CI log, a registry export), stores it as a native secret, links the finding
// to that secret version together with the history commits that still hold
// the value (a repository's; an export has none), and prints the reference to
// use instead. The value is wiped and never printed.

func secretScanMoveUsage(w io.Writer) {
	_, _ = fmt.Fprintln(w, "Usage: trstctl secrets scans move <finding-id> (--repo <checkout> | --export <path>) --name <secret-name> [--gitleaks-bin path]")
	_, _ = fmt.Fprintln(w, "\nRe-finds a leaked-secret finding's value in your checkout of the scanned repository (--repo) or in your copy of the scanned third-party export (--export: the directory or file the scan read), stores it as a native secret and links the finding to it. The value goes only to the secret store and is never printed.")
	_, _ = fmt.Fprintln(w, "\nExample: trstctl secrets scans move 3f2a9c1e-0000-4000-8000-000000000000 --repo ./payments --name payments/slack-bot-token")
	_, _ = fmt.Fprintln(w, "Example: trstctl secrets scans move 7b1d0c4e-0000-4000-8000-000000000000 --export ./slack-export --name deploys/slack-bot-token")
}

// thirdPartyCapability marks a finding from a third-party scan (A174).
const thirdPartyCapability = "CAP-SCAN-04"

type movedFinding struct {
	ID       string `json:"id"`
	Kind     string `json:"kind"`
	Metadata struct {
		RuleID     string `json:"rule_id"`
		File       string `json:"file"`
		Line       int    `json:"line"`
		Capability string `json:"capability"`
		Provider   string `json:"provider"`
		Mode       string `json:"mode"`
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
	export := fs.String("export", "", "your copy of the scanned third-party export: the directory or file the scan read")
	name := fs.String("name", "", "the native secret to create, for example payments/slack-bot-token")
	gitleaksBin := fs.String("gitleaks-bin", "", "the pinned gitleaks binary (default: TRSTCTL_GITLEAKS_BIN, tools/bin/gitleaks, PATH)")
	if err := fs.Parse(args[1:]); err != nil {
		return 2
	}
	if (*repo == "") == (*export == "") || strings.TrimSpace(*name) == "" {
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
	thirdParty := finding.Metadata.Capability == thirdPartyCapability
	switch {
	case thirdParty && finding.Metadata.Mode == "collected":
		return fail("finding %s was collected from %s by trstctl, so there is no export of it to re-find the value in; rotate it at its issuer and store the new value as a native secret", findingID, finding.Metadata.Provider)
	case thirdParty && *export == "":
		return fail("finding %s is from a %s export: name your copy of that export with --export", findingID, finding.Metadata.Provider)
	case !thirdParty && *repo == "":
		return fail("finding %s is from a repository scan: name your checkout with --repo", findingID)
	}
	want := secretscan.SecretLocation{RuleID: finding.Metadata.RuleID, File: finding.Metadata.File, Line: finding.Metadata.Line}
	runner := secretscan.NewGitleaksRunner(*gitleaksBin)
	var (
		value   []byte
		residue []secretscan.SecretLocation
		where   = *repo
	)
	if thirdParty {
		// P6-L7: the export holds the value; it has no history residue.
		where = *export
		runner.AllowedRoots = []string{exportRoot(*export)}
		value, err = runner.LocateSecretInExport(ctx, *export, want)
	} else {
		runner.AllowedRoots = []string{*repo}
		value, residue, err = runner.LocateSecretForMove(ctx, *repo, want)
	}
	if err != nil {
		if errors.Is(err, secretscan.ErrSecretNotLocated) && thirdParty {
			return fail("%s:%d holds no %s value in %s: use a copy of the export the scan read", finding.Metadata.File, finding.Metadata.Line, finding.Metadata.RuleID, where)
		}
		if errors.Is(err, secretscan.ErrSecretNotLocated) {
			return fail("%s:%d holds no %s value in %s: check out the commit the scan saw", finding.Metadata.File, finding.Metadata.Line, finding.Metadata.RuleID, where)
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
	if thirdParty {
		_, _ = fmt.Fprintf(stdout, "next:      rotate the value at its issuer, store the new one (trstctl secrets store update %s -f new.json) and remove it at %s; the finding closes when a consumer reads the new version and a scan of a new export no longer sees the leak\n", *name, finding.Metadata.Provider)
		return 0
	}
	_, _ = fmt.Fprintf(stdout, "next:      rotate the value at its issuer, store the new one (trstctl secrets store update %s -f new.json), remove it from %s and commit; the finding closes when a consumer reads the new version and a scan no longer sees the leak\n", *name, finding.Metadata.File)
	return 0
}

// exportRoot is the directory an export path confines the locate to: the
// export directory, or the directory holding an export file.
func exportRoot(export string) string {
	if info, err := os.Stat(export); err == nil && !info.IsDir() {
		return filepath.Dir(export)
	}
	return export
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
	body := slices.Concat([]byte(`{"name":`), quotedName, []byte(`,"value":`), quotedValue, []byte{'}'})
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
