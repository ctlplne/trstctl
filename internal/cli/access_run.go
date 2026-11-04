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
	"os/exec"
	"strings"
	"time"

	"trstctl.com/trstctl/internal/auditsink"
	"trstctl.com/trstctl/internal/crypto/secret"
	"trstctl.com/trstctl/internal/secretjson"
	"trstctl.com/trstctl/internal/secretscli"
)

// `trstctl-cli access run` (A251): mint a run's credential under the caller's
// own live grants of the named access bundles, run a command with it as
// TRSTCTL_TOKEN, and revoke the run when the command exits. The caller's own
// token never reaches the child, and the run's token is held as bytes and
// wiped.

type accessRunFlags []string

func (f *accessRunFlags) String() string { return strings.Join(*f, ",") }

func (f *accessRunFlags) Set(value string) error {
	value = strings.TrimSpace(value)
	if value == "" {
		return errors.New("value must not be empty")
	}
	*f = append(*f, value)
	return nil
}

func accessRunUsage(w io.Writer) {
	_, _ = fmt.Fprintln(w, "Usage: trstctl access run --bundle NAME_OR_ID [--bundle ...] [--permission P ...] [--ttl 10m] [--label TEXT] [--keep] -- <cmd> [args]")
	_, _ = fmt.Fprintln(w, "\nMints a short-lived run credential under your live grants of the bundles, runs the command with it as TRSTCTL_TOKEN")
	_, _ = fmt.Fprintln(w, "(your own token is not passed on), and revokes the run when the command exits unless --keep is given.")
	_, _ = fmt.Fprintln(w, "\nExample: trstctl access run --bundle deploy --ttl 10m --label \"job 42\" -- ./deploy.sh")
}

func runAccessRun(ctx context.Context, args []string, env Env, stdin io.Reader, stdout, stderr io.Writer, server, token, tenant, caFile string) int {
	fs := flag.NewFlagSet("trstctl-cli access run", flag.ContinueOnError)
	fs.SetOutput(stderr)
	var bundles, permissions accessRunFlags
	fs.Var(&bundles, "bundle", "access bundle name or ID (repeatable)")
	fs.Var(&permissions, "permission", "narrow the run to this permission (repeatable; default: every permission the bundles give)")
	ttl := fs.Duration("ttl", 0, "run lifetime (default: 15 minutes, or the bundles' ceiling if shorter)")
	label := fs.String("label", "", "a label for activity search, such as a CI job ID")
	keep := fs.Bool("keep", false, "leave the run active when the command exits (it still expires)")
	fs.Usage = func() { accessRunUsage(stderr) }
	if err := fs.Parse(args); err != nil {
		return 2
	}
	argv := fs.Args()
	if len(argv) == 0 || len(bundles) == 0 {
		accessRunUsage(stderr)
		return 2
	}
	if server == "" {
		_, _ = fmt.Fprintln(stderr, "error: --server (or TRSTCTL_SERVER) is required")
		return 2
	}
	if *ttl < 0 || (*ttl > 0 && *ttl%time.Second != 0) {
		_, _ = fmt.Fprintln(stderr, "error: --ttl must be a whole number of seconds")
		return 2
	}
	httpClient, err := httpClientForEnv(env, caFile)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "error: CA file: %v\n", err)
		return 2
	}
	ids, err := resolveAccessBundleIDs(ctx, httpClient, server, token, tenant, bundles)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "error: %v\n", err)
		return 1
	}
	request, err := json.Marshal(map[string]any{
		"bundle_ids": ids, "permissions": []string(permissions), "ttl_seconds": int(ttl.Seconds()), "label": *label,
	})
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "error: %v\n", err)
		return 1
	}
	status, body, err := do(ctx, httpClient, server, http.MethodPost, "/api/v1/access/runs", nil, request, token, tenant, generateIdempotencyKey(), "")
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "error: mint run: %v\n", err)
		return 1
	}
	var issued struct {
		Run struct {
			ID        string    `json:"id"`
			ExpiresAt time.Time `json:"expires_at"`
		} `json:"run"`
		Token secretjson.StringBytes `json:"token"`
	}
	decodeErr := json.Unmarshal(body, &issued)
	if status != http.StatusCreated || decodeErr != nil || issued.Run.ID == "" || len(issued.Token) == 0 {
		secret.Wipe(issued.Token)
		_, _ = fmt.Fprintf(stderr, "error: mint run: status %d: %s\n", status, problemDetail(body))
		secret.Wipe(body)
		return 1
	}
	secret.Wipe(body)
	runToken := []byte(issued.Token)
	defer secret.Wipe(runToken)
	_, _ = fmt.Fprintf(stderr, "access run %s until %s\n", issued.Run.ID, issued.Run.ExpiresAt.UTC().Format(time.RFC3339))

	injected := map[string][]byte{"TRSTCTL_TOKEN": runToken, "TRSTCTL_SERVER": []byte(server)}
	if caFile != "" {
		injected["TRSTCTL_CA_FILE"] = []byte(caFile)
	}
	runErr := secretscli.New(tenant, nil, auditsink.Nop{}).InjectIO(ctx, injected, argv, stdin, stdout, stderr)
	exitCode := 0
	if runErr != nil {
		var exitErr *exec.ExitError
		if errors.As(runErr, &exitErr) {
			exitCode = exitErr.ExitCode()
		} else {
			_, _ = fmt.Fprintf(stderr, "error: %v\n", runErr)
			exitCode = 1
		}
	}
	if !*keep {
		status, body, err := do(context.WithoutCancel(ctx), httpClient, server, http.MethodPost,
			"/api/v1/access/runs/"+issued.Run.ID+"/revoke", nil, nil, token, tenant, generateIdempotencyKey(), "")
		switch {
		case err != nil:
			_, _ = fmt.Fprintf(stderr, "warning: revoke run %s: %v (it expires at %s)\n", issued.Run.ID, err, issued.Run.ExpiresAt.UTC().Format(time.RFC3339))
		case status != http.StatusOK:
			_, _ = fmt.Fprintf(stderr, "warning: revoke run %s: status %d: %s (it expires at %s)\n", issued.Run.ID, status, problemDetail(body),
				issued.Run.ExpiresAt.UTC().Format(time.RFC3339))
		default:
			_, _ = fmt.Fprintf(stderr, "access run %s revoked\n", issued.Run.ID)
		}
	}
	return exitCode
}

// resolveAccessBundleIDs turns bundle names into IDs through the bundle list;
// an argument that is already an ID of a listed bundle passes through.
func resolveAccessBundleIDs(ctx context.Context, client *http.Client, server, token, tenant string, refs []string) ([]string, error) {
	status, body, err := do(ctx, client, server, http.MethodGet, "/api/v1/access/bundles", nil, nil, token, tenant, "", "")
	if err != nil {
		return nil, fmt.Errorf("list access bundles: %w", err)
	}
	if status != http.StatusOK {
		return nil, fmt.Errorf("list access bundles: status %d: %s", status, problemDetail(body))
	}
	var list struct {
		Items []struct {
			ID   string `json:"id"`
			Name string `json:"name"`
		} `json:"items"`
	}
	if err := json.Unmarshal(body, &list); err != nil {
		return nil, fmt.Errorf("list access bundles: %w", err)
	}
	out := make([]string, 0, len(refs))
	for _, ref := range refs {
		found := ""
		for _, b := range list.Items {
			if b.ID == ref || strings.EqualFold(b.Name, ref) {
				found = b.ID
				break
			}
		}
		if found == "" {
			return nil, fmt.Errorf("no live access bundle named %q", ref)
		}
		out = append(out, found)
	}
	return out, nil
}

// problemDetail is a problem+json response's detail (or title), for messages.
func problemDetail(body []byte) string {
	var p struct {
		Title  string `json:"title"`
		Detail string `json:"detail"`
	}
	if json.Unmarshal(body, &p) == nil {
		if p.Detail != "" {
			return p.Detail
		}
		if p.Title != "" {
			return p.Title
		}
	}
	return "no detail"
}
