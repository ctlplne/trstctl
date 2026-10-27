// SPDX-License-Identifier: BUSL-1.1

package evaluate

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"

	"trstctl.com/trstctl/internal/crypto/jose"
	"trstctl.com/trstctl/internal/crypto/mtls"
	"trstctl.com/trstctl/internal/netsec"
	"trstctl.com/trstctl/internal/signing"
)

// ExitError carries the command's exit code: 0 the journey passed, 1 it failed
// or a pack did not verify, 2 the command could not run.
type ExitError struct{ Code int }

func (e ExitError) Error() string { return fmt.Sprintf("evaluate: exit %d", e.Code) }

func usage(w io.Writer) {
	_, _ = fmt.Fprintln(w, "Usage: trstctl evaluate --server <url> --deployment-target <id> [--endpoint host:port] [--name dns-name]")
	_, _ = fmt.Fprintln(w, "                        [--owner name] [--profile name] [--timeout 10m] [--out evaluation-pack.json]")
	_, _ = fmt.Fprintln(w, "                        [--ca-file file] [--token-file file] [--sign --signer-socket path]")
	_, _ = fmt.Fprintln(w, "       trstctl evaluate verify --pack <file> --audit-jwks <file>")
	_, _ = fmt.Fprintln(w, "\nRuns one certificate journey against the endpoint your deployment target serves: discovery, ownership,")
	_, _ = fmt.Fprintln(w, "issuance, deployment, verification from this machine, renewal, revocation checked over OCSP, and a signed")
	_, _ = fmt.Fprintln(w, "audit export. Writes an evidence pack with each step's outcome, a pass/fail verdict and its limits. The")
	_, _ = fmt.Fprintln(w, "API token comes from $TRSTCTL_TOKEN or --token-file, never the command line. --sign signs the pack with")
	_, _ = fmt.Fprintln(w, "the deployment's audit-evidence key through the signer socket. Exit 0: passed; 1: failed; 2: could not run.")
}

// Run is the `trstctl evaluate` command.
func Run(ctx context.Context, args []string, getenv func(string) string, stdout, stderr io.Writer) error {
	if len(args) > 0 && args[0] == "verify" {
		return runVerify(args[1:], stdout, stderr)
	}
	fs := flag.NewFlagSet("trstctl evaluate", flag.ContinueOnError)
	fs.SetOutput(stderr)
	fs.Usage = func() { usage(stderr) }
	server := fs.String("server", getenv("TRSTCTL_SERVER"), "control-plane base URL (default $TRSTCTL_SERVER)")
	tokenFile := fs.String("token-file", "", "file holding the operator API token (default $TRSTCTL_TOKEN)")
	caFile := fs.String("ca-file", getenv("TRSTCTL_CA_FILE"), "PEM CA bundle for control-plane TLS (default $TRSTCTL_CA_FILE)")
	target := fs.String("deployment-target", "", "the connector target configured for the endpoint (required)")
	endpoint := fs.String("endpoint", "", "host:port to evaluate (default the target's verify_address)")
	name := fs.String("name", "", "DNS name clients use (default the target's verify_server_name)")
	owner := fs.String("owner", "design-partner-evaluation", "owner of the issued identity, created when missing")
	profile := fs.String("profile", "", "certificate profile to issue under")
	timeout := fs.Duration("timeout", 10*time.Minute, "longest wait for any one step")
	out := fs.String("out", "evaluation-pack.json", "where to write the evidence pack")
	sign := fs.Bool("sign", false, "sign the pack with the deployment's audit-evidence key")
	signerSocket := fs.String("signer-socket", getenv("TRSTCTL_SIGNER_SOCKET"), "the signer's Unix socket; required by --sign")
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return nil
		}
		return ExitError{2}
	}
	token := strings.TrimSpace(getenv("TRSTCTL_TOKEN"))
	if *tokenFile != "" {
		raw, err := os.ReadFile(*tokenFile) // #nosec G304 -- operator-named token file (CWE-22)
		if err != nil {
			_, _ = fmt.Fprintf(stderr, "evaluate: read token: %v\n", err)
			return ExitError{2}
		}
		token = strings.TrimSpace(string(raw))
	}
	if *server == "" || token == "" || *target == "" {
		_, _ = fmt.Fprintln(stderr, "evaluate: --server (or $TRSTCTL_SERVER), an API token ($TRSTCTL_TOKEN or --token-file) and --deployment-target are required")
		return ExitError{2}
	}
	if *sign && *signerSocket == "" {
		_, _ = fmt.Fprintln(stderr, "evaluate: --sign requires --signer-socket or $TRSTCTL_SIGNER_SOCKET; private audit keys are never loaded by evaluate")
		return ExitError{2}
	}
	client, err := httpClient(*caFile)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "evaluate: %v\n", err)
		return ExitError{2}
	}
	pack, err := Evaluate(ctx, Options{Server: *server, Token: token, HTTPClient: client, DeploymentTarget: *target,
		Endpoint: *endpoint, Name: *name, Owner: *owner, Profile: *profile, Timeout: *timeout})
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "%v\n", err)
		return ExitError{2}
	}
	if *sign {
		if err := signPack(ctx, &pack, *signerSocket); err != nil {
			_, _ = fmt.Fprintf(stderr, "evaluate: %v\n", err)
			return ExitError{2}
		}
	}
	raw, err := json.MarshalIndent(pack, "", "  ")
	if err != nil {
		return err
	}
	if err := os.WriteFile(*out, append(raw, '\n'), 0o600); err != nil {
		_, _ = fmt.Fprintf(stderr, "evaluate: write pack: %v\n", err)
		return ExitError{2}
	}
	report(stdout, pack)
	_, _ = fmt.Fprintf(stdout, "\nEvidence pack written to %s", *out)
	if pack.Signature == nil {
		_, _ = fmt.Fprint(stdout, " (unsigned; pass --sign to sign it)")
	}
	_, _ = fmt.Fprintln(stdout)
	if pack.Verdict != StatusPass {
		return ExitError{1}
	}
	return nil
}

func httpClient(caFile string) (*http.Client, error) {
	if caFile == "" {
		return netsec.HardenedClient(60 * time.Second), nil
	}
	caPEM, err := os.ReadFile(caFile) // #nosec G304 -- the operator names the public trust-bundle path (CWE-22)
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", caFile, err)
	}
	transport, err := mtls.HTTPTransport(caPEM)
	if err != nil {
		return nil, err
	}
	return netsec.ClientFor(transport, 60*time.Second, nil), nil
}

func signPack(ctx context.Context, p *Pack, signerSocket string) error {
	client, err := signing.DialReady(ctx, signerSocket, 10*time.Second)
	if err != nil {
		return fmt.Errorf("connect signer: %w", err)
	}
	defer func() { _ = client.Close() }()
	remote, err := client.SignerForHandleWithPurpose(ctx, "audit-export", signing.PurposeAuditEvidence)
	if err != nil {
		return fmt.Errorf("bind audit-export signer handle: %w", err)
	}
	key, err := jose.NewDigestSigningKey("audit-export", remote)
	if err != nil {
		return fmt.Errorf("wrap audit-export signer handle: %w", err)
	}
	return Sign(p, key, "audit-export")
}

func report(w io.Writer, p Pack) {
	_, _ = fmt.Fprintf(w, "trstctl evaluate: %s at %s (%s)\n", p.Target.Name, p.Target.Endpoint, p.Server)
	for _, s := range p.Steps {
		_, _ = fmt.Fprintf(w, "  %-8s %-13s %s\n", strings.ToUpper(string(s.Status)), s.Name, s.Detail)
	}
	_, _ = fmt.Fprintf(w, "Verdict: %s (%d passed, %d failed, %d skipped)\n", strings.ToUpper(string(p.Verdict)), p.Summary.Passed, p.Summary.Failed, p.Summary.Skipped)
}

func runVerify(args []string, stdout, stderr io.Writer) error {
	fs := flag.NewFlagSet("trstctl evaluate verify", flag.ContinueOnError)
	fs.SetOutput(stderr)
	packFile := fs.String("pack", "", "an evidence pack written by trstctl evaluate --sign")
	jwksFile := fs.String("audit-jwks", "", "the audit evidence public JWK set you pinned separately")
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return nil
		}
		return ExitError{2}
	}
	if *packFile == "" || *jwksFile == "" {
		_, _ = fmt.Fprintln(stderr, "evaluate verify: --pack and --audit-jwks are required")
		return ExitError{2}
	}
	document, err := os.ReadFile(*packFile) // #nosec G304 -- operator-named local file (CWE-22)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "evaluate verify: %v\n", err)
		return ExitError{2}
	}
	jwks, err := os.ReadFile(*jwksFile) // #nosec G304 -- operator-named local file (CWE-22)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "evaluate verify: %v\n", err)
		return ExitError{2}
	}
	keys, err := jose.ParseJWKSet(jwks)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "evaluate verify: parse audit JWK set: %v\n", err)
		return ExitError{2}
	}
	pack, kid, err := Verify(document, keys)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "evaluate verify: %v\n", err)
		return ExitError{1}
	}
	if err := VerifyAuditExport(pack, keys); err != nil {
		_, _ = fmt.Fprintf(stderr, "evaluate verify: %v\n", err)
		return ExitError{1}
	}
	_, _ = fmt.Fprintf(stdout, "verified: evaluation pack signed by key %s, generated %s\n", kid, pack.GeneratedAt.UTC().Format(time.RFC3339))
	report(stdout, pack)
	return nil
}
