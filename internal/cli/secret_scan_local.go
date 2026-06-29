package cli

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"trstctl.com/trstctl/internal/secretscan"
)

type localSecretScanFinding struct {
	RuleID        string `json:"rule_id"`
	File          string `json:"file"`
	Line          int    `json:"line"`
	CredentialRef string `json:"credential_ref"`
}

type localSecretScanResponse struct {
	Capability    string                   `json:"capability"`
	Mode          string                   `json:"mode"`
	Repository    string                   `json:"repository"`
	FilesScanned  int                      `json:"files_scanned"`
	Files         []string                 `json:"files"`
	Scanner       string                   `json:"scanner"`
	EngineVersion string                   `json:"engine_version"`
	RulesActive   int                      `json:"rules_active"`
	FindingsCount int                      `json:"findings_count"`
	Findings      []localSecretScanFinding `json:"findings"`
}

type preCommitInstallResponse struct {
	Capability string `json:"capability"`
	Installed  bool   `json:"installed"`
	HookPath   string `json:"hook_path"`
	Command    string `json:"command"`
}

func runSecretScanStagedDiff(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("trstctl secrets scans staged-diff", flag.ContinueOnError)
	fs.SetOutput(stderr)
	repo := fs.String("repo", ".", "git repository path")
	base := fs.String("base", "", "base ref for CI diff scans")
	head := fs.String("head", "", "head ref for CI diff scans")
	gitleaksBin := fs.String("gitleaks-bin", "", "path to the pinned Gitleaks binary")
	advisory := fs.Bool("advisory", false, "exit 0 even when findings are detected")
	fs.Usage = func() { secretScanStagedDiffUsage(stderr) }
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if fs.NArg() != 0 {
		_, _ = fmt.Fprintf(stderr, "error: unexpected argument(s): %s\n", strings.Join(fs.Args(), " "))
		return 2
	}
	target, err := secretscan.PrepareGitDiffTarget(ctx, secretscan.GitDiffConfig{Repo: *repo, Base: *base, Head: *head})
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "error: %v\n", err)
		return 1
	}
	defer target.Cleanup()
	report, err := secretscan.NewGitleaksRunner(*gitleaksBin).Scan(ctx, target.Path)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "error: %v\n", err)
		return 1
	}
	root, err := secretscan.GitTopLevel(ctx, *repo)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "error: %v\n", err)
		return 1
	}
	out := localSecretScanResponse{
		Capability:    "CAP-SCAN-02",
		Mode:          target.Mode,
		Repository:    root,
		FilesScanned:  len(target.Files),
		Files:         target.Files,
		Scanner:       report.Scanner,
		EngineVersion: report.EngineVersion,
		RulesActive:   report.RulesActive,
		FindingsCount: len(report.Findings),
		Findings:      localFindings(report.Findings),
	}
	writeJSONValue(stdout, out)
	if len(report.Findings) > 0 && !*advisory {
		_, _ = fmt.Fprintf(stderr, "error: %d secret finding(s) detected in %s scan\n", len(report.Findings), target.Mode)
		return 1
	}
	return 0
}

func runSecretScanPreCommitInstall(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("trstctl secrets scans pre-commit install", flag.ContinueOnError)
	fs.SetOutput(stderr)
	repo := fs.String("repo", ".", "git repository path")
	command := fs.String("command", "trstctl-cli", "trstctl CLI command used by the hook")
	gitleaksBin := fs.String("gitleaks-bin", "", "path to the pinned Gitleaks binary")
	force := fs.Bool("force", false, "replace an existing pre-commit hook")
	fs.Usage = func() { secretScanPreCommitInstallUsage(stderr) }
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if fs.NArg() != 0 {
		_, _ = fmt.Fprintf(stderr, "error: unexpected argument(s): %s\n", strings.Join(fs.Args(), " "))
		return 2
	}
	root, err := secretscan.GitTopLevel(ctx, *repo)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "error: %v\n", err)
		return 1
	}
	hookPath, err := secretscan.GitPath(ctx, root, "hooks/pre-commit")
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "error: %v\n", err)
		return 1
	}
	if _, err := os.Stat(hookPath); err == nil && !*force {
		_, _ = fmt.Fprintf(stderr, "error: %s already exists; rerun with --force to replace it\n", hookPath)
		return 2
	} else if err != nil && !os.IsNotExist(err) {
		_, _ = fmt.Fprintf(stderr, "error: stat pre-commit hook: %v\n", err)
		return 1
	}
	if err := os.MkdirAll(filepath.Dir(hookPath), 0o700); err != nil {
		_, _ = fmt.Fprintf(stderr, "error: create hook directory: %v\n", err)
		return 1
	}
	hookCommand := hookScanCommand(*command, root, *gitleaksBin)
	script := "#!/bin/sh\nset -eu\nexec " + hookCommand + "\n"
	if err := os.WriteFile(hookPath, []byte(script), 0o755); err != nil {
		_, _ = fmt.Fprintf(stderr, "error: write pre-commit hook: %v\n", err)
		return 1
	}
	writeJSONValue(stdout, preCommitInstallResponse{
		Capability: "CAP-SCAN-02",
		Installed:  true,
		HookPath:   hookPath,
		Command:    hookCommand,
	})
	return 0
}

func localFindings(findings []secretscan.Finding) []localSecretScanFinding {
	out := make([]localSecretScanFinding, 0, len(findings))
	for _, finding := range findings {
		ref := finding.CredentialRef
		if ref == "" {
			ref = finding.RuleID + "@" + finding.File
		}
		out = append(out, localSecretScanFinding{
			RuleID:        finding.RuleID,
			File:          finding.File,
			Line:          finding.Line,
			CredentialRef: ref,
		})
	}
	return out
}

func writeJSONValue(w io.Writer, value any) {
	data, err := json.Marshal(value)
	if err != nil {
		_, _ = fmt.Fprintf(w, `{"error":%q}`+"\n", err.Error())
		return
	}
	writeJSON(w, data)
}

func hookScanCommand(command, repo, gitleaksBin string) string {
	parts := []string{shellQuote(command), "secrets", "scans", "staged-diff", "--repo", shellQuote(repo)}
	if strings.TrimSpace(gitleaksBin) != "" {
		parts = append(parts, "--gitleaks-bin", shellQuote(gitleaksBin))
	}
	return strings.Join(parts, " ")
}

func shellQuote(value string) string {
	return "'" + strings.ReplaceAll(value, "'", "'\"'\"'") + "'"
}

func secretScanStagedDiffUsage(w io.Writer) {
	_, _ = fmt.Fprintln(w, "Usage: trstctl secrets scans staged-diff [--repo path] [--base ref --head ref] [--gitleaks-bin path] [--advisory]")
	_, _ = fmt.Fprintln(w, "\nScans only staged Git blobs, or the Head-side files in a CI base/head diff, and prints redacted JSON findings.")
	_, _ = fmt.Fprintln(w, "\nExample: trstctl secrets scans staged-diff --repo .")
}

func secretScanPreCommitInstallUsage(w io.Writer) {
	_, _ = fmt.Fprintln(w, "Usage: trstctl secrets scans pre-commit install [--repo path] [--command trstctl-cli] [--gitleaks-bin path] [--force]")
	_, _ = fmt.Fprintln(w, "\nInstalls a Git pre-commit hook that blocks commits when the staged-diff scanner detects a secret.")
	_, _ = fmt.Fprintln(w, "\nExample: trstctl secrets scans pre-commit install --repo .")
}
