// SPDX-License-Identifier: BUSL-1.1

package secretscan

import (
	"bytes"
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	boundarycrypto "trstctl.com/trstctl/internal/crypto"
)

const (
	// GitleaksPinnedVersion is the scanner version trstctl validates and documents
	// for the served secret-scan bridge. The binary does the detection; this package
	// only invokes it and parses the redacted report metadata.
	GitleaksPinnedVersion = "v8.27.2"
	// GitleaksDefaultRulesActive is the number of rules in the pinned version's
	// embedded default gitleaks.toml. It gives the served API an auditable floor for
	// "the real default scanner is active" without importing the scanner library.
	GitleaksDefaultRulesActive = 213
	GitleaksMinRulesActive     = 140
)

var (
	ErrGitleaksBinaryNotFound = errors.New("secretscan: gitleaks binary not found")
	ErrInvalidScanTarget      = errors.New("secretscan: invalid scan target")
	ErrInvalidScanMode        = errors.New("secretscan: invalid scan mode")
	ErrInvalidCustomRules     = errors.New("secretscan: invalid custom rules")
)

const (
	ScanModeWorkspace  = "workspace"
	ScanModeGitHistory = "git_history"
)

// ScanOptions controls the Gitleaks execution mode. Workspace scans inspect the
// current filesystem; git_history scans every reachable commit in a local Git repo.
type ScanOptions struct {
	Mode            string
	CustomRulesPath string
}

// Report is the redacted metadata returned by a Gitleaks run.
type Report struct {
	Scanner       string
	EngineVersion string
	RulesActive   int
	Mode          string
	CustomRules   bool
	Capabilities  []string
	Findings      []Finding
}

// Plan is the effect-free, filesystem-validated description of one future
// Gitleaks run. It contains configuration metadata only. Building it never
// starts Git, Gitleaks, or any other process and never creates a report/config
// file, which makes it safe to expose through an authenticated review route.
type Plan struct {
	TargetPath        string
	TargetRoot        string
	Mode              string
	CustomRulesPath   string
	CustomRulesSHA256 string
	CustomRules       bool
	RulesActive       int
	Capabilities      []string
}

// GitleaksRunner invokes the pinned Gitleaks CLI as a subprocess.
type GitleaksRunner struct {
	Binary             string
	Timeout            time.Duration
	MaxTargetMegabytes int
	// AllowedRoots confines every served scan target and custom-rules file to
	// operator-approved filesystem trees. Empty means the process working
	// directory, which keeps the default fail-closed without breaking local CLI
	// use from a repository checkout.
	AllowedRoots        []string
	rulesActiveOverride int
}

// NewGitleaksRunner returns a runner. An empty binary resolves from
// TRSTCTL_GITLEAKS_BIN, tools/bin/gitleaks, then PATH at scan time.
func NewGitleaksRunner(binary string) *GitleaksRunner {
	return &GitleaksRunner{Binary: strings.TrimSpace(binary), Timeout: 2 * time.Minute, MaxTargetMegabytes: 50, AllowedRoots: []string{"."}}
}

// Scan runs the default workspace scan for compatibility with older embedders.
func (r *GitleaksRunner) Scan(ctx context.Context, target string) (Report, error) {
	return r.ScanWithOptions(ctx, target, ScanOptions{})
}

// Plan validates the exact target, confinement boundary, mode, scanner binary,
// and additive custom rules without starting a process or writing a file.
func (r *GitleaksRunner) Plan(target string, opts ScanOptions) (Plan, error) {
	mode, err := NormalizeScanMode(opts.Mode)
	if err != nil {
		return Plan{}, err
	}
	targetPath, targetRoot, err := normalizeTarget(target, r.AllowedRoots)
	if err != nil {
		return Plan{}, err
	}
	if mode == ScanModeGitHistory {
		root, err := gitRootWithoutProcess(targetPath)
		if err != nil {
			return Plan{}, err
		}
		root, err = resolveAllowedPath(root, r.AllowedRoots)
		if err != nil {
			return Plan{}, fmt.Errorf("%w: repository root is outside the configured scan roots", ErrInvalidScanTarget)
		}
		targetPath, targetRoot = root, root
	}
	if _, err := r.resolveBinary(); err != nil {
		return Plan{}, err
	}
	rulesActive := GitleaksDefaultRulesActive
	customRulesPath := ""
	customRulesSHA256 := ""
	if strings.TrimSpace(opts.CustomRulesPath) != "" {
		var data []byte
		customRulesPath, data, err = loadCustomRulesFragment(opts.CustomRulesPath, r.AllowedRoots)
		if err != nil {
			return Plan{}, err
		}
		rulesActive += countCustomRuleTables(data)
		digest, digestErr := boundarycrypto.Digest(boundarycrypto.SHA256, data)
		if digestErr != nil {
			return Plan{}, fmt.Errorf("secretscan: digest custom rules: %w", digestErr)
		}
		customRulesSHA256 = hex.EncodeToString(digest)
	}
	return Plan{
		TargetPath: targetPath, TargetRoot: targetRoot, Mode: mode,
		CustomRulesPath: customRulesPath, CustomRulesSHA256: customRulesSHA256, CustomRules: customRulesPath != "",
		RulesActive: rulesActive, Capabilities: ScanCapabilities(mode, customRulesPath != ""),
	}, nil
}

// ScanWithOptions runs gitleaks against a directory, file, or full Git history. The
// command is executed without a shell, with a report path outside the target tree,
// and with full secret redaction.
func (r *GitleaksRunner) ScanWithOptions(ctx context.Context, target string, opts ScanOptions) (Report, error) {
	mode, err := NormalizeScanMode(opts.Mode)
	if err != nil {
		return Report{}, err
	}
	targetPath, targetRoot, err := normalizeTarget(target, r.AllowedRoots)
	if err != nil {
		return Report{}, err
	}
	if mode == ScanModeGitHistory {
		root, err := GitTopLevel(ctx, targetPath)
		if err != nil {
			return Report{}, fmt.Errorf("%w: git history scan requires a local repository: %v", ErrInvalidScanTarget, err)
		}
		targetPath = root
		targetRoot = root
	}
	bin, err := r.resolveBinary()
	if err != nil {
		return Report{}, err
	}
	timeout := r.Timeout
	if timeout <= 0 {
		timeout = 2 * time.Minute
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	report, err := os.CreateTemp("", "trstctl-gitleaks-*.json")
	if err != nil {
		return Report{}, fmt.Errorf("secretscan: create gitleaks report: %w", err)
	}
	reportPath := report.Name()
	_ = report.Close()
	defer func() { _ = os.Remove(reportPath) }()

	maxMB := r.MaxTargetMegabytes
	if maxMB <= 0 {
		maxMB = 50
	}
	configPath, configCleanup, err := prepareCustomRulesConfig(opts.CustomRulesPath, r.AllowedRoots)
	if err != nil {
		return Report{}, err
	}
	defer configCleanup()
	command := "dir"
	if mode == ScanModeGitHistory {
		command = "git"
	}
	args := []string{
		command,
		"--no-banner",
		"--redact",
		"--exit-code", "0",
		"--report-format", "json",
		"--report-path", reportPath,
		"--max-target-megabytes", fmt.Sprintf("%d", maxMB),
	}
	if configPath != "" {
		args = append(args, "--config", configPath)
	}
	if mode == ScanModeGitHistory {
		args = append(args, "--log-opts", "--all")
	}
	args = append(args, targetPath)
	cmd := exec.CommandContext(ctx, bin, args...) // #nosec G204 -- fixed git/gitleaks binaries over the operator's own repository (CWE-78)
	cmd.Dir = targetRoot
	cmd.Env = sanitizedGitleaksEnv(os.Environ())
	var stderr limitedBuffer
	cmd.Stdout = io.Discard
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		if ctx.Err() != nil {
			return Report{}, fmt.Errorf("secretscan: gitleaks timed out after %s", timeout)
		}
		return Report{}, fmt.Errorf("secretscan: gitleaks failed: %w%s", err, stderr.suffix())
	}
	data, err := os.ReadFile(reportPath) // #nosec G304 -- reads the report file this process asked gitleaks to write in its own tempdir (CWE-22)
	if err != nil {
		return Report{}, fmt.Errorf("secretscan: read gitleaks report: %w", err)
	}
	findings, err := ParseGitleaks(data)
	if err != nil {
		return Report{}, err
	}
	relativizeFindings(findings, targetRoot)
	rules := GitleaksDefaultRulesActive
	if configPath != "" {
		// A custom config replaces or extends the default rule set, so the default
		// count stops describing what ran. Reporting 213 alongside custom_rules:true
		// asserts a measurement that was never taken: an operator scanning with a
		// five-rule config gets evidence claiming 213 active rules, and rules_active
		// is documented as "an auditable floor for the real default scanner is
		// active". Count what the config actually declares instead.
		counted, err := countGitleaksRules(configPath)
		if err != nil {
			return Report{}, err
		}
		rules = counted
	}
	if r.rulesActiveOverride > 0 {
		rules = r.rulesActiveOverride
	}
	return Report{
		Scanner:       "gitleaks",
		EngineVersion: GitleaksPinnedVersion,
		RulesActive:   rules,
		Mode:          mode,
		CustomRules:   configPath != "",
		Capabilities:  ScanCapabilities(mode, configPath != ""),
		Findings:      findings,
	}, nil
}

// NormalizeScanMode accepts the wire values used by the API and CLI docs.
func NormalizeScanMode(raw string) (string, error) {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case "", ScanModeWorkspace:
		return ScanModeWorkspace, nil
	case ScanModeGitHistory, "history", "deep":
		return ScanModeGitHistory, nil
	default:
		return "", fmt.Errorf("%w: %s", ErrInvalidScanMode, raw)
	}
}

func prepareCustomRulesConfig(customRulesPath string, allowedRoots []string) (string, func(), error) {
	cleanup := func() {}
	customRulesPath = strings.TrimSpace(customRulesPath)
	if customRulesPath == "" {
		return "", cleanup, nil
	}
	_, data, err := loadCustomRulesFragment(customRulesPath, allowedRoots)
	if err != nil {
		return "", cleanup, err
	}
	cfg, err := os.CreateTemp("", "trstctl-gitleaks-config-*.toml")
	if err != nil {
		return "", cleanup, fmt.Errorf("secretscan: create gitleaks config: %w", err)
	}
	configPath := cfg.Name()
	cleanup = func() { _ = os.Remove(configPath) }
	_, writeErr := cfg.Write([]byte("[extend]\nuseDefault = true\n\n"))
	if writeErr == nil {
		_, writeErr = cfg.Write(data)
	}
	closeErr := cfg.Close()
	if writeErr != nil {
		cleanup()
		return "", func() {}, fmt.Errorf("secretscan: write gitleaks config: %w", writeErr)
	}
	if closeErr != nil {
		cleanup()
		return "", func() {}, fmt.Errorf("secretscan: close gitleaks config: %w", closeErr)
	}
	return configPath, cleanup, nil
}

func loadCustomRulesFragment(customRulesPath string, allowedRoots []string) (string, []byte, error) {
	abs, err := filepath.Abs(strings.TrimSpace(customRulesPath))
	if err != nil {
		return "", nil, fmt.Errorf("%w: %v", ErrInvalidCustomRules, err)
	}
	abs = filepath.Clean(abs)
	abs, err = resolveAllowedPath(abs, allowedRoots)
	if err != nil {
		return "", nil, fmt.Errorf("%w: custom rules path is outside the configured scan roots", ErrInvalidCustomRules)
	}
	info, err := os.Stat(abs)
	if err != nil {
		return "", nil, fmt.Errorf("%w: %v", ErrInvalidCustomRules, err)
	}
	if info.IsDir() {
		return "", nil, fmt.Errorf("%w: custom rules path must be a file", ErrInvalidCustomRules)
	}
	if info.Size() > 1<<20 {
		return "", nil, fmt.Errorf("%w: custom rules file is larger than 1 MiB", ErrInvalidCustomRules)
	}
	data, err := os.ReadFile(abs) // #nosec G304 -- path is resolved inside an operator-configured scan root
	if err != nil {
		return "", nil, fmt.Errorf("%w: %v", ErrInvalidCustomRules, err)
	}
	if err := validateCustomRulesFragment(data); err != nil {
		return "", nil, err
	}
	return abs, data, nil
}

func countCustomRuleTables(data []byte) int {
	rules := 0
	for _, line := range strings.Split(string(data), "\n") {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "[[rules]]") {
			rules++
		}
	}
	return rules
}

func gitRootWithoutProcess(target string) (string, error) {
	info, err := os.Stat(target)
	if err != nil {
		return "", fmt.Errorf("%w: %v", ErrInvalidScanTarget, err)
	}
	dir := target
	if !info.IsDir() {
		dir = filepath.Dir(target)
	}
	for {
		if gitInfo, statErr := os.Stat(filepath.Join(dir, ".git")); statErr == nil && (gitInfo.IsDir() || gitInfo.Mode().IsRegular()) {
			return dir, nil
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			return "", fmt.Errorf("%w: git history scan requires a local repository", ErrInvalidScanTarget)
		}
		dir = parent
	}
}

func validateCustomRulesFragment(data []byte) error {
	lower := strings.ToLower(string(data))
	for _, blocked := range []string{"[extend]", "allowlist", "disabledrules"} {
		if strings.Contains(lower, blocked) {
			return fmt.Errorf("%w: custom rules may add rules but may not extend, allowlist, or disable defaults", ErrInvalidCustomRules)
		}
	}
	if !strings.Contains(lower, "[[rules]]") {
		return fmt.Errorf("%w: custom rules must contain at least one [[rules]] block", ErrInvalidCustomRules)
	}
	return nil
}

func ScanCapabilities(mode string, customRules bool) []string {
	caps := []string{"pattern-rules", "entropy-rules", "default-rules-100-plus"}
	if mode == ScanModeGitHistory {
		caps = append(caps, "full-git-history")
	} else {
		caps = append(caps, "workspace")
	}
	if customRules {
		caps = append(caps, "custom-rules")
	}
	return caps
}

func (r *GitleaksRunner) resolveBinary() (string, error) {
	candidates := []string{r.Binary, os.Getenv("TRSTCTL_GITLEAKS_BIN"), filepath.Join("tools", "bin", "gitleaks")}
	for _, candidate := range candidates {
		if candidate == "" {
			continue
		}
		if filepath.IsAbs(candidate) || strings.ContainsRune(candidate, filepath.Separator) {
			if info, err := os.Stat(candidate); err == nil && !info.IsDir() { // #nosec G703 -- locates the pinned gitleaks binary in known tool dirs (CWE-22)
				return candidate, nil
			}
			continue
		}
		if path, err := exec.LookPath(candidate); err == nil {
			return path, nil
		}
	}
	if path, err := exec.LookPath("gitleaks"); err == nil {
		return path, nil
	}
	return "", ErrGitleaksBinaryNotFound
}

func normalizeTarget(target string, allowedRoots []string) (targetPath string, root string, err error) {
	target = strings.TrimSpace(target)
	if target == "" {
		return "", "", fmt.Errorf("%w: path is required", ErrInvalidScanTarget)
	}
	abs, err := filepath.Abs(target)
	if err != nil {
		return "", "", fmt.Errorf("%w: %v", ErrInvalidScanTarget, err)
	}
	abs = filepath.Clean(abs)
	abs, err = resolveAllowedPath(abs, allowedRoots)
	if err != nil {
		return "", "", fmt.Errorf("%w: path is outside the configured scan roots", ErrInvalidScanTarget)
	}
	info, err := os.Stat(abs)
	if err != nil {
		return "", "", fmt.Errorf("%w: %v", ErrInvalidScanTarget, err)
	}
	root = abs
	if !info.IsDir() {
		root = filepath.Dir(abs)
	}
	return abs, root, nil
}

func resolveAllowedPath(path string, allowedRoots []string) (string, error) {
	resolvedPath, err := filepath.EvalSymlinks(path)
	if err != nil {
		return "", err
	}
	if len(allowedRoots) == 0 {
		allowedRoots = []string{"."}
	}
	for _, configuredRoot := range allowedRoots {
		configuredRoot = strings.TrimSpace(configuredRoot)
		if configuredRoot == "" {
			continue
		}
		root, err := filepath.Abs(configuredRoot)
		if err != nil {
			continue
		}
		root, err = filepath.EvalSymlinks(root)
		if err != nil {
			continue
		}
		rel, err := filepath.Rel(root, resolvedPath)
		if err == nil && rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator)) && !filepath.IsAbs(rel) {
			return resolvedPath, nil
		}
	}
	return "", errors.New("path is outside configured roots")
}

func relativizeFindings(findings []Finding, root string) {
	for i := range findings {
		file := filepath.Clean(findings[i].File)
		if rel, err := filepath.Rel(root, file); err == nil && rel != "." && !strings.HasPrefix(rel, ".."+string(filepath.Separator)) && rel != ".." {
			file = filepath.ToSlash(rel)
		}
		findings[i].File = file
		findings[i].CredentialRef = findings[i].RuleID + "@" + file
	}
}

func sanitizedGitleaksEnv(env []string) []string {
	out := make([]string, 0, len(env)+3)
	for _, kv := range env {
		if strings.HasPrefix(kv, "GITLEAKS_CONFIG=") || strings.HasPrefix(kv, "GITLEAKS_CONFIG_TOML=") {
			continue
		}
		out = append(out, kv)
	}
	out = append(out, "NO_COLOR=1", "GITLEAKS_NO_UPDATE_CHECK=true")
	return out
}

type limitedBuffer struct{ bytes.Buffer }

func (b *limitedBuffer) Write(p []byte) (int, error) {
	if b.Len() < 4096 {
		_, _ = b.Buffer.Write(p[:min(len(p), 4096-b.Len())])
	}
	return len(p), nil
}

func (b *limitedBuffer) suffix() string {
	msg := strings.TrimSpace(b.String())
	if msg == "" {
		return ""
	}
	return ": " + msg
}

// countGitleaksRules reports how many rules a gitleaks config actually activates.
//
// It counts [[rules]] tables and adds the pinned default count when the config
// extends the defaults ([extend] useDefault = true), which is how a gitleaks
// config layers on top of the built-in set.
//
// This scans lines rather than parsing TOML. That is a deliberate trade: the
// package has no TOML dependency, and the two constructs it needs — a [[rules]]
// table header and a useDefault key — are unambiguous at the start of a line.
// Getting the count slightly wrong for an exotic config is a much smaller problem
// than reporting a number that describes a rule set which never ran.
func countGitleaksRules(configPath string) (int, error) {
	body, err := os.ReadFile(configPath) // #nosec G304 -- the operator's own scanner config, already validated as a path this process was told to use (CWE-22)
	if err != nil {
		return 0, fmt.Errorf("secretscan: read gitleaks config to count active rules: %w", err)
	}
	rules, extendsDefault := 0, false
	for _, line := range strings.Split(string(body), "\n") {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "#") {
			continue
		}
		if strings.HasPrefix(trimmed, "[[rules]]") {
			rules++
			continue
		}
		if strings.HasPrefix(trimmed, "useDefault") && strings.Contains(trimmed, "true") {
			extendsDefault = true
		}
	}
	if extendsDefault {
		rules += GitleaksDefaultRulesActive
	}
	return rules, nil
}
