// SPDX-License-Identifier: MPL-2.0

// dodcensus proves that advertised capabilities are compiled into cmd/trstctl,
// assembled by buildRunDeps, and exercised through the resulting served handler.
// A package that only appears in a test can never satisfy the dependency tier.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"go/ast"
	"go/build"
	"go/parser"
	"go/token"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
)

const (
	enforcementPending  = "pending"
	enforcementRequired = "required"
	releasePlanned      = "planned"
	releaseShipped      = "shipped"

	statusServed      = "served"
	statusLibraryOnly = "library-only"
	statusStub        = "stub"
	statusUnknown     = "unknown"
)

var (
	errSelectionNoMatch = errors.New("selection matches no exact manifest entry")

	entryIDPattern     = regexp.MustCompile(`^[a-z0-9_]+(?:\.[a-z0-9_]+)+$`)
	capabilityPattern  = regexp.MustCompile(`^[a-z0-9_]+$`)
	testNamePattern    = regexp.MustCompile(`^TestDOD[A-Za-z0-9_]+$`)
	cardIDPattern      = regexp.MustCompile(`^[A-Z][A-Z0-9-]+$`)
	digestPattern      = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)
	receiptMACPattern  = regexp.MustCompile(`^hmac-sha256:[0-9a-f]{64}$`)
	pinnedImagePattern = regexp.MustCompile(`^[^[:space:]@]+@sha256:[0-9a-f]{64}$`)
	buildArgPattern    = regexp.MustCompile(`^[A-Z][A-Z0-9_]*$`)
)

// Manifest is the versioned, repo-owned list of product claims under the DoD gate.
type Manifest struct {
	SchemaVersion       int                     `json:"schema_version"`
	ManifestVersion     int                     `json:"manifest_version"`
	BinaryPackage       string                  `json:"binary_package"`
	DefaultBuildProfile string                  `json:"default_build_profile"`
	BuildProfiles       map[string]BuildProfile `json:"build_profiles"`
	Substrates          map[string]Substrate    `json:"substrates"`
	Entries             []Entry                 `json:"entries"`
}

// BuildProfile identifies one artifact shape. Release is deliberately explicit:
// a profile is either structurally tied to a published OCI image, or it is only a
// plan. A planned profile can never make a capability SERVED.
type BuildProfile struct {
	BinaryPackage      string             `json:"binary_package"`
	CGOEnabled         string             `json:"cgo_enabled"`
	GOOS               string             `json:"goos"`
	GOARCH             string             `json:"goarch"`
	Tags               []string           `json:"tags"`
	Release            string             `json:"release"`
	Artifact           ArtifactProof      `json:"artifact"`
	RuntimeRunner      RuntimeRunnerProof `json:"runtime_runner"`
	RuntimeEnv         map[string]string  `json:"-"`
	HostRuntime        bool               `json:"-"`
	RuntimeExecution   bool               `json:"-"`
	RuntimeRunnerImage string             `json:"-"`
	RuntimeScratchDir  string             `json:"-"`
	RuntimeBroker      *substrateBroker   `json:"-"`
}

// RuntimeRunnerProof pins the native execution environment used when the
// harness host cannot execute a shipped profile directly. IdentityFiles bind
// the Dockerfile and the exact Go module inputs copied into that image.
type RuntimeRunnerProof struct {
	Dockerfile    string   `json:"dockerfile"`
	Platform      string   `json:"platform"`
	Identity      string   `json:"identity"`
	IdentityFiles []string `json:"identity_files"`
}

// ArtifactProof binds a profile to the exact publishing step and exact executable
// inside the resulting OCI image. It is not a local Make target: local compilation
// does not prove that users receive those bytes.
type ArtifactProof struct {
	Workflow      string              `json:"workflow,omitempty"`
	Job           string              `json:"job,omitempty"`
	Dockerfile    string              `json:"dockerfile,omitempty"`
	BuilderAction string              `json:"builder_action,omitempty"`
	BuilderOutput string              `json:"builder_output,omitempty"`
	BuilderTags   string              `json:"builder_tags,omitempty"`
	BuildOutput   string              `json:"build_output,omitempty"`
	BinaryPath    string              `json:"binary_path,omitempty"`
	Platform      string              `json:"platform,omitempty"`
	Companions    []CompanionArtifact `json:"companions,omitempty"`
	BuildArgs     map[string]string   `json:"build_args,omitempty"`
}

// CompanionArtifact is a second executable required for the entrypoint binary
// to serve its advertised paths. The static control plane supervises the signer
// as a separate process, so proving only the entrypoint would prove a car with
// its engine omitted from the published image.
type CompanionArtifact struct {
	BinaryPackage string `json:"binary_package"`
	BuildOutput   string `json:"build_output"`
	BinaryPath    string `json:"binary_path"`
}

// Substrate is the closed set of non-in-process systems accepted by the runtime
// gate. Identity and contract pins prevent a test from silently swapping in an
// easier fake. ContractSHA256 is formatted as sha256:<lowercase hex>.
type Substrate struct {
	Kind           string   `json:"kind"`
	Verifier       string   `json:"verifier"`
	Execution      string   `json:"execution"`
	Command        []string `json:"command,omitempty"`
	CommandSHA256  string   `json:"command_sha256,omitempty"`
	IdentityFiles  []string `json:"identity_files,omitempty"`
	Image          string   `json:"image,omitempty"`
	Identity       string   `json:"identity"`
	ContractFile   string   `json:"contract_file"`
	ContractSHA256 string   `json:"contract_sha256"`
}

// Entry is one card-sized proof target. Inventory is explicit because docs count
// advertised backends, while registry/dispatch umbrella cards are not backends.
type Entry struct {
	ID           string        `json:"id"`
	CardID       string        `json:"card_id"`
	Capability   string        `json:"capability"`
	Inventory    *bool         `json:"inventory"`
	Enforcement  string        `json:"enforcement"`
	BuildProfile string        `json:"build_profile,omitempty"`
	Dependencies []string      `json:"dependencies"`
	Assembly     AssemblyProof `json:"assembly"`
	Runtime      RuntimeProof  `json:"runtime,omitempty"`
}

// AssemblyProof names exact production code. Calls are checked in the transitive
// same-package call graph rooted at Function, never by grepping a comment.
type AssemblyProof struct {
	File     string   `json:"file"`
	Function string   `json:"function"`
	Binding  string   `json:"binding,omitempty"`
	Field    string   `json:"field,omitempty"`
	Calls    []string `json:"calls"`
}

// RuntimeProof names a test which must directly pass buildRunDeps output to Build,
// use the resulting Handler, call the typed proof helper, execute, not skip, and
// emit the exact served receipt.
type RuntimeProof struct {
	Package     string `json:"package,omitempty"`
	Test        string `json:"test,omitempty"`
	File        string `json:"file,omitempty"`
	Mode        string `json:"mode,omitempty"`
	Method      string `json:"method,omitempty"`
	Path        string `json:"path,omitempty"`
	SubstrateID string `json:"substrate_id,omitempty"`
}

type checkEvidence struct {
	OK       bool     `json:"ok"`
	Detail   string   `json:"detail"`
	Required []string `json:"required,omitempty"`
	Found    []string `json:"found,omitempty"`
}

type entryEvidence struct {
	Artifact   checkEvidence `json:"artifact"`
	Dependency checkEvidence `json:"dependency"`
	Assembly   checkEvidence `json:"assembly"`
	Runtime    checkEvidence `json:"runtime"`
}

type entryResult struct {
	CardID       string        `json:"card_id"`
	Capability   string        `json:"capability"`
	Inventory    bool          `json:"inventory"`
	Enforcement  string        `json:"enforcement"`
	BuildProfile string        `json:"build_profile"`
	Status       string        `json:"status"`
	Evidence     entryEvidence `json:"evidence"`
}

type capabilityResult struct {
	Status    string   `json:"status"`
	Evidence  string   `json:"evidence"`
	Served    int      `json:"served"`
	Total     int      `json:"total"`
	Inventory int      `json:"inventory"`
	Required  int      `json:"required"`
	EntryIDs  []string `json:"entries"`
}

type reportSummary struct {
	Total           int `json:"total"`
	Served          int `json:"served"`
	LibraryOnly     int `json:"library_only"`
	Stub            int `json:"stub"`
	Unknown         int `json:"unknown"`
	Pending         int `json:"pending"`
	Required        int `json:"required"`
	RequiredFailed  int `json:"required_failed"`
	Inventory       int `json:"inventory"`
	InventoryServed int `json:"inventory_served"`
}

// Report contains both granular rows and conservative family aggregates. The
// top-level served/total fields retain the harness dashboard's aggregate schema.
type Report struct {
	SchemaVersion       int                         `json:"schema_version"`
	ManifestVersion     int                         `json:"manifest_version"`
	GeneratedAt         string                      `json:"generated_at"`
	Repo                string                      `json:"repo"`
	BinaryPackage       string                      `json:"binary_package"`
	DefaultBuildProfile string                      `json:"default_build_profile"`
	ToolchainOK         bool                        `json:"toolchain_available"`
	BuildProfiles       map[string]BuildProfile     `json:"build_profiles"`
	Served              int                         `json:"served"`
	Total               int                         `json:"total"`
	Summary             reportSummary               `json:"summary"`
	Entries             map[string]entryResult      `json:"entries"`
	Capabilities        map[string]capabilityResult `json:"capabilities"`
}

func (r Report) hasRequiredFailures() bool { return r.Summary.RequiredFailed > 0 }

type selection struct {
	Capability string
	CardID     string
}

type commandCall struct {
	Dir     string
	Profile BuildProfile
	Name    string
	Args    []string
}

type commandResult struct {
	Stdout   string
	Stderr   string
	ExitCode int
	Err      error
}

type commandRunner interface {
	Run(context.Context, string, BuildProfile, string, ...string) commandResult
}

type runtimeProfilePreparer interface {
	PrepareRuntime(context.Context, string, BuildProfile) (BuildProfile, error)
}

type substrateBrokerProvider interface {
	StartSubstrateBroker(string, string, bool) (*substrateBroker, error)
}

type osRunner struct {
	CacheDir    string
	LinuxRunner *linuxRuntimeExecutor
}

func (r osRunner) PrepareRuntime(ctx context.Context, repo string, profile BuildProfile) (BuildProfile, error) {
	if r.LinuxRunner == nil {
		return profile, fmt.Errorf("DoD runtime has no reviewed pinned Linux runner")
	}
	image, err := r.LinuxRunner.prepare(ctx, repo, profile)
	if err != nil {
		return profile, err
	}
	profile.RuntimeRunnerImage = image
	return profile, nil
}

func (r osRunner) StartSubstrateBroker(repo, receiptDir string, crossHost bool) (*substrateBroker, error) {
	return startSubstrateBroker(repo, receiptDir, crossHost)
}

func (r osRunner) Run(ctx context.Context, dir string, profile BuildProfile, name string, args ...string) commandResult {
	if err := validateDODGoInvocation(name, args); err != nil {
		return commandResult{Err: err, ExitCode: -1}
	}
	if profile.RuntimeExecution {
		if r.LinuxRunner == nil {
			return commandResult{Err: fmt.Errorf("DoD runtime has no reviewed pinned Linux runner"), ExitCode: -1}
		}
		if profile.RuntimeRunnerImage == "" {
			return commandResult{Err: fmt.Errorf("DoD runtime pinned Linux runner was not prepared"), ExitCode: -1}
		}
		return r.LinuxRunner.run(ctx, dir, r.CacheDir, profile, args)
	}
	if err := os.MkdirAll(r.CacheDir, 0o700); err != nil {
		return commandResult{Err: fmt.Errorf("create isolated Go cache: %w", err), ExitCode: -1}
	}
	cmd := exec.CommandContext(ctx, name, args...)
	cmd.Dir = dir
	cmd.Env = dodCommandEnvironment(os.Environ(), r.CacheDir, profile)
	var stdout, stderr strings.Builder
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	err := cmd.Run()
	result := commandResult{Stdout: stdout.String(), Stderr: stderr.String(), Err: err}
	if err != nil {
		result.ExitCode = -1
		var exitErr *exec.ExitError
		if errors.As(err, &exitErr) {
			result.ExitCode = exitErr.ExitCode()
		}
	}
	return result
}

// validateDODGoInvocation is the reviewed argv boundary for the census tool.
// The evaluator only needs two exact Go operations. Keeping their argv shapes
// closed prevents a future manifest or call-site change from smuggling in Go's
// process-launching flags such as -exec or -toolexec.
func validateDODGoInvocation(name string, args []string) error {
	if name != "go" || len(args) == 0 {
		return fmt.Errorf("DoD census only executes the go tool with a closed argv shape")
	}
	index := 1
	proofTagged := false
	if index < len(args) && strings.HasPrefix(args[index], "-tags=") {
		tags := strings.TrimPrefix(args[index], "-tags=")
		if tags == "" || strings.ContainsAny(tags, " \t\r\n\x00") {
			return fmt.Errorf("DoD census go tags are invalid")
		}
		for _, tag := range strings.Split(tags, ",") {
			if tag == "" || !capabilityPattern.MatchString(tag) {
				return fmt.Errorf("DoD census go tags are invalid")
			}
			proofTagged = proofTagged || tag == dodProofBuildTag
		}
		index++
	}
	validPackage := func(value string) bool {
		return strings.HasPrefix(value, "./") && !strings.Contains(value, "..") && !strings.ContainsAny(value, " \t\r\n\x00")
	}
	switch args[0] {
	case "list":
		if proofTagged {
			return fmt.Errorf("DoD census dependency listing must use only shipped artifact tags")
		}
		if len(args)-index != 2 || args[index] != "-deps" || !validPackage(args[index+1]) {
			return fmt.Errorf("DoD census go list argv is outside the closed -deps package shape")
		}
	case "test":
		if !proofTagged {
			return fmt.Errorf("DoD census receipt test requires reserved build tag %q", dodProofBuildTag)
		}
		if len(args)-index != 6 || args[index] != "-json" || args[index+1] != "-count=1" || args[index+2] != dodReceiptTestTimeoutArg || args[index+3] != "-run" || args[index+4] == "" || !validPackage(args[index+5]) {
			return fmt.Errorf("DoD census go test argv is outside the closed receipt-test shape")
		}
		// There are six values after index: -json, -count=1, the exact
		// receipt-test timeout, -run, regex, and package. Rejecting any extra
		// value is what excludes -exec and -toolexec even if a caller later
		// tries to append one.
		if index+6 != len(args) {
			return fmt.Errorf("DoD census go test argv contains trailing values")
		}
	default:
		return fmt.Errorf("DoD census go subcommand %q is not allowed", args[0])
	}
	return nil
}

func dodCommandEnvironment(base []string, cacheDir string, profile BuildProfile) []string {
	out := make([]string, 0, len(base)+8+len(profile.RuntimeEnv))
	for _, item := range base {
		if strings.HasPrefix(item, "CGO_ENABLED=") || strings.HasPrefix(item, "GOCACHE=") || strings.HasPrefix(item, "GOFLAGS=") || strings.HasPrefix(item, "GOOS=") || strings.HasPrefix(item, "GOARCH=") || strings.HasPrefix(item, "TRSTCTL_") {
			continue
		}
		out = append(out, item)
	}
	out = append(out, "CGO_ENABLED="+profile.CGOEnabled, "GOCACHE="+cacheDir, "GOFLAGS=")
	if !profile.HostRuntime {
		out = append(out, "GOOS="+profile.GOOS, "GOARCH="+profile.GOARCH)
	}
	keys := make([]string, 0, len(profile.RuntimeEnv))
	for key := range profile.RuntimeEnv {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for _, key := range keys {
		out = append(out, key+"="+profile.RuntimeEnv[key])
	}
	return out
}

func main() {
	os.Exit(runCLI(context.Background(), os.Args[1:], os.Stdout, os.Stderr))
}

func runCLI(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	flags := flag.NewFlagSet("dodcensus", flag.ContinueOnError)
	flags.SetOutput(stderr)
	repoFlag := flags.String("repo", ".", "repository root")
	manifestFlag := flags.String("manifest", "tools/dodcensus/manifest.json", "versioned capability manifest")
	outFlag := flags.String("out", "wiring-census.json", "JSON receipt path")
	capabilityFlag := flags.String("capability", "", "require one exact manifest entry ID to be REQUIRED and SERVED")
	cardFlag := flags.String("card", "", "require the entry for one DoD card ID to be served")
	if err := flags.Parse(args); err != nil {
		return 2
	}
	repo, err := filepath.Abs(*repoFlag)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "dodcensus: resolve repo: %v\n", err)
		return 2
	}
	manifestPath := *manifestFlag
	if !filepath.IsAbs(manifestPath) {
		manifestPath = filepath.Join(repo, manifestPath)
	}
	manifest, err := loadManifest(manifestPath)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "dodcensus: %v\n", err)
		return 2
	}
	sel := selection{Capability: strings.TrimSpace(*capabilityFlag), CardID: strings.TrimSpace(*cardFlag)}
	if sel.Capability != "" && sel.CardID != "" {
		_, _ = fmt.Fprintln(stderr, "dodcensus: choose only one of --capability or --card")
		return 2
	}
	cacheDir := strings.TrimSpace(os.Getenv("TRSTCTL_DOD_GOCACHE"))
	if cacheDir == "" {
		cacheDir = filepath.Join(os.TempDir(), "trstctl-dodcensus-gocache")
	}
	report, err := evaluate(ctx, repo, manifest, osRunner{CacheDir: cacheDir, LinuxRunner: newLinuxRuntimeExecutor()}, sel)
	if err != nil {
		if errors.Is(err, errSelectionNoMatch) {
			_, _ = fmt.Fprintln(stderr, "dodcensus: selection matches no exact manifest entry")
			return 2
		}
		_, _ = fmt.Fprintf(stderr, "dodcensus: evaluate: %v\n", err)
		return 2
	}
	// The feature-map, README denominators, and managed-key disclosure must be
	// checked against this exact in-memory census. Keeping this in the full gate
	// avoids a second recursive census (and prevents a stale receipt from
	// certifying product claims). Exact focused runs deliberately have no full
	// denominator, so they do not evaluate breadth-wide claims.
	claimsErr := validateClaimsForSelection(repo, manifest, report, sel)
	outPath := *outFlag
	if !filepath.IsAbs(outPath) {
		outPath = filepath.Join(repo, outPath)
	}
	return finishCLIReport(outPath, report, sel, claimsErr, stdout, stderr)
}

func finishCLIReport(outPath string, report Report, sel selection, claimsErr error, stdout, stderr io.Writer) int {
	if err := writeReport(outPath, report); err != nil {
		_, _ = fmt.Fprintf(stderr, "dodcensus: write receipt: %v\n", err)
		return 2
	}
	printReport(stdout, report, outPath)
	if claimsErr != nil {
		_, _ = fmt.Fprintf(stderr, "dodcensus: product claims do not match the fresh wiring census: %v\n", claimsErr)
		return 1
	}
	if sel.Capability != "" || sel.CardID != "" {
		matched, served := selectedStatus(report, sel)
		if !matched {
			_, _ = fmt.Fprintln(stderr, "dodcensus: selection matches no manifest entry")
			return 2
		}
		if !served {
			return 1
		}
		return 0
	}
	if report.hasRequiredFailures() {
		return 1
	}
	return 0
}

func loadManifest(path string) (Manifest, error) {
	f, err := os.Open(path)
	if err != nil {
		return Manifest{}, fmt.Errorf("open manifest %s: %w", path, err)
	}
	defer func() { _ = f.Close() }()
	decoder := json.NewDecoder(f)
	decoder.DisallowUnknownFields()
	var manifest Manifest
	if err := decoder.Decode(&manifest); err != nil {
		return Manifest{}, fmt.Errorf("decode manifest %s: %w", path, err)
	}
	if err := decoder.Decode(&struct{}{}); err != io.EOF {
		if err == nil {
			err = fmt.Errorf("multiple JSON values")
		}
		return Manifest{}, fmt.Errorf("decode manifest %s: %w", path, err)
	}
	if err := validateManifest(manifest); err != nil {
		return Manifest{}, fmt.Errorf("validate manifest %s: %w", path, err)
	}
	return manifest, nil
}

func validateManifest(manifest Manifest) error {
	if manifest.SchemaVersion != 1 {
		return fmt.Errorf("schema_version %d is unsupported (want 1)", manifest.SchemaVersion)
	}
	if manifest.ManifestVersion < 1 {
		return fmt.Errorf("manifest_version must be positive")
	}
	if manifest.BinaryPackage == "" {
		return fmt.Errorf("binary_package is required")
	}
	if manifest.DefaultBuildProfile == "" {
		return fmt.Errorf("default_build_profile is required")
	}
	defaultProfile, ok := manifest.BuildProfiles[manifest.DefaultBuildProfile]
	if !ok {
		return fmt.Errorf("default_build_profile %q is not defined", manifest.DefaultBuildProfile)
	}
	if defaultProfile.BinaryPackage != manifest.BinaryPackage {
		return fmt.Errorf("top-level binary_package must match the default build profile")
	}
	for name, profile := range manifest.BuildProfiles {
		if !capabilityPattern.MatchString(name) {
			return fmt.Errorf("build profile name %q must be lowercase snake case", name)
		}
		if profile.BinaryPackage == "" || (profile.CGOEnabled != "0" && profile.CGOEnabled != "1") || profile.GOOS == "" || profile.GOARCH == "" {
			return fmt.Errorf("build profile %q must name binary_package, cgo_enabled 0 or 1, goos, and goarch", name)
		}
		if profile.GOOS == "host" || profile.GOARCH == "host" {
			return fmt.Errorf("build profile %q must pin an artifact platform; host is runtime-dependent", name)
		}
		if profile.Release != releasePlanned && profile.Release != releaseShipped {
			return fmt.Errorf("build profile %q release %q must be planned or shipped", name, profile.Release)
		}
		if profile.Release == releaseShipped && !artifactConfigured(profile.Artifact) {
			return fmt.Errorf("shipped build profile %q has no complete OCI release proof", name)
		}
		if profile.Release == releaseShipped {
			if err := validateRuntimeRunnerProof("build profile "+name, profile); err != nil {
				return err
			}
		}
		if profile.Release == releasePlanned && artifactConfigured(profile.Artifact) {
			return fmt.Errorf("planned build profile %q must not claim a fictional release artifact", name)
		}
		seenCompanion := map[string]bool{}
		for _, companion := range profile.Artifact.Companions {
			if companion.BinaryPackage == "" || companion.BuildOutput == "" || companion.BinaryPath == "" ||
				!strings.HasPrefix(companion.BinaryPackage, "./") || !filepath.IsAbs(companion.BuildOutput) || !filepath.IsAbs(companion.BinaryPath) || seenCompanion[companion.BinaryPath] {
				return fmt.Errorf("build profile %q has an invalid or duplicate companion artifact %+v", name, companion)
			}
			seenCompanion[companion.BinaryPath] = true
		}
		for key, value := range profile.Artifact.BuildArgs {
			if !buildArgPattern.MatchString(key) || value == "" || strings.TrimSpace(value) != value {
				return fmt.Errorf("build profile %q has invalid required artifact build arg %q=%q", name, key, value)
			}
		}
		for _, tag := range profile.Tags {
			if !capabilityPattern.MatchString(tag) {
				return fmt.Errorf("build profile %q has invalid tag %q", name, tag)
			}
			if tag == dodProofBuildTag {
				return fmt.Errorf("build profile %q may not claim reserved runtime-proof tag %q", name, tag)
			}
		}
	}
	for id, substrate := range manifest.Substrates {
		if !capabilityPattern.MatchString(id) {
			return fmt.Errorf("substrate id %q must be lowercase snake case", id)
		}
		if err := validateSubstrate("substrates."+id, substrate); err != nil {
			return err
		}
	}
	if len(manifest.Entries) == 0 {
		return fmt.Errorf("entries must not be empty")
	}
	entryIDs := map[string]bool{}
	cardIDs := map[string]bool{}
	for i, entry := range manifest.Entries {
		where := fmt.Sprintf("entries[%d]", i)
		if !entryIDPattern.MatchString(entry.ID) {
			return fmt.Errorf("%s.id %q must be a dotted lowercase key", where, entry.ID)
		}
		if entryIDs[entry.ID] {
			return fmt.Errorf("duplicate entry id %q", entry.ID)
		}
		entryIDs[entry.ID] = true
		if !cardIDPattern.MatchString(entry.CardID) || cardIDs[entry.CardID] {
			return fmt.Errorf("%s.card_id %q is invalid or duplicated", where, entry.CardID)
		}
		cardIDs[entry.CardID] = true
		if !capabilityPattern.MatchString(entry.Capability) || !strings.HasPrefix(entry.ID, entry.Capability+".") {
			return fmt.Errorf("%s capability %q does not own id %q", where, entry.Capability, entry.ID)
		}
		if entry.Inventory == nil {
			return fmt.Errorf("%s.inventory must be explicitly true or false", where)
		}
		if entry.Enforcement != enforcementPending && entry.Enforcement != enforcementRequired {
			return fmt.Errorf("%s.enforcement %q must be pending or required", where, entry.Enforcement)
		}
		profileName := entry.BuildProfile
		if profileName == "" {
			profileName = manifest.DefaultBuildProfile
		}
		if _, ok := manifest.BuildProfiles[profileName]; !ok {
			return fmt.Errorf("%s.build_profile %q is not defined", where, profileName)
		}
		if len(entry.Dependencies) == 0 {
			return fmt.Errorf("%s.dependencies must name exact shipped packages", where)
		}
		seenDependency := map[string]bool{}
		for _, dependency := range entry.Dependencies {
			if dependency == "" || strings.ContainsAny(dependency, "*?[]") || seenDependency[dependency] {
				return fmt.Errorf("%s dependency %q is empty, globbed, or duplicated", where, dependency)
			}
			seenDependency[dependency] = true
		}
		if entry.Assembly.File == "" || entry.Assembly.Function == "" || len(entry.Assembly.Calls) == 0 {
			return fmt.Errorf("%s.assembly must name a production file, root function, and exact call", where)
		}
		if entry.Enforcement == enforcementRequired {
			switch entry.Assembly.Binding {
			case "returned-field":
				if entry.Assembly.Field == "" {
					return fmt.Errorf("%s returned-field binding must name the returned Deps field", where)
				}
			case "returned-value", "served-effect":
				if entry.Assembly.Field != "" {
					return fmt.Errorf("%s %s binding must not name a Deps field", where, entry.Assembly.Binding)
				}
			default:
				return fmt.Errorf("%s required entry must choose returned-field, returned-value, or served-effect assembly dataflow", where)
			}
		}
		if strings.HasSuffix(entry.Assembly.File, "_test.go") || filepath.IsAbs(entry.Assembly.File) || strings.Contains(entry.Assembly.File, "..") {
			return fmt.Errorf("%s.assembly.file must be a repo-relative production Go file", where)
		}
		if runtimeConfigured(entry.Runtime) {
			if err := validateRuntime(where, entry.Runtime, manifest.Substrates); err != nil {
				return err
			}
		} else if entry.Enforcement == enforcementRequired {
			return fmt.Errorf("%s required entry has no runtime proof", where)
		}
	}
	return nil
}

func resolvedProfile(manifest Manifest, entry Entry) (string, BuildProfile) {
	name := entry.BuildProfile
	if name == "" {
		name = manifest.DefaultBuildProfile
	}
	return name, normalizedProfile(manifest.BuildProfiles[name])
}

func normalizedProfile(profile BuildProfile) BuildProfile {
	return profile
}

func normalizedProfiles(profiles map[string]BuildProfile) map[string]BuildProfile {
	out := make(map[string]BuildProfile, len(profiles))
	for name, profile := range profiles {
		out[name] = normalizedProfile(profile)
	}
	return out
}

func runtimeConfigured(proof RuntimeProof) bool {
	return proof.Package != "" || proof.Test != "" || proof.File != "" || proof.Mode != "" || proof.Method != "" || proof.Path != "" || proof.SubstrateID != ""
}

func artifactConfigured(proof ArtifactProof) bool {
	return proof.Workflow != "" && proof.Job != "" && proof.Dockerfile != "" && proof.BuilderAction != "" && proof.BuilderOutput != "" && proof.BuilderTags != "" && proof.BuildOutput != "" && proof.BinaryPath != "" && proof.Platform != ""
}

func validateRuntime(where string, proof RuntimeProof, substrates map[string]Substrate) error {
	if proof.Package == "" || proof.Test == "" || proof.File == "" || proof.Mode == "" || proof.Method == "" || proof.Path == "" || proof.SubstrateID == "" {
		return fmt.Errorf("%s.runtime is partially configured", where)
	}
	if !testNamePattern.MatchString(proof.Test) {
		return fmt.Errorf("%s.runtime.test %q must be a dedicated TestDOD* test", where, proof.Test)
	}
	if !strings.HasSuffix(proof.File, "_test.go") || filepath.IsAbs(proof.File) || strings.Contains(proof.File, "..") {
		return fmt.Errorf("%s.runtime.file must be a repo-relative _test.go file", where)
	}
	wantPackage := "./" + filepath.ToSlash(filepath.Dir(proof.File))
	if proof.Package != wantPackage {
		return fmt.Errorf("%s.runtime.package %q does not own %q (want %q)", where, proof.Package, proof.File, wantPackage)
	}
	if proof.Method != strings.ToUpper(proof.Method) || strings.ContainsAny(proof.Method, " \t\r\n") || !strings.HasPrefix(proof.Path, "/") {
		return fmt.Errorf("%s.runtime must name an uppercase HTTP method and absolute served path", where)
	}
	if proof.Mode != "assembled-handler" && proof.Mode != "launched-binary" {
		return fmt.Errorf("%s.runtime.mode %q must be assembled-handler or launched-binary", where, proof.Mode)
	}
	if _, ok := substrates[proof.SubstrateID]; !ok {
		return fmt.Errorf("%s.runtime.substrate_id %q is not declared", where, proof.SubstrateID)
	}
	return nil
}

func evaluate(ctx context.Context, repo string, manifest Manifest, runner commandRunner, sel selection) (Report, error) {
	if err := validateManifest(manifest); err != nil {
		return Report{}, err
	}
	selectedID, selectionActive, err := resolveSelection(manifest, sel)
	if err != nil {
		return Report{}, err
	}
	absRepo, err := filepath.Abs(repo)
	if err != nil {
		return Report{}, err
	}
	report := Report{
		SchemaVersion: manifest.SchemaVersion, ManifestVersion: manifest.ManifestVersion,
		GeneratedAt: time.Now().UTC().Truncate(time.Second).Format(time.RFC3339),
		Repo:        absRepo, BinaryPackage: manifest.BinaryPackage,
		DefaultBuildProfile: manifest.DefaultBuildProfile,
		BuildProfiles:       normalizedProfiles(manifest.BuildProfiles),
		Entries:             map[string]entryResult{}, Capabilities: map[string]capabilityResult{},
	}
	type profileState struct {
		profile      BuildProfile
		listed       commandResult
		dependencies map[string]bool
		ok           bool
	}
	states := map[string]profileState{}
	for _, entry := range manifest.Entries {
		if selectionActive && entry.ID != selectedID {
			continue
		}
		name, profile := resolvedProfile(manifest, entry)
		if _, exists := states[name]; exists {
			continue
		}
		if profile.Release != releaseShipped {
			states[name] = profileState{profile: profile, dependencies: map[string]bool{}}
			continue
		}
		args := []string{"list"}
		if len(profile.Tags) > 0 {
			args = append(args, "-tags="+strings.Join(profile.Tags, ","))
		}
		args = append(args, "-deps", profile.BinaryPackage)
		listed := runner.Run(ctx, absRepo, profile, "go", args...)
		dependencies := map[string]bool{}
		if listed.Err == nil {
			for _, line := range strings.Split(listed.Stdout, "\n") {
				if pkg := strings.TrimSpace(line); pkg != "" {
					dependencies[pkg] = true
				}
			}
		}
		states[name] = profileState{profile: profile, listed: listed, dependencies: dependencies, ok: listed.Err == nil && len(dependencies) > 0}
	}
	report.ToolchainOK = true
	for _, state := range states {
		if state.profile.Release == releaseShipped {
			report.ToolchainOK = report.ToolchainOK && state.ok
		}
	}
	runtimeExecutions := map[string]*runtimeTestExecution{}
	// Static binding must audit the execution shape of the unfocused manifest
	// even during an exact-card run. The runtime command itself remains filtered
	// below, but a focused proof may not hide a test-only full-group branch.
	fullRuntimeGroups := groupRuntimeEntries(manifest, "", false)
	runtimeGroups := groupRuntimeEntries(manifest, selectedID, selectionActive)
	launched, err := launchedBinarySpecForManifest(absRepo, manifest)
	if err != nil {
		return Report{}, err
	}
	defer cleanupRuntimeExecutions(runtimeExecutions)
	for _, entry := range manifest.Entries {
		profileName, profile := resolvedProfile(manifest, entry)
		if selectionActive && entry.ID != selectedID {
			result := notEvaluatedEntryResult(entry, profileName, selectedID)
			report.Entries[entry.ID] = result
			updateSummary(&report.Summary, result)
			continue
		}
		state := states[profileName]
		artifactEvidence := inspectArtifactDeclaration(absRepo, profile)
		dependencyEvidence := inspectDependencies(entry, state.dependencies, state.ok, state.listed)
		assemblyEvidence := inspectAssembly(absRepo, entry, profile)
		runtimeEvidence := checkEvidence{Detail: "not evaluated because dependency or assembly proof failed"}
		var status string
		switch {
		case !artifactEvidence.OK:
			status = statusLibraryOnly
		case !state.ok:
			status = statusUnknown
		case !dependencyEvidence.OK || !assemblyEvidence.OK:
			status = statusLibraryOnly
		default:
			cacheKey := runtimeCacheKey(profileName, entry)
			runtimeEvidence = inspectRuntimeBindingForGroup(absRepo, entry, manifest.Substrates, fullRuntimeGroups[cacheKey], profile)
			if runtimeEvidence.OK {
				runtimeEvidence = runRuntimeProof(ctx, absRepo, entry, profileName, profile, launched, manifest.Substrates[entry.Runtime.SubstrateID], runner, runtimeGroups[cacheKey], runtimeExecutions)
			}
			if runtimeEvidence.OK {
				status = statusServed
			} else {
				status = statusStub
			}
		}
		result := entryResult{
			CardID: entry.CardID, Capability: entry.Capability, Inventory: *entry.Inventory,
			Enforcement: entry.Enforcement, BuildProfile: profileName, Status: status,
			Evidence: entryEvidence{Artifact: artifactEvidence, Dependency: dependencyEvidence, Assembly: assemblyEvidence, Runtime: runtimeEvidence},
		}
		report.Entries[entry.ID] = result
		updateSummary(&report.Summary, result)
	}
	report.Capabilities = aggregateCapabilities(report.Entries)
	for _, capability := range report.Capabilities {
		if capability.Status == statusServed {
			report.Served++
		}
	}
	report.Total = len(report.Capabilities)
	return report, nil
}

// resolveSelection deliberately accepts only a granular manifest entry ID or
// the unique card which owns that entry. A family name such as "connector" is
// not a focused proof: treating one green sibling as the family would let the
// other advertised backends hide behind it.
func resolveSelection(manifest Manifest, sel selection) (string, bool, error) {
	if sel.Capability == "" && sel.CardID == "" {
		return "", false, nil
	}
	if sel.Capability != "" && sel.CardID != "" {
		return "", false, fmt.Errorf("choose only one selection kind")
	}
	for _, entry := range manifest.Entries {
		if (sel.Capability != "" && entry.ID == sel.Capability) || (sel.CardID != "" && entry.CardID == sel.CardID) {
			return entry.ID, true, nil
		}
	}
	return "", false, errSelectionNoMatch
}

func notEvaluatedEntryResult(entry Entry, profileName, selectedID string) entryResult {
	detail := fmt.Sprintf("not evaluated: exact selection %q excludes this row; no proof command ran and the row is non-SERVED", selectedID)
	notEvaluated := checkEvidence{Detail: detail}
	return entryResult{
		CardID: entry.CardID, Capability: entry.Capability, Inventory: *entry.Inventory,
		Enforcement: entry.Enforcement, BuildProfile: profileName, Status: statusUnknown,
		Evidence: entryEvidence{
			Artifact: notEvaluated, Dependency: notEvaluated,
			Assembly: notEvaluated, Runtime: notEvaluated,
		},
	}
}

func inspectArtifactDeclaration(repo string, profile BuildProfile) checkEvidence {
	artifact := inspectOCIArtifact(repo, profile)
	if !artifact.OK {
		return artifact
	}
	runner := inspectRuntimeRunnerProof(repo, profile)
	artifact.Required = append(artifact.Required, runner.Required...)
	artifact.Found = append(artifact.Found, runner.Found...)
	if !runner.OK {
		artifact.OK = false
		artifact.Detail = runner.Detail
		return artifact
	}
	artifact.Detail += "; cross-host runtime runner identity and package inputs are pinned"
	return artifact
}

func inspectDependencies(entry Entry, packages map[string]bool, toolchainOK bool, listed commandResult) checkEvidence {
	evidence := checkEvidence{Required: append([]string(nil), entry.Dependencies...)}
	if !toolchainOK {
		detail := strings.TrimSpace(listed.Stderr)
		if detail == "" && listed.Err != nil {
			detail = listed.Err.Error()
		}
		if detail == "" {
			detail = "go list returned no packages"
		}
		evidence.Detail = "cannot inspect shipped dependency graph: " + detail
		return evidence
	}
	for _, dependency := range entry.Dependencies {
		if packages[dependency] {
			evidence.Found = append(evidence.Found, dependency)
		}
	}
	evidence.OK = len(evidence.Found) == len(entry.Dependencies)
	if evidence.OK {
		evidence.Detail = "every exact implementation package appears in go list -deps ./cmd/trstctl"
	} else {
		evidence.Detail = "one or more exact implementation packages are absent from the shipped dependency graph"
	}
	return evidence
}

type parsedFunction struct {
	decl    *ast.FuncDecl
	file    string
	imports map[string]string
}

func inspectAssembly(repo string, entry Entry, profiles ...BuildProfile) checkEvidence {
	profile := normalizedProfile(BuildProfile{CGOEnabled: "0", GOOS: "host", GOARCH: "host"})
	if len(profiles) > 0 {
		profile = profiles[0]
	}
	proof := entry.Assembly
	required := append([]string(nil), proof.Calls...)
	if proof.Field != "" {
		required = append(required, "Deps."+proof.Field)
	}
	evidence := checkEvidence{Required: required}
	rootPath := filepath.Join(repo, filepath.FromSlash(proof.File))
	rootInfo, err := os.Stat(rootPath)
	if err != nil || rootInfo.IsDir() {
		evidence.Detail = fmt.Sprintf("production assembly file %s is missing", proof.File)
		return evidence
	}
	dir := filepath.Dir(rootPath)
	files, err := filepath.Glob(filepath.Join(dir, "*.go"))
	if err != nil {
		evidence.Detail = "enumerate assembly package: " + err.Error()
		return evidence
	}
	functions := map[string]parsedFunction{}
	rootFunctions := map[string]bool{}
	fset := token.NewFileSet()
	buildContext := build.Default
	buildContext.GOOS = profile.GOOS
	buildContext.GOARCH = profile.GOARCH
	buildContext.CgoEnabled = profile.CGOEnabled == "1"
	buildContext.BuildTags = append([]string(nil), profile.Tags...)
	for _, path := range files {
		if strings.HasSuffix(path, "_test.go") {
			continue
		}
		matches, matchErr := buildContext.MatchFile(dir, filepath.Base(path))
		if matchErr != nil {
			evidence.Detail = "evaluate production build constraints: " + matchErr.Error()
			return evidence
		}
		if !matches {
			continue
		}
		parsed, parseErr := parser.ParseFile(fset, path, nil, 0)
		if parseErr != nil {
			evidence.Detail = "parse production assembly: " + parseErr.Error()
			return evidence
		}
		imports := map[string]string{}
		for _, spec := range parsed.Imports {
			importPath, unquoteErr := strconv.Unquote(spec.Path.Value)
			if unquoteErr != nil {
				continue
			}
			alias := filepath.Base(importPath)
			if spec.Name != nil {
				alias = spec.Name.Name
			}
			if alias != "." && alias != "_" {
				imports[alias] = importPath
			}
		}
		for _, decl := range parsed.Decls {
			fn, ok := decl.(*ast.FuncDecl)
			if !ok || fn.Recv != nil || fn.Body == nil {
				continue
			}
			functions[fn.Name.Name] = parsedFunction{decl: fn, file: path, imports: imports}
			if path == rootPath {
				rootFunctions[fn.Name.Name] = true
			}
		}
	}
	if !rootFunctions[proof.Function] || functions[proof.Function].decl == nil {
		evidence.Detail = fmt.Sprintf("root function %s is not declared in %s", proof.Function, proof.File)
		return evidence
	}
	foundCalls := map[string]bool{}
	foundFields := map[string]bool{}
	visitedFunctions := map[string]bool{}
	visitedVariables := map[string]bool{}
	var visitFunction func(string)
	var visitNode func(string, ast.Node)
	visitNode = func(functionName string, node ast.Node) {
		if node == nil {
			return
		}
		fn := functions[functionName]
		ast.Inspect(node, func(current ast.Node) bool {
			switch value := current.(type) {
			case *ast.CallExpr:
				raw, canonical := assemblyCallName(value.Fun, fn.imports)
				if canonical != "" {
					foundCalls[canonical] = true
				}
				if _, local := functions[raw]; local {
					visitFunction(raw)
				}
			case *ast.Ident:
				key := functionName + ":" + value.Name
				if visitedVariables[key] {
					break
				}
				visitedVariables[key] = true
				for _, source := range assignedExpressions(fn.decl, value.Name) {
					visitNode(functionName, source)
				}
			}
			return true
		})
	}
	visitFunction = func(name string) {
		if visitedFunctions[name] || functions[name].decl == nil {
			return
		}
		visitedFunctions[name] = true
		visitNode(name, functions[name].decl.Body)
	}
	switch proof.Binding {
	case "returned-field":
		if fieldValue, ok := returnedDepsField(functions[proof.Function].decl, proof.Field); ok {
			foundFields[proof.Field] = true
			visitNode(proof.Function, fieldValue)
		}
	case "returned-value":
		for _, value := range returnedExpressions(functions[proof.Function].decl) {
			visitNode(proof.Function, value)
		}
	case "served-effect":
		visitFunction(proof.Function)
	default:
		// Pending W0 rows predate the explicit binding field. Keep them honestly
		// inspectable, but validateManifest refuses to promote one to required
		// until its dataflow shape is declared.
		if proof.Field == "" {
			visitFunction(proof.Function)
		} else if fieldValue, ok := returnedDepsField(functions[proof.Function].decl, proof.Field); ok {
			foundFields[proof.Field] = true
			visitNode(proof.Function, fieldValue)
		}
	}
	for _, call := range proof.Calls {
		if foundCalls[canonicalRequiredCall(entry, call)] {
			evidence.Found = append(evidence.Found, call)
		}
	}
	if proof.Field != "" && foundFields[proof.Field] {
		evidence.Found = append(evidence.Found, "Deps."+proof.Field)
	}
	sort.Strings(evidence.Found)
	evidence.OK = len(evidence.Found) == len(evidence.Required)
	if evidence.OK {
		evidence.Detail = fmt.Sprintf("production call graph rooted at %s in %s satisfies %s dataflow", proof.Function, proof.File, proof.Binding)
	} else {
		evidence.Detail = fmt.Sprintf("production call graph rooted at %s does not construct every required field/call", proof.Function)
	}
	return evidence
}

func assemblyCallName(expression ast.Expr, imports map[string]string) (string, string) {
	raw := expressionName(expression)
	selector, ok := expression.(*ast.SelectorExpr)
	if !ok {
		return raw, raw
	}
	ident, ok := selector.X.(*ast.Ident)
	if !ok || imports[ident.Name] == "" {
		return raw, raw
	}
	return raw, imports[ident.Name] + "." + selector.Sel.Name
}

func canonicalRequiredCall(entry Entry, call string) string {
	parts := strings.SplitN(call, ".", 2)
	if len(parts) != 2 {
		return call
	}
	for _, dependency := range entry.Dependencies {
		if filepath.Base(dependency) == parts[0] {
			return dependency + "." + parts[1]
		}
	}
	return call
}

func returnedDepsField(fn *ast.FuncDecl, field string) (ast.Expr, bool) {
	var value ast.Expr
	ast.Inspect(fn.Body, func(node ast.Node) bool {
		if value != nil {
			return false
		}
		ret, ok := node.(*ast.ReturnStmt)
		if !ok {
			return true
		}
		for _, result := range ret.Results {
			literal, ok := result.(*ast.CompositeLit)
			if !ok || (expressionName(literal.Type) != "Deps" && !strings.HasSuffix(expressionName(literal.Type), ".Deps")) {
				continue
			}
			for _, element := range literal.Elts {
				pair, ok := element.(*ast.KeyValueExpr)
				if !ok {
					continue
				}
				if ident, ok := pair.Key.(*ast.Ident); ok && ident.Name == field {
					value = pair.Value
					return false
				}
			}
		}
		return true
	})
	return value, value != nil
}

func returnedExpressions(fn *ast.FuncDecl) []ast.Expr {
	var values []ast.Expr
	ast.Inspect(fn.Body, func(node ast.Node) bool {
		ret, ok := node.(*ast.ReturnStmt)
		if !ok {
			return true
		}
		values = append(values, ret.Results...)
		return false
	})
	return values
}

func assignedExpressions(fn *ast.FuncDecl, variable string) []ast.Expr {
	var out []ast.Expr
	ast.Inspect(fn.Body, func(node ast.Node) bool {
		switch value := node.(type) {
		case *ast.AssignStmt:
			for index, lhs := range value.Lhs {
				ident, ok := lhs.(*ast.Ident)
				if !ok || ident.Name != variable || len(value.Rhs) == 0 {
					continue
				}
				if len(value.Rhs) == 1 {
					out = append(out, value.Rhs[0])
				} else if index < len(value.Rhs) {
					out = append(out, value.Rhs[index])
				}
			}
		case *ast.ValueSpec:
			for index, name := range value.Names {
				if name.Name == variable && index < len(value.Values) {
					out = append(out, value.Values[index])
				}
			}
		}
		return true
	})
	return out
}

func expressionName(expression ast.Expr) string {
	switch value := expression.(type) {
	case *ast.Ident:
		return value.Name
	case *ast.SelectorExpr:
		prefix := expressionName(value.X)
		if prefix == "" {
			return value.Sel.Name
		}
		return prefix + "." + value.Sel.Name
	case *ast.ParenExpr:
		return expressionName(value.X)
	default:
		return ""
	}
}

func updateSummary(summary *reportSummary, result entryResult) {
	summary.Total++
	if result.Inventory {
		summary.Inventory++
	}
	if result.Enforcement == enforcementRequired {
		summary.Required++
		if result.Status != statusServed {
			summary.RequiredFailed++
		}
	} else {
		summary.Pending++
	}
	switch result.Status {
	case statusServed:
		summary.Served++
		if result.Inventory {
			summary.InventoryServed++
		}
	case statusLibraryOnly:
		summary.LibraryOnly++
	case statusStub:
		summary.Stub++
	default:
		summary.Unknown++
	}
}

func aggregateCapabilities(entries map[string]entryResult) map[string]capabilityResult {
	groups := map[string][]string{}
	for id, entry := range entries {
		groups[entry.Capability] = append(groups[entry.Capability], id)
	}
	out := map[string]capabilityResult{}
	for capability, ids := range groups {
		sort.Strings(ids)
		result := capabilityResult{Status: statusServed, Total: len(ids), EntryIDs: ids}
		for _, id := range ids {
			entry := entries[id]
			if entry.Status == statusServed {
				result.Served++
			}
			if entry.Inventory {
				result.Inventory++
			}
			if entry.Enforcement == enforcementRequired {
				result.Required++
			}
			result.Status = worseStatus(result.Status, entry.Status)
		}
		result.Evidence = fmt.Sprintf("%d/%d granular entries served; %d inventory rows; %d required", result.Served, result.Total, result.Inventory, result.Required)
		out[capability] = result
	}
	return out
}

func worseStatus(left, right string) string {
	rank := map[string]int{statusServed: 0, statusStub: 1, statusLibraryOnly: 2, statusUnknown: 3}
	if rank[right] > rank[left] {
		return right
	}
	return left
}

func selectedStatus(report Report, sel selection) (bool, bool) {
	if sel.CardID != "" {
		for _, entry := range report.Entries {
			if entry.CardID == sel.CardID {
				return true, entry.Status == statusServed && entry.Enforcement == enforcementRequired
			}
		}
		return false, false
	}
	if entry, ok := report.Entries[sel.Capability]; ok {
		return true, entry.Status == statusServed && entry.Enforcement == enforcementRequired
	}
	return false, false
}

func writeReport(path string, report Report) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	temporary, err := os.CreateTemp(filepath.Dir(path), ".wiring-census-*.json")
	if err != nil {
		return err
	}
	temporaryPath := temporary.Name()
	defer func() { _ = os.Remove(temporaryPath) }()
	encoder := json.NewEncoder(temporary)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(report); err != nil {
		_ = temporary.Close()
		return err
	}
	if err := temporary.Close(); err != nil {
		return err
	}
	return os.Rename(temporaryPath, path)
}

func printReport(w io.Writer, report Report, outputPath string) {
	_, _ = fmt.Fprintf(w, "wiring-census: %d/%d granular entries SERVED; %d required failures; receipt=%s\n", report.Summary.Served, report.Summary.Total, report.Summary.RequiredFailed, outputPath)
	ids := make([]string, 0, len(report.Entries))
	for id := range report.Entries {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	for _, id := range ids {
		entry := report.Entries[id]
		_, _ = fmt.Fprintf(w, "  %-42s %-12s %-8s %s\n", id, entry.Status, entry.Enforcement, entry.Evidence.Runtime.Detail)
	}
}
