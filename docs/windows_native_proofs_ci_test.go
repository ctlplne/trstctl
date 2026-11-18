// SPDX-License-Identifier: BUSL-1.1

package docs

import (
	"fmt"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

// CR-150: the Windows lab proofs had never executed in CI. The A267 lab script
// stopped at its first red stage; the A268 local administrator proofs (with the
// A238 file-DACL and service-reload proofs) sat behind the always-red A240 step
// in the same job; and the MSI build and Windows Installer lifecycle sat behind
// the always-red Windows test step. GitHub skips a step after any earlier
// failure unless its condition says otherwise, so a red early step hid every
// native proof after it while the portable spy-driver tests stayed green.
//
// This guard keeps the A267, A268 and A238 native proofs and the MSI lifecycle
// independent of each other and of the steps around them:
//   - a proof step runs on every CI run whatever an earlier step did: its job has
//     no needs, job condition or continue-on-error; the step has no
//     continue-on-error and no step limit; and either nothing but runner setup
//     runs before it, or its condition is exactly ${{ !cancelled() &&
//     steps.<id>.outcome == 'success' }} for a setup step that always runs, or
//     for a listed build prerequisite that itself holds to this rule;
//   - a proof step runs one test or lab (a second one would sit behind the
//     first's throw, the deleted A267 script's shape), with -count=1 so a cached
//     pass cannot replay its marker, and throws when its marker is missing;
//   - in a job that runs such a proof, any other step that runs go test or a
//     scripts/ci lab is a proof too, and no step without a condition follows a
//     test, so a proof appended behind an always-red step is caught (that is how
//     CR-150 began);
//   - in a job made only of native proofs, every step after setup holds to the
//     rule and sets its own go test deadline, and the job limit sits above the
//     deadlines' sum, so a hung proof fails itself instead of cutting off the
//     proofs after it.

const (
	windowsNativeProofWorkflow = "../.github/workflows/ci.yml"
	// windowsNativeDeadlineMargin is the job-limit headroom above the summed go
	// test deadlines: runner setup, test-binary builds and cmd/go's grace after
	// a deadline.
	windowsNativeDeadlineMargin = 15
	// windowsNativeGatedTestStep is the one test step in a native proof job that
	// may wait on an earlier step (its own build): the Windows job's portable test
	// step, which gates no proof.
	windowsNativeGatedTestStep = "go test ./internal/agent/... ./internal/dist/... ./internal/crypto/..."
)

// windowsNativeProofMarkers are checked by exactly one workflow step each: the
// line the proving test prints only after it passed.
var windowsNativeProofMarkers = []string{
	// A267 (job a267-windows-dependents, one step per stage).
	"A267_WINDOWS_SERVICE_OK",
	"A267_WINDOWS_AUTOMATION_OK",
	"A267_WINDOWS_NATIVE_BUFFER_OK",
	"A267_WINDOWS_TASK_OK",
	"A267_WINDOWS_IIS_OK",
	"--- PASS: TestTaskExecutionAbruptProcessExitDoesNotRepeatA267",
	"A267_WINDOWS_INVENTORY_OK",
	"A267_WINDOWS_EXECUTOR_OK",
	// A268 and A238 (job a268-windows-native).
	"A268_WINDOWS_LOCAL_INVENTORY_OK",
	"A268_WINDOWS_LOCAL_ROTATION_OK",
	"A268_LOCAL_ROTATION_JOURNAL_OK",
	"A268_HOST_ROTATION_RECEIPT_OK",
	"--- PASS: TestWindowsRenderedFileHasAnExplicitProtectedDACLA238L10",
	"A238L3_WINDOWS_SERVICE_RELOAD_OK",
}

// windowsNativeLabScripts are native proofs a workflow step runs as a script
// (matched by file name: the MSI step spells its path with backslashes).
var windowsNativeLabScripts = []string{
	"a240-windows-accounts-lab.ps1",
	"windows-msi-lifecycle.ps1",
}

// windowsNativeDedicatedJobs hold nothing but native proofs after runner setup.
var windowsNativeDedicatedJobs = []string{"a267-windows-dependents", "a268-windows-native"}

// windowsNativePrerequisites are the only non-setup steps, by id, a proof may
// wait on: steps that build what the proof consumes (the MSI lifecycle installs
// the MSIs step msi builds). A test, lab or marker step is never one, or its
// failure would skip the proof after it again.
var windowsNativePrerequisites = []string{"msi"}

type windowsProofStep struct {
	ID              string `yaml:"id"`
	Name            string `yaml:"name"`
	If              string `yaml:"if"`
	Uses            string `yaml:"uses"`
	Run             string `yaml:"run"`
	ContinueOnError any    `yaml:"continue-on-error"`
	TimeoutMinutes  any    `yaml:"timeout-minutes"`
}

type windowsProofJob struct {
	Name            string `yaml:"name"`
	If              string `yaml:"if"`
	Needs           any    `yaml:"needs"`
	ContinueOnError any    `yaml:"continue-on-error"`
	TimeoutMinutes  any    `yaml:"timeout-minutes"`
	Strategy        struct {
		FailFast *bool `yaml:"fail-fast"`
		Matrix   any   `yaml:"matrix"`
	} `yaml:"strategy"`
	Steps []windowsProofStep `yaml:"steps"`
}

var (
	// windowsProofIndependentIf is the one condition that keeps a step running
	// after an earlier step failed, yet stops it when the run was cancelled or
	// the step it needs did not succeed.
	windowsProofIndependentIf = regexp.MustCompile(`^\$\{\{ !cancelled\(\) && steps\.([A-Za-z0-9_-]+)\.outcome == 'success' \}\}$`)
	// windowsProofDeadline is a go test -timeout with its unit.
	windowsProofDeadline = regexp.MustCompile(`-timeout[= ](\d+)(h|m|s)\b`)
	// windowsProofGoTest is a go test command and windowsProofGoTestBuild one that
	// only compiles a test binary (-c); windowsProofLab runs a scripts/ci lab.
	windowsProofGoTest      = regexp.MustCompile(`(^|[\s&;|(])go test\s`)
	windowsProofGoTestBuild = regexp.MustCompile(`(^|[\s&;|(])go test\s+-c\s`)
	windowsProofLab         = regexp.MustCompile(`scripts[/\\]ci[/\\][a-z0-9-]+\.(ps1|sh)`)
	// windowsProofTestBinaryRun is a test binary run directly: a test run too.
	windowsProofTestBinaryRun = regexp.MustCompile(`-test\.run[= ]`)
	// windowsProofLabInvocation is one PowerShell invocation of a lab script
	// (with backtick-continued parameters for the MSI lifecycle).
	windowsProofLabInvocation = regexp.MustCompile("^\\.[/\\\\]scripts[/\\\\]ci[/\\\\][a-z0-9-]+\\.ps1(\\s+`?\\s*-[A-Za-z]+\\s+\\([^()]*(\\([^()]*\\))?[^()]*\\))*\\s*$")
	windowsProofRunEnder      = regexp.MustCompile(`(?i)(^|[^A-Za-z0-9_-])(exit|return|throw)($|[^A-Za-z0-9_-])`)
)

// windowsProofSetupStep reports whether step only prepares the runner (checkout,
// toolchain, module prefetch): a failed setup step may skip the proofs after it,
// because nothing could run without it.
func windowsProofSetupStep(step windowsProofStep) bool {
	uses := strings.TrimSpace(step.Uses)
	return strings.HasPrefix(uses, "actions/checkout@") || strings.HasPrefix(uses, "actions/setup-go@") ||
		strings.TrimSpace(step.Run) == "scripts/ci/go-mod-download.sh"
}

// windowsProofRunsTests reports whether run runs tests (a go test other than a
// -c test-binary build).
func windowsProofRunsTests(run string) bool {
	return len(windowsProofGoTest.FindAllStringIndex(run, -1)) > len(windowsProofGoTestBuild.FindAllStringIndex(run, -1)) ||
		windowsProofTestBinaryRun.MatchString(run)
}

// windowsProofStepIsProof reports whether step runs tests, a lab or a marker
// check. Such a step is never a prerequisite another proof may wait on.
func windowsProofStepIsProof(step windowsProofStep) bool {
	// The prefetch script is runner setup, not a lab.
	if windowsProofSetupStep(step) {
		return false
	}
	if windowsProofRunsTests(step.Run) || windowsProofLab.MatchString(step.Run) {
		return true
	}
	for _, marker := range windowsNativeProofMarkers {
		if strings.Contains(step.Run, marker) {
			return true
		}
	}
	return false
}

// windowsProofIndependent reports why step i of job could be skipped by an
// earlier step's failure, or "" when it cannot.
func windowsProofIndependent(job windowsProofJob, i int) string {
	step := job.Steps[i]
	if strings.TrimSpace(step.If) == "" {
		for _, earlier := range job.Steps[:i] {
			if !windowsProofSetupStep(earlier) {
				return fmt.Sprintf("it runs only when the earlier step %q passed", earlier.Name)
			}
		}
		return ""
	}
	m := windowsProofIndependentIf.FindStringSubmatch(strings.TrimSpace(step.If))
	if m == nil {
		return fmt.Sprintf("its condition %q is not ${{ !cancelled() && steps.<id>.outcome == 'success' }}", step.If)
	}
	for j, earlier := range job.Steps[:i] {
		if earlier.ID != m[1] {
			continue
		}
		// The step it waits on must itself always run and fail the job.
		if earlier.ContinueOnError != nil {
			return fmt.Sprintf("it needs step %q, whose continue-on-error lets that step fail without failing the job while this proof is skipped", earlier.Name)
		}
		if windowsProofSetupStep(earlier) {
			if strings.TrimSpace(earlier.If) != "" {
				return fmt.Sprintf("it needs setup step %q, whose own condition %q can skip it and so skip this proof with a green job", earlier.Name, earlier.If)
			}
			// A setup step with no condition runs only
			// when every step before it passed.
			if why := windowsProofIndependent(job, j); why != "" {
				return fmt.Sprintf("it needs setup step %q, and %s", earlier.Name, why)
			}
			return ""
		}
		if !slices.Contains(windowsNativePrerequisites, earlier.ID) || windowsProofStepIsProof(earlier) {
			return fmt.Sprintf("it waits on step %q, which is neither runner setup nor a build prerequisite (%v), so that step's failure would skip this proof", earlier.Name, windowsNativePrerequisites)
		}
		if why := windowsProofIndependent(job, j); why != "" {
			return fmt.Sprintf("it needs step %q, and %s", earlier.Name, why)
		}
		return ""
	}
	return fmt.Sprintf("its condition names step %q, which is not an earlier step of the job", m[1])
}

// checkWindowsProofStep requires that step i of jobID runs on every CI run and
// fails its job when the proof fails.
func checkWindowsProofStep(t *testing.T, jobID string, job windowsProofJob, i int, proof string) {
	t.Helper()
	step := job.Steps[i]
	if job.Needs != nil {
		t.Errorf("CR-150: job %s, which runs %s, needs %v; a failed or skipped need would skip the whole native proof job", jobID, proof, job.Needs)
	}
	if strings.TrimSpace(job.If) != "" {
		t.Errorf("CR-150: job %s, which runs %s, has a job-level condition %q; a native proof job must run on every CI run", jobID, proof, job.If)
	}
	if job.ContinueOnError != nil || step.ContinueOnError != nil {
		t.Errorf("CR-150: job %s step %q runs %s with continue-on-error set; a failed native proof must fail its job", jobID, step.Name, proof)
	}
	// A matrix fails fast by default: one red leg cancels the legs still running.
	if job.Strategy.Matrix != nil && (job.Strategy.FailFast == nil || *job.Strategy.FailFast) {
		t.Errorf("CR-150: job %s, which runs %s, is a matrix without fail-fast: false; one red leg would cancel the other native proofs", jobID, proof)
	}
	// A step limit can cut a proof short.
	if step.TimeoutMinutes != nil {
		t.Errorf("CR-150: job %s step %q runs %s with its own timeout-minutes %v; keep the limit on the job, above the proof deadlines", jobID, step.Name, proof, step.TimeoutMinutes)
	}
	if why := windowsProofIndependent(job, i); why != "" {
		t.Errorf("CR-150: job %s step %q (%s) can be skipped by an earlier failure: %s", jobID, step.Name, proof, why)
	}
	// One test or lab per step. In one step a second test sits
	// behind the first one's throw and never runs while the first is red: the
	// deleted A267 script's shape.
	if n := windowsProofTestRuns(step.Run); n > 1 {
		t.Errorf("CR-150: job %s step %q runs %d tests or labs; give each its own step, or a red one skips the ones after it", jobID, step.Name, n)
	}
	// A cached result replays a pass without running
	// the native proof, so every test run in a proof step disables the cache.
	for _, line := range strings.Split(windowsProofCode(step.Run), "\n") {
		if windowsProofRunsTests(line) && !strings.Contains(line, "-count=1") {
			t.Errorf("CR-150: job %s step %q runs %q without -count=1; a cached pass would replay its marker without running the proof", jobID, step.Name, strings.TrimSpace(line))
		}
	}
}

// windowsProofCode returns run without its comment lines.
func windowsProofCode(run string) string {
	var b strings.Builder
	for _, line := range strings.Split(run, "\n") {
		if !strings.HasPrefix(strings.TrimSpace(line), "#") {
			b.WriteString(line)
			b.WriteByte('\n')
		}
	}
	return b.String()
}

// windowsProofTestRuns counts the tests and labs run runs: go test commands
// other than -c builds, test binaries run directly, and scripts/ci labs.
func windowsProofTestRuns(run string) int {
	code := windowsProofCode(run)
	return len(windowsProofGoTest.FindAllStringIndex(code, -1)) - len(windowsProofGoTestBuild.FindAllStringIndex(code, -1)) +
		len(windowsProofTestBinaryRun.FindAllStringIndex(code, -1)) + len(windowsProofLab.FindAllStringIndex(code, -1))
}

// windowsProofSteps returns every (job, step index) whose run contains needle.
func windowsProofSteps(jobs map[string]windowsProofJob, needle string) [][2]any {
	var out [][2]any
	for jobID, job := range jobs {
		for i, step := range job.Steps {
			if strings.Contains(step.Run, needle) {
				out = append(out, [2]any{jobID, i})
			}
		}
	}
	return out
}

func windowsProofTimeout(t *testing.T, jobID string, job windowsProofJob) int {
	t.Helper()
	switch v := job.TimeoutMinutes.(type) {
	case int:
		return v
	case string:
		n, err := strconv.Atoi(strings.TrimSpace(v))
		if err == nil {
			return n
		}
	}
	t.Errorf("CR-150: job %s has no fixed timeout-minutes (%v); a native proof job needs one above its proof deadlines", jobID, job.TimeoutMinutes)
	return 0
}

// windowsProofDeadlineMinutes sums text's go test deadlines in whole minutes.
func windowsProofDeadlineMinutes(text string) int {
	total := 0
	for _, m := range windowsProofDeadline.FindAllStringSubmatch(text, -1) {
		n, _ := strconv.Atoi(m[1])
		switch m[2] {
		case "h":
			total += n * 60
		case "m":
			total += n
		case "s":
			total += (n + 59) / 60
		}
	}
	return total
}

func TestWindowsNativeLabProofsRunEvenAfterAnEarlierRedStep(t *testing.T) {
	var wf struct {
		Jobs map[string]windowsProofJob `yaml:"jobs"`
	}
	if err := yaml.Unmarshal([]byte(read(t, windowsNativeProofWorkflow)), &wf); err != nil {
		t.Fatalf("CR-150: parse %s: %v", windowsNativeProofWorkflow, err)
	}
	if len(wf.Jobs) == 0 {
		t.Fatal("CR-150: parsed no jobs out of ci.yml; the workflow shape changed, so revisit this guard")
	}

	// checked holds every proof step already checked, by job, so the sweep
	// below covers the jobs that run a guarded proof.
	checked := map[string]map[int]bool{}
	mark := func(jobID string, i int) {
		if checked[jobID] == nil {
			checked[jobID] = map[int]bool{}
		}
		checked[jobID][i] = true
	}

	for _, marker := range windowsNativeProofMarkers {
		found := windowsProofSteps(wf.Jobs, marker)
		if len(found) != 1 {
			t.Errorf("CR-150: %d workflow steps check the native proof marker %s, want exactly 1", len(found), marker)
			continue
		}
		jobID, i := found[0][0].(string), found[0][1].(int)
		checkWindowsProofStep(t, jobID, wf.Jobs[jobID], i, marker)
		mark(jobID, i)
		// A missing marker fails the step.
		if !strings.Contains(windowsProofCode(wf.Jobs[jobID].Steps[i].Run), "-notmatch '"+marker+"') { throw ") {
			t.Errorf("CR-150: job %s step %q does not throw when %s is missing; a skipped proof would pass", jobID, wf.Jobs[jobID].Steps[i].Name, marker)
		}
	}
	for _, script := range windowsNativeLabScripts {
		found := windowsProofSteps(wf.Jobs, script)
		if len(found) != 1 {
			t.Errorf("CR-150: %d workflow steps run the native lab %s, want exactly 1", len(found), script)
			continue
		}
		jobID, i := found[0][0].(string), found[0][1].(int)
		step := wf.Jobs[jobID].Steps[i]
		checkWindowsProofStep(t, jobID, wf.Jobs[jobID], i, script)
		mark(jobID, i)
		// The step runs the lab and nothing after it, so the lab's exit code is
		// the step's: a trailing statement could replace a red result.
		if run := strings.TrimSpace(step.Run); strings.ContainsAny(run, ";|&") || windowsProofRunEnder.MatchString(run) || !windowsProofLabInvocation.MatchString(run) {
			t.Errorf("CR-150: job %s step %q runs %q; it must run the lab script alone (one invocation, no other statement)", jobID, step.Name, run)
		}
	}
	for _, jobID := range windowsNativeDedicatedJobs {
		job, ok := wf.Jobs[jobID]
		if !ok {
			t.Errorf("CR-150: the native proof job %s is missing from ci.yml", jobID)
			continue
		}
		setup := true
		var deadlines strings.Builder
		for i, step := range job.Steps {
			if setup && windowsProofSetupStep(step) {
				continue
			}
			setup = false
			checkWindowsProofStep(t, jobID, job, i, "a native proof")
			mark(jobID, i)
			// Without its own -timeout a test gets cmd/go's 10-minute default,
			// which the job limit below would not count.
			if windowsProofRunsTests(step.Run) && !windowsProofDeadline.MatchString(step.Run) {
				t.Errorf("CR-150: job %s step %q runs go test without -timeout; give it one so the job limit covers it", jobID, step.Name)
			}
			deadlines.WriteString(step.Run + "\n")
		}
		if sum, limit := windowsProofDeadlineMinutes(deadlines.String()), windowsProofTimeout(t, jobID, job); limit < sum+windowsNativeDeadlineMargin {
			t.Errorf("CR-150: job %s has %d minutes for %d minutes of proof deadlines; give it at least %d so a hung proof cannot cut off the ones after it", jobID, limit, sum, sum+windowsNativeDeadlineMargin)
		}
	}

	// In a job that runs a guarded proof, any other step that runs go test or a
	// scripts/ci lab is a native proof too: a proof appended behind an always-red
	// step gets the same checks. The Windows job's portable test step is the one
	// exemption: it waits on its own build and gates no proof.
	for jobID := range checked {
		job := wf.Jobs[jobID]
		afterTest := ""
		for i, step := range job.Steps {
			// A step with no condition after a test or lab
			// is skipped whenever that test is red, and so is what a proof needs from it.
			if afterTest != "" && strings.TrimSpace(step.If) == "" {
				t.Errorf("CR-150: job %s step %q has no condition after the test step %q, so that test's failure skips it and whatever a later proof needs from it", jobID, step.Name, afterTest)
			}
			if windowsProofStepIsProof(step) {
				afterTest = step.Name
			}
			if checked[jobID][i] || strings.TrimSpace(step.Run) == windowsNativeGatedTestStep || !windowsProofStepIsProof(step) {
				continue
			}
			checkWindowsProofStep(t, jobID, job, i, "a native proof")
		}
	}
}
