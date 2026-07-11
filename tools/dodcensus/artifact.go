// SPDX-License-Identifier: MPL-2.0

package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"
)

var pinnedBuildPushAction = regexp.MustCompile(`^docker/build-push-action@[0-9a-f]{40}$`)

type releaseWorkflow struct {
	Jobs map[string]releaseJob `yaml:"jobs"`
}

type releaseJob struct {
	Permissions map[string]string `yaml:"permissions"`
	Steps       []releaseStep     `yaml:"steps"`
}

type releaseStep struct {
	Uses string         `yaml:"uses"`
	With map[string]any `yaml:"with"`
}

// inspectOCIArtifact follows one exact data path:
// release workflow job -> pinned build-push action -> Dockerfile -> go build
// output -> final-image COPY -> ENTRYPOINT. Merely mentioning these strings in a
// different job or local target cannot satisfy the proof.
func inspectOCIArtifact(repo string, profile BuildProfile) checkEvidence {
	proof := profile.Artifact
	required := []string{
		"release=shipped", "workflow=" + proof.Workflow, "job=" + proof.Job,
		"builder=" + proof.BuilderAction, "dockerfile=" + proof.Dockerfile,
		"platform=" + proof.Platform, "builder_output=" + proof.BuilderOutput,
		"builder_tags=" + proof.BuilderTags, "packages=write",
		"go_build=" + profile.BinaryPackage, "cgo=" + profile.CGOEnabled,
		"build_output=" + proof.BuildOutput, "binary_path=" + proof.BinaryPath,
		"entrypoint=" + proof.BinaryPath,
	}
	evidence := checkEvidence{Required: required}
	if profile.Release != releaseShipped {
		evidence.Detail = "build profile is planned, not shipped; planned artifacts never serve a capability"
		return evidence
	}
	if !artifactConfigured(proof) {
		evidence.Detail = "shipped profile has an incomplete OCI artifact declaration"
		return evidence
	}
	if !pinnedBuildPushAction.MatchString(proof.BuilderAction) {
		evidence.Detail = "builder_action is not docker/build-push-action pinned to a 40-hex commit"
		return evidence
	}
	if proof.Platform != profile.GOOS+"/"+profile.GOARCH {
		evidence.Detail = fmt.Sprintf("artifact platform %q does not match profile %s/%s", proof.Platform, profile.GOOS, profile.GOARCH)
		return evidence
	}
	workflowPath, err := safeRepoPath(repo, proof.Workflow)
	if err != nil {
		evidence.Detail = "release workflow path: " + err.Error()
		return evidence
	}
	workflowBytes, err := os.ReadFile(workflowPath)
	if err != nil {
		evidence.Detail = "read release workflow: " + err.Error()
		return evidence
	}
	var workflow releaseWorkflow
	decoder := yaml.NewDecoder(strings.NewReader(string(workflowBytes)))
	decoder.KnownFields(false) // GitHub's full schema is larger than this proof view.
	if err := decoder.Decode(&workflow); err != nil {
		evidence.Detail = "parse release workflow YAML: " + err.Error()
		return evidence
	}
	job, ok := workflow.Jobs[proof.Job]
	if !ok {
		evidence.Detail = fmt.Sprintf("release workflow has no exact job id %q", proof.Job)
		return evidence
	}
	if strings.TrimSpace(job.Permissions["packages"]) != "write" {
		evidence.Detail = "publishing job lacks exact permissions.packages: write registry authority"
		return evidence
	}
	var builder *releaseStep
	for i := range job.Steps {
		step := &job.Steps[i]
		file, fileOK := scalarString(step.With["file"])
		platforms, platformsOK := scalarString(step.With["platforms"])
		push, pushOK := scalarBool(step.With["push"])
		output, outputOK := scalarString(step.With["outputs"])
		tags, tagsOK := scalarString(step.With["tags"])
		if step.Uses == proof.BuilderAction && fileOK && file == proof.Dockerfile && platformsOK && commaSetContains(platforms, proof.Platform) && pushOK && push && outputOK && output == proof.BuilderOutput && tagsOK && tags == proof.BuilderTags {
			if builder != nil {
				evidence.Detail = "release job has more than one exact matching publishing builder step"
				return evidence
			}
			builder = step
		}
	}
	if builder == nil {
		evidence.Detail = "exact release job has no pinned builder step with the required file/platform/push/output dataflow"
		return evidence
	}
	file, ok := scalarString(builder.With["file"])
	if !ok || file != proof.Dockerfile {
		evidence.Detail = fmt.Sprintf("publishing builder file = %q, want exact %q", file, proof.Dockerfile)
		return evidence
	}
	platforms, ok := scalarString(builder.With["platforms"])
	if !ok || !commaSetContains(platforms, proof.Platform) {
		evidence.Detail = fmt.Sprintf("publishing builder platforms %q do not contain exact %q", platforms, proof.Platform)
		return evidence
	}
	push, ok := scalarBool(builder.With["push"])
	if !ok || !push {
		evidence.Detail = "publishing builder must structurally set push: true"
		return evidence
	}
	output, ok := scalarString(builder.With["outputs"])
	if !ok || output != proof.BuilderOutput {
		evidence.Detail = fmt.Sprintf("publishing builder outputs = %q, want exact %q", output, proof.BuilderOutput)
		return evidence
	}
	tags, ok := scalarString(builder.With["tags"])
	if !ok || tags == "" || tags != proof.BuilderTags {
		evidence.Detail = fmt.Sprintf("publishing builder tags = %q, want exact nonempty %q", tags, proof.BuilderTags)
		return evidence
	}
	dockerfilePath, err := safeRepoPath(repo, proof.Dockerfile)
	if err != nil {
		evidence.Detail = "Dockerfile path: " + err.Error()
		return evidence
	}
	dockerfile, err := os.ReadFile(dockerfilePath)
	if err != nil {
		evidence.Detail = "read Dockerfile: " + err.Error()
		return evidence
	}
	if err := inspectDockerfile(string(dockerfile), profile); err != nil {
		evidence.Detail = "Dockerfile proof: " + err.Error()
		return evidence
	}
	evidence.Found = append([]string(nil), required...)
	evidence.OK = true
	evidence.Detail = "parsed publishing job builds and pushes the exact Dockerfile whose pinned profile binary is copied to the final ENTRYPOINT"
	return evidence
}

func safeRepoPath(repo, name string) (string, error) {
	if name == "" || filepath.IsAbs(name) || strings.Contains(name, "..") || filepath.ToSlash(name) != name {
		return "", fmt.Errorf("%q is not a clean repo-relative path", name)
	}
	return filepath.Join(repo, filepath.FromSlash(name)), nil
}

func scalarString(value any) (string, bool) {
	switch v := value.(type) {
	case string:
		return strings.TrimSpace(v), true
	case nil:
		return "", false
	default:
		return fmt.Sprint(v), true
	}
}

func scalarBool(value any) (bool, bool) {
	switch v := value.(type) {
	case bool:
		return v, true
	case string:
		if strings.TrimSpace(v) == "true" {
			return true, true
		}
		if strings.TrimSpace(v) == "false" {
			return false, true
		}
	}
	return false, false
}

func commaSetContains(value, want string) bool {
	for _, part := range strings.Split(value, ",") {
		if strings.TrimSpace(part) == want {
			return true
		}
	}
	return false
}

func inspectDockerfile(source string, profile BuildProfile) error {
	proof := profile.Artifact
	instructions := dockerInstructions(source)
	if len(instructions) == 0 {
		return fmt.Errorf("no Dockerfile instructions")
	}
	cgoFound := false
	goosFound := false
	goarchFound := false
	buildFound := false
	copyFound := false
	entrypointFound := false
	expectedTags := append([]string(nil), profile.Tags...)
	sort.Strings(expectedTags)
	for _, instruction := range instructions {
		upper := strings.ToUpper(instruction)
		if strings.HasPrefix(upper, "ENV ") && envAssignment(instruction[4:], "CGO_ENABLED") == profile.CGOEnabled {
			cgoFound = true
		}
		if strings.HasPrefix(upper, "ENV ") && envAssignment(instruction[4:], "GOOS") == "${TARGETOS}" {
			goosFound = true
		}
		if strings.HasPrefix(upper, "ENV ") && envAssignment(instruction[4:], "GOARCH") == "${TARGETARCH}" {
			goarchFound = true
		}
		if strings.HasPrefix(upper, "RUN ") {
			command := strings.TrimSpace(instruction[4:])
			if dockerGoBuildMatches(command, profile.BinaryPackage, proof.BuildOutput, expectedTags) {
				buildFound = true
			}
		}
		if strings.HasPrefix(upper, "COPY ") {
			fields := strings.Fields(instruction)
			if len(fields) == 4 && fields[0] == "COPY" && fields[1] == "--from=build" && fields[2] == proof.BuildOutput && fields[3] == proof.BinaryPath {
				copyFound = true
			}
		}
		if strings.HasPrefix(upper, "ENTRYPOINT ") {
			var argv []string
			if json.Unmarshal([]byte(strings.TrimSpace(instruction[len("ENTRYPOINT "):])), &argv) == nil && len(argv) == 1 && argv[0] == proof.BinaryPath {
				entrypointFound = true
			}
		}
	}
	if !cgoFound {
		return fmt.Errorf("missing exact CGO_ENABLED=%s in build environment", profile.CGOEnabled)
	}
	if !goosFound || !goarchFound {
		return fmt.Errorf("missing exact GOOS=${TARGETOS} and GOARCH=${TARGETARCH} target binding")
	}
	if !buildFound {
		return fmt.Errorf("missing exact go build package=%s output=%s tags=%v", profile.BinaryPackage, proof.BuildOutput, profile.Tags)
	}
	if !copyFound {
		return fmt.Errorf("missing exact final COPY --from=build %s %s", proof.BuildOutput, proof.BinaryPath)
	}
	if !entrypointFound {
		return fmt.Errorf("missing exact JSON ENTRYPOINT [%q]", proof.BinaryPath)
	}
	return nil
}

func dockerInstructions(source string) []string {
	var out []string
	var current strings.Builder
	for _, raw := range strings.Split(strings.ReplaceAll(source, "\r\n", "\n"), "\n") {
		line := strings.TrimSpace(raw)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		continued := strings.HasSuffix(line, "\\")
		line = strings.TrimSpace(strings.TrimSuffix(line, "\\"))
		if current.Len() > 0 {
			current.WriteByte(' ')
		}
		current.WriteString(line)
		if continued {
			continue
		}
		out = append(out, current.String())
		current.Reset()
	}
	if current.Len() > 0 {
		out = append(out, current.String())
	}
	return out
}

func envAssignment(source, key string) string {
	for _, field := range strings.Fields(source) {
		parts := strings.SplitN(field, "=", 2)
		if len(parts) == 2 && parts[0] == key {
			return strings.TrimSpace(parts[1])
		}
	}
	return ""
}

func dockerGoBuildMatches(command, packageName, output string, expectedTags []string) bool {
	if !strings.HasPrefix(command, "go build ") || !strings.HasSuffix(command, " "+packageName) {
		return false
	}
	outputPattern := regexp.MustCompile(`(?:^|[[:space:]])-o[[:space:]]+` + regexp.QuoteMeta(output) + `(?:[[:space:]]|$)`)
	if !outputPattern.MatchString(command) {
		return false
	}
	tagPattern := regexp.MustCompile(`(?:^|[[:space:]])-tags(?:=|[[:space:]]+)([^[:space:]]+)`)
	match := tagPattern.FindStringSubmatch(command)
	if len(expectedTags) == 0 {
		return match == nil
	}
	if match == nil {
		return false
	}
	actual := strings.Split(strings.Trim(match[1], `"'`), ",")
	sort.Strings(actual)
	return strings.Join(actual, ",") == strings.Join(expectedTags, ",")
}
