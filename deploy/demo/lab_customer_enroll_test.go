// SPDX-License-Identifier: BUSL-1.1

package demo

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// Exercise the operator entrypoint with a recording Docker process. Real
// enrollment is an installed journey; these cases prevent the launcher from
// rebuilding/reconciling a running licensed lab or exposing token bytes.
func TestCustomerEnrollmentPreservesRunningLab(t *testing.T) {
	for _, tc := range []struct {
		name, project, image, stopped string
		mode                          os.FileMode
		wantRun                       bool
	}{
		{name: "project image", project: "owned-provider", mode: 0o600, wantRun: true},
		{name: "custom image", project: "owned-provider", image: "owned-seed:v2", mode: 0o400, wantRun: true},
		{name: "invalid project", project: "other;project", mode: 0o600},
		{name: "public token", project: "owned-provider", mode: 0o644},
		{name: "stopped control plane", project: "owned-provider", mode: 0o600, stopped: "trstctl"},
		{name: "stopped front door", project: "owned-provider", mode: 0o600, stopped: "frontdoors-lab"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			root, err := os.OpenRoot(dir)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = root.Close() })
			log := filepath.Join(dir, "docker.calls")
			tokenFile := filepath.Join(dir, "customer token")
			const token = "private-customer-token-never-in-process-arguments"
			if err := os.WriteFile(tokenFile, []byte(token), tc.mode); err != nil {
				t.Fatal(err)
			}
			if err := os.Chmod(tokenFile, tc.mode); err != nil {
				t.Fatal(err)
			}
			shim := `#!/bin/sh
printf '%s\n' BEGIN "$@" END >> "$QA_DOCKER_LOG"
if [ "$1" = image ] && [ "$2" = inspect ]; then
  printf '%s\n' sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
  exit 0
fi
mode=""
last=""
for arg do
  case "$arg" in ps|run) mode="$arg" ;; esac
  last="$arg"
done
case "$mode" in
  ps) [ "$last" = "$QA_STOPPED_SERVICE" ] || printf '%s\n' aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa ; exit 0 ;;
  run) exit 0 ;;
  *) exit 99 ;;
esac
`
			// Publish one new owner-only executable inside the test root. An
			// existing file/symlink cannot be followed or overwritten.
			shimFile, err := root.OpenFile("docker", os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o500)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = shimFile.Close() })
			if _, err := shimFile.WriteString(shim); err != nil {
				t.Fatal(err)
			}
			if err := shimFile.Close(); err != nil {
				t.Fatal(err)
			}
			info, err := root.Stat("docker")
			if err != nil || info.Mode().Perm() != 0o500 {
				t.Fatalf("helper must be published as an owner-only executable: %v", err)
			}
			t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))
			t.Setenv("QA_DOCKER_LOG", log)
			t.Setenv("QA_STOPPED_SERVICE", tc.stopped)
			t.Setenv("TRSTCTL_LAB_PROJECT", tc.project)
			t.Setenv("TRSTCTL_DEMO_SEED_IMAGE", tc.image)
			t.Setenv("TRSTCTL_LAB_CUSTOMER_TOKEN_FILE", tokenFile)
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			output, err := exec.CommandContext(ctx, "sh", "lab/enroll-customer.sh").CombinedOutput()
			if (err == nil) != tc.wantRun {
				t.Fatalf("launcher error=%v, want enrollment=%t: %s", err, tc.wantRun, output)
			}
			calls, readErr := root.ReadFile("docker.calls")
			if readErr != nil && !os.IsNotExist(readErr) {
				t.Fatal(readErr)
			}
			trace := string(calls)
			if strings.Contains(trace+string(output), token) {
				t.Fatal("launcher exposed the token")
			}
			for _, forbidden := range []string{"\nup\n", "\nbuild\n", "\nstart\n", "\nrestart\n", "\ndown\n", "\npull\n"} {
				if strings.Contains(trace, forbidden) {
					t.Fatalf("launcher changed the running lab: %s", trace)
				}
			}
			if !tc.wantRun {
				if strings.Contains(trace, "\nrun\n") {
					t.Fatal("refused setup nevertheless started enrollment")
				}
				return
			}
			wantImage := tc.image
			if wantImage == "" {
				wantImage = tc.project + "-seed:local"
			}
			if !strings.Contains(trace, "\n"+wantImage+"\n") {
				t.Fatalf("did not resolve the project's installed helper image: %s", trace)
			}
			for _, call := range strings.Split(trace, "BEGIN\n") {
				if !strings.Contains(call, "\nrun\n") {
					continue
				}
				for _, required := range []string{"\n-p\n" + tc.project + "\n", "\n--profile\npartner-lab\n", "\n--profile\npartner-lab-customer\n", "\n--no-deps\n", "\n--pull\nnever\n", "\nlab-customer-enroll\n"} {
					if !strings.Contains(call, required) {
						t.Fatalf("unsafe enrollment invocation missing %q: %s", required, call)
					}
				}
			}
			if strings.Count(trace, "\nrun\n") != 1 {
				t.Fatalf("want one enrollment invocation: %s", trace)
			}
		})
	}
}
