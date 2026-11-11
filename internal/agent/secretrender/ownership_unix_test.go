// SPDX-License-Identifier: BUSL-1.1

//go:build !windows

package secretrender

import (
	"context"
	"log/slog"
	"os"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"

	"gopkg.in/yaml.v3"
)

// TestRenderGivesTheFileToItsOwnerAsRootA238L2 runs as root (the container
// proof runs this binary as root in a Linux image): the rendered file belongs
// to the template's owner and group from its first write, keeps them across a
// changed value, and no temporary file is left beside it.
func TestRenderGivesTheFileToItsOwnerAsRootA238L2(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("giving a file to another user needs root; the container proof runs this as root")
	}
	owner, group := "nobody", "nogroup"
	if _, err := user.LookupGroup(group); err != nil {
		group = "nobody"
	}
	u, err := user.Lookup(owner)
	if err != nil {
		t.Skipf("no %s user here: %v", owner, err)
	}
	g, err := user.LookupGroup(group)
	if err != nil {
		t.Skipf("no %s group here: %v", group, err)
	}
	wantUID, _ := strconv.Atoi(u.Uid)
	wantGID, _ := strconv.Atoi(g.Gid)

	dir := t.TempDir()
	file := filepath.Join(dir, "app.env")
	src := &fakeSource{values: map[string]string{}, versions: map[string]int{}}
	src.set("app/prod/token", "token-one")
	// The configuration as the agent reads its render file.
	var cfg Config
	if err := yaml.Unmarshal([]byte(`server: unused
token_file: unused
consumer: web-1/app
state_dir: `+filepath.Join(dir, "state")+`
templates:
  - name: app
    destination: `+file+`
    mode: "0440"
    owner: `+owner+`
    group: `+group+`
    template: "TOKEN={{ secret \"app/prod/token\" }}\n"
`), &cfg); err != nil {
		t.Fatal(err)
	}
	r, err := New(cfg, src, &fakeReporter{}, slog.New(slog.NewTextHandler(os.Stderr, nil)))
	if err != nil {
		t.Fatal(err)
	}
	check := func(stage, want string) {
		t.Helper()
		info, err := os.Stat(file)
		if err != nil {
			t.Fatalf("%s: %v", stage, err)
		}
		st, ok := info.Sys().(*syscall.Stat_t)
		if !ok || int(st.Uid) != wantUID || int(st.Gid) != wantGID || info.Mode().Perm() != 0o440 {
			t.Fatalf("%s: %s is %d:%d %v, want %d:%d 0440", stage, file, st.Uid, st.Gid, info.Mode().Perm(), wantUID, wantGID)
		}
		raw, err := os.ReadFile(file) // #nosec G304 -- the test's own temp file (CWE-22)
		if err != nil || string(raw) != want {
			t.Fatalf("%s: content %q, %v", stage, raw, err)
		}
		entries, err := os.ReadDir(dir)
		if err != nil {
			t.Fatal(err)
		}
		for _, e := range entries {
			if strings.Contains(e.Name(), ".trstctl-") {
				t.Fatalf("%s: a temporary file was left: %s", stage, e.Name())
			}
		}
	}
	r.Once(context.Background())
	check("first write", "TOKEN=token-one\n")
	src.set("app/prod/token", "token-two")
	r.Once(context.Background())
	check("changed value", "TOKEN=token-two\n")
	t.Logf("A238L2_OWNERSHIP_OK %s:%s=%d:%d", owner, group, wantUID, wantGID)
}
