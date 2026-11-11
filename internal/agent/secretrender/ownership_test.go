// SPDX-License-Identifier: BUSL-1.1

package secretrender

import (
	"runtime"
	"strings"
	"testing"
)

// TestTemplateOwnershipNeedsRootA238L2: a template that gives its file to an
// owner or a group is refused unless the agent runs as root (and on
// Windows); as root, numeric IDs are taken as written and names come from the
// system database; an unknown name is refused, and only the set half changes.
func TestTemplateOwnershipNeedsRootA238L2(t *testing.T) {
	base := Config{Server: "unused", TokenFile: "unused", Consumer: "web-1/app", StateDir: t.TempDir()}
	withTemplate := func(owner, group string) *Config {
		c := base
		c.Templates = []Template{{Name: "app", Destination: "/etc/app/secret", Text: "x", Owner: owner, Group: group}}
		return &c
	}
	if runtime.GOOS == "windows" {
		if err := withTemplate("app", "").Validate(); err == nil || !strings.Contains(err.Error(), "DACL") {
			t.Fatalf("owner on Windows = %v, want the DACL refusal", err)
		}
		return
	}
	defer func(prev func() int) { effectiveUID = prev }(effectiveUID)

	effectiveUID = func() int { return 1000 }
	if err := withTemplate("nobody", "").Validate(); err == nil || !strings.Contains(err.Error(), "needs the agent to run as root") {
		t.Fatalf("an owner without root = %v", err)
	}
	if err := withTemplate("", "").Validate(); err != nil {
		t.Fatalf("no owner without root = %v", err)
	}

	effectiveUID = func() int { return 0 }
	own, err := Template{Name: "app", Owner: "123", Group: "456"}.ownership()
	if err != nil || own.uid != 123 || own.gid != 456 {
		t.Fatalf("numeric owner and group = %+v, %v", own, err)
	}
	own, err = Template{Name: "app", Group: "456"}.ownership()
	if err != nil || own.uid != -1 || own.gid != 456 {
		t.Fatalf("group alone = %+v, %v", own, err)
	}
	if _, err := (Template{Name: "app", Owner: "no-such-user-a238l2"}).ownership(); err == nil || !strings.Contains(err.Error(), `owner "no-such-user-a238l2"`) {
		t.Fatalf("an unknown owner = %v", err)
	}
	if _, err := (Template{Name: "app", Owner: "-5"}).ownership(); err == nil {
		t.Fatal("a negative owner ID was taken")
	}
	if own, err := (Template{Name: "app", Owner: "root"}).ownership(); err != nil || own.uid != 0 {
		t.Fatalf("owner root by name = %+v, %v", own, err)
	}
	if err := withTemplate("root", "").Validate(); err != nil {
		t.Fatalf("an owner as root = %v", err)
	}
}
