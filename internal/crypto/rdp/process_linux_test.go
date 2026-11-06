// SPDX-License-Identifier: BUSL-1.1

package rdp

import (
	"context"
	"reflect"
	"testing"
)

func TestNativeHelperReplacesInheritedArgumentsAndEnvironment(t *testing.T) {
	t.Setenv("LD_PRELOAD", "untrusted-parent-preload")
	t.Setenv("UPSTREAM_PASSWORD", "untrusted-parent-value")
	cmd := nativeCommand(context.Background(), nil)
	if !reflect.DeepEqual(cmd.Args, []string{"/proc/self/fd/3"}) || !reflect.DeepEqual(cmd.Env, []string{"PATH=/usr/bin:/bin", "HOME=/nonexistent", "WLOG_LEVEL=OFF"}) || len(cmd.ExtraFiles) != 1 {
		t.Fatal("native credential process inherited parent arguments or environment")
	}
}

func TestNativeHelperRequiresProtocolProbe(t *testing.T) {
	if CheckHelper("/bin/true") == nil {
		t.Fatal("unrelated executable advertised as a native desktop helper")
	}
}
