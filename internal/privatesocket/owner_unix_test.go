// SPDX-License-Identifier: BUSL-1.1

//go:build aix || android || darwin || dragonfly || freebsd || illumos || ios || linux || netbsd || openbsd || solaris

package privatesocket

import (
	"os"
	"syscall"
	"testing"
)

type ownerTestInfo struct {
	os.FileInfo
	stat *syscall.Stat_t
}

func (i ownerTestInfo) Sys() any { return i.stat }

func TestOwnedByProcessRefusesForeignUID(t *testing.T) {
	info, err := os.Lstat(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	ownStat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		t.Fatal("test filesystem did not expose a Unix uid")
	}
	foreignStat := *ownStat
	foreignStat.Uid++
	own := ownerTestInfo{FileInfo: info, stat: ownStat}
	foreign := ownerTestInfo{FileInfo: info, stat: &foreignStat}
	if okay, err := OwnedByProcess(own); err != nil || !okay {
		t.Fatalf("own uid rejected: %v", err)
	}
	if okay, err := OwnedByProcess(foreign); err != nil || okay {
		t.Fatalf("foreign uid accepted: %v", err)
	}
}
