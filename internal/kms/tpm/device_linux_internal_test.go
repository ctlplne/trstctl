//go:build linux

// SPDX-License-Identifier: MPL-2.0

package tpm

import (
	"encoding/binary"
	"strings"
	"testing"

	gotpm "github.com/google/go-tpm/legacy/tpm2"

	"trstctl.com/trstctl/internal/crypto"
)

func TestConfiguredPersistentHandleBaseBoundaries(t *testing.T) {
	const (
		persistentFirst = uint32(gotpm.PersistentFirst)
		platformFirst   = uint32(gotpm.PlatformPersistent)
	)
	tests := []struct {
		name       string
		configured uint32
		want       uint32
		wantErr    bool
	}{
		{name: "default", configured: 0, want: defaultPersistentHandleBase},
		{name: "below persistent range", configured: persistentFirst - 1, wantErr: true},
		{name: "persistent lower boundary", configured: persistentFirst, want: persistentFirst},
		{name: "owner upper boundary", configured: platformFirst - 0x100, want: platformFirst - 0x100},
		{name: "first platform-overlapping window", configured: platformFirst - 0xff, wantErr: true},
		{name: "platform range", configured: platformFirst, wantErr: true},
		{name: "uint32 wraparound", configured: ^uint32(0), wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := configuredPersistentHandleBase(tt.configured)
			if tt.wantErr {
				if err == nil {
					t.Fatalf("configuredPersistentHandleBase(0x%08x) = 0x%08x, want error", tt.configured, got)
				}
				return
			}
			if err != nil {
				t.Fatalf("configuredPersistentHandleBase(0x%08x): %v", tt.configured, err)
			}
			if got != tt.want {
				t.Fatalf("configuredPersistentHandleBase(0x%08x) = 0x%08x, want 0x%08x", tt.configured, got, tt.want)
			}
		})
	}
}

func TestOpenDeviceRejectsInvalidPersistentHandleBaseBeforeOpeningTransport(t *testing.T) {
	_, err := OpenDevice(DeviceConfig{
		Path:                 "/path/that/must/not/be-opened",
		PersistentHandleBase: uint32(gotpm.PersistentFirst) - 1,
	})
	if err == nil {
		t.Fatal("OpenDevice accepted a handle base below the persistent range")
	}
	if !strings.Contains(err.Error(), "persistent handle base") {
		t.Fatalf("OpenDevice error = %q, want persistent handle base validation", err)
	}
}

func TestOwnerOperationHandleRangeExcludesPlatformHierarchy(t *testing.T) {
	const operationID = "managedkey:f33ac9bf481b73ddbe76e35b7cdaaea2c591394475d895912ceb23dba3d07123"
	tag, err := crypto.Digest(crypto.SHA256, []byte("trstctl:tpm2:managed-key:"+operationID))
	if err != nil {
		t.Fatal(err)
	}
	minHandle, maxHandle, err := ownerOperationHandleRange(defaultPersistentHandleBase)
	if err != nil {
		t.Fatal(err)
	}
	if maxHandle != uint64(gotpm.PlatformPersistent)-1 {
		t.Fatalf("owner operation max handle = 0x%08x, want 0x%08x", maxHandle, uint64(gotpm.PlatformPersistent)-1)
	}
	legacyCandidate := minHandle + (binary.BigEndian.Uint64(tag[:8]) % (uint64(gotpm.PersistentLast) - minHandle + 1))
	if legacyCandidate < uint64(gotpm.PlatformPersistent) {
		t.Fatalf("regression fixture legacy candidate = 0x%08x, want platform-persistent range", legacyCandidate)
	}
	ownerCandidate := minHandle + (binary.BigEndian.Uint64(tag[:8]) % (maxHandle - minHandle + 1))
	if ownerCandidate >= uint64(gotpm.PlatformPersistent) {
		t.Fatalf("owner-authorized operation candidate = 0x%08x, entered platform hierarchy", ownerCandidate)
	}
}

func TestOwnerOperationHandleRangeRejectsPlatformBase(t *testing.T) {
	if _, _, err := ownerOperationHandleRange(uint32(gotpm.PlatformPersistent)); err == nil {
		t.Fatal("platform-persistent base was accepted for owner-authorized operations")
	}
}
