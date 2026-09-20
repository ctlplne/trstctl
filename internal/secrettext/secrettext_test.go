// SPDX-License-Identifier: BUSL-1.1

package secrettext

import "testing"

func TestPrefixedBuildsEdgeStringWithoutMutatingSource(t *testing.T) {
	src := []byte("token-value")
	got := Prefixed("Bearer ", src)
	if got != "Bearer token-value" {
		t.Fatalf("Prefixed() = %q", got)
	}
	if string(src) != "token-value" {
		t.Fatalf("Prefixed mutated source bytes: %q", src)
	}
}

func TestCloneOwnsCredentialBytes(t *testing.T) {
	src := []byte("credential")
	got := Clone(src)
	src[0] = 'X'
	if string(got) != "credential" {
		t.Fatalf("Clone aliases source, got %q", got)
	}
}
