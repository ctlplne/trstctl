// SPDX-License-Identifier: BUSL-1.1

package store

import (
	"errors"
	"testing"
	"time"
)

func TestRecoverUniquePostgresNanosecondRemainderFailsClosed(t *testing.T) {
	base := time.Date(2026, 8, 11, 15, 0, 0, 0, time.UTC)
	want := "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"

	exact, err := recoverUniquePostgresNanosecondRemainder(
		base, want,
		func(candidate time.Time) (string, error) {
			if candidate.Equal(base.Add(731 * time.Nanosecond)) {
				return want, nil
			}
			return "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb", nil
		},
	)
	if err != nil || !exact.Equal(base.Add(731*time.Nanosecond)) {
		t.Fatalf("unique nanosecond proof = %s err=%v", exact, err)
	}

	for _, tc := range []struct {
		name       string
		semantic   string
		semanticAt func(time.Time) (string, error)
	}{
		{
			name: "zero matches", semantic: want,
			semanticAt: func(time.Time) (string, error) {
				return "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb", nil
			},
		},
		{
			name: "multiple matches", semantic: want,
			semanticAt: func(candidate time.Time) (string, error) {
				remainder := candidate.Sub(base)
				if remainder == time.Nanosecond || remainder == 2*time.Nanosecond {
					return want, nil
				}
				return "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb", nil
			},
		},
		{
			name: "invalid digest", semantic: "not-a-sha256",
			semanticAt: func(time.Time) (string, error) {
				t.Fatal("invalid digest reached semantic callback")
				return "", nil
			},
		},
		{
			name: "invalid hexadecimal", semantic: "gggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggg",
			semanticAt: func(time.Time) (string, error) {
				t.Fatal("invalid hexadecimal digest reached semantic callback")
				return "", nil
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := recoverUniquePostgresNanosecondRemainder(
				base, tc.semantic, tc.semanticAt,
			); !errors.Is(err, ErrIdempotencyConflict) {
				t.Fatalf("remainder proof error=%v, want ErrIdempotencyConflict", err)
			}
		})
	}
}
