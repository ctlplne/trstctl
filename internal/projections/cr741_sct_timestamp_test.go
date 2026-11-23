// SPDX-License-Identifier: BUSL-1.1

package projections

import (
	"math"
	"strings"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/store"
)

func TestCR741SCTTimeCannotPoisonPostgresProjection(t *testing.T) {
	pl := CertificateSCTRecorded{
		SubmissionID: "11111111-1111-4111-8111-111111111111", LeafFingerprint: strings.Repeat("a", 64),
		LogURL: "https://ct.example.test", EntryType: "certificate",
		SCTStatus: store.SCTUnverified, SCTReason: "no log key",
	}
	for _, timestamp := range []uint64{math.MaxUint64, math.MaxInt64, uint64(time.Date(294277, 1, 1, 0, 0, 0, 0, time.UTC).UnixMilli())} {
		pl.SCTTimestampMillis = timestamp
		if err := ValidateCertificateSCTRecorded(pl); err == nil {
			t.Errorf("SCT timestamp %d passed projection admission", timestamp)
		}
	}
}

func TestCR741SCTClockWindowIsOnlyCheckedAtAdmission(t *testing.T) {
	clock := time.Now()
	if err := ValidateCertificateSCTTimestampAt(uint64(clock.Add(4*time.Minute).UnixMilli()), clock); err != nil {
		t.Fatalf("an SCT four minutes ahead exceeded the five-minute allowance: %v", err)
	}
	if err := ValidateCertificateSCTTimestampAt(uint64(clock.Add(6*time.Minute).UnixMilli()), clock); err == nil {
		t.Fatal("an SCT six minutes ahead passed the five-minute allowance")
	}
	issued := time.Now().Add(-time.Hour)
	if err := ValidateCertificateSCTTimestampAt(uint64(issued.UnixMilli()), issued); err != nil {
		t.Fatalf("an SCT issued at the admission time was refused: %v", err)
	}
	pl := CertificateSCTRecorded{
		SubmissionID: "11111111-1111-4111-8111-111111111111", LeafFingerprint: strings.Repeat("a", 64),
		LogURL: "https://ct.example.test", EntryType: "certificate", SCTTimestampMillis: uint64(issued.UnixMilli()),
		SCTStatus: store.SCTUnverified, SCTReason: "no log key",
	}
	if err := ValidateCertificateSCTRecorded(pl); err != nil {
		t.Fatalf("replay of a past accepted SCT was refused: %v", err)
	}
}
