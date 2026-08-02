// SPDX-License-Identifier: LicenseRef-trstctl-EE

package rounds_test

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"trstctl.com/trstctl/ee/reconcile/canon"
	"trstctl.com/trstctl/ee/reconcile/digest"
	"trstctl.com/trstctl/ee/reconcile/rounds"
	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/eventspec"
)

// Exercises anti-entropy round scheduling (XREC-claim-3).
func TestRounds_ScheduledPerConfig(t *testing.T) {
	now := time.Date(2026, 7, 8, 4, 0, 0, 0, time.UTC)
	log := &memoryLog{}
	root := bytes.Repeat([]byte{0x99}, 32)
	src := digestSource{
		"vault": signedDigest(t, "tenant-a", "vault", "42", root),
		"kms":   signedDigest(t, "tenant-a", "kms", "84", root),
	}
	s, err := rounds.NewScheduler(rounds.Config{
		TenantID: "tenant-a",
		Cadence:  time.Hour,
		Jitter:   10 * time.Minute,
		Planes: []rounds.PlaneConfig{
			{AuthorityID: "vault", Liveness: 2 * time.Hour},
			{AuthorityID: "kms", Liveness: 2 * time.Hour},
		},
	}, src, log, rounds.WithClock(func() time.Time { return now }), rounds.WithIDGenerator(func(time.Time) string { return "round-001" }), rounds.WithJitter(func(max time.Duration) time.Duration { return max / 2 }))
	if err != nil {
		t.Fatalf("NewScheduler: %v", err)
	}

	result, fired, err := s.RunDue(context.Background())
	if err != nil {
		t.Fatalf("RunDue: %v", err)
	}
	if !fired || result.RoundID != "round-001" {
		t.Fatalf("fired=%v round=%q, want true round-001", fired, result.RoundID)
	}
	if got := src.calls(); !equalStrings(got, []string{"vault", "kms"}) {
		t.Fatalf("digest calls = %v, want [vault kms]", got)
	}
	if len(log.events) == 0 || log.events[0].Type != rounds.EventTypeRoundInitiated {
		t.Fatalf("first event = %#v, want %s", log.events, rounds.EventTypeRoundInitiated)
	}
	var initiated rounds.RoundInitiated
	decodeEvent(t, log.events[0], &initiated)
	if initiated.RoundID != "round-001" || initiated.TenantID != "tenant-a" {
		t.Fatalf("initiated payload = %+v", initiated)
	}
	if got := s.NextDue(); got.Before(now.Add(50*time.Minute)) || got.After(now.Add(70*time.Minute)) {
		t.Fatalf("NextDue = %s, want cadence ± jitter around %s", got, now.Add(time.Hour))
	}
}

// Exercises monotone watermark advance (XREC-claim-3).
func TestRounds_WatermarkMonotonic(t *testing.T) {
	tracker := rounds.NewWatermarkTracker(time.Hour)
	base := time.Date(2026, 7, 8, 4, 0, 0, 0, time.UTC)
	if decision, err := tracker.Advance("vault", rounds.Watermark{Position: "10", ObservedAt: base}, base); err != nil || decision.Divergent {
		t.Fatalf("first advance decision=%+v err=%v, want accepted", decision, err)
	}
	decision, err := tracker.Advance("vault", rounds.Watermark{Position: "9", ObservedAt: base.Add(time.Minute)}, base.Add(time.Minute))
	if !errors.Is(err, rounds.ErrWatermarkRegressed) {
		t.Fatalf("regressed watermark err = %v, want ErrWatermarkRegressed", err)
	}
	if !decision.Divergent || decision.Class != rounds.DivergenceClassStaleness || decision.Reason != rounds.StalenessReasonRegressed {
		t.Fatalf("regression decision = %+v, want staleness divergence", decision)
	}
}

func TestRounds_AgreementRecordBindsDigests(t *testing.T) {
	now := time.Date(2026, 7, 8, 4, 0, 0, 0, time.UTC)
	log := &memoryLog{}
	root := bytes.Repeat([]byte{0x99}, 32)
	a := signedDigest(t, "tenant-a", "vault", "42", root)
	b := signedDigest(t, "tenant-a", "kms", "84", root)
	src := digestSource{"vault": a, "kms": b}
	s := mustScheduler(t, now, src, log)

	result, fired, err := s.RunDue(context.Background())
	if err != nil {
		t.Fatalf("RunDue: %v", err)
	}
	if !fired || !result.Agreed || len(result.Divergences) != 0 {
		t.Fatalf("result = %+v, want agreement", result)
	}
	ev := findEvent(t, log.events, rounds.EventTypeRoundAgreement)
	var agreement rounds.RoundAgreement
	decodeEvent(t, ev, &agreement)
	if agreement.Semantics != rounds.SemanticsAgreementAsOfWatermarks {
		t.Fatalf("semantics = %q, want as-of-watermarks", agreement.Semantics)
	}
	wantA := hex.EncodeToString(a.DigestHash)
	wantB := hex.EncodeToString(b.DigestHash)
	if !hasDigestHash(agreement.Digests, "vault", wantA) || !hasDigestHash(agreement.Digests, "kms", wantB) {
		t.Fatalf("agreement digests = %+v, want vault=%s kms=%s", agreement.Digests, wantA, wantB)
	}
	if bytes.Equal(a.DigestHash, b.DigestHash) {
		t.Fatal("test fixture must use plane-scoped digest hashes so the agreement binds both")
	}
}

func TestRounds_StalenessIsDivergence(t *testing.T) {
	tracker := rounds.NewWatermarkTracker(time.Hour)
	base := time.Date(2026, 7, 8, 4, 0, 0, 0, time.UTC)
	if _, err := tracker.Advance("vault", rounds.Watermark{Position: "10", ObservedAt: base}, base); err != nil {
		t.Fatalf("initial advance: %v", err)
	}
	decision, err := tracker.Advance("vault", rounds.Watermark{Position: "10", ObservedAt: base}, base.Add(time.Hour+time.Second))
	if err != nil {
		t.Fatalf("stalled advance: %v", err)
	}
	if !decision.Divergent || decision.Class != rounds.DivergenceClassStaleness || decision.Reason != rounds.StalenessReasonStalled {
		t.Fatalf("stalled decision = %+v, want staleness divergence", decision)
	}
}

// A regressed watermark becomes staleness (XREC-claims-3, 22).
func TestRounds_RegressedWatermarkTreatedStale(t *testing.T) {
	clock := time.Date(2026, 7, 8, 4, 0, 0, 0, time.UTC)
	log := &memoryLog{}
	root := bytes.Repeat([]byte{0x99}, 32)
	src := digestSource{
		"vault": signedDigest(t, "tenant-a", "vault", "10", root),
		"kms":   signedDigest(t, "tenant-a", "kms", "10", root),
	}
	s, err := rounds.NewScheduler(rounds.Config{
		TenantID: "tenant-a",
		Cadence:  time.Hour,
		Planes: []rounds.PlaneConfig{
			{AuthorityID: "vault", Liveness: time.Hour},
			{AuthorityID: "kms", Liveness: time.Hour},
		},
	}, src, log, rounds.WithClock(func() time.Time { return clock }), rounds.WithIDGenerator(func(time.Time) string { return "round-001" }))
	if err != nil {
		t.Fatalf("NewScheduler: %v", err)
	}
	if _, _, err := s.RunDue(context.Background()); err != nil {
		t.Fatalf("first RunDue: %v", err)
	}

	src["vault"] = signedDigest(t, "tenant-a", "vault", "9", root)
	clock = clock.Add(time.Hour)
	_, _, err = s.RunDue(context.Background())
	if !errors.Is(err, rounds.ErrWatermarkRegressed) {
		t.Fatalf("second RunDue err = %v, want ErrWatermarkRegressed", err)
	}
	ev := findEvent(t, log.events, rounds.EventTypeRoundStaleness)
	var stale rounds.StalenessDivergence
	decodeEvent(t, ev, &stale)
	if stale.AuthorityID != "vault" || stale.DivergenceClass != rounds.DivergenceClassStaleness || stale.Reason != rounds.StalenessReasonRegressed {
		t.Fatalf("staleness payload = %+v, want vault regressed", stale)
	}
}

type memoryLog struct {
	events []eventspec.Event
}

func (m *memoryLog) Append(_ context.Context, e eventspec.Event) (eventspec.Event, error) {
	e.Sequence = uint64(len(m.events) + 1)
	m.events = append(m.events, e)
	return e, nil
}

type digestSource map[string]digest.SignedDigest

func (d digestSource) DigestForRound(_ context.Context, req rounds.DigestRequest) (digest.SignedDigest, error) {
	calls := d["__calls__"]
	calls.Body.AuthorityID += "," + req.AuthorityID
	d["__calls__"] = calls
	if out, ok := d[req.AuthorityID]; ok {
		return out, nil
	}
	return digest.SignedDigest{}, errors.New("missing digest fixture")
}

func (d digestSource) calls() []string {
	raw := d["__calls__"].Body.AuthorityID
	if raw == "" {
		return nil
	}
	return splitCalls(raw[1:])
}

func mustScheduler(t *testing.T, now time.Time, src digestSource, log *memoryLog) *rounds.Scheduler {
	t.Helper()
	s, err := rounds.NewScheduler(rounds.Config{
		TenantID: "tenant-a",
		Cadence:  time.Hour,
		Planes: []rounds.PlaneConfig{
			{AuthorityID: "vault", Liveness: time.Hour},
			{AuthorityID: "kms", Liveness: time.Hour},
		},
	}, src, log, rounds.WithClock(func() time.Time { return now }), rounds.WithIDGenerator(func(time.Time) string { return "round-001" }))
	if err != nil {
		t.Fatalf("NewScheduler: %v", err)
	}
	return s
}

func signedDigest(t *testing.T, tenantID, authorityID, position string, root []byte) digest.SignedDigest {
	t.Helper()
	if len(root) != 32 {
		t.Fatalf("root len = %d, want 32", len(root))
	}
	body := digest.Body{
		Version:     digest.DigestVersionV1,
		SpecVersion: canon.SpecVersionV1,
		AuthorityID: authorityID,
		TenantID:    tenantID,
		MerkleRoot:  append([]byte(nil), root...),
		RecordCount: 2,
		HashAlg:     digest.HashAlgSHA256,
		PostureSummary: digest.PostureSummary{
			PolicySetHash: bytes.Repeat([]byte{0x42}, 32),
			PerRule: []digest.RuleCount{{
				RuleID:          "active-only",
				SatisfyingCount: 2,
				ViolatingCount:  0,
			}},
		},
		Watermark:   digest.Watermark{Position: position, ObservedAt: time.Date(2026, 7, 8, 4, 0, 0, 0, time.UTC).Unix()},
		GeneratedAt: time.Date(2026, 7, 8, 4, 0, 30, 0, time.UTC).Unix(),
	}
	hash, err := body.DigestHash()
	if err != nil {
		t.Fatalf("DigestHash: %v", err)
	}
	return digest.SignedDigest{
		Body:         body,
		DigestHash:   hash,
		KeyID:        "test-key",
		Algorithm:    crypto.ECDSAP256,
		PublicKeyDER: []byte("public"),
		Signature:    []byte("signature"),
	}
}

func decodeEvent(t *testing.T, e eventspec.Event, out any) {
	t.Helper()
	if err := json.Unmarshal(e.Data, out); err != nil {
		t.Fatalf("decode %s: %v\n%s", e.Type, err, e.Data)
	}
}

func findEvent(t *testing.T, events []eventspec.Event, typ string) eventspec.Event {
	t.Helper()
	for _, e := range events {
		if e.Type == typ {
			return e
		}
	}
	t.Fatalf("event %s not found in %#v", typ, events)
	return eventspec.Event{}
}

func hasDigestHash(in []rounds.DigestRef, authorityID, digestHash string) bool {
	for _, ref := range in {
		if ref.AuthorityID == authorityID && ref.DigestHash == digestHash {
			return true
		}
	}
	return false
}

func equalStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func splitCalls(s string) []string {
	var out []string
	for len(s) > 0 {
		i := 0
		for i < len(s) && s[i] != ',' {
			i++
		}
		out = append(out, s[:i])
		if i == len(s) {
			break
		}
		s = s[i+1:]
	}
	return out
}
