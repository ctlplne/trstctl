// SPDX-License-Identifier: LicenseRef-trstctl-EE

package rounds

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"hash/fnv"
	"sort"
	"strings"
	"time"

	"trstctl.com/trstctl/ee/reconcile/digest"
	"trstctl.com/trstctl/internal/eventspec"
)

var ErrInvalidConfig = errors.New("xrec rounds: invalid scheduler config")

type Option func(*Scheduler)

type Scheduler struct {
	cfg     Config
	source  DigestSource
	log     EventAppender
	tracker *WatermarkTracker

	clock  func() time.Time
	idgen  func(time.Time) string
	jitter func(time.Duration) time.Duration

	nextDue time.Time
}

func NewScheduler(cfg Config, source DigestSource, log EventAppender, opts ...Option) (*Scheduler, error) {
	cfg, err := normalizeConfig(cfg)
	if err != nil {
		return nil, err
	}
	if source == nil || log == nil {
		return nil, fmt.Errorf("%w: source and event appender are required", ErrInvalidConfig)
	}
	tracker := NewWatermarkTracker(cfg.Liveness)
	for _, plane := range cfg.Planes {
		tracker.SetLiveness(plane.AuthorityID, plane.Liveness)
	}
	s := &Scheduler{
		cfg:     cfg,
		source:  source,
		log:     log,
		tracker: tracker,
		clock:   func() time.Time { return time.Now().UTC() },
		idgen:   defaultRoundID,
		jitter:  deterministicJitter,
	}
	for _, opt := range opts {
		opt(s)
	}
	return s, nil
}

func WithClock(f func() time.Time) Option {
	return func(s *Scheduler) {
		if f != nil {
			s.clock = f
		}
	}
}

func WithIDGenerator(f func(time.Time) string) Option {
	return func(s *Scheduler) {
		if f != nil {
			s.idgen = f
		}
	}
}

func WithJitter(f func(time.Duration) time.Duration) Option {
	return func(s *Scheduler) {
		if f != nil {
			s.jitter = f
		}
	}
}

func (s *Scheduler) NextDue() time.Time {
	return s.nextDue
}

func (s *Scheduler) RunDue(ctx context.Context) (RoundResult, bool, error) {
	now := s.clock().UTC()
	if !s.nextDue.IsZero() && now.Before(s.nextDue) {
		return RoundResult{}, false, nil
	}
	roundID := strings.TrimSpace(s.idgen(now))
	if roundID == "" {
		roundID = defaultRoundID(now)
	}
	result, err := s.runRound(ctx, roundID, now)
	s.nextDue = now.Add(s.cfg.Cadence + clampJitter(s.jitter(s.cfg.Jitter), s.cfg.Jitter))
	return result, true, err
}

func (s *Scheduler) runRound(ctx context.Context, roundID string, now time.Time) (RoundResult, error) {
	if err := s.appendEvent(ctx, EventTypeRoundInitiated, RoundInitiated{
		RoundID:        roundID,
		TenantID:       s.cfg.TenantID,
		PlaneIDs:       s.planeIDs(),
		InitiatedAt:    now.Format(time.RFC3339Nano),
		CadenceSeconds: int64(s.cfg.Cadence.Seconds()),
	}); err != nil {
		return RoundResult{}, err
	}

	var (
		result RoundResult
		bodies []digest.Body
		retErr error
	)
	result.RoundID = roundID
	for _, plane := range s.cfg.Planes {
		signed, err := s.source.DigestForRound(ctx, DigestRequest{
			RoundID: roundID, TenantID: s.cfg.TenantID, AuthorityID: plane.AuthorityID,
		})
		if err != nil {
			return result, err
		}
		ref, wm, err := digestRef(plane.AuthorityID, signed)
		if err != nil {
			return result, err
		}
		result.Digests = append(result.Digests, ref)
		bodies = append(bodies, signed.Body)
		decision, derr := s.tracker.Advance(plane.AuthorityID, wm, now)
		if decision.Divergent {
			div := Divergence{
				AuthorityID: plane.AuthorityID,
				Class:       decision.Class,
				Reason:      decision.Reason,
				Watermark:   decision.Current,
				Err:         derr,
			}
			result.Divergences = append(result.Divergences, div)
			if err := s.appendStaleness(ctx, roundID, plane.AuthorityID, decision, now); err != nil {
				return result, err
			}
		}
		if derr != nil && retErr == nil {
			retErr = derr
		}
	}
	if len(result.Divergences) == 0 && bodiesAgree(bodies) {
		result.Agreed = true
		if err := s.appendEvent(ctx, EventTypeRoundAgreement, RoundAgreement{
			RoundID:    roundID,
			TenantID:   s.cfg.TenantID,
			Digests:    result.Digests,
			Semantics:  SemanticsAgreementAsOfWatermarks,
			RecordedAt: now.Format(time.RFC3339Nano),
		}); err != nil {
			return result, err
		}
	}
	return result, retErr
}

func (s *Scheduler) appendStaleness(ctx context.Context, roundID, authorityID string, decision WatermarkDecision, now time.Time) error {
	return s.appendEvent(ctx, EventTypeRoundStaleness, StalenessDivergence{
		RoundID:         roundID,
		TenantID:        s.cfg.TenantID,
		AuthorityID:     authorityID,
		DivergenceClass: decision.Class,
		Reason:          decision.Reason,
		Watermark:       decision.Current,
		Previous:        decision.Previous,
		RecordedAt:      now.Format(time.RFC3339Nano),
	})
}

func (s *Scheduler) appendEvent(ctx context.Context, typ string, payload any) error {
	data, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	_, err = s.log.Append(ctx, eventspec.Event{
		Type:          typ,
		TenantID:      s.cfg.TenantID,
		SchemaVersion: eventspec.DefaultSchemaVersion,
		Data:          data,
	})
	return err
}

func (s *Scheduler) planeIDs() []string {
	out := make([]string, 0, len(s.cfg.Planes))
	for _, plane := range s.cfg.Planes {
		out = append(out, plane.AuthorityID)
	}
	return out
}

func normalizeConfig(cfg Config) (Config, error) {
	cfg.TenantID = strings.TrimSpace(cfg.TenantID)
	if cfg.TenantID == "" {
		return Config{}, fmt.Errorf("%w: tenant id required", ErrInvalidConfig)
	}
	if cfg.Cadence <= 0 {
		return Config{}, fmt.Errorf("%w: cadence must be positive", ErrInvalidConfig)
	}
	if cfg.Liveness <= 0 {
		cfg.Liveness = 2 * cfg.Cadence
	}
	if len(cfg.Planes) < 2 {
		return Config{}, fmt.Errorf("%w: at least two planes required", ErrInvalidConfig)
	}
	seen := map[string]struct{}{}
	for i := range cfg.Planes {
		id := strings.TrimSpace(cfg.Planes[i].AuthorityID)
		if id == "" {
			return Config{}, fmt.Errorf("%w: authority id required", ErrInvalidConfig)
		}
		if _, ok := seen[id]; ok {
			return Config{}, fmt.Errorf("%w: duplicate authority %q", ErrInvalidConfig, id)
		}
		seen[id] = struct{}{}
		cfg.Planes[i].AuthorityID = id
		if cfg.Planes[i].Liveness <= 0 {
			cfg.Planes[i].Liveness = cfg.Liveness
		}
	}
	if cfg.Jitter < 0 {
		cfg.Jitter = -cfg.Jitter
	}
	return cfg, nil
}

func digestRef(authorityID string, signed digest.SignedDigest) (DigestRef, Watermark, error) {
	hash := append([]byte(nil), signed.DigestHash...)
	if len(hash) == 0 {
		h, err := signed.Body.DigestHash()
		if err != nil {
			return DigestRef{}, Watermark{}, err
		}
		hash = h
	}
	if signed.Body.AuthorityID != authorityID {
		return DigestRef{}, Watermark{}, fmt.Errorf("%w: digest authority %q does not match %q", ErrInvalidConfig, signed.Body.AuthorityID, authorityID)
	}
	wm := Watermark{
		Position:   signed.Body.Watermark.Position,
		ObservedAt: time.Unix(signed.Body.Watermark.ObservedAt, 0).UTC(),
	}
	return DigestRef{
		AuthorityID:       authorityID,
		DigestHash:        hex.EncodeToString(hash),
		WatermarkPosition: wm.Position,
		WatermarkTime:     wm.ObservedAt,
	}, wm, nil
}

func bodiesAgree(bodies []digest.Body) bool {
	if len(bodies) < 2 {
		return false
	}
	first := bodies[0]
	for _, body := range bodies[1:] {
		if !stateBodyEqual(first, body) {
			return false
		}
	}
	return true
}

func stateBodyEqual(a, b digest.Body) bool {
	if a.SpecVersion != b.SpecVersion || a.TenantID != b.TenantID || a.RecordCount != b.RecordCount || a.HashAlg != b.HashAlg {
		return false
	}
	if !bytes.Equal(a.MerkleRoot, b.MerkleRoot) || !bytes.Equal(a.PostureSummary.PolicySetHash, b.PostureSummary.PolicySetHash) {
		return false
	}
	pa := append([]digest.RuleCount(nil), a.PostureSummary.PerRule...)
	pb := append([]digest.RuleCount(nil), b.PostureSummary.PerRule...)
	sort.Slice(pa, func(i, j int) bool { return pa[i].RuleID < pa[j].RuleID })
	sort.Slice(pb, func(i, j int) bool { return pb[i].RuleID < pb[j].RuleID })
	if len(pa) != len(pb) {
		return false
	}
	for i := range pa {
		if pa[i] != pb[i] {
			return false
		}
	}
	return true
}

func defaultRoundID(now time.Time) string {
	return "xrec-round-" + now.UTC().Format("20060102T150405.000000000Z")
}

func deterministicJitter(max time.Duration) time.Duration {
	if max <= 0 {
		return 0
	}
	h := fnv.New64a()
	_, _ = h.Write([]byte(time.Now().UTC().Format(time.RFC3339Nano)))
	span := int64(max) * 2
	if span <= 0 {
		return 0
	}
	return time.Duration(int64(h.Sum64()%uint64(span+1)) - int64(max))
}

func clampJitter(v, max time.Duration) time.Duration {
	if max <= 0 {
		return 0
	}
	if v > max {
		return max
	}
	if v < -max {
		return -max
	}
	return v
}
