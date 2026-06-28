// Package nhibehavior normalizes metadata-only non-human identity activity
// observations into anomaly findings. It builds a per-principal baseline from
// known-good events, then flags unfamiliar IP, geo, user-agent, usage-spike, and
// off-hours activity without accepting credential bodies.
package nhibehavior

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"
)

const (
	// SourceKind is the served discovery source kind for CAP-ITDR-01.
	SourceKind = "nhi_behavior"
	// FindingKind is the read-model kind emitted for behavior anomalies.
	FindingKind = "nhi_behavior_anomaly"
	// MaxEvents caps a single served source config so one run cannot exhaust the
	// discovery worker lane.
	MaxEvents = 10000
)

var anomalyOrder = []string{"unfamiliar_ip", "unfamiliar_geo", "unfamiliar_user_agent", "usage_spike", "off_hours"}

// Config is the persisted source configuration for NHI behavior analysis.
// Events are metadata-only activity observations exported from IdPs, SaaS logs,
// cloud audit trails, or API gateways.
type Config struct {
	Events        []Event       `json:"events"`
	BusinessHours BusinessHours `json:"business_hours,omitempty"`
}

// BusinessHours defines the local allowed activity window. Times are evaluated
// against the offset carried by each RFC3339 event timestamp.
type BusinessHours struct {
	StartHour int `json:"start_hour,omitempty"`
	EndHour   int `json:"end_hour,omitempty"`
}

// Event is one NHI activity observation. Baseline events teach normal behavior;
// non-baseline events are scored against the learned per-principal baseline.
type Event struct {
	Principal  string `json:"principal"`
	OccurredAt string `json:"occurred_at"`
	IP         string `json:"ip,omitempty"`
	Geo        string `json:"geo,omitempty"`
	UserAgent  string `json:"user_agent,omitempty"`
	Action     string `json:"action,omitempty"`
	UsageCount int    `json:"usage_count,omitempty"`
	Count      int    `json:"count,omitempty"`
	Baseline   bool   `json:"baseline,omitempty"`
}

// Finding is the normalized discovery finding material emitted by the server.
type Finding struct {
	Ref         string
	Provenance  string
	Fingerprint string
	RiskScore   int
	Metadata    map[string]any
}

type parsedEvent struct {
	Event
	occurredAt time.Time
	usageCount int
}

type principalBaseline struct {
	ips        map[string]bool
	geos       map[string]bool
	userAgents map[string]bool
	totalUsage int
	samples    int
}

// Findings decodes, validates, builds baselines, and emits anomaly findings for
// non-baseline observations. A valid source needs at least one baseline event and
// one observed event, so CAP-ITDR-01 proves both baselining and detection.
func Findings(raw json.RawMessage) ([]Finding, error) {
	var cfg Config
	if err := json.Unmarshal(raw, &cfg); err != nil {
		return nil, fmt.Errorf("decode NHI behavior discovery config: %w", err)
	}
	if len(cfg.Events) == 0 {
		return nil, errors.New("NHI behavior discovery requires events")
	}
	if len(cfg.Events) > MaxEvents {
		return nil, fmt.Errorf("NHI behavior discovery source has %d events; maximum is %d", len(cfg.Events), MaxEvents)
	}
	hours, err := normalizeBusinessHours(cfg.BusinessHours)
	if err != nil {
		return nil, err
	}

	baselines := map[string]*principalBaseline{}
	observed := make([]parsedEvent, 0, len(cfg.Events))
	for i, event := range cfg.Events {
		parsed, err := normalizeEvent(event)
		if err != nil {
			return nil, fmt.Errorf("NHI behavior event %d: %w", i, err)
		}
		if parsed.Baseline {
			baseline := baselineFor(baselines, parsed.Principal)
			baseline.add(parsed)
			continue
		}
		observed = append(observed, parsed)
	}
	if len(baselines) == 0 {
		return nil, errors.New("NHI behavior discovery requires at least one baseline event")
	}
	if len(observed) == 0 {
		return nil, errors.New("NHI behavior discovery requires at least one observed event")
	}

	findings := make([]Finding, 0, len(observed))
	for _, event := range observed {
		baseline := baselines[event.Principal]
		if baseline == nil || baseline.samples == 0 {
			continue
		}
		reasons := anomalyReasons(event, baseline, hours)
		if len(reasons) == 0 {
			continue
		}
		provenance := SourceKind + ":" + event.Principal + ":" + event.occurredAt.Format(time.RFC3339)
		findings = append(findings, Finding{
			Ref:         event.Principal,
			Provenance:  provenance,
			Fingerprint: provenance,
			RiskScore:   riskScore(reasons),
			Metadata: map[string]any{
				"principal":          event.Principal,
				"occurred_at":        event.occurredAt.Format(time.RFC3339),
				"ip":                 strings.TrimSpace(event.IP),
				"geo":                normalizeGeo(event.Geo),
				"user_agent":         strings.TrimSpace(event.UserAgent),
				"action":             strings.TrimSpace(event.Action),
				"usage_count":        event.usageCount,
				"baseline_samples":   baseline.samples,
				"baseline_avg_usage": baseline.averageUsage(),
				"business_hours": map[string]any{
					"start_hour": hours.start,
					"end_hour":   hours.end,
				},
				"anomaly_reasons": reasons,
			},
		})
	}
	return findings, nil
}

// ValidateConfig checks the source config without returning normalized findings.
func ValidateConfig(raw json.RawMessage) error {
	_, err := Findings(raw)
	return err
}

func normalizeEvent(event Event) (parsedEvent, error) {
	principal := strings.TrimSpace(event.Principal)
	if principal == "" {
		return parsedEvent{}, errors.New("principal is required")
	}
	if strings.TrimSpace(event.OccurredAt) == "" {
		return parsedEvent{}, errors.New("occurred_at is required")
	}
	occurredAt, err := time.Parse(time.RFC3339, strings.TrimSpace(event.OccurredAt))
	if err != nil {
		return parsedEvent{}, fmt.Errorf("occurred_at must be RFC3339: %w", err)
	}
	usage := event.UsageCount
	if usage == 0 && event.Count > 0 {
		usage = event.Count
	}
	if usage < 0 {
		return parsedEvent{}, errors.New("usage_count must be non-negative")
	}
	event.Principal = principal
	event.OccurredAt = occurredAt.Format(time.RFC3339)
	event.IP = strings.TrimSpace(event.IP)
	event.Geo = normalizeGeo(event.Geo)
	event.UserAgent = strings.TrimSpace(event.UserAgent)
	event.Action = strings.TrimSpace(event.Action)
	return parsedEvent{Event: event, occurredAt: occurredAt, usageCount: usage}, nil
}

type businessWindow struct {
	start int
	end   int
}

func normalizeBusinessHours(hours BusinessHours) (businessWindow, error) {
	start := 8
	end := 18
	if hours.StartHour != 0 || hours.EndHour != 0 {
		start = hours.StartHour
		end = hours.EndHour
	}
	if start < 0 || start > 23 {
		return businessWindow{}, errors.New("business_hours.start_hour must be between 0 and 23")
	}
	if end < 1 || end > 24 {
		return businessWindow{}, errors.New("business_hours.end_hour must be between 1 and 24")
	}
	if start >= end {
		return businessWindow{}, errors.New("business_hours.start_hour must be before end_hour")
	}
	return businessWindow{start: start, end: end}, nil
}

func baselineFor(baselines map[string]*principalBaseline, principal string) *principalBaseline {
	b := baselines[principal]
	if b != nil {
		return b
	}
	b = &principalBaseline{
		ips:        map[string]bool{},
		geos:       map[string]bool{},
		userAgents: map[string]bool{},
	}
	baselines[principal] = b
	return b
}

func (b *principalBaseline) add(event parsedEvent) {
	if event.IP != "" {
		b.ips[event.IP] = true
	}
	if event.Geo != "" {
		b.geos[event.Geo] = true
	}
	if event.UserAgent != "" {
		b.userAgents[event.UserAgent] = true
	}
	b.totalUsage += event.usageCount
	b.samples++
}

func (b *principalBaseline) averageUsage() float64 {
	if b.samples == 0 {
		return 0
	}
	return float64(b.totalUsage) / float64(b.samples)
}

func anomalyReasons(event parsedEvent, baseline *principalBaseline, hours businessWindow) []string {
	seen := map[string]bool{}
	if event.IP != "" && len(baseline.ips) > 0 && !baseline.ips[event.IP] {
		seen["unfamiliar_ip"] = true
	}
	if event.Geo != "" && len(baseline.geos) > 0 && !baseline.geos[event.Geo] {
		seen["unfamiliar_geo"] = true
	}
	if event.UserAgent != "" && len(baseline.userAgents) > 0 && !baseline.userAgents[event.UserAgent] {
		seen["unfamiliar_user_agent"] = true
	}
	if usageSpike(event.usageCount, baseline.averageUsage()) {
		seen["usage_spike"] = true
	}
	hour := event.occurredAt.Hour()
	if hour < hours.start || hour >= hours.end {
		seen["off_hours"] = true
	}
	out := make([]string, 0, len(seen))
	for _, reason := range anomalyOrder {
		if seen[reason] {
			out = append(out, reason)
		}
	}
	return out
}

func usageSpike(observed int, baselineAverage float64) bool {
	if observed <= 0 || baselineAverage <= 0 {
		return false
	}
	return float64(observed) >= baselineAverage*3 && float64(observed)-baselineAverage >= 20
}

func riskScore(reasons []string) int {
	score := 45
	for _, reason := range reasons {
		switch reason {
		case "usage_spike":
			score += 15
		case "off_hours":
			score += 10
		default:
			score += 10
		}
	}
	if score > 100 {
		return 100
	}
	return score
}

func normalizeGeo(raw string) string {
	return strings.ToUpper(strings.TrimSpace(raw))
}
