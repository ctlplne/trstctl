package notify

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"
)

// S10.2 — the notification template. notify already defines the Alert vocabulary and
// the notification.* outbox destinations (the producer side); this adds the consumer
// side: a Notifier interface every channel implements, a Dispatcher that delivers a
// notification.* outbox entry to the registered channels (AN-6), and a conformance
// harness each channel self-validates against — the notification analogue of the
// connector SDK (S5.5).

// Notifier delivers an Alert to one channel (Slack, Teams, PagerDuty, OpsGenie, a
// generic webhook, email, ...).
type Notifier interface {
	// Name identifies the channel.
	Name() string
	// Notify delivers the alert. Delivery is at-least-once (the outbox may retry), so
	// Notify must be safe to call more than once for the same alert and must never
	// panic on a sparse alert.
	Notify(ctx context.Context, alert Alert) error
}

// RoutingPolicy is the tenant-scoped severity-to-channel matrix used at dispatch
// time. Channel names are matched against Notifier.Name case-insensitively.
type RoutingPolicy struct {
	TenantID           string
	ID                 string
	ChannelsBySeverity map[string][]string
	DefaultChannels    []string
}

// EffectiveAlertChannels resolves the channel set for severity. Unknown severity
// values fall back to the low/informational tier, then to DefaultChannels. An
// empty result means the dispatcher should use its back-compat fan-out behavior.
func (p RoutingPolicy) EffectiveAlertChannels(severity string) []string {
	matrix := normalizeChannelMatrix(p.ChannelsBySeverity)
	sev := normalizeSeverity(severity)
	if channels := cleanChannelNames(matrix[sev]); len(channels) > 0 {
		return channels
	}
	if sev != AlertSeverityLow {
		if channels := cleanChannelNames(matrix[AlertSeverityLow]); len(channels) > 0 {
			return channels
		}
	}
	if sev != AlertSeverityInformational {
		if channels := cleanChannelNames(matrix[AlertSeverityInformational]); len(channels) > 0 {
			return channels
		}
	}
	return cleanChannelNames(p.DefaultChannels)
}

// PolicyResolver loads a routing policy under the alert tenant. Implementations
// backed by PostgreSQL must filter by tenant_id and let RLS enforce isolation.
type PolicyResolver interface {
	ResolveNotificationPolicy(ctx context.Context, tenantID, policyID string) (RoutingPolicy, bool, error)
}

// ChannelResolver loads tenant-authored notification channels at dispatch time.
// Implementations return configured Notifier instances without exposing channel
// credential values to the API response or outbox payload.
type ChannelResolver interface {
	ResolveNotificationChannels(ctx context.Context, tenantID string, names []string) ([]Notifier, error)
}

// ThresholdNotificationDelivery is one successfully delivered expiry alert on
// one channel. It is keyed by tenant, subject, threshold, and channel.
type ThresholdNotificationDelivery struct {
	TenantID      string
	Subject       string
	ThresholdDays int
	Channel       string
	SentAt        time.Time
}

// ThresholdDedupLedger is the projected read model the dispatcher consults
// before sending an expiry threshold alert to one channel.
type ThresholdDedupLedger interface {
	HasThresholdNotificationOnChannel(ctx context.Context, tenantID, subject string, threshold int, channel string) (bool, error)
	RecordThresholdNotificationOnChannel(ctx context.Context, rec ThresholdNotificationDelivery) error
}

// Dispatcher fans a notification.* outbox entry out to its registered channels. It is
// the outbox handler for the notification surface: the producer enqueued the Alert in
// the same transaction as the state change that raised it, and this delivers it. One
// failing channel does not suppress the others; a returned error tells the outbox to
// retry (at-least-once).
type Dispatcher struct {
	channels      []Notifier
	resolver      PolicyResolver
	channelSource ChannelResolver
	defaultPolicy RoutingPolicy
	dedup         ThresholdDedupLedger
}

// NewDispatcher builds a Dispatcher over the given channels.
func NewDispatcher(channels ...Notifier) *Dispatcher {
	return &Dispatcher{channels: append([]Notifier(nil), channels...)}
}

// Register adds a channel.
func (d *Dispatcher) Register(n Notifier) { d.channels = append(d.channels, n) }

// SetPolicyResolver installs the tenant-scoped routing-policy resolver.
func (d *Dispatcher) SetPolicyResolver(r PolicyResolver) { d.resolver = r }

// SetChannelResolver installs the tenant-scoped channel resolver.
func (d *Dispatcher) SetChannelResolver(r ChannelResolver) { d.channelSource = r }

// SetDefaultRoutingPolicy installs the policy used when an alert does not name a
// stored routing policy. This preserves old all-channel fan-out when unset.
func (d *Dispatcher) SetDefaultRoutingPolicy(p RoutingPolicy) { d.defaultPolicy = p }

// SetThresholdDedupLedger installs the projected per-threshold delivery ledger.
func (d *Dispatcher) SetThresholdDedupLedger(l ThresholdDedupLedger) { d.dedup = l }

// Dispatch decodes an Alert from a notification.* outbox payload and delivers it to
// the effective channel set, accumulating per-channel failures.
func (d *Dispatcher) Dispatch(ctx context.Context, payload []byte) error {
	var alert Alert
	if err := json.Unmarshal(payload, &alert); err != nil {
		return fmt.Errorf("notify: malformed alert payload: %w", err)
	}
	channels, err := d.effectiveChannels(ctx, alert)
	if err != nil {
		return err
	}
	var failed []string
	now := time.Now()
	for _, ch := range channels {
		channel := normalizeChannelName(ch.Name())
		skip, err := d.thresholdAlreadySent(ctx, alert, channel)
		if err != nil {
			failed = append(failed, ch.Name()+": dedup check: "+err.Error())
			continue
		}
		if skip {
			continue
		}
		if err := ch.Notify(ctx, alert); err != nil {
			failed = append(failed, ch.Name()+": "+err.Error())
			continue
		}
		if err := d.recordThresholdSent(ctx, alert, channel, now); err != nil {
			failed = append(failed, ch.Name()+": dedup record: "+err.Error())
		}
	}
	if len(failed) > 0 {
		return fmt.Errorf("notify: %d channel(s) failed: %s", len(failed), strings.Join(failed, "; "))
	}
	return nil
}

func (d *Dispatcher) thresholdAlreadySent(ctx context.Context, alert Alert, channel string) (bool, error) {
	subject, ok := alert.thresholdDedupSubject()
	if !ok || d.dedup == nil {
		return false, nil
	}
	return d.dedup.HasThresholdNotificationOnChannel(ctx, alert.TenantID, subject, *alert.ThresholdDays, channel)
}

func (d *Dispatcher) recordThresholdSent(ctx context.Context, alert Alert, channel string, at time.Time) error {
	subject, ok := alert.thresholdDedupSubject()
	if !ok || d.dedup == nil {
		return nil
	}
	return d.dedup.RecordThresholdNotificationOnChannel(ctx, ThresholdNotificationDelivery{
		TenantID: alert.TenantID, Subject: subject, ThresholdDays: *alert.ThresholdDays,
		Channel: channel, SentAt: at,
	})
}

func (a Alert) thresholdDedupSubject() (string, bool) {
	if a.Kind != KindCertificateExpiry || a.ThresholdDays == nil || strings.TrimSpace(a.TenantID) == "" {
		return "", false
	}
	subject := strings.TrimSpace(a.CertificateID)
	if subject == "" {
		subject = strings.TrimSpace(a.Subject)
	}
	if subject == "" {
		return "", false
	}
	return subject, true
}

func (d *Dispatcher) effectiveChannels(ctx context.Context, alert Alert) ([]Notifier, error) {
	if len(d.channels) == 0 && d.channelSource == nil {
		return nil, nil
	}
	if alert.Kind == KindNotificationChannelTest && strings.TrimSpace(alert.TargetChannel) != "" {
		channels := d.channelsByNameStrict([]string{alert.TargetChannel})
		if len(channels) == 0 && d.channelSource != nil {
			dynamic, err := d.channelSource.ResolveNotificationChannels(ctx, alert.TenantID, []string{alert.TargetChannel})
			if err != nil {
				return nil, fmt.Errorf("notify: resolve channel %q: %w", alert.TargetChannel, err)
			}
			channels = append(channels, dynamic...)
		}
		if len(channels) == 0 {
			return nil, fmt.Errorf("notify: channel %q is not configured", alert.TargetChannel)
		}
		return channels, nil
	}
	var names []string
	if alert.RoutingPolicyID != "" && d.resolver != nil {
		policy, ok, err := d.resolver.ResolveNotificationPolicy(ctx, alert.TenantID, alert.RoutingPolicyID)
		if err != nil {
			return nil, fmt.Errorf("notify: resolve routing policy: %w", err)
		}
		if ok {
			names = policy.EffectiveAlertChannels(alert.Severity)
		}
	}
	if len(names) == 0 && d.defaultPolicy.hasRoutes() {
		names = d.defaultPolicy.EffectiveAlertChannels(alert.Severity)
	}
	channels := d.channelsByName(names)
	if d.channelSource != nil {
		dynamic, err := d.channelSource.ResolveNotificationChannels(ctx, alert.TenantID, names)
		if err != nil {
			return nil, fmt.Errorf("notify: resolve tenant channels: %w", err)
		}
		channels = append(channels, dynamic...)
	}
	return channels, nil
}

func (d *Dispatcher) channelsByNameStrict(names []string) []Notifier {
	wanted := make(map[string]bool, len(names))
	for _, name := range names {
		wanted[normalizeChannelName(name)] = true
	}
	var out []Notifier
	for _, ch := range d.channels {
		if wanted[normalizeChannelName(ch.Name())] {
			out = append(out, ch)
		}
	}
	return out
}

func (d *Dispatcher) channelsByName(names []string) []Notifier {
	if len(names) == 0 {
		return append([]Notifier(nil), d.channels...)
	}
	wanted := make(map[string]bool, len(names))
	for _, name := range names {
		wanted[normalizeChannelName(name)] = true
	}
	var out []Notifier
	for _, ch := range d.channels {
		if wanted[normalizeChannelName(ch.Name())] {
			out = append(out, ch)
		}
	}
	if len(out) == 0 {
		return append([]Notifier(nil), d.channels...)
	}
	return out
}

func (p RoutingPolicy) hasRoutes() bool {
	return len(p.ChannelsBySeverity) > 0 || len(p.DefaultChannels) > 0
}

func normalizeSeverity(severity string) string {
	switch strings.ToLower(strings.TrimSpace(severity)) {
	case AlertSeverityCritical:
		return AlertSeverityCritical
	case AlertSeverityWarning:
		return AlertSeverityWarning
	case AlertSeverityInformational:
		return AlertSeverityInformational
	default:
		return AlertSeverityLow
	}
}

func normalizeChannelMatrix(in map[string][]string) map[string][]string {
	if len(in) == 0 {
		return nil
	}
	out := make(map[string][]string, len(in))
	for severity, channels := range in {
		sev := normalizeSeverity(severity)
		out[sev] = append(out[sev], channels...)
	}
	return out
}

func cleanChannelNames(in []string) []string {
	if len(in) == 0 {
		return nil
	}
	out := make([]string, 0, len(in))
	seen := make(map[string]bool, len(in))
	for _, name := range in {
		name = normalizeChannelName(name)
		if name == "" || seen[name] {
			continue
		}
		seen[name] = true
		out = append(out, name)
	}
	return out
}

func normalizeChannelName(name string) string {
	name = strings.ToLower(strings.TrimSpace(name))
	compact := strings.NewReplacer(" ", "", "-", "", "_", "").Replace(name)
	switch compact {
	case "teams", "microsoftteams", "msftteams", "msteams":
		return "msteams"
	default:
		return name
	}
}

// FormatMessage renders an alert as a short human-readable line for chat/email
// channels. It is deliberately plain text so every channel can reuse it.
func FormatMessage(a Alert) string {
	var b strings.Builder
	switch a.Kind {
	case KindCertificateExpiry:
		b.WriteString("Certificate expiring")
	case KindUnexpectedIssuance:
		b.WriteString("Unexpected certificate issuance")
	case KindCredentialDrift:
		b.WriteString("Credential drift")
	default:
		b.WriteString("trstctl alert")
		if a.Kind != "" {
			b.WriteString(" (" + a.Kind + ")")
		}
	}
	if a.Subject != "" {
		b.WriteString(": " + a.Subject)
	}
	if a.Serial != "" {
		b.WriteString(" [serial " + a.Serial + "]")
	}
	if !a.NotAfter.IsZero() {
		b.WriteString(" — not after " + a.NotAfter.UTC().Format("2006-01-02"))
	}
	if owner := ownerLabel(a); owner != "" {
		b.WriteString(" — owner " + owner)
	}
	if a.Detail != "" {
		b.WriteString(" — " + a.Detail)
	}
	return b.String()
}

func ownerLabel(a Alert) string {
	if a.OwnerEmail != "" && a.OwnerName != "" {
		return a.OwnerName + " <" + a.OwnerEmail + ">"
	}
	if a.OwnerEmail != "" {
		return a.OwnerEmail
	}
	if a.OwnerName != "" {
		return a.OwnerName
	}
	return a.OwnerID
}

// Conform exercises a Notifier: it must report a name and deliver a well-formed alert
// without error. A channel plugin self-validates by passing this (the role connector
// conformance plays for deployment connectors).
func Conform(ctx context.Context, n Notifier) error {
	if n == nil {
		return fmt.Errorf("notify: Conform: nil notifier")
	}
	if n.Name() == "" {
		return fmt.Errorf("notify: Conform: notifier reports no name")
	}
	alert := Alert{
		Kind:     KindCertificateExpiry,
		TenantID: "t-conformance",
		Subject:  "cn=conformance.example",
		Detail:   "notification conformance probe",
	}
	if err := n.Notify(ctx, alert); err != nil {
		return fmt.Errorf("notify: channel %q failed to deliver a valid alert: %w", n.Name(), err)
	}
	return nil
}
