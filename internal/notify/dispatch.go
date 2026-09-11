// SPDX-License-Identifier: MPL-2.0

package notify

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"sync"
	"time"

	"trstctl.com/trstctl/internal/crypto"
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

// noReceiverError carries a fixed public class; receiver URLs, credentials and
// raw transport errors must never enter the outbox's operator-visible error.
type noReceiverError struct{}

func (noReceiverError) Error() string {
	return "notify: no configured notification receiver; configure a channel and retry delivery"
}
func (noReceiverError) SafeDeliveryClass() string { return "notification_receiver_not_configured" }

// RoutingPolicy is the tenant-scoped severity-to-channel matrix used at dispatch
// time. Channel names are matched against Notifier.Name case-insensitively.
type RoutingPolicy struct {
	TenantID           string
	ID                 string
	ScopeKind          string
	ScopeRef           string
	ChannelsBySeverity map[string][]string
	DefaultChannels    []string
}

// RoutingSelector is the hierarchy location used for automatic routing.
type RoutingSelector struct {
	Workspace string
	OwnerRef  string
	AssetRef  string
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

// EffectivePolicyResolver is an optional extension implemented by resolvers
// that can choose a policy from the global -> workspace -> owner -> asset
// hierarchy when the producer did not pin a policy UUID.
type EffectivePolicyResolver interface {
	ResolveEffectiveNotificationPolicy(context.Context, string, RoutingSelector) (RoutingPolicy, bool, error)
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

// DeliveryMessage is the notification-safe subset of an outbox message. Keeping
// this type here avoids a notify -> orchestrator import cycle while still binding
// receipts to the exact tenant, destination, receiver key, and payload.
type DeliveryMessage struct {
	TenantID       string
	Destination    string
	IdempotencyKey string
	Payload        []byte
	OutboxID       int64
	Attempts       int
}

// NotificationDeliveryReceipt is the durable evidence for one successful
// channel in one fan-out. Idempotency keys and alert bodies are retained only as
// SHA-256 digests.
type NotificationDeliveryReceipt struct {
	TenantID              string
	ID                    string
	Destination           string
	NotificationKeyDigest string
	PayloadDigest         string
	Channel               string
	OutboxID              *int64
	Attempts              int
	DeliveredAt           time.Time
}

// DeliveryReceiptLedger is the event-sourced per-channel delivery authority.
// HasNotificationDelivery must fail closed when the id resolves to a receipt with
// different destination/key/payload/channel bindings.
type DeliveryReceiptLedger interface {
	HasNotificationDelivery(context.Context, NotificationDeliveryReceipt) (bool, error)
	RecordNotificationDelivery(context.Context, NotificationDeliveryReceipt) error
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
	deliveries    DeliveryReceiptLedger
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

// SetDeliveryReceiptLedger installs the durable per-channel fan-out ledger.
func (d *Dispatcher) SetDeliveryReceiptLedger(l DeliveryReceiptLedger) { d.deliveries = l }

// Close releases credential material held by long-lived channel implementations.
// The server calls it only after its final outbox drain, so no delivery can race a
// credential wipe. Close is deliberately optional on Notifier to keep stateless
// channels small and to preserve the public notification SDK contract.
func (d *Dispatcher) Close() {
	if d == nil {
		return
	}
	for _, channel := range d.channels {
		if closer, ok := channel.(interface{ Close() }); ok {
			closer.Close()
		}
	}
	d.channels = nil
}

// Dispatch decodes an Alert from a notification.* outbox payload and delivers it to
// the effective channel set, accumulating per-channel failures.
func (d *Dispatcher) Dispatch(ctx context.Context, payload []byte) error {
	var alert Alert
	if err := json.Unmarshal(payload, &alert); err != nil {
		return fmt.Errorf("notify: malformed alert payload: %w", err)
	}
	// Compatibility callers do not have the outbox envelope. Use a deterministic
	// synthetic envelope; the served binary always calls DispatchMessage below.
	return d.dispatchAlert(ctx, DeliveryMessage{
		TenantID: alert.TenantID, Destination: "notification.compat",
		IdempotencyKey: "payload:" + crypto.SHA256Hex(payload), Payload: payload,
	}, alert)
}

// DispatchMessage delivers one fully bound outbox message. The envelope is part
// of every receipt identity, so a reused receiver key with altered payload cannot
// inherit another command's successful channels.
func (d *Dispatcher) DispatchMessage(ctx context.Context, message DeliveryMessage) error {
	if strings.TrimSpace(message.TenantID) == "" || strings.TrimSpace(message.Destination) == "" ||
		strings.TrimSpace(message.IdempotencyKey) == "" || len(message.Payload) == 0 {
		return fmt.Errorf("notify: delivery message requires tenant, destination, idempotency key, and payload")
	}
	var alert Alert
	if err := json.Unmarshal(message.Payload, &alert); err != nil {
		return fmt.Errorf("notify: malformed alert payload: %w", err)
	}
	if alert.TenantID == "" {
		alert.TenantID = message.TenantID
	}
	if alert.TenantID != message.TenantID {
		return fmt.Errorf("notify: alert tenant does not match outbox tenant")
	}
	return d.dispatchAlert(ctx, message, alert)
}

func (d *Dispatcher) dispatchAlert(ctx context.Context, message DeliveryMessage, alert Alert) error {
	channels, err := d.effectiveChannels(ctx, alert)
	if err != nil {
		return err
	}
	if len(channels) == 0 {
		return noReceiverError{}
	}
	failed := make([]string, 0)
	type deliveryAttempt struct {
		notifier Notifier
		receipt  NotificationDeliveryReceipt
	}
	ready := make([]deliveryAttempt, 0, len(channels))
	seenChannels := make(map[string]bool, len(channels))
	for _, ch := range channels {
		channel := normalizeChannelName(ch.Name())
		if channel == "" || seenChannels[channel] {
			continue
		}
		seenChannels[channel] = true
		receipt := notificationDeliveryReceipt(message, channel)
		delivered, err := d.deliveryAlreadyRecorded(ctx, receipt)
		if err != nil {
			failed = append(failed, ch.Name()+": delivery receipt check: "+err.Error())
			continue
		}
		if delivered {
			// A crash may have landed the generic receipt before the older expiry
			// threshold projection. Heal that secondary dedup fact without resending.
			thresholdRecorded, thresholdErr := d.thresholdAlreadySent(ctx, alert, channel)
			if thresholdErr != nil {
				failed = append(failed, ch.Name()+": threshold dedup check: "+thresholdErr.Error())
				continue
			}
			if !thresholdRecorded {
				thresholdErr = d.recordThresholdSent(ctx, alert, channel, time.Now().UTC())
			}
			if thresholdErr != nil {
				failed = append(failed, ch.Name()+": threshold dedup record: "+thresholdErr.Error())
			}
			continue
		}
		skip, err := d.thresholdAlreadySent(ctx, alert, channel)
		if err != nil {
			failed = append(failed, ch.Name()+": dedup check: "+err.Error())
			continue
		}
		if skip {
			continue
		}
		ready = append(ready, deliveryAttempt{notifier: ch, receipt: receipt})
	}

	// Fan-out is a bounded bulkhead. All advertised channel families fit in one
	// wave, while tenant-authored overflow waits in the local bounded worker set.
	// A hung first receiver therefore cannot consume the parent outbox deadline
	// before later healthy receivers are even attempted (AN-7).
	const (
		maxParallelChannels = 16
		perChannelTimeout   = 5 * time.Second
	)
	type channelResult struct {
		index int
		err   error
	}
	results := make(chan channelResult, len(ready))
	jobs := make(chan int)
	workerCount := len(ready)
	if workerCount > maxParallelChannels {
		workerCount = maxParallelChannels
	}
	var workers sync.WaitGroup
	workers.Add(workerCount)
	for range workerCount {
		go func() {
			defer workers.Done()
			for index := range jobs {
				channelCtx, cancel := context.WithTimeout(ctx, perChannelTimeout)
				err := ready[index].notifier.Notify(channelCtx, alert)
				cancel()
				results <- channelResult{index: index, err: err}
			}
		}()
	}
	go func() {
		defer close(jobs)
		for index := range ready {
			jobs <- index
		}
	}()
	workers.Wait()
	close(results)

	byIndex := make([]error, len(ready))
	for result := range results {
		byIndex[result.index] = result.err
	}
	now := time.Now()
	for index, attempt := range ready {
		ch := attempt.notifier
		if err := byIndex[index]; err != nil {
			failed = append(failed, ch.Name()+": "+err.Error())
			continue
		}
		attempt.receipt.DeliveredAt = now
		if err := d.recordDelivery(ctx, attempt.receipt); err != nil {
			failed = append(failed, ch.Name()+": delivery receipt: "+err.Error())
			continue
		}
		if err := d.recordThresholdSent(ctx, alert, normalizeChannelName(ch.Name()), now); err != nil {
			failed = append(failed, ch.Name()+": dedup record: "+err.Error())
		}
	}
	if len(failed) > 0 {
		return fmt.Errorf("notify: %d channel(s) failed: %s", len(failed), strings.Join(failed, "; "))
	}
	return nil
}

func notificationDeliveryReceipt(message DeliveryMessage, channel string) NotificationDeliveryReceipt {
	keyDigest := crypto.SHA256Hex([]byte(message.IdempotencyKey))
	payloadDigest := crypto.SHA256Hex(message.Payload)
	id := "notification.delivery:" + crypto.SHA256Hex([]byte(
		message.TenantID+"\x00"+message.Destination+"\x00"+keyDigest+"\x00"+channel))
	var outboxID *int64
	if message.OutboxID != 0 {
		value := message.OutboxID
		outboxID = &value
	}
	return NotificationDeliveryReceipt{
		TenantID: message.TenantID, ID: id, Destination: message.Destination,
		NotificationKeyDigest: keyDigest, PayloadDigest: payloadDigest, Channel: channel,
		OutboxID: outboxID, Attempts: message.Attempts,
	}
}

func (d *Dispatcher) deliveryAlreadyRecorded(ctx context.Context, rec NotificationDeliveryReceipt) (bool, error) {
	if d.deliveries == nil {
		return false, nil
	}
	return d.deliveries.HasNotificationDelivery(ctx, rec)
}

func (d *Dispatcher) recordDelivery(ctx context.Context, rec NotificationDeliveryReceipt) error {
	if d.deliveries == nil {
		return nil
	}
	return d.deliveries.RecordNotificationDelivery(ctx, rec)
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
		requested := []string{alert.TargetChannel}
		channels := d.channelsByNameStrict(requested)
		if len(channels) == 0 && d.channelSource != nil {
			dynamic, err := d.channelSource.ResolveNotificationChannels(ctx, alert.TenantID, requested)
			if err != nil {
				return nil, fmt.Errorf("notify: resolve channel %q: %w", alert.TargetChannel, err)
			}
			channels = append(channels, dynamic...)
		}
		if len(missingChannelNames(requested, channels)) != 0 {
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
	if len(names) == 0 && strings.TrimSpace(alert.RoutingPolicyID) == "" {
		if resolver, ok := d.resolver.(EffectivePolicyResolver); ok {
			policy, found, err := resolver.ResolveEffectiveNotificationPolicy(ctx, alert.TenantID, routingSelectorForAlert(alert))
			if err != nil {
				return nil, fmt.Errorf("notify: resolve effective routing policy: %w", err)
			}
			if found {
				names = policy.EffectiveAlertChannels(alert.Severity)
			}
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
	if missing := missingChannelNames(names, channels); len(missing) > 0 {
		return nil, fmt.Errorf("notify: requested channel(s) are not configured: %s", strings.Join(missing, ", "))
	}
	return channels, nil
}

func routingSelectorForAlert(alert Alert) RoutingSelector {
	selector := RoutingSelector{}
	switch alert.Kind {
	case KindCertificateExpiry:
		selector.Workspace = "certificate-lifecycle"
	default:
		selector.Workspace = "trust-operations"
	}
	if id := strings.TrimSpace(alert.OwnerID); id != "" {
		selector.OwnerRef = "owner/" + id
	}
	if id := strings.TrimSpace(alert.CertificateID); id != "" {
		selector.AssetRef = "certificate/" + id
	}
	return selector
}

func missingChannelNames(requested []string, channels []Notifier) []string {
	if len(requested) == 0 {
		return nil
	}
	configured := make(map[string]bool, len(channels))
	for _, channel := range channels {
		if channel != nil {
			configured[normalizeChannelName(channel.Name())] = true
		}
	}
	var missing []string
	for _, name := range cleanChannelNames(requested) {
		if !configured[name] {
			missing = append(missing, name)
		}
	}
	return missing
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
	case KindApprovalRequest:
		b.WriteString("Approval requested")
	case KindEndpointVerificationFailed:
		// The wording is chosen to be unmistakable at 3am. "Verification
		// failed" would read as a tooling problem; this says what is actually
		// true of production traffic right now.
		b.WriteString("Endpoint is serving the wrong certificate")
	case KindEndpointUnreachable:
		b.WriteString("Endpoint could not be reached for verification")
	case KindCAHorizon:
		b.WriteString("CA hierarchy expiry horizon")
	case KindCAValidityCompression:
		b.WriteString("CA horizon is compressing leaf validity")
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
	// The vantage is part of the claim, not decoration: a local divergence
	// means the serving host itself disagrees, a relay one means clients cannot
	// get the right certificate, and an operator triages those differently.
	if a.Vantage != "" {
		b.WriteString(" [" + a.Vantage + " vantage]")
	}
	if a.Mismatch != "" {
		b.WriteString(" [" + a.Mismatch + "]")
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
