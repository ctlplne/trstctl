// SPDX-License-Identifier: MPL-2.0

package server

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"trstctl.com/trstctl/internal/crypto/secret"
	dnsacmedns "trstctl.com/trstctl/internal/dns/acmedns"
	dnsakamai "trstctl.com/trstctl/internal/dns/akamai"
	dnsazuredns "trstctl.com/trstctl/internal/dns/azuredns"
	dnscloudflare "trstctl.com/trstctl/internal/dns/cloudflare"
	dnsgoogledns "trstctl.com/trstctl/internal/dns/googledns"
	dnsns1 "trstctl.com/trstctl/internal/dns/ns1"
	dnsrfc2136 "trstctl.com/trstctl/internal/dns/rfc2136"
	dnsroute53 "trstctl.com/trstctl/internal/dns/route53"
	dnsultradns "trstctl.com/trstctl/internal/dns/ultradns"
	dnswebhook "trstctl.com/trstctl/internal/dns/webhook"
	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/orchestrator"
	"trstctl.com/trstctl/internal/projections"
	"trstctl.com/trstctl/internal/protocols/acme"
	"trstctl.com/trstctl/internal/store"
	"trstctl.com/trstctl/internal/tenantseal"
)

const (
	destinationACMEDNS01Present = "acme.dns01.present"
	destinationACMEDNS01Cleanup = "acme.dns01.cleanup"

	acmeDNS01OutboxPollInterval = 20 * time.Millisecond
	acmeDNS01OutboxWait         = 30 * time.Second
)

type servedACMEDNS01Automation struct {
	store   *store.Store
	log     *events.Log
	outbox  *orchestrator.Outbox
	kek     sealKeyWrapper
	crypto  tenantseal.Access
	plugins *PluginManager

	cnameResolver acme.CNAMEResolver
	caaResolver   acme.CAAResolver
	txtResolvers  []acme.Resolver
}

type acmeDNS01OutboxPayload struct {
	ConfigID            string          `json:"config_id"`
	ConfigName          string          `json:"config_name,omitempty"`
	Provider            string          `json:"provider"`
	Domain              string          `json:"domain"`
	Zone                string          `json:"zone,omitempty"`
	ChallengeDomain     string          `json:"challenge_domain,omitempty"`
	DelegationTarget    string          `json:"delegation_target,omitempty"`
	RecordName          string          `json:"record_name"`
	Value               string          `json:"value"`
	CredentialRefs      json.RawMessage `json:"credential_refs,omitempty"`
	Config              json.RawMessage `json:"config,omitempty"`
	QualificationID     string          `json:"qualification_id,omitempty"`
	QualificationStatus string          `json:"qualification_status,omitempty"`
	PropagationStatus   string          `json:"propagation_status,omitempty"`
	FailureStage        string          `json:"failure_stage,omitempty"`
	ErrorCategory       string          `json:"error_category,omitempty"`
	RecoveryOf          string          `json:"recovery_of,omitempty"`
}

type acmeDNS01RecordEvent struct {
	ConfigID        string `json:"config_id"`
	Provider        string `json:"provider"`
	Domain          string `json:"domain"`
	RecordName      string `json:"record_name"`
	OutboxID        int64  `json:"outbox_id"`
	QualificationID string `json:"qualification_id,omitempty"`
}

func newServedACMEDNS01Automation(st *store.Store, log *events.Log, outbox *orchestrator.Outbox, kek sealKeyWrapper, plugins *PluginManager, tenantCrypto ...tenantseal.Access) *servedACMEDNS01Automation {
	var access tenantseal.Access
	if len(tenantCrypto) > 0 {
		access = tenantCrypto[0]
	}
	return &servedACMEDNS01Automation{store: st, log: log, outbox: outbox, kek: kek, crypto: access, plugins: plugins}
}

func (a *servedACMEDNS01Automation) Present(ctx context.Context, tenantID, domain, _ string, keyAuth string) (func(context.Context) error, error) {
	if a == nil || a.store == nil || a.outbox == nil {
		return nil, errors.New("acme: served dns-01 automation is not configured")
	}
	tenantID = strings.TrimSpace(tenantID)
	domain = strings.TrimSpace(domain)
	if tenantID == "" || domain == "" {
		return nil, errors.New("acme: served dns-01 automation requires tenant and domain")
	}
	cfg, err := a.selectProviderConfig(ctx, tenantID, domain)
	if err != nil {
		return nil, err
	}
	if err := a.enforceLiveCAA(ctx, domain, cfg); err != nil {
		return nil, err
	}
	recordName := acme.DNS01RecordName(domain)
	value := acme.DNS01RecordValue(keyAuth)
	return a.presentRecord(ctx, tenantID, cfg, domain, recordName, value)
}

// presentRecord publishes one TXT record and returns its retraction.
//
// Split out of Present so the upstream client solver (epic B7) publishes
// through exactly this path rather than a second one. Two publish paths would
// drift, and the one that drifts is always the one exercised less — which here
// would be the one that runs unattended every validation cycle.
func (a *servedACMEDNS01Automation) presentRecord(ctx context.Context, tenantID string, cfg store.ACMEDNS01ProviderConfig, domain, recordName, value string) (func(context.Context) error, error) {
	payload := acmeDNS01OutboxPayload{
		ConfigID:         cfg.ID,
		Provider:         cfg.Provider,
		Domain:           domain,
		Zone:             cfg.Zone,
		ChallengeDomain:  cfg.ChallengeDomain,
		DelegationTarget: cfg.DelegationTarget,
		RecordName:       recordName,
		Value:            value,
		CredentialRefs:   cfg.CredentialRefs,
		Config:           cfg.Config,
	}
	// The key carries a per-publish nonce, and it has to.
	//
	// Keyed on (config, record, value) alone, a SECOND solve of the same
	// authorization — a retried order, the same token, therefore the same key
	// authorization and the same TXT value — found the earlier row already
	// enqueued and delivered, and returned success. But that first publish had
	// been retracted when its attempt finished, so the solver reported a record
	// live in DNS that was not there, the authority found nothing, and the
	// authorization went invalid with no failure anywhere in trstctl.
	//
	// AN-5 is preserved where it is meant to apply: a retried DELIVERY of one
	// enqueued row is still deduplicated by the same key. What is no longer
	// deduplicated is two separate publish intents, which are genuinely two
	// effects because the first one was undone. Republishing an identical TXT
	// value is an upsert at every supported provider, so the cost of being
	// wrong in this direction is nothing.
	publishNonce := uuid.NewString()
	presentKey := acmeDNS01IdempotencyKey(destinationACMEDNS01Present, cfg.ID, recordName, value+"#"+publishNonce)
	if err := a.enqueueAndWait(ctx, tenantID, destinationACMEDNS01Present, presentKey, payload); err != nil {
		return nil, fmt.Errorf("acme: dns-01 present %s: %w", recordName, err)
	}
	// The cleanup pairs with THIS publish, so it carries the same nonce: a
	// retraction deduplicated against an earlier attempt's cleanup would leave
	// this attempt's record live in public DNS.
	cleanupKey := acmeDNS01IdempotencyKey(destinationACMEDNS01Cleanup, cfg.ID, recordName, value+"#"+publishNonce)
	return func(cleanupCtx context.Context) error {
		return a.enqueueAndWait(cleanupCtx, tenantID, destinationACMEDNS01Cleanup, cleanupKey, payload)
	}, nil
}

func (a *servedACMEDNS01Automation) Deliver(ctx context.Context, m orchestrator.Message) error {
	if a == nil || a.store == nil || a.log == nil {
		return errors.New("server: acme dns-01 automation is not configured")
	}
	var payload acmeDNS01OutboxPayload
	if err := json.Unmarshal(m.Payload, &payload); err != nil {
		return fmt.Errorf("server: decode acme dns-01 payload: %w", err)
	}
	if payload.ConfigID == "" || payload.Provider == "" || payload.Domain == "" || payload.RecordName == "" || payload.Value == "" {
		return errors.New("server: acme dns-01 payload requires config_id, provider, domain, record_name, and value")
	}
	provider, err := a.providerForPayload(ctx, m.TenantID, payload)
	if err != nil {
		return err
	}
	provider, err = a.wrapDelegatedDNS01Provider(payload, provider)
	if err != nil {
		return err
	}
	switch m.Destination {
	case destinationACMEDNS01Present:
		if err := provider.PresentTXT(ctx, payload.RecordName, payload.Value); err != nil {
			return err
		}
		return a.appendRecordEvent(ctx, m, payload, projections.EventACMEDNS01RecordPresented)
	case destinationACMEDNS01Cleanup:
		if err := provider.CleanupTXT(ctx, payload.RecordName, payload.Value); err != nil {
			return err
		}
		return a.appendRecordEvent(ctx, m, payload, projections.EventACMEDNS01RecordCleaned)
	default:
		return fmt.Errorf("server: unsupported acme dns-01 outbox destination %q", m.Destination)
	}
}

// selectProviderConfigForUpstream is selectProviderConfig plus the upstream
// consent check (epic B7).
//
// A separate entry point rather than a flag, so the consent requirement cannot
// be forgotten at a call site: the upstream solver has no way to reach the
// unchecked selector by accident.
func (a *servedACMEDNS01Automation) selectProviderConfigForUpstream(ctx context.Context, tenantID, domain string) (store.ACMEDNS01ProviderConfig, error) {
	// The domain keeps its "*." here. Stripping it before selection — which an
	// earlier version did — silently disabled the selector's own wildcard
	// filter, because that filter is guarded by acme.IsWildcard(domain). A zone
	// with two configs, only one of them wildcard-capable, could then pick the
	// wrong one and fail the order while a config that would have worked sat
	// right beside it.
	cfg, err := a.selectProviderConfig(ctx, tenantID, domain, upstreamDVConsented)
	if err != nil {
		return store.ACMEDNS01ProviderConfig{}, err
	}
	return cfg, nil
}

// upstreamDVConsented filters selection to configs an operator has enabled for
// upstream domain validation.
//
// A FILTER, not a post-hoc check on whichever config matched first. Consent is
// per config, so a zone covered by two of them — one consented, one not — must
// select the consented one rather than reporting that the zone is not enabled.
// The error when nothing matches still names the flag, because "no config
// matches" would leave an operator with nothing to act on.
func upstreamDVConsented(cfg store.ACMEDNS01ProviderConfig) bool { return cfg.AllowUpstreamDV }

func (a *servedACMEDNS01Automation) selectProviderConfig(ctx context.Context, tenantID, domain string, extra ...func(store.ACMEDNS01ProviderConfig) bool) (store.ACMEDNS01ProviderConfig, error) {
	configs, err := a.store.ListACMEDNS01ProviderConfigs(ctx, tenantID)
	if err != nil {
		return store.ACMEDNS01ProviderConfig{}, err
	}
	rejectedByExtra := false
	for _, cfg := range configs {
		if !stringIn(acme.ChallengeDNS01, cfg.AllowedMethods) {
			continue
		}
		if acme.IsWildcard(domain) && !cfg.AllowWildcards {
			continue
		}
		if !dns01ConfigMatchesDomain(cfg, domain) {
			continue
		}
		if !allExtraPredicatesPass(cfg, extra) {
			// Remembered so the error can say WHY: a config covering this zone
			// exists and was rejected by an operator-settable flag, which is a
			// different problem from no config at all.
			rejectedByExtra = true
			continue
		}
		return cfg, nil
	}
	if rejectedByExtra {
		return store.ACMEDNS01ProviderConfig{}, fmt.Errorf(
			"server: a DNS-01 provider config covers %s but none of them is enabled for upstream "+
				"domain validation; enable allow_upstream_dv on the one that should publish "+
				"challenge records into that zone on an external CA's behalf", domain)
	}
	return store.ACMEDNS01ProviderConfig{}, fmt.Errorf("acme: no served dns-01 provider config matches %s", domain)
}

func allExtraPredicatesPass(cfg store.ACMEDNS01ProviderConfig, extra []func(store.ACMEDNS01ProviderConfig) bool) bool {
	for _, ok := range extra {
		if ok != nil && !ok(cfg) {
			return false
		}
	}
	return true
}

func (a *servedACMEDNS01Automation) AllowedMethods(ctx context.Context, tenantID, domain string) ([]string, bool, error) {
	if a == nil || a.store == nil {
		return nil, false, nil
	}
	tenantID = strings.TrimSpace(tenantID)
	domain = strings.TrimSpace(domain)
	if tenantID == "" || domain == "" {
		return nil, false, nil
	}
	configs, err := a.store.ListACMEDNS01ProviderConfigs(ctx, tenantID)
	if err != nil {
		return nil, false, err
	}
	matched := false
	allowed := map[string]bool{}
	wildcard := acme.IsWildcard(domain)
	for _, cfg := range configs {
		if !dns01ConfigMatchesDomain(cfg, domain) {
			continue
		}
		matched = true
		if wildcard && !cfg.AllowWildcards {
			continue
		}
		for _, method := range cfg.AllowedMethods {
			method = strings.TrimSpace(strings.ToLower(method))
			if wildcard && method != acme.ChallengeDNS01 {
				continue
			}
			if method != "" {
				allowed[method] = true
			}
		}
	}
	if !matched {
		return nil, false, nil
	}
	methods := make([]string, 0, len(allowed))
	for _, method := range []string{acme.ChallengeHTTP01, acme.ChallengeDNS01, acme.ChallengeTLSALPN01} {
		if allowed[method] {
			methods = append(methods, method)
		}
	}
	return methods, true, nil
}

func (a *servedACMEDNS01Automation) enforceLiveCAA(ctx context.Context, domain string, cfg store.ACMEDNS01ProviderConfig) error {
	issuer := strings.TrimSpace(cfg.CAAIssuerDomain)
	if issuer == "" {
		return nil
	}
	resolver := a.caaResolver
	if resolver == nil {
		resolver = acme.DefaultCAAResolver()
	}
	checker := acme.CAAChecker{Resolver: resolver, IssuerDomain: issuer}
	if err := checker.Check(ctx, domain, acme.IsWildcard(domain)); err != nil {
		return fmt.Errorf("acme: live CAA policy rejected %s before DNS-01 publish: %w", domain, err)
	}
	return nil
}

func (a *servedACMEDNS01Automation) enqueueAndWait(ctx context.Context, tenantID, destination, idempotencyKey string, payload acmeDNS01OutboxPayload) error {
	_, err := a.enqueueAndWaitRecord(ctx, tenantID, destination, idempotencyKey, payload)
	return err
}

func (a *servedACMEDNS01Automation) enqueueAndWaitRecord(ctx context.Context, tenantID, destination, idempotencyKey string, payload acmeDNS01OutboxPayload) (orchestrator.Record, error) {
	body, err := json.Marshal(payload)
	if err != nil {
		return orchestrator.Record{}, err
	}
	if err := a.store.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		_, err := a.outbox.EnqueueIfAbsent(ctx, tx, orchestrator.Entry{
			TenantID: tenantID, Destination: destination, IdempotencyKey: idempotencyKey, Payload: body,
		})
		return err
	}); err != nil {
		return orchestrator.Record{}, err
	}
	return a.waitOutboxDeliveredRecord(ctx, tenantID, destination, idempotencyKey)
}

func (a *servedACMEDNS01Automation) waitOutboxDeliveredRecord(ctx context.Context, tenantID, destination, idempotencyKey string) (orchestrator.Record, error) {
	waitCtx := ctx
	cancel := func() {}
	if _, ok := ctx.Deadline(); !ok {
		waitCtx, cancel = context.WithTimeout(ctx, acmeDNS01OutboxWait)
	}
	defer cancel()

	ticker := time.NewTicker(acmeDNS01OutboxPollInterval)
	defer ticker.Stop()
	for {
		rec, ok, err := a.outboxRecord(waitCtx, tenantID, destination, idempotencyKey)
		if err != nil {
			return rec, err
		}
		if ok {
			switch rec.Status {
			case "delivered":
				return rec, nil
			case "failed":
				if rec.LastError != "" {
					return rec, errors.New(rec.LastError)
				}
				return rec, errors.New("outbox delivery failed")
			}
		}
		select {
		case <-waitCtx.Done():
			return rec, fmt.Errorf("outbox delivery timed out: %w", waitCtx.Err())
		case <-ticker.C:
		}
	}
}

func (a *servedACMEDNS01Automation) outboxRecord(ctx context.Context, tenantID, destination, idempotencyKey string) (orchestrator.Record, bool, error) {
	var rec orchestrator.Record
	err := a.store.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx,
			`SELECT id, tenant_id::text, destination, payload, idempotency_key, status, attempts, COALESCE(last_error, '')
			   FROM outbox
			  WHERE tenant_id = $1 AND destination = $2 AND idempotency_key = $3
			  ORDER BY id
			  LIMIT 1`, tenantID, destination, idempotencyKey).
			Scan(&rec.ID, &rec.TenantID, &rec.Destination, &rec.Payload, &rec.IdempotencyKey, &rec.Status, &rec.Attempts, &rec.LastError)
	})
	if errors.Is(err, pgx.ErrNoRows) {
		return orchestrator.Record{}, false, nil
	}
	if err != nil {
		return orchestrator.Record{}, false, err
	}
	return rec, true, nil
}

func (a *servedACMEDNS01Automation) providerForPayload(ctx context.Context, tenantID string, payload acmeDNS01OutboxPayload) (acme.DNSProvider, error) {
	switch payload.Provider {
	case "route53":
		return a.route53ProviderForPayload(ctx, tenantID, payload)
	case "googledns":
		return a.googleDNSProviderForPayload(ctx, tenantID, payload)
	case "azuredns":
		return a.azureDNSProviderForPayload(ctx, tenantID, payload)
	case "cloudflare":
		return a.cloudflareProviderForPayload(ctx, tenantID, payload)
	case "rfc2136":
		return a.rfc2136ProviderForPayload(ctx, tenantID, payload)
	case "webhook":
		return a.webhookProviderForPayload(ctx, tenantID, payload)
	case "ns1":
		return a.ns1ProviderForPayload(ctx, tenantID, payload)
	case "akamai":
		return a.akamaiProviderForPayload(ctx, tenantID, payload)
	case "ultradns":
		return a.ultradnsProviderForPayload(ctx, tenantID, payload)
	case "acmedns":
		return a.acmeDNSProviderForPayload(ctx, tenantID, payload)
	default:
		if a.plugins != nil && a.plugins.HasDNS(payload.Provider) {
			return a.pluginProviderForPayload(ctx, tenantID, payload)
		}
		return nil, fmt.Errorf("server: acme dns-01 provider %q is not wired for order-time automation", payload.Provider)
	}
}

func (a *servedACMEDNS01Automation) route53ProviderForPayload(ctx context.Context, tenantID string, payload acmeDNS01OutboxPayload) (acme.DNSProvider, error) {
	var cfg struct {
		HostedZoneID string `json:"hosted_zone_id"`
		AccessKeyID  string `json:"access_key_id,omitempty"`
		Endpoint     string `json:"endpoint,omitempty"`
	}
	if err := decodeACMEDNS01ProviderConfig(payload.Config, &cfg); err != nil {
		return nil, fmt.Errorf("server: decode route53 dns-01 config: %w", err)
	}
	accessKeyID := strings.TrimSpace(cfg.AccessKeyID)
	if accessKeyID == "" {
		var err error
		accessKeyID, err = a.secretRefString(ctx, tenantID, payload.CredentialRefs, "aws_access_key_ref")
		if err != nil {
			return nil, err
		}
	}
	secretAccessKey, err := a.secretRef(ctx, tenantID, payload.CredentialRefs, "aws_secret_key_ref")
	if err != nil {
		return nil, err
	}
	defer secret.Wipe(secretAccessKey)
	sessionToken, err := a.secretRef(ctx, tenantID, payload.CredentialRefs, "aws_session_token_ref")
	if err != nil {
		return nil, err
	}
	defer secret.Wipe(sessionToken)
	if err := requireACMEDNS01Fields("route53", map[string]string{
		"hosted_zone_id": cfg.HostedZoneID,
		"access_key_id":  accessKeyID,
	}); err != nil {
		return nil, err
	}
	if len(secretAccessKey) == 0 {
		return nil, errors.New("server: route53 dns-01 credential ref aws_secret_key_ref is required")
	}
	opts := []dnsroute53.Option{}
	if endpoint := strings.TrimSpace(cfg.Endpoint); endpoint != "" {
		opts = append(opts, dnsroute53.WithEndpoint(endpoint))
	}
	return dnsroute53.New(cfg.HostedZoneID, dnsroute53.Credentials{
		AccessKeyID: accessKeyID, SecretAccessKey: secretAccessKey, SessionToken: sessionToken,
	}, opts...), nil
}

func (a *servedACMEDNS01Automation) googleDNSProviderForPayload(ctx context.Context, tenantID string, payload acmeDNS01OutboxPayload) (acme.DNSProvider, error) {
	var cfg struct {
		Project     string `json:"project"`
		ManagedZone string `json:"managed_zone"`
		Endpoint    string `json:"endpoint,omitempty"`
	}
	if err := decodeACMEDNS01ProviderConfig(payload.Config, &cfg); err != nil {
		return nil, fmt.Errorf("server: decode googledns dns-01 config: %w", err)
	}
	token, err := a.secretRef(ctx, tenantID, payload.CredentialRefs, "oauth_token_ref")
	if err != nil {
		return nil, err
	}
	defer secret.Wipe(token)
	if err := requireACMEDNS01Fields("googledns", map[string]string{"project": cfg.Project, "managed_zone": cfg.ManagedZone}); err != nil {
		return nil, err
	}
	if len(token) == 0 {
		return nil, errors.New("server: googledns dns-01 credential ref oauth_token_ref is required")
	}
	opts := []dnsgoogledns.Option{}
	if endpoint := strings.TrimSpace(cfg.Endpoint); endpoint != "" {
		opts = append(opts, dnsgoogledns.WithEndpoint(endpoint))
	}
	return dnsgoogledns.New(cfg.Project, cfg.ManagedZone, dnsgoogledns.Credentials{BearerToken: token}, opts...), nil
}

func (a *servedACMEDNS01Automation) azureDNSProviderForPayload(ctx context.Context, tenantID string, payload acmeDNS01OutboxPayload) (acme.DNSProvider, error) {
	var cfg struct {
		SubscriptionID string `json:"subscription_id"`
		ResourceGroup  string `json:"resource_group"`
		Zone           string `json:"zone,omitempty"`
		Endpoint       string `json:"endpoint,omitempty"`
	}
	if err := decodeACMEDNS01ProviderConfig(payload.Config, &cfg); err != nil {
		return nil, fmt.Errorf("server: decode azuredns dns-01 config: %w", err)
	}
	if strings.TrimSpace(cfg.Zone) == "" {
		cfg.Zone = payloadZoneFallback(payload)
	}
	token, err := a.secretRef(ctx, tenantID, payload.CredentialRefs, "aad_token_ref")
	if err != nil {
		return nil, err
	}
	defer secret.Wipe(token)
	if err := requireACMEDNS01Fields("azuredns", map[string]string{"subscription_id": cfg.SubscriptionID, "resource_group": cfg.ResourceGroup, "zone": cfg.Zone}); err != nil {
		return nil, err
	}
	if len(token) == 0 {
		return nil, errors.New("server: azuredns dns-01 credential ref aad_token_ref is required")
	}
	opts := []dnsazuredns.Option{}
	if endpoint := strings.TrimSpace(cfg.Endpoint); endpoint != "" {
		opts = append(opts, dnsazuredns.WithEndpoint(endpoint))
	}
	return dnsazuredns.New(cfg.SubscriptionID, cfg.ResourceGroup, cfg.Zone, dnsazuredns.Credentials{BearerToken: token}, opts...), nil
}

func (a *servedACMEDNS01Automation) cloudflareProviderForPayload(ctx context.Context, tenantID string, payload acmeDNS01OutboxPayload) (acme.DNSProvider, error) {
	var cfg struct {
		ZoneID   string `json:"zone_id"`
		Endpoint string `json:"endpoint,omitempty"`
	}
	if err := decodeACMEDNS01ProviderConfig(payload.Config, &cfg); err != nil {
		return nil, fmt.Errorf("server: decode cloudflare dns-01 config: %w", err)
	}
	token, err := a.secretRef(ctx, tenantID, payload.CredentialRefs, "api_token_ref")
	if err != nil {
		return nil, err
	}
	defer secret.Wipe(token)
	if err := requireACMEDNS01Fields("cloudflare", map[string]string{"zone_id": cfg.ZoneID}); err != nil {
		return nil, err
	}
	if len(token) == 0 {
		return nil, errors.New("server: cloudflare dns-01 credential ref api_token_ref is required")
	}
	opts := []dnscloudflare.Option{}
	if endpoint := strings.TrimSpace(cfg.Endpoint); endpoint != "" {
		opts = append(opts, dnscloudflare.WithEndpoint(endpoint))
	}
	return dnscloudflare.New(cfg.ZoneID, dnscloudflare.Credentials{APIToken: token}, opts...), nil
}

func (a *servedACMEDNS01Automation) rfc2136ProviderForPayload(ctx context.Context, tenantID string, payload acmeDNS01OutboxPayload) (acme.DNSProvider, error) {
	var cfg struct {
		Server      string `json:"server"`
		Zone        string `json:"zone,omitempty"`
		TSIGKeyName string `json:"tsig_key_name,omitempty"`
		TTL         uint32 `json:"ttl,omitempty"`
	}
	if err := decodeACMEDNS01ProviderConfig(payload.Config, &cfg); err != nil {
		return nil, fmt.Errorf("server: decode rfc2136 dns-01 config: %w", err)
	}
	if strings.TrimSpace(cfg.Zone) == "" {
		cfg.Zone = payloadZoneFallback(payload)
	}
	tsigSecret, err := a.secretRef(ctx, tenantID, payload.CredentialRefs, "tsig_secret_ref")
	if err != nil {
		return nil, err
	}
	defer secret.Wipe(tsigSecret)
	if err := requireACMEDNS01Fields("rfc2136", map[string]string{"server": cfg.Server, "zone": cfg.Zone}); err != nil {
		return nil, err
	}
	opts := []dnsrfc2136.Option{}
	if cfg.TTL > 0 {
		opts = append(opts, dnsrfc2136.WithTTL(cfg.TTL))
	}
	return dnsrfc2136.New(cfg.Server, cfg.Zone, dnsrfc2136.Credentials{KeyName: cfg.TSIGKeyName, Secret: tsigSecret}, opts...), nil
}

func (a *servedACMEDNS01Automation) webhookProviderForPayload(ctx context.Context, tenantID string, payload acmeDNS01OutboxPayload) (acme.DNSProvider, error) {
	var cfg struct {
		Endpoint string `json:"endpoint"`
	}
	if err := decodeACMEDNS01ProviderConfig(payload.Config, &cfg); err != nil {
		return nil, fmt.Errorf("server: decode webhook dns-01 config: %w", err)
	}
	cfg.Endpoint = strings.TrimSpace(cfg.Endpoint)
	if cfg.Endpoint == "" {
		return nil, errors.New("server: webhook dns-01 config requires endpoint")
	}
	token, err := a.secretRef(ctx, tenantID, payload.CredentialRefs, "bearer_token_ref")
	if err != nil {
		return nil, err
	}
	provider := dnswebhook.New(cfg.Endpoint, dnswebhook.Credentials{BearerToken: token})
	secret.Wipe(token)
	return provider, nil
}

func (a *servedACMEDNS01Automation) ns1ProviderForPayload(ctx context.Context, tenantID string, payload acmeDNS01OutboxPayload) (acme.DNSProvider, error) {
	var cfg struct {
		Zone     string `json:"zone,omitempty"`
		Endpoint string `json:"endpoint,omitempty"`
	}
	if err := decodeACMEDNS01ProviderConfig(payload.Config, &cfg); err != nil {
		return nil, fmt.Errorf("server: decode ns1 dns-01 config: %w", err)
	}
	if strings.TrimSpace(cfg.Zone) == "" {
		cfg.Zone = payloadZoneFallback(payload)
	}
	apiKey, err := a.secretRef(ctx, tenantID, payload.CredentialRefs, "api_key_ref")
	if err != nil {
		return nil, err
	}
	defer secret.Wipe(apiKey)
	if err := requireACMEDNS01Fields("ns1", map[string]string{"zone": cfg.Zone}); err != nil {
		return nil, err
	}
	if len(apiKey) == 0 {
		return nil, errors.New("server: ns1 dns-01 credential ref api_key_ref is required")
	}
	opts := []dnsns1.Option{}
	if endpoint := strings.TrimSpace(cfg.Endpoint); endpoint != "" {
		opts = append(opts, dnsns1.WithEndpoint(endpoint))
	}
	return dnsns1.New(cfg.Zone, dnsns1.Credentials{APIKey: apiKey}, opts...), nil
}

func (a *servedACMEDNS01Automation) akamaiProviderForPayload(ctx context.Context, tenantID string, payload acmeDNS01OutboxPayload) (acme.DNSProvider, error) {
	var cfg struct {
		Zone     string `json:"zone,omitempty"`
		Endpoint string `json:"endpoint"`
	}
	if err := decodeACMEDNS01ProviderConfig(payload.Config, &cfg); err != nil {
		return nil, fmt.Errorf("server: decode akamai dns-01 config: %w", err)
	}
	if strings.TrimSpace(cfg.Zone) == "" {
		cfg.Zone = payloadZoneFallback(payload)
	}
	clientToken, err := a.secretRef(ctx, tenantID, payload.CredentialRefs, "client_token_ref")
	if err != nil {
		return nil, err
	}
	defer secret.Wipe(clientToken)
	clientSecret, err := a.secretRef(ctx, tenantID, payload.CredentialRefs, "client_secret_ref")
	if err != nil {
		return nil, err
	}
	defer secret.Wipe(clientSecret)
	accessToken, err := a.secretRef(ctx, tenantID, payload.CredentialRefs, "access_token_ref")
	if err != nil {
		return nil, err
	}
	defer secret.Wipe(accessToken)
	if err := requireACMEDNS01Fields("akamai", map[string]string{"zone": cfg.Zone, "endpoint": cfg.Endpoint}); err != nil {
		return nil, err
	}
	if len(clientToken) == 0 || len(clientSecret) == 0 || len(accessToken) == 0 {
		return nil, errors.New("server: akamai dns-01 credential refs client_token_ref, client_secret_ref, and access_token_ref are required")
	}
	return dnsakamai.New(cfg.Zone, dnsakamai.Credentials{
		ClientToken: clientToken, ClientSecret: clientSecret, AccessToken: accessToken,
	}, dnsakamai.WithEndpoint(cfg.Endpoint)), nil
}

func (a *servedACMEDNS01Automation) ultradnsProviderForPayload(ctx context.Context, tenantID string, payload acmeDNS01OutboxPayload) (acme.DNSProvider, error) {
	var cfg struct {
		Zone     string `json:"zone,omitempty"`
		Endpoint string `json:"endpoint,omitempty"`
	}
	if err := decodeACMEDNS01ProviderConfig(payload.Config, &cfg); err != nil {
		return nil, fmt.Errorf("server: decode ultradns dns-01 config: %w", err)
	}
	if strings.TrimSpace(cfg.Zone) == "" {
		cfg.Zone = payloadZoneFallback(payload)
	}
	token, err := a.secretRef(ctx, tenantID, payload.CredentialRefs, "bearer_token_ref")
	if err != nil {
		return nil, err
	}
	defer secret.Wipe(token)
	if err := requireACMEDNS01Fields("ultradns", map[string]string{"zone": cfg.Zone}); err != nil {
		return nil, err
	}
	if len(token) == 0 {
		return nil, errors.New("server: ultradns dns-01 credential ref bearer_token_ref is required")
	}
	opts := []dnsultradns.Option{}
	if endpoint := strings.TrimSpace(cfg.Endpoint); endpoint != "" {
		opts = append(opts, dnsultradns.WithEndpoint(endpoint))
	}
	return dnsultradns.New(cfg.Zone, dnsultradns.Credentials{BearerToken: token}, opts...), nil
}

func (a *servedACMEDNS01Automation) acmeDNSProviderForPayload(ctx context.Context, tenantID string, payload acmeDNS01OutboxPayload) (acme.DNSProvider, error) {
	var cfg struct {
		Subdomain string `json:"subdomain"`
		Endpoint  string `json:"endpoint,omitempty"`
	}
	if err := decodeACMEDNS01ProviderConfig(payload.Config, &cfg); err != nil {
		return nil, fmt.Errorf("server: decode acmedns dns-01 config: %w", err)
	}
	username, err := a.secretRefString(ctx, tenantID, payload.CredentialRefs, "username_ref")
	if err != nil {
		return nil, err
	}
	password, err := a.secretRef(ctx, tenantID, payload.CredentialRefs, "password_ref")
	if err != nil {
		return nil, err
	}
	defer secret.Wipe(password)
	if err := requireACMEDNS01Fields("acmedns", map[string]string{"subdomain": cfg.Subdomain}); err != nil {
		return nil, err
	}
	if username == "" || len(password) == 0 {
		return nil, errors.New("server: acmedns dns-01 credential refs username_ref and password_ref are required")
	}
	opts := []dnsacmedns.Option{}
	if endpoint := strings.TrimSpace(cfg.Endpoint); endpoint != "" {
		opts = append(opts, dnsacmedns.WithEndpoint(endpoint))
	}
	return dnsacmedns.New(cfg.Subdomain, dnsacmedns.Credentials{Username: username, Password: password}, opts...), nil
}

func (a *servedACMEDNS01Automation) pluginProviderForPayload(ctx context.Context, tenantID string, payload acmeDNS01OutboxPayload) (acme.DNSProvider, error) {
	var cfg struct {
		Endpoint string `json:"endpoint"`
	}
	if err := decodeACMEDNS01ProviderConfig(payload.Config, &cfg); err != nil {
		return nil, fmt.Errorf("server: decode DNS plugin provider config: %w", err)
	}
	cfg.Endpoint = strings.TrimSpace(cfg.Endpoint)
	if cfg.Endpoint == "" {
		return nil, fmt.Errorf("server: DNS provider plugin %q config requires endpoint", payload.Provider)
	}
	token, err := a.secretRef(ctx, tenantID, payload.CredentialRefs, "bearer_token_ref")
	if err != nil {
		return nil, err
	}
	provider := dnswebhook.New(cfg.Endpoint, dnswebhook.Credentials{BearerToken: token})
	secret.Wipe(token)
	return &dns01PluginProvider{
		plugins: a.plugins, log: a.log, tenantID: tenantID, provider: payload.Provider,
		delegate: provider,
	}, nil
}

type dns01PluginProvider struct {
	plugins  *PluginManager
	log      *events.Log
	tenantID string
	provider string
	delegate acme.DNSProvider
}

var _ acme.DNSProvider = (*dns01PluginProvider)(nil)

func (p *dns01PluginProvider) PresentTXT(ctx context.Context, name, value string) error {
	if err := p.plugins.InvokeDNS(ctx, p.provider, dnsPluginPresentEntrypoint); err != nil {
		p.appendEvent(ctx, "acme.dns01.plugin.denied", name, err.Error())
		return err
	}
	if err := p.delegate.PresentTXT(ctx, name, value); err != nil {
		p.appendEvent(ctx, "acme.dns01.plugin.failed", name, err.Error())
		return err
	}
	p.appendEvent(ctx, "acme.dns01.plugin.presented", name, "")
	return nil
}

func (p *dns01PluginProvider) CleanupTXT(ctx context.Context, name, value string) error {
	if err := p.plugins.InvokeDNS(ctx, p.provider, dnsPluginCleanupEntrypoint); err != nil {
		p.appendEvent(ctx, "acme.dns01.plugin.denied", name, err.Error())
		return err
	}
	if err := p.delegate.CleanupTXT(ctx, name, value); err != nil {
		p.appendEvent(ctx, "acme.dns01.plugin.failed", name, err.Error())
		return err
	}
	p.appendEvent(ctx, "acme.dns01.plugin.cleaned", name, "")
	return nil
}

func (p *dns01PluginProvider) appendEvent(ctx context.Context, eventType, recordName, detail string) {
	if p.log == nil {
		return
	}
	data, err := json.Marshal(struct {
		Provider   string `json:"provider"`
		RecordName string `json:"record_name"`
		Detail     string `json:"detail,omitempty"`
	}{Provider: p.provider, RecordName: recordName, Detail: detail})
	if err != nil {
		return
	}
	_, _ = p.log.Append(ctx, events.Event{Type: eventType, TenantID: p.tenantID, Data: data})
}

func decodeACMEDNS01ProviderConfig(raw json.RawMessage, out any) error {
	if len(raw) == 0 {
		return nil
	}
	return json.Unmarshal(raw, out)
}

func requireACMEDNS01Fields(provider string, fields map[string]string) error {
	for name, value := range fields {
		if strings.TrimSpace(value) == "" {
			return fmt.Errorf("server: %s dns-01 config requires %s", provider, name)
		}
	}
	return nil
}

func payloadZoneFallback(payload acmeDNS01OutboxPayload) string {
	for _, zone := range []string{payload.Zone, payload.ChallengeDomain} {
		if zone = strings.TrimSuffix(strings.ToLower(strings.TrimSpace(zone)), "."); zone != "" {
			return zone
		}
	}
	domain := strings.TrimSuffix(strings.TrimPrefix(strings.ToLower(strings.TrimSpace(payload.Domain)), "*."), ".")
	if domain != "" {
		return domain
	}
	return strings.TrimSuffix(strings.ToLower(strings.TrimPrefix(strings.TrimSpace(payload.RecordName), "_acme-challenge.")), ".")
}

func (a *servedACMEDNS01Automation) wrapDelegatedDNS01Provider(payload acmeDNS01OutboxPayload, provider acme.DNSProvider) (acme.DNSProvider, error) {
	target := strings.TrimSuffix(strings.TrimSpace(payload.DelegationTarget), ".")
	if target == "" {
		return provider, nil
	}
	resolver := a.cnameResolver
	if resolver == nil {
		resolver = net.DefaultResolver
	}
	return acme.DelegatingProvider{
		Base: provider,
		Resolver: acmeDNS01ExpectedCNAMEResolver{
			resolver:   resolver,
			wantTarget: target,
		},
	}, nil
}

type acmeDNS01ExpectedCNAMEResolver struct {
	resolver   acme.CNAMEResolver
	wantTarget string
}

func (r acmeDNS01ExpectedCNAMEResolver) LookupCNAME(ctx context.Context, name string) (string, error) {
	if r.resolver == nil {
		return "", errors.New("server: acme dns-01 delegation requires a CNAME resolver")
	}
	got, err := r.resolver.LookupCNAME(ctx, name)
	if err != nil {
		return "", err
	}
	want := strings.TrimSuffix(strings.TrimSpace(r.wantTarget), ".")
	got = strings.TrimSuffix(strings.TrimSpace(got), ".")
	if want == "" {
		return "", errors.New("server: acme dns-01 delegation target is empty")
	}
	if !strings.EqualFold(got, want) {
		return "", fmt.Errorf("server: acme dns-01 delegation target mismatch for %s: got %q, want %q", name, got, want)
	}
	return got, nil
}

func (a *servedACMEDNS01Automation) secretRef(ctx context.Context, tenantID string, refsJSON json.RawMessage, field string) ([]byte, error) {
	var refs map[string]string
	if len(refsJSON) > 0 {
		if err := json.Unmarshal(refsJSON, &refs); err != nil {
			return nil, fmt.Errorf("server: decode acme dns-01 credential refs: %w", err)
		}
	}
	ref := strings.TrimSpace(refs[field])
	if ref == "" {
		return nil, nil
	}
	name := strings.TrimSpace(strings.TrimPrefix(ref, "secret://"))
	if name == "" || name == ref {
		return nil, fmt.Errorf("server: acme dns-01 credential ref %q must use secret://", field)
	}
	if a.kek == nil {
		return nil, errors.New("server: acme dns-01 credential references require the secret store KEK")
	}
	rec, err := a.store.GetSecret(ctx, tenantID, name)
	if err != nil {
		return nil, err
	}
	value, err := openTenantValue(ctx, a.crypto, a.kek, tenantID, rec.Sealed, []byte(tenantID+"/secret-store/"+name))
	if err != nil {
		return nil, err
	}
	return value, nil
}

func (a *servedACMEDNS01Automation) secretRefString(ctx context.Context, tenantID string, refsJSON json.RawMessage, field string) (string, error) {
	value, err := a.secretRef(ctx, tenantID, refsJSON, field)
	if err != nil {
		return "", err
	}
	defer secret.Wipe(value)
	return strings.TrimSpace(string(value)), nil
}

func (a *servedACMEDNS01Automation) appendRecordEvent(ctx context.Context, m orchestrator.Message, payload acmeDNS01OutboxPayload, eventType string) error {
	body, err := json.Marshal(acmeDNS01RecordEvent{
		ConfigID: payload.ConfigID, Provider: payload.Provider, Domain: payload.Domain,
		RecordName: payload.RecordName, OutboxID: m.ID, QualificationID: payload.QualificationID,
	})
	if err != nil {
		return err
	}
	_, err = a.log.Append(ctx, events.Event{Type: eventType, TenantID: m.TenantID, Data: body})
	return err
}

func acmeDNS01IdempotencyKey(destination, configID, recordName, value string) string {
	return destination + ":" + configID + ":" + recordName + ":" + value
}

func dns01ConfigMatchesDomain(cfg store.ACMEDNS01ProviderConfig, domain string) bool {
	base := strings.TrimSuffix(strings.TrimPrefix(strings.ToLower(strings.TrimSpace(domain)), "*."), ".")
	for _, zone := range []string{cfg.Zone, cfg.ChallengeDomain} {
		zone = strings.TrimSuffix(strings.ToLower(strings.TrimSpace(zone)), ".")
		if zone == "" {
			continue
		}
		if base == zone || strings.HasSuffix(base, "."+zone) {
			return true
		}
		recordName := strings.TrimSuffix(strings.ToLower(acme.DNS01RecordName(domain)), ".")
		if recordName == zone || strings.HasSuffix(recordName, "."+zone) {
			return true
		}
	}
	return false
}

func stringIn(needle string, haystack []string) bool {
	for _, item := range haystack {
		if item == needle {
			return true
		}
	}
	return false
}
