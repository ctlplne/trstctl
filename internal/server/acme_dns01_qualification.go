// SPDX-License-Identifier: MPL-2.0

package server

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"trstctl.com/trstctl/internal/api"
	trstcrypto "trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/crypto/secret"
	"trstctl.com/trstctl/internal/orchestrator"
	"trstctl.com/trstctl/internal/protocols/acme"
)

// #nosec G101 -- this is an operator-facing disclosure sentence, not credential material.
const acmeDNS01QualificationSecretBoundary = "No TXT value, provider credential, credential reference value, idempotency key, raw provider configuration, raw outbox payload, or raw worker error is returned."

// PreviewACMEDNS01Qualification proves what one exact provider test would do.
// It reads the tenant-scoped config and in-memory runtime only: CAA lookup,
// provider calls, probe generation, event appends, SQL writes, and signer calls
// all remain on the execute side of the explicit operator decision.
func (s *Server) PreviewACMEDNS01Qualification(ctx context.Context, tenantID, configID string, req api.ACMEDNS01QualificationRequest) (api.ACMEDNS01QualificationPreview, error) {
	if s == nil || s.store == nil {
		return api.ACMEDNS01QualificationPreview{}, api.ErrACMEDNS01QualificationUnavailable
	}
	cfg, err := s.store.GetACMEDNS01ProviderConfig(ctx, tenantID, strings.TrimSpace(configID))
	if err != nil {
		return api.ACMEDNS01QualificationPreview{}, err
	}
	domain, domainOK := normalizeDNS01QualificationDomain(req.Domain)
	recordName := ""
	if domainOK {
		recordName = acme.DNS01RecordName(domain)
	}
	referenceFields, refsOK := dns01CredentialReferenceFields(cfg.CredentialRefs)
	automationReady := s.acmeDNS01 != nil && s.acmeDNS01.store != nil && s.acmeDNS01.outbox != nil && s.acmeDNS01.log != nil
	resolverReady := automationReady && len(s.acmeDNS01.txtResolvers) > 0
	methodReady := stringIn(acme.ChallengeDNS01, cfg.AllowedMethods)
	coverageReady := domainOK && dns01ConfigMatchesDomain(cfg, domain)
	wildcardReady := domainOK && (!acme.IsWildcard(domain) || cfg.AllowWildcards)

	checks := []api.ACMEDNS01QualificationCheck{
		qualificationCheck("domain", "DNS name", domainOK,
			"The domain is a normalized ASCII DNS name.",
			"Enter a hostname such as api.example.com; use its ASCII/Punycode form and at most one leading wildcard."),
		qualificationCheck("domain-policy", "Domain policy", coverageReady,
			"This provider config covers the requested domain.",
			"Choose a config whose zone or challenge domain covers this DNS name."),
		qualificationCheck("dns-01-policy", "DNS-01 permission", methodReady,
			"The config permits DNS-01 for this zone.",
			"Add dns-01 to the config's allowed methods before testing or issuing."),
		qualificationCheck("wildcard-policy", "Wildcard permission", wildcardReady,
			"The config's wildcard policy allows this request shape.",
			"Use a non-wildcard name or explicitly allow wildcard issuance on this config."),
		qualificationCheck("reference-shape", "Credential references", refsOK,
			"Credential references are structurally valid and remain server-side.",
			"Replace credential_refs with a JSON object containing secret:// references; never paste provider tokens into config JSON."),
		qualificationCheck("production-path", "Production provider path", automationReady,
			"Publish and cleanup will use the served DNS-01 outbox worker.",
			"Restore the DNS-01 automation and outbox worker, then review the test again."),
		qualificationCheck("propagation-view", "DNS visibility check", resolverReady,
			"The test will use the same DNS resolver wired into served ACME validation.",
			"Enable served ACME with a real DNS-01 validator/resolver, then review the test again."),
	}
	blockers := qualificationBlockers(checks)
	return api.ACMEDNS01QualificationPreview{
		Ready:                     domainOK && coverageReady && methodReady && wildcardReady && refsOK && automationReady && resolverReady,
		EffectFree:                true,
		ConfigID:                  cfg.ID,
		ConfigName:                cfg.Name,
		Provider:                  cfg.Provider,
		Domain:                    domain,
		RecordName:                recordName,
		Wildcard:                  acme.IsWildcard(domain),
		CredentialReferenceFields: referenceFields,
		Checks:                    checks,
		Blockers:                  blockers,
		PreviewWrites:             []string{},
		PreviewExternalEffects:    []string{},
		PreviewSignerCalls:        []string{},
		ExecuteWrites: []string{
			"Create bounded publish and cleanup outbox receipts for this one probe.",
			"Append sanitized publish and cleanup audit events after each receiver action succeeds.",
		},
		ExecuteExternalEffects: []string{
			"Publish one server-generated random TXT probe at " + displayRecordName(recordName) + ".",
			"Remove that exact TXT probe after DNS visibility is checked, including when the visibility check fails.",
		},
		ExecuteSignerCalls: []string{},
		RecoverySteps: []string{
			"If publish fails, repair only the named provider/config/reference boundary and run a new test.",
			"If DNS visibility fails, repair authoritative DNS or CNAME delegation; cleanup still runs before the result returns.",
			"If cleanup needs attention, use Retry cleanup from qualification history; the server reuses its retained recovery payload.",
		},
		LeastPrivilegeChecklist: []string{
			"Grant TXT create/update/delete only for " + displayRecordName(recordName) + " or the narrowest supported _acme-challenge subtree.",
			"Use a dedicated provider credential reference; do not reuse an account-wide administrator token.",
			"Allow only the provider API host required by this config and keep wildcard issuance off unless it is needed.",
		},
		SecretDataHandling: "The browser receives credential reference field names only. " + acmeDNS01QualificationSecretBoundary,
	}, nil
}

// RunACMEDNS01Qualification performs the real provider test. Every provider
// call travels through the same outbox delivery code as an ACME order, and the
// server attempts cleanup with an independent bounded context even if the
// caller disconnects or propagation fails.
func (s *Server) RunACMEDNS01Qualification(ctx context.Context, tenantID, configID, _ string, req api.ACMEDNS01QualificationRequest) (api.ACMEDNS01QualificationRun, error) {
	preview, err := s.PreviewACMEDNS01Qualification(ctx, tenantID, configID, req)
	if err != nil {
		return api.ACMEDNS01QualificationRun{}, err
	}
	started := time.Now().UTC()
	runID := uuid.NewString()
	if !preview.Ready {
		return qualificationBlockedRun(runID, preview, started), nil
	}
	cfg, err := s.store.GetACMEDNS01ProviderConfig(ctx, tenantID, configID)
	if err != nil {
		return api.ACMEDNS01QualificationRun{}, err
	}
	if err := s.acmeDNS01.enforceLiveCAA(ctx, preview.Domain, cfg); err != nil {
		return qualificationFailureRun(runID, preview, started, "review", "not_run", "not_needed", "caa_policy_rejected", 0), nil
	}
	probe, err := trstcrypto.RandomBytes(32)
	if err != nil {
		return api.ACMEDNS01QualificationRun{}, fmt.Errorf("server: generate DNS-01 qualification probe: %w", err)
	}
	value := trstcrypto.SHA256Base64URL(probe)
	secret.Wipe(probe)

	payload := acmeDNS01OutboxPayload{
		ConfigID: cfg.ID, ConfigName: cfg.Name, Provider: cfg.Provider, Domain: preview.Domain,
		Zone: cfg.Zone, ChallengeDomain: cfg.ChallengeDomain, DelegationTarget: cfg.DelegationTarget,
		RecordName: preview.RecordName, Value: value, CredentialRefs: cfg.CredentialRefs, Config: cfg.Config,
		QualificationID: runID, QualificationStatus: "running", PropagationStatus: "pending",
	}
	presentKey := acmeDNS01IdempotencyKey(destinationACMEDNS01Present, cfg.ID, preview.RecordName, value+"#qualification#"+runID)
	presentRec, presentErr := s.acmeDNS01.enqueueAndWaitRecord(ctx, tenantID, destinationACMEDNS01Present, presentKey, payload)

	propagationStatus := "not_run"
	failureStage := ""
	errorCategory := ""
	if presentErr != nil {
		failureStage = "publish"
		errorCategory = "publish_delivery_failed"
	} else {
		checker := &acme.PropagationChecker{Resolvers: append([]acme.Resolver(nil), s.acmeDNS01.txtResolvers...)}
		if err := checker.Wait(ctx, preview.RecordName, value); err != nil {
			propagationStatus = "failed"
			failureStage = "propagation"
			errorCategory = "propagation_not_visible"
		} else {
			propagationStatus = "passed"
		}
	}

	cleanupPayload := payload
	cleanupPayload.PropagationStatus = propagationStatus
	cleanupPayload.FailureStage = failureStage
	cleanupPayload.ErrorCategory = errorCategory
	if failureStage == "" {
		cleanupPayload.QualificationStatus = "passed"
	} else {
		cleanupPayload.QualificationStatus = "failed"
	}
	cleanupKey := acmeDNS01IdempotencyKey(destinationACMEDNS01Cleanup, cfg.ID, preview.RecordName, value+"#qualification#"+runID)
	cleanupCtx, cancelCleanup := context.WithTimeout(context.WithoutCancel(ctx), acmeDNS01OutboxWait)
	cleanupRec, cleanupErr := s.acmeDNS01.enqueueAndWaitRecord(cleanupCtx, tenantID, destinationACMEDNS01Cleanup, cleanupKey, cleanupPayload)
	cancelCleanup()

	completed := time.Now().UTC()
	attempts := presentRec.Attempts + cleanupRec.Attempts
	if cleanupErr != nil {
		return qualificationFailureRun(runID, preview, started, "cleanup", propagationStatus, "failed", "cleanup_delivery_failed", attempts), nil
	}
	if presentErr != nil {
		return qualificationFailureRun(runID, preview, started, "publish", propagationStatus, "delivered", errorCategory, attempts), nil
	}
	if propagationStatus != "passed" {
		return qualificationFailureRun(runID, preview, started, "propagation", propagationStatus, "delivered", errorCategory, attempts), nil
	}
	return qualificationRun(runID, preview, "passed", "complete", "passed", "delivered", "", attempts, started, completed), nil
}

type dns01QualificationOutboxRow struct {
	ID          int64
	Destination string
	Status      string
	Attempts    int
	CreatedAt   time.Time
	DeliveredAt *time.Time
	Payload     acmeDNS01OutboxPayload
}

// ListACMEDNS01QualificationRuns derives durable, sanitized operator history
// from the production outbox receipts. The payload is decoded only in-process;
// only the small allowlisted response above crosses the API boundary.
func (s *Server) ListACMEDNS01QualificationRuns(ctx context.Context, tenantID, configID string, limit int) ([]api.ACMEDNS01QualificationRun, error) {
	if s == nil || s.store == nil {
		return nil, api.ErrACMEDNS01QualificationUnavailable
	}
	if limit <= 0 || limit > 100 {
		limit = 25
	}
	rows, err := s.loadDNS01QualificationOutboxRows(ctx, tenantID, strings.TrimSpace(configID), limit*4)
	if err != nil {
		return nil, err
	}
	type group struct {
		ID       string
		MaxID    int64
		Present  *dns01QualificationOutboxRow
		Cleanups []dns01QualificationOutboxRow
	}
	groups := map[string]*group{}
	for i := range rows {
		row := rows[i]
		id := row.Payload.QualificationID
		if id == "" {
			continue
		}
		g := groups[id]
		if g == nil {
			g = &group{ID: id}
			groups[id] = g
		}
		if row.ID > g.MaxID {
			g.MaxID = row.ID
		}
		if row.Destination == destinationACMEDNS01Present && g.Present == nil {
			copyRow := row
			g.Present = &copyRow
		}
		if row.Destination == destinationACMEDNS01Cleanup {
			g.Cleanups = append(g.Cleanups, row)
		}
	}
	ordered := make([]*group, 0, len(groups))
	for _, g := range groups {
		ordered = append(ordered, g)
	}
	sort.Slice(ordered, func(i, j int) bool { return ordered[i].MaxID > ordered[j].MaxID })
	out := make([]api.ACMEDNS01QualificationRun, 0, min(limit, len(ordered)))
	for _, g := range ordered {
		if len(out) >= limit {
			break
		}
		out = append(out, dns01QualificationRunFromRows(g.ID, g.Present, g.Cleanups))
	}
	return out, nil
}

func (s *Server) RetryACMEDNS01QualificationCleanup(ctx context.Context, tenantID, runID, _ string) (api.ACMEDNS01QualificationRun, error) {
	if s == nil || s.acmeDNS01 == nil || s.store == nil {
		return api.ACMEDNS01QualificationRun{}, api.ErrACMEDNS01QualificationUnavailable
	}
	runID = strings.TrimSpace(runID)
	rows, err := s.loadDNS01QualificationOutboxRows(ctx, tenantID, "", 400)
	if err != nil {
		return api.ACMEDNS01QualificationRun{}, err
	}
	var source *dns01QualificationOutboxRow
	for i := range rows {
		if rows[i].Payload.QualificationID != runID {
			continue
		}
		if source == nil || (source.Destination != destinationACMEDNS01Cleanup && rows[i].Destination == destinationACMEDNS01Cleanup) {
			copyRow := rows[i]
			source = &copyRow
		}
	}
	if source == nil {
		return api.ACMEDNS01QualificationRun{}, api.ErrACMEDNS01QualificationRunNotFound
	}
	current, err := s.ListACMEDNS01QualificationRuns(ctx, tenantID, source.Payload.ConfigID, 100)
	if err != nil {
		return api.ACMEDNS01QualificationRun{}, err
	}
	for _, run := range current {
		if run.ID == runID && run.CleanupStatus == "delivered" {
			return run, nil
		}
	}
	payload := source.Payload
	payload.RecoveryOf = runID
	payload.FailureStage = ""
	payload.ErrorCategory = ""
	cleanupKey := acmeDNS01IdempotencyKey(destinationACMEDNS01Cleanup, payload.ConfigID, payload.RecordName, payload.Value+"#recovery#"+uuid.NewString())
	cleanupCtx, cancelCleanup := context.WithTimeout(context.WithoutCancel(ctx), acmeDNS01OutboxWait)
	_, cleanupErr := s.acmeDNS01.enqueueAndWaitRecord(cleanupCtx, tenantID, destinationACMEDNS01Cleanup, cleanupKey, payload)
	cancelCleanup()
	listCtx, cancelList := context.WithTimeout(context.WithoutCancel(ctx), acmeDNS01OutboxWait)
	defer cancelList()
	runs, listErr := s.ListACMEDNS01QualificationRuns(listCtx, tenantID, payload.ConfigID, 100)
	if listErr != nil {
		return api.ACMEDNS01QualificationRun{}, listErr
	}
	for _, run := range runs {
		if run.ID == runID {
			if cleanupErr != nil {
				run.Status = "recovery_required"
				run.Stage = "cleanup"
				run.CleanupStatus = "failed"
				run.ErrorCategory = "cleanup_delivery_failed"
			}
			return run, nil
		}
	}
	return api.ACMEDNS01QualificationRun{}, api.ErrACMEDNS01QualificationRunNotFound
}

func (s *Server) loadDNS01QualificationOutboxRows(ctx context.Context, tenantID, configID string, limit int) ([]dns01QualificationOutboxRow, error) {
	var out []dns01QualificationOutboxRow
	err := s.store.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx,
			`SELECT id, destination, status, attempts, created_at, delivered_at, payload
			   FROM outbox
			  WHERE tenant_id = $1
			    AND destination IN ('acme.dns01.present', 'acme.dns01.cleanup')
			    AND COALESCE(convert_from(payload, 'UTF8')::jsonb ->> 'qualification_id', '') <> ''
			    AND ($2 = '' OR convert_from(payload, 'UTF8')::jsonb ->> 'config_id' = $2)
			  ORDER BY id DESC
			  LIMIT $3`, tenantID, configID, limit)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var rec dns01QualificationOutboxRow
			var payload []byte
			if err := rows.Scan(&rec.ID, &rec.Destination, &rec.Status, &rec.Attempts, &rec.CreatedAt, &rec.DeliveredAt, &payload); err != nil {
				return err
			}
			if err := json.Unmarshal(payload, &rec.Payload); err != nil {
				return fmt.Errorf("server: decode DNS-01 qualification recovery payload: %w", err)
			}
			out = append(out, rec)
		}
		return rows.Err()
	})
	return out, err
}

func dns01QualificationRunFromRows(runID string, present *dns01QualificationOutboxRow, cleanups []dns01QualificationOutboxRow) api.ACMEDNS01QualificationRun {
	var source dns01QualificationOutboxRow
	if present != nil {
		source = *present
	}
	if len(cleanups) > 0 {
		sort.Slice(cleanups, func(i, j int) bool { return cleanups[i].ID > cleanups[j].ID })
		if present == nil {
			source = cleanups[0]
		}
	}
	started := source.CreatedAt.UTC()
	completed := time.Time{}
	status, stage := "running", "publish"
	propagationStatus, cleanupStatus, errorCategory := "pending", "pending", ""
	attempts := 0
	if present != nil {
		started = present.CreatedAt.UTC()
		attempts += present.Attempts
		if present.Status == "failed" {
			status, stage, propagationStatus, errorCategory = "failed", "publish", "not_run", "publish_delivery_failed"
		}
	}
	if len(cleanups) > 0 {
		latest := cleanups[0]
		attempts += latest.Attempts
		propagationStatus = firstNonEmpty(latest.Payload.PropagationStatus, propagationStatus)
		if latest.DeliveredAt != nil {
			completed = latest.DeliveredAt.UTC()
		} else {
			completed = latest.CreatedAt.UTC()
		}
		switch latest.Status {
		case "delivered":
			cleanupStatus = "delivered"
			if propagationStatus == "passed" && latest.Payload.QualificationStatus == "passed" {
				status, stage = "passed", "complete"
			} else {
				status = "failed"
				stage = firstNonEmpty(latest.Payload.FailureStage, "propagation")
				errorCategory = firstNonEmpty(latest.Payload.ErrorCategory, "propagation_not_visible")
			}
		case "failed":
			status, stage, cleanupStatus, errorCategory = "recovery_required", "cleanup", "failed", "cleanup_delivery_failed"
		default:
			status, stage, cleanupStatus = "running", "cleanup", "pending"
		}
	}
	duration := int64(0)
	if !completed.IsZero() && !started.IsZero() {
		duration = completed.Sub(started).Milliseconds()
		if duration < 0 {
			duration = 0
		}
	}
	run := api.ACMEDNS01QualificationRun{
		ID: runID, ConfigID: source.Payload.ConfigID, ConfigName: source.Payload.ConfigName,
		Provider: source.Payload.Provider, Domain: source.Payload.Domain, RecordName: source.Payload.RecordName,
		Status: status, Stage: stage, PropagationStatus: propagationStatus, CleanupStatus: cleanupStatus,
		ErrorCategory: errorCategory, Attempts: attempts, StartedAt: started.Format(time.RFC3339), DurationMS: duration,
		RecoverySteps: qualificationRecoverySteps(stage, cleanupStatus), SecretDataHandling: acmeDNS01QualificationSecretBoundary,
	}
	if !completed.IsZero() {
		run.CompletedAt = completed.Format(time.RFC3339)
	}
	return run
}

func qualificationRun(id string, preview api.ACMEDNS01QualificationPreview, status, stage, propagation, cleanup, category string, attempts int, started, completed time.Time) api.ACMEDNS01QualificationRun {
	duration := completed.Sub(started).Milliseconds()
	if duration < 0 {
		duration = 0
	}
	return api.ACMEDNS01QualificationRun{
		ID: id, ConfigID: preview.ConfigID, ConfigName: preview.ConfigName, Provider: preview.Provider,
		Domain: preview.Domain, RecordName: preview.RecordName, Status: status, Stage: stage,
		PropagationStatus: propagation, CleanupStatus: cleanup, ErrorCategory: category, Attempts: attempts,
		StartedAt: started.Format(time.RFC3339), CompletedAt: completed.Format(time.RFC3339), DurationMS: duration,
		RecoverySteps: qualificationRecoverySteps(stage, cleanup), SecretDataHandling: acmeDNS01QualificationSecretBoundary,
	}
}

func qualificationBlockedRun(id string, preview api.ACMEDNS01QualificationPreview, started time.Time) api.ACMEDNS01QualificationRun {
	return qualificationRun(id, preview, "failed", "review", "not_run", "not_needed", "review_blocked", 0, started, time.Now().UTC())
}

func qualificationFailureRun(id string, preview api.ACMEDNS01QualificationPreview, started time.Time, stage, propagation, cleanup, category string, attempts int) api.ACMEDNS01QualificationRun {
	status := "failed"
	if cleanup == "failed" {
		status = "recovery_required"
	}
	return qualificationRun(id, preview, status, stage, propagation, cleanup, category, attempts, started, time.Now().UTC())
}

func qualificationRecoverySteps(stage, cleanup string) []string {
	if cleanup == "failed" {
		return []string{
			"Repair the provider credential reference, provider permission, network route, or provider service named by server logs.",
			"Use Retry cleanup on this qualification row. The server retains the exact probe recovery payload; do not paste a TXT value or token into the browser.",
			"Confirm the TXT record is absent before starting another qualification or ACME order.",
		}
	}
	switch stage {
	case "publish":
		return []string{"Repair the provider configuration or credential reference, then run a new provider test. Cleanup was still attempted conservatively."}
	case "propagation":
		return []string{"Repair authoritative DNS or CNAME delegation, wait for the intended TTL, then run a new provider test. The failed probe was cleaned up."}
	case "review":
		return []string{"Resolve every blocked review check, review the effect-free plan again, then run the provider test."}
	default:
		return []string{"No recovery is required. Run the test again whenever DNS provider configuration, credentials, delegation, or authoritative nameservers change."}
	}
}

func qualificationCheck(id, label string, passed bool, success, recovery string) api.ACMEDNS01QualificationCheck {
	detail := success
	if !passed {
		detail = recovery
	}
	return api.ACMEDNS01QualificationCheck{ID: id, Label: label, Passed: passed, Detail: detail, Recovery: recovery}
}

func qualificationBlockers(checks []api.ACMEDNS01QualificationCheck) []string {
	blockers := make([]string, 0)
	for _, check := range checks {
		if !check.Passed {
			blockers = append(blockers, check.Label+": "+check.Recovery)
		}
	}
	return blockers
}

func dns01CredentialReferenceFields(raw json.RawMessage) ([]string, bool) {
	if len(raw) == 0 {
		return []string{}, true
	}
	var refs map[string]json.RawMessage
	if err := json.Unmarshal(raw, &refs); err != nil || refs == nil {
		return []string{}, false
	}
	fields := make([]string, 0, len(refs))
	for field := range refs {
		field = strings.TrimSpace(field)
		if field == "" {
			return []string{}, false
		}
		fields = append(fields, field)
	}
	sort.Strings(fields)
	return fields, true
}

func normalizeDNS01QualificationDomain(raw string) (string, bool) {
	domain := strings.ToLower(strings.TrimSuffix(strings.TrimSpace(raw), "."))
	wildcard := strings.HasPrefix(domain, "*.")
	base := strings.TrimPrefix(domain, "*.")
	if base == "" || len(base) > 253 || strings.ContainsAny(base, " /\\\t\r\n\x00") || strings.Contains(base, "..") {
		return domain, false
	}
	labels := strings.Split(base, ".")
	if len(labels) < 2 {
		return domain, false
	}
	for _, label := range labels {
		if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return domain, false
		}
		for _, ch := range label {
			if (ch < 'a' || ch > 'z') && (ch < '0' || ch > '9') && ch != '-' {
				return domain, false
			}
		}
	}
	if wildcard {
		return "*." + base, true
	}
	return base, true
}

func displayRecordName(name string) string {
	if name == "" {
		return "the reviewed _acme-challenge name"
	}
	return name
}

var _ orchestrator.Handler = (*servedACMEDNS01Automation)(nil)
var _ api.ACMEDNS01QualificationService = (*Server)(nil)
