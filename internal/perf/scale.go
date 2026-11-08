// SPDX-License-Identifier: BUSL-1.1

package perf

import (
	"context"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"net/http"
	"runtime"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/jackc/pgx/v5"

	"trstctl.com/trstctl/internal/connector"
	"trstctl.com/trstctl/internal/connector/acm"
	"trstctl.com/trstctl/internal/connector/acm/acmtest"
	trstcrypto "trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/netsec"
	"trstctl.com/trstctl/internal/server"
	"trstctl.com/trstctl/internal/switchkit"
)

// The enterprise-scale harness (A266). It boots the eval stack the served
// live-load gate uses — a real loopback listener, bundled PostgreSQL,
// embedded JetStream and the signer as a child process over its Unix socket
// — and enters through the product's own API:
//
//  1. inventory: Inventory certificates another product's export describes,
//     generated from Seed so a rerun imports the same rows, imported through
//     the switching kit (preview, then apply against the reviewed digest) in
//     exports no larger than one may be, and applied by the leader's bounded
//     batches, each row becoming a certificate;
//  2. fleet: Renewals managed identities under a certificate profile whose
//     validity ceiling is FleetLifetimeSeconds, each bound to its own AWS
//     Certificate Manager target (the in-process ACM double that verifies
//     each request's SigV4 signature), requested by Clients concurrent
//     clients, issued through the built-in CA and deployed to its target;
//  3. renewal storm: once the last fleet certificate has entered its renewal
//     window (the last third of its lifetime), the scheduler's sweep, on the
//     real clock, finds the whole fleet due at once, and the outbox mints
//     and deploys every successor while readers page the inventory. The
//     successors' own windows open a lifetime later, so a renewal counted
//     twice is a defect, not the next cycle.
//
// Workers run as the runtime runs them (the switching-import recorder, the
// outbox drain, the lifecycle sweep), called directly as the live-load gate
// calls the issuance dispatcher. The report carries each phase's throughput
// and latency, the storm's drain time and queue depth, the control plane's,
// signer's and database's resources, and every correctness gap: a row not
// recorded, a fleet identity not renewed or renewed twice, a dead letter.

const scaleSchema = "trstctl.scale.v1"

// The ACM double's credentials: fabricated, accepted only by it.
const (
	scaleACMAccessKey = "AKIASCALEHARNESS0266"
	scaleACMSecretKey = "ScaleHarnessSecretForSigV4Only" // #nosec G101 -- a fabricated credential only the in-process ACM double accepts (CWE-798)
)

// ScaleConfig sizes one run.
type ScaleConfig struct {
	Inventory int    `json:"inventory"`
	Renewals  int    `json:"renewals"`
	Clients   int    `json:"clients"`
	Chunk     int    `json:"chunk"`
	Seed      uint64 `json:"seed"`
	// FleetLifetimeSeconds is the fleet's full signed certificate lifetime,
	// the built-in CA's NotBefore backdate included. A certificate enters its
	// renewal window two thirds of the way through, so the run waits about
	// two thirds of it less the backdate after issuing the fleet, and the
	// storm has as long again before the first successor's window opens.
	FleetLifetimeSeconds int `json:"fleet_lifetime_seconds"`
}

// The default storm budget is 200 ms a renewal and at least three minutes;
// the default lifetime gives the wait and the storm that budget each. The
// lifetime stays under the built-in CA's default leaf lifetime, at or above
// which a profile ceiling has no effect.
const (
	scaleMinStormBudget     = 3 * time.Minute
	scaleStormBudgetPerItem = 200 * time.Millisecond
	scaleMaxFleetLifetime   = 29 * 24 * time.Hour
)

// scaleLifetimeFor is the fleet lifetime that leaves the storm budget after
// the backdate: two thirds of it, less the backdate, is the budget.
func scaleLifetimeFor(budget, backdate time.Duration) time.Duration {
	return (budget + backdate) * 3 / 2
}

// Normalized fills defaults and bounds: an export is at most
// switchkit.MaxRows rows, and the default chunk stays well inside its byte
// limit.
func (c ScaleConfig) Normalized() ScaleConfig {
	if c.Inventory < 0 {
		c.Inventory = 0
	}
	if c.Renewals < 0 {
		c.Renewals = 0
	}
	if c.Clients <= 0 {
		c.Clients = 8
	}
	if c.Chunk <= 0 || c.Chunk > switchkit.MaxRows {
		c.Chunk = 25000
	}
	if c.Seed == 0 {
		c.Seed = 266
	}
	backdate := trstcrypto.IssuanceBackdateSkew()
	if c.FleetLifetimeSeconds <= 0 {
		budget := max(scaleMinStormBudget, time.Duration(c.Renewals)*scaleStormBudgetPerItem)
		c.FleetLifetimeSeconds = int(scaleLifetimeFor(budget, backdate) / time.Second)
	}
	// Never shorter than a minute's storm, never at the default leaf lifetime.
	floor := int(scaleLifetimeFor(time.Minute, backdate) / time.Second)
	c.FleetLifetimeSeconds = min(max(c.FleetLifetimeSeconds, floor), int(scaleMaxFleetLifetime/time.Second))
	return c
}

// fleetLifetime is the configured fleet certificate lifetime.
func (c ScaleConfig) fleetLifetime() time.Duration {
	return time.Duration(c.FleetLifetimeSeconds) * time.Second
}

// stormBudget is how long the storm has before the first successor's own
// renewal window opens.
func (c ScaleConfig) stormBudget() time.Duration {
	return c.fleetLifetime()*2/3 - trstcrypto.IssuanceBackdateSkew()
}

// ScaleReport is one run's receipt.
type ScaleReport struct {
	Schema     string                     `json:"schema"`
	Stack      string                     `json:"stack"`
	Config     ScaleConfig                `json:"config"`
	Host       ScaleHost                  `json:"host"`
	StartedAt  time.Time                  `json:"started_at"`
	FinishedAt time.Time                  `json:"finished_at"`
	Phases     []ScalePhase               `json:"phases"`
	Inventory  ScaleInventory             `json:"inventory"`
	Storm      ScaleStorm                 `json:"storm"`
	Resources  []ComponentResourceMetrics `json:"resources,omitempty"`
	Failures   []string                   `json:"failures"`
	OK         bool                       `json:"ok"`
}

// ScaleHost is where the run happened, without naming the machine.
type ScaleHost struct {
	OS        string `json:"os"`
	Arch      string `json:"arch"`
	CPUs      int    `json:"cpus"`
	GoVersion string `json:"go_version"`
}

// ScalePhase is one phase's work: how many items, how long, how fast, and,
// for phases made of requests, their latency.
type ScalePhase struct {
	Name      string        `json:"name"`
	Items     int           `json:"items"`
	Seconds   float64       `json:"seconds"`
	PerSecond float64       `json:"per_second"`
	Latency   *ScaleLatency `json:"latency_ms,omitempty"`
	Errors    int           `json:"errors"`
}

// ScaleLatency summarizes request latencies in milliseconds.
type ScaleLatency struct {
	Count int     `json:"count"`
	P50   float64 `json:"p50"`
	P95   float64 `json:"p95"`
	P99   float64 `json:"p99"`
	Max   float64 `json:"max"`
}

// ScaleInventory is what the inventory phase left behind.
type ScaleInventory struct {
	Imports       int            `json:"imports"`
	RowsTotal     int            `json:"rows_total"`
	RowsRecorded  int            `json:"rows_recorded"`
	RowsApplied   int            `json:"rows_applied"`
	Outcomes      map[string]int `json:"outcomes"`
	Certificates  int            `json:"certificates"`
	DatabaseBytes int64          `json:"database_bytes"`
}

// ScaleStorm is the renewal storm's account.
type ScaleStorm struct {
	Due               int          `json:"due"`
	Queued            int          `json:"queued"`
	Sweeps            int          `json:"sweeps"`
	Renewed           int          `json:"renewed"`
	Delivered         int          `json:"delivered"`
	NotRenewed        int          `json:"not_renewed"`
	RenewedTwice      int          `json:"renewed_twice"`
	DeadLetters       int          `json:"dead_letters"`
	MaxOutboxPending  int          `json:"max_outbox_pending"`
	DrainSeconds      float64      `json:"drain_seconds"`
	RenewalsPerSecond float64      `json:"renewals_per_second"`
	Reads             ScaleLatency `json:"reads_ms"`
}

func summarizeLatency(samples []float64) *ScaleLatency {
	if len(samples) == 0 {
		return nil
	}
	sorted := append([]float64(nil), samples...)
	sort.Float64s(sorted)
	return &ScaleLatency{Count: len(sorted), P50: percentile(sorted, 0.50), P95: percentile(sorted, 0.95),
		P99: percentile(sorted, 0.99), Max: maxOfSorted(sorted)}
}

func phase(name string, items int, elapsed time.Duration, latencies []float64, errs int) ScalePhase {
	p := ScalePhase{Name: name, Items: items, Seconds: elapsed.Seconds(), Latency: summarizeLatency(latencies), Errors: errs}
	if elapsed > 0 {
		p.PerSecond = float64(items) / elapsed.Seconds()
	}
	return p
}

// scaleExport renders inventory rows [from, to) as a switching export:
// metadata-only rows, the shape another product's export takes. Each row's
// fingerprint derives from the seed and its number, so a rerun is the same
// inventory.
func scaleExport(seed uint64, from, to int, now time.Time) ([]byte, error) {
	rows := make([]map[string]any, 0, to-from)
	for i := from; i < to; i++ {
		group := i % 20
		name := fmt.Sprintf("inv-%07d.scale.trstctl.test", i)
		rows = append(rows, map[string]any{
			"fingerprint_sha256": trstcrypto.SHA256Hex([]byte(fmt.Sprintf("trstctl-scale/%d/%d", seed, i))),
			"common_name":        name,
			"sans":               name,
			"serial":             trstcrypto.SHA256Hex([]byte(fmt.Sprintf("trstctl-scale-serial/%d/%d", seed, i)))[:20],
			"issuer":             fmt.Sprintf("CN=Scale Import CA %d", i%4),
			"not_after":          now.Add(time.Duration(30+i%335) * 24 * time.Hour).UTC().Format(time.RFC3339),
			"key_algorithm":      "ECDSA-P256",
			"folder":             fmt.Sprintf("Scale/Group-%02d", group),
			"application":        fmt.Sprintf("app-%02d", group),
			"owner_email":        fmt.Sprintf("owner-%02d@scale.trstctl.test", group),
		})
	}
	return json.Marshal(map[string]any{"certificates": rows})
}

// scaleParallel runs work(i) for i in [0, n) on clients goroutines and
// returns each call's latency in milliseconds and how many failed (the first
// failure is kept).
func scaleParallel(ctx context.Context, clients, n int, work func(context.Context, int) error) ([]float64, int, error) {
	var mu sync.Mutex
	latencies := make([]float64, 0, n)
	var failures int
	var first error
	var next atomic.Int64
	var wg sync.WaitGroup
	for c := 0; c < clients; c++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				i := int(next.Add(1) - 1)
				if i >= n || ctx.Err() != nil {
					return
				}
				start := time.Now()
				err := work(ctx, i)
				ms := float64(time.Since(start).Microseconds()) / 1000
				mu.Lock()
				latencies = append(latencies, ms)
				if err != nil {
					failures++
					if first == nil {
						first = err
					}
				}
				mu.Unlock()
			}
		}()
	}
	wg.Wait()
	return latencies, failures, first
}

// RunScale runs the harness once at cfg.
func RunScale(ctx context.Context, cfg ScaleConfig) (ScaleReport, error) {
	cfg = cfg.Normalized()
	report := ScaleReport{Schema: scaleSchema, Stack: liveStackProfile, Config: cfg, StartedAt: time.Now().UTC(),
		Host: ScaleHost{OS: runtime.GOOS, Arch: runtime.GOARCH, CPUs: runtime.NumCPU(), GoVersion: runtime.Version()}}
	fail := func(format string, args ...any) {
		report.Failures = append(report.Failures, fmt.Sprintf(format, args...))
	}
	// The fleet deploys to an ACM double. The fixed renewal horizon stays
	// inside the last quarter of a fleet certificate's life, so the renewal
	// window (its last third) is what makes the fleet due.
	provider := acmtest.New(scaleACMAccessKey, scaleACMSecretKey)
	defer provider.Close()
	registry := connector.NewRegistry(func(string) connector.Ops { return connector.NewHTTPOps(provider.Client()) })
	registry.Register(acm.New("us-east-1", acm.Credentials{AccessKeyID: scaleACMAccessKey, SecretAccessKey: []byte(scaleACMSecretKey)},
		acm.WithEndpoint(provider.URL())))
	stack, err := startLiveEvalStack(ctx, func(d *server.Deps) {
		d.LifecycleRenewBefore = cfg.fleetLifetime() / 4
		d.ConnectorRegistry = registry
	})
	if err != nil {
		return report, err
	}
	defer stack.Close()
	// Imports of tens of thousands of rows take longer than one hot-path call.
	stack.httpClient = netsec.InsecureLoopbackClient(15 * time.Minute)

	if err := stack.scaleInventory(ctx, cfg, &report, fail); err != nil {
		return report, err
	}
	fleet, err := stack.scaleFleet(ctx, cfg, provider, &report, fail)
	if err != nil {
		return report, err
	}
	if err := stack.scaleAge(ctx, cfg, &report); err != nil {
		return report, err
	}
	if err := stack.scaleStorm(ctx, cfg, fleet, provider, &report, fail); err != nil {
		return report, err
	}
	if resources, err := stack.componentResourceMetrics(ctx, 0); err == nil {
		report.Resources = resources
	} else {
		fail("resource metrics: %v", err)
	}
	report.FinishedAt = time.Now().UTC()
	report.OK = len(report.Failures) == 0
	return report, nil
}

func (s *liveEvalStack) scaleInventory(ctx context.Context, cfg ScaleConfig, report *ScaleReport, fail func(string, ...any)) error {
	if cfg.Inventory == 0 {
		return nil
	}
	report.Inventory.Outcomes = map[string]int{}
	var ids []string
	var applyMS []float64
	start := time.Now()
	for from := 0; from < cfg.Inventory; from += cfg.Chunk {
		to := min(from+cfg.Chunk, cfg.Inventory)
		export, err := scaleExport(cfg.Seed, from, to, start)
		if err != nil {
			return err
		}
		name := fmt.Sprintf("scale-%d-%07d", cfg.Seed, from)
		var preview struct {
			Rows   int            `json:"rows"`
			Counts map[string]int `json:"counts"`
			Digest string         `json:"digest"`
		}
		if err := s.doJSON(ctx, http.MethodPost, "/api/v1/switching/imports/preview", "", map[string]any{
			"name": name, "export": string(export),
		}, http.StatusOK, &preview); err != nil {
			return fmt.Errorf("scale: preview import %s: %w", name, err)
		}
		if preview.Rows != to-from || preview.Digest == "" {
			fail("import %s previewed %d rows, want %d", name, preview.Rows, to-from)
		}
		for outcome, n := range preview.Counts {
			report.Inventory.Outcomes[outcome] += n
		}
		applyStart := time.Now()
		var applied struct {
			ID        string `json:"id"`
			RowsTotal int    `json:"rows_total"`
		}
		if err := s.doJSON(ctx, http.MethodPost, "/api/v1/switching/imports", "scale-apply-"+name, map[string]any{
			"name": name, "export": string(export), "preview_digest": preview.Digest,
		}, http.StatusCreated, &applied); err != nil {
			return fmt.Errorf("scale: apply import %s: %w", name, err)
		}
		applyMS = append(applyMS, float64(time.Since(applyStart).Microseconds())/1000)
		ids = append(ids, applied.ID)
		report.Inventory.RowsTotal += applied.RowsTotal
	}
	applied := time.Since(start)
	report.Phases = append(report.Phases, phase("inventory.import", report.Inventory.RowsTotal, applied, applyMS, 0))

	// The leader records each import's certificates and owners in bounded
	// batches.
	recordStart := time.Now()
	for {
		n, err := s.srv.ApplySwitchingImportsOnce(ctx)
		if err != nil {
			return fmt.Errorf("scale: record imports: %w", err)
		}
		if n == 0 {
			break
		}
	}
	for _, id := range ids {
		var view struct {
			Status       string `json:"status"`
			RowsTotal    int    `json:"rows_total"`
			RowsRecorded int    `json:"rows_recorded"`
			RowsApplied  int    `json:"rows_applied"`
		}
		if err := s.doJSON(ctx, http.MethodGet, "/api/v1/switching/imports/"+id, "", nil, http.StatusOK, &view); err != nil {
			return err
		}
		report.Inventory.Imports++
		report.Inventory.RowsRecorded += view.RowsRecorded
		report.Inventory.RowsApplied += view.RowsApplied
		// Every generated row maps, so every row becomes a certificate.
		if view.Status != "completed" || view.RowsRecorded != view.RowsTotal || view.RowsApplied != view.RowsTotal {
			fail("import %s is %s with %d of %d rows recorded and %d applied", id, view.Status, view.RowsRecorded, view.RowsTotal, view.RowsApplied)
		}
	}
	report.Phases = append(report.Phases, phase("inventory.record", report.Inventory.RowsApplied, time.Since(recordStart), nil, 0))
	if err := s.store.WithTenant(ctx, liveTenantID, func(tx pgx.Tx) error {
		if err := tx.QueryRow(ctx, `SELECT count(*) FROM certificates WHERE tenant_id = $1`, liveTenantID).Scan(&report.Inventory.Certificates); err != nil {
			return err
		}
		return tx.QueryRow(ctx, `SELECT pg_database_size(current_database())`).Scan(&report.Inventory.DatabaseBytes)
	}); err != nil {
		return fmt.Errorf("scale: count inventory: %w", err)
	}
	if report.Inventory.Certificates < cfg.Inventory {
		fail("inventory holds %d certificates, want at least %d", report.Inventory.Certificates, cfg.Inventory)
	}
	return nil
}

// scaleFleetMember is one fleet identity and the ACM certificate it deploys to.
type scaleFleetMember struct {
	Name string
	ID   string
	ARN  string
}

// scaleFleetProfile is the certificate profile that gives the fleet its
// short lifetime.
const scaleFleetProfile = "scale-fleet"

func (s *liveEvalStack) scaleFleet(ctx context.Context, cfg ScaleConfig, provider *acmtest.Server, report *ScaleReport, fail func(string, ...any)) ([]scaleFleetMember, error) {
	fleet := make([]scaleFleetMember, cfg.Renewals)
	if cfg.Renewals == 0 {
		return fleet, nil
	}
	if err := s.doJSON(ctx, http.MethodPost, "/api/v1/profiles", "scale-fleet-profile", map[string]any{
		"name": scaleFleetProfile, "spec": map[string]any{"max_validity": cfg.fleetLifetime().String()},
	}, http.StatusCreated, nil); err != nil {
		return nil, fmt.Errorf("scale: fleet profile: %w", err)
	}
	start := time.Now()
	latencies, failed, firstErr := scaleParallel(ctx, cfg.Clients, cfg.Renewals, func(ctx context.Context, i int) error {
		m := scaleFleetMember{Name: fmt.Sprintf("fleet-%06d.scale.trstctl.test", i),
			ARN: fmt.Sprintf("arn:aws:acm:us-east-1:123456789012:certificate/scale-%06d", i)}
		var target, ident struct {
			ID string `json:"id"`
		}
		if err := s.doJSON(ctx, http.MethodPost, "/api/v1/connectors/targets", fmt.Sprintf("scale-target-%d", i), map[string]any{
			"name": m.ARN, "connector": "aws-acm", "enabled": true,
			"config": map[string]any{"region": "us-east-1", "access_key_id": scaleACMAccessKey,
				"secret_access_key_ref": "secret://connectors/aws-acm/scale"},
		}, http.StatusCreated, &target); err != nil {
			return err
		}
		if err := s.doJSON(ctx, http.MethodPost, "/api/v1/identities", fmt.Sprintf("scale-identity-%d", i), map[string]any{
			"kind": "x509_certificate", "name": m.Name, "owner_id": s.ownerID, "issuer_id": s.issuerID,
			"attributes": map[string]any{"profile_name": scaleFleetProfile},
		}, http.StatusCreated, &ident); err != nil {
			return err
		}
		m.ID = ident.ID
		fleet[i] = m
		if err := s.doJSON(ctx, http.MethodPost, "/api/v1/identities/"+ident.ID+"/connector-target", fmt.Sprintf("scale-bind-%d", i),
			map[string]any{"target_id": target.ID}, http.StatusOK, nil); err != nil {
			return err
		}
		return s.doJSON(ctx, http.MethodPost, "/api/v1/identities/"+ident.ID+"/transitions", fmt.Sprintf("scale-issue-%d", i), map[string]any{
			"to": "issued", "reason": "scale fleet",
		}, http.StatusOK, nil)
	})
	if failed > 0 {
		fail("fleet: %d of %d identities failed to queue issuance (first: %v)", failed, cfg.Renewals, firstErr)
	}
	report.Phases = append(report.Phases, phase("fleet.request", cfg.Renewals, time.Since(start), latencies, failed))

	// The outbox issues each certificate and deploys it to the identity's
	// target, as the runtime's drain does.
	issueStart := time.Now()
	if err := s.srv.Drain(ctx); err != nil {
		return nil, fmt.Errorf("scale: issue and deploy the fleet: %w", err)
	}
	certs, err := s.fleetCertificates(ctx)
	if err != nil {
		return nil, err
	}
	deployed, err := s.fleetDeployed(ctx)
	if err != nil {
		return nil, err
	}
	delivered, missing := 0, 0
	for _, m := range fleet {
		got := certs[m.Name]
		switch {
		case m.ID == "" || got.Count != 1 || !deployed[m.ID]:
			missing++
		case scaleDelivered(provider, m.ARN) == got.Latest:
			delivered++
		default:
			missing++
		}
	}
	report.Phases = append(report.Phases, phase("fleet.issue_deploy", delivered, time.Since(issueStart), nil, missing))
	if missing > 0 {
		fail("fleet: %d of %d identities were not issued exactly one certificate, deployed, and delivered to their ACM target", missing, cfg.Renewals)
	}
	return fleet, nil
}

// scaleAge waits until the last fleet certificate is inside its renewal
// window: its last third, the window the scheduler renews in.
func (s *liveEvalStack) scaleAge(ctx context.Context, cfg ScaleConfig, report *ScaleReport) error {
	if cfg.Renewals == 0 {
		return nil
	}
	var opens *time.Time
	if err := s.store.WithTenant(ctx, liveTenantID, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT max(c.not_after - ((c.not_after - c.not_before) / 3.0)) FROM certificates c
			WHERE c.tenant_id = $1 AND c.owner_id = $2 AND c.source = 'issued' AND c.status = 'active'
			  AND EXISTS (SELECT 1 FROM unnest(c.sans) AS name WHERE name LIKE 'fleet-%')`, liveTenantID, s.ownerID).Scan(&opens)
	}); err != nil {
		return err
	}
	start := time.Now()
	if opens != nil {
		wait := time.Until(opens.Add(time.Second))
		if wait > 0 {
			timer := time.NewTimer(wait)
			defer timer.Stop()
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-timer.C:
			}
		}
	}
	report.Phases = append(report.Phases, phase("fleet.age", cfg.Renewals, time.Since(start), nil, 0))
	return nil
}

// scaleDelivered is the SHA-256 fingerprint of the certificate the ACM
// double holds under arn, or "" when it holds none.
func scaleDelivered(provider *acmtest.Server, arn string) string {
	imported, ok := provider.Imported(arn)
	if !ok || len(imported.Certificate) == 0 {
		return ""
	}
	der := imported.Certificate
	if block, _ := pem.Decode(imported.Certificate); block != nil {
		der = block.Bytes
	}
	return trstcrypto.SHA256Hex(der)
}

// scaleFleetCerts is one fleet name's issued certificates: how many, and the
// newest one's fingerprint.
type scaleFleetCerts struct {
	Count  int
	Latest string
}

// fleetCertificates counts each fleet name's issued certificates.
func (s *liveEvalStack) fleetCertificates(ctx context.Context) (map[string]scaleFleetCerts, error) {
	out := map[string]scaleFleetCerts{}
	err := s.store.WithTenant(ctx, liveTenantID, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `SELECT name, count(*) OVER (PARTITION BY name), fingerprint FROM (
			SELECT unnest(sans) AS name, fingerprint, created_at FROM certificates WHERE tenant_id = $1 AND owner_id = $2 AND source = 'issued'
		) issued WHERE name LIKE 'fleet-%' ORDER BY name, created_at`, liveTenantID, s.ownerID)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var name, fingerprint string
			var n int
			if err := rows.Scan(&name, &n, &fingerprint); err != nil {
				return err
			}
			out[name] = scaleFleetCerts{Count: n, Latest: fingerprint}
		}
		return rows.Err()
	})
	return out, err
}

// fleetDeployed reports which fleet identities the lifecycle holds deployed.
func (s *liveEvalStack) fleetDeployed(ctx context.Context) (map[string]bool, error) {
	out := map[string]bool{}
	err := s.store.WithTenant(ctx, liveTenantID, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `SELECT id::text FROM identities WHERE tenant_id = $1 AND owner_id = $2
			AND name LIKE 'fleet-%' AND status = 'deployed'`, liveTenantID, s.ownerID)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var id string
			if err := rows.Scan(&id); err != nil {
				return err
			}
			out[id] = true
		}
		return rows.Err()
	})
	return out, err
}

// dispatchUntilIdle runs the runtime's outbox dispatcher until no entry of
// the tenant waits or runs.
func (s *liveEvalStack) dispatchUntilIdle(ctx context.Context) error {
	dispatch, stop := context.WithCancel(ctx)
	done := make(chan struct{})
	go func() {
		defer close(done)
		s.srv.RunDispatcher(dispatch)
	}()
	defer func() {
		stop()
		<-done
	}()
	tick := time.NewTicker(100 * time.Millisecond)
	defer tick.Stop()
	for {
		pending, _, err := s.outboxCounts(ctx)
		if err != nil {
			return err
		}
		if pending == 0 {
			return nil
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-tick.C:
		}
	}
}

func (s *liveEvalStack) outboxCounts(ctx context.Context) (pending, failed int, err error) {
	err = s.store.WithTenant(ctx, liveTenantID, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT count(*) FILTER (WHERE status IN ('pending', 'processing')),
			count(*) FILTER (WHERE status = 'failed') FROM outbox WHERE tenant_id = $1`, liveTenantID).Scan(&pending, &failed)
	})
	return pending, failed, err
}

func (s *liveEvalStack) scaleStorm(ctx context.Context, cfg ScaleConfig, fleet []scaleFleetMember, provider *acmtest.Server, report *ScaleReport, fail func(string, ...any)) error {
	if cfg.Renewals == 0 {
		return nil
	}
	before, err := s.fleetCertificates(ctx)
	if err != nil {
		return err
	}
	for _, m := range fleet {
		if before[m.Name].Count == 1 {
			report.Storm.Due++
		}
	}
	if report.Storm.Due != cfg.Renewals {
		fail("storm: %d of %d fleet identities hold one certificate before the storm", report.Storm.Due, cfg.Renewals)
	}

	// Readers page the inventory throughout the storm; a sampler watches the
	// outbox's depth.
	stormCtx, stopStorm := context.WithCancel(ctx)
	var readMu sync.Mutex
	var reads []float64
	var readErrors atomic.Int64
	var maxPending atomic.Int64
	var bg sync.WaitGroup
	for r := 0; r < max(1, cfg.Clients/2); r++ {
		bg.Add(1)
		go func() {
			defer bg.Done()
			for stormCtx.Err() == nil {
				start := time.Now()
				err := s.doJSON(stormCtx, http.MethodGet, "/api/v1/certificates?limit=50", "", nil, http.StatusOK, nil)
				if stormCtx.Err() != nil {
					return
				}
				readMu.Lock()
				reads = append(reads, float64(time.Since(start).Microseconds())/1000)
				readMu.Unlock()
				if err != nil {
					readErrors.Add(1)
				}
			}
		}()
	}
	bg.Add(1)
	go func() {
		defer bg.Done()
		ticker := time.NewTicker(200 * time.Millisecond)
		defer ticker.Stop()
		for {
			select {
			case <-stormCtx.Done():
				return
			case <-ticker.C:
				if pending, _, err := s.outboxCounts(stormCtx); err == nil && int64(pending) > maxPending.Load() {
					maxPending.Store(int64(pending))
				}
			}
		}
	}()
	start := time.Now()
	var stormErr error
	// The runtime's dispatcher delivers the storm, as it does in production:
	// its ticker and wake signal, its bounded family pools and the outbox's
	// per-tenant and per-lane caps.
	for {
		queued, err := s.srv.RunLifecycleOnce(ctx)
		if err != nil {
			stormErr = fmt.Errorf("scale: lifecycle sweep: %w", err)
			break
		}
		report.Storm.Sweeps++
		report.Storm.Queued += queued
		if err := s.dispatchUntilIdle(ctx); err != nil {
			stormErr = fmt.Errorf("scale: deliver the storm: %w", err)
			break
		}
		if queued == 0 {
			break
		}
	}
	elapsed := time.Since(start)
	stopStorm()
	bg.Wait()
	if stormErr != nil {
		return stormErr
	}
	report.Storm.DrainSeconds = elapsed.Seconds()
	report.Storm.MaxOutboxPending = int(maxPending.Load())
	if r := summarizeLatency(reads); r != nil {
		report.Storm.Reads = *r
	}
	if n := readErrors.Load(); n > 0 {
		fail("storm: %d inventory reads failed", n)
	}

	after, err := s.fleetCertificates(ctx)
	if err != nil {
		return err
	}
	deployed, err := s.fleetDeployed(ctx)
	if err != nil {
		return err
	}
	for _, m := range fleet {
		switch got := after[m.Name]; {
		case got.Count == 2:
			report.Storm.Renewed++
			// The successor is what the target serves, and the lifecycle holds
			// the identity deployed again.
			if deployed[m.ID] && got.Latest != before[m.Name].Latest && scaleDelivered(provider, m.ARN) == got.Latest {
				report.Storm.Delivered++
			}
		case got.Count > 2:
			report.Storm.RenewedTwice++
		default:
			report.Storm.NotRenewed++
		}
	}
	if elapsed > 0 {
		report.Storm.RenewalsPerSecond = float64(report.Storm.Renewed) / elapsed.Seconds()
	}
	if _, failed, err := s.outboxCounts(ctx); err != nil {
		return err
	} else {
		report.Storm.DeadLetters = failed
	}
	report.Phases = append(report.Phases, phase("storm.renew", report.Storm.Renewed, elapsed, nil, report.Storm.NotRenewed+report.Storm.RenewedTwice))
	if report.Storm.NotRenewed > 0 || report.Storm.RenewedTwice > 0 {
		fail("storm: %d fleet identities not renewed and %d renewed more than once", report.Storm.NotRenewed, report.Storm.RenewedTwice)
	}
	if report.Storm.Delivered != report.Storm.Renewed {
		fail("storm: %d of %d renewed identities do not have their successor deployed and delivered to their ACM target",
			report.Storm.Renewed-report.Storm.Delivered, report.Storm.Renewed)
	}
	if report.Storm.RenewedTwice > 0 && elapsed > cfg.stormBudget() {
		fail("storm: the storm took %s, longer than its %s budget before the first successor's renewal window opens; rerun with a longer --fleet-lifetime",
			elapsed.Round(time.Second), cfg.stormBudget().Round(time.Second))
	}
	if report.Storm.DeadLetters > 0 {
		fail("storm: %d outbox entries dead-lettered", report.Storm.DeadLetters)
	}
	if !strings.HasPrefix(report.Stack, "eval-") {
		fail("scale: unexpected stack profile %q", report.Stack)
	}
	return nil
}
