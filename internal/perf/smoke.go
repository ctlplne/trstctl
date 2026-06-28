package perf

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"time"

	"google.golang.org/protobuf/proto"

	trstcrypto "trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/crypto/seal"
	"trstctl.com/trstctl/internal/crypto/secret"
	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/graph"
	"trstctl.com/trstctl/internal/projections"
	"trstctl.com/trstctl/internal/protocols/acme"
	"trstctl.com/trstctl/internal/risk"
	signerpb "trstctl.com/trstctl/internal/signing/proto"
	"trstctl.com/trstctl/internal/store"
)

type Result struct {
	HotPath             string           `json:"hot_path"`
	SLOID               string           `json:"slo_id"`
	Benchmark           string           `json:"benchmark"`
	Phase               string           `json:"phase,omitempty"`
	Samples             int              `json:"samples"`
	P50MS               float64          `json:"p50_ms"`
	P95MS               float64          `json:"p95_ms"`
	P99MS               float64          `json:"p99_ms"`
	MaxMS               float64          `json:"max_ms"`
	ThroughputPerSecond float64          `json:"throughput_per_second"`
	TargetRatePerSecond float64          `json:"target_rate_per_second,omitempty"`
	ErrorBudgetPercent  float64          `json:"error_budget_percent"`
	QueueSaturation     float64          `json:"queue_saturation"`
	ProjectionLagEvents int              `json:"projection_lag_events"`
	Errors              int              `json:"errors"`
	ServedStack         bool             `json:"served_stack,omitempty"`
	StackProfile        string           `json:"stack_profile,omitempty"`
	Transport           string           `json:"transport,omitempty"`
	ResourceMetrics     *ResourceMetrics `json:"resource_metrics,omitempty"`
	Met                 bool             `json:"met"`
	Failures            []string         `json:"failures,omitempty"`
}

type Observation struct {
	ErrorBudgetPercent  float64 `json:"error_budget_percent"`
	QueueSaturation     float64 `json:"queue_saturation"`
	ProjectionLagEvents int     `json:"projection_lag_events"`
}

type ResourceMetrics struct {
	Goroutines        int    `json:"goroutines"`
	CPUCount          int    `json:"cpu_count"`
	OpenFDs           int    `json:"open_fds"`
	HeapAllocBytes    uint64 `json:"heap_alloc_bytes"`
	HeapInuseBytes    uint64 `json:"heap_inuse_bytes"`
	StackInuseBytes   uint64 `json:"stack_inuse_bytes"`
	TotalAllocBytes   uint64 `json:"total_alloc_bytes"`
	MemorySysBytes    uint64 `json:"memory_sys_bytes"`
	NumGC             uint32 `json:"num_gc"`
	ProjectionLagHint int    `json:"projection_lag_hint"`
}

type LoadPhase struct {
	Name                 string  `json:"name"`
	Samples              int     `json:"samples"`
	TargetRateMultiplier float64 `json:"target_rate_multiplier"`
	RateMultiplier       float64 `json:"rate_multiplier"`
}

type Report struct {
	SchemaVersion       int              `json:"schema_version"`
	Profile             string           `json:"profile"`
	GeneratedAt         string           `json:"generated_at"`
	MeasurementArtifact string           `json:"measurement_artifact"`
	CapacityTiers       []string         `json:"capacity_tiers"`
	ServedStack         bool             `json:"served_stack,omitempty"`
	StackProfile        string           `json:"stack_profile,omitempty"`
	LoadPhases          []LoadPhase      `json:"load_phases,omitempty"`
	ResourceMetrics     *ResourceMetrics `json:"resource_metrics,omitempty"`
	Results             []Result         `json:"results"`
	Summary             Summary          `json:"summary"`
}

type Summary struct {
	HotPaths     int      `json:"hot_paths"`
	Measurements int      `json:"measurements,omitempty"`
	Phases       []string `json:"phases,omitempty"`
	Met          int      `json:"met"`
	Failed       int      `json:"failed"`
	OK           bool     `json:"ok"`
}

type operation func() error

func RunSmoke(profile string, samples int) (Report, error) {
	return RunSmokeWithObservations(profile, samples, nil)
}

func RunSmokeWithObservations(profile string, samples int, observations map[string]Observation) (Report, error) {
	if profile == "" {
		profile = "smoke"
	}
	if samples <= 0 {
		samples = 64
	}
	if err := validateObservations(observations); err != nil {
		return Report{}, err
	}
	ops, cleanup, err := operations()
	if err != nil {
		return Report{}, err
	}
	defer cleanup()

	report := Report{
		SchemaVersion:       1,
		Profile:             profile,
		GeneratedAt:         time.Now().UTC().Format(time.RFC3339),
		MeasurementArtifact: MeasurementArtifact,
		CapacityTiers:       capacityTierIDs(),
	}
	for _, slo := range HotPaths() {
		op, ok := ops[slo.HotPath]
		if !ok {
			return Report{}, fmt.Errorf("perf: no smoke operation for hot path %s", slo.HotPath)
		}
		result := measure(slo, op, samples, observations[slo.HotPath])
		report.Results = append(report.Results, result)
		if result.Met {
			report.Summary.Met++
		} else {
			report.Summary.Failed++
		}
	}
	report.Summary.HotPaths = len(report.Results)
	report.Summary.OK = report.Summary.Failed == 0 && report.Summary.HotPaths == len(HotPaths())
	return report, nil
}

func LoadSmokeObservations(path string) (map[string]Observation, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read perf observations: %w", err)
	}
	observations := map[string]Observation{}
	if err := json.Unmarshal(data, &observations); err != nil {
		return nil, fmt.Errorf("decode perf observations: %w", err)
	}
	if err := validateObservations(observations); err != nil {
		return nil, err
	}
	return observations, nil
}

func validateObservations(observations map[string]Observation) error {
	if len(observations) == 0 {
		return nil
	}
	known := map[string]bool{}
	for _, slo := range HotPaths() {
		known[slo.HotPath] = true
	}
	for hotPath := range observations {
		if !known[hotPath] {
			return fmt.Errorf("perf: observation for unknown hot path %s", hotPath)
		}
	}
	return nil
}

func capacityTierIDs() []string {
	tiers := CapacityTiers()
	out := make([]string, 0, len(tiers))
	for _, tier := range tiers {
		out = append(out, tier.ID)
	}
	return out
}

func measure(slo HotPathSLO, op operation, samples int, observation Observation) Result {
	_ = op() // warm the path before measuring.
	durations := make([]float64, 0, samples)
	startAll := time.Now()
	failures := []string{}
	for i := 0; i < samples; i++ {
		start := time.Now()
		if err := op(); err != nil {
			failures = append(failures, err.Error())
		}
		durations = append(durations, float64(time.Since(start).Nanoseconds())/1_000_000)
	}
	elapsed := time.Since(startAll).Seconds()
	sort.Float64s(durations)
	result := Result{
		HotPath:             slo.HotPath,
		SLOID:               slo.ID,
		Benchmark:           slo.Benchmark,
		Samples:             samples,
		P50MS:               percentile(durations, 0.50),
		P95MS:               percentile(durations, 0.95),
		P99MS:               percentile(durations, 0.99),
		MaxMS:               maxOfSorted(durations),
		ThroughputPerSecond: float64(samples) / elapsed,
		ErrorBudgetPercent:  observation.ErrorBudgetPercent,
		QueueSaturation:     observation.QueueSaturation,
		ProjectionLagEvents: observation.ProjectionLagEvents,
		Failures:            failures,
	}
	result.Errors = len(failures)
	if result.P50MS > slo.P50MS {
		result.Failures = append(result.Failures, fmt.Sprintf("p50 %.2fms exceeds %.2fms", result.P50MS, slo.P50MS))
	}
	if result.P95MS > slo.P95MS {
		result.Failures = append(result.Failures, fmt.Sprintf("p95 %.2fms exceeds %.2fms", result.P95MS, slo.P95MS))
	}
	if result.P99MS > slo.P99MS {
		result.Failures = append(result.Failures, fmt.Sprintf("p99 %.2fms exceeds %.2fms", result.P99MS, slo.P99MS))
	}
	if result.ThroughputPerSecond < slo.MinThroughputPerSecond {
		result.Failures = append(result.Failures, fmt.Sprintf("throughput %.2f/s below %.2f/s", result.ThroughputPerSecond, slo.MinThroughputPerSecond))
	}
	if result.ErrorBudgetPercent > slo.ErrorBudgetPercent {
		result.Failures = append(result.Failures, fmt.Sprintf("error budget %.2f%% exceeds %.2f%%", result.ErrorBudgetPercent, slo.ErrorBudgetPercent))
	}
	if result.QueueSaturation > slo.MaxQueueSaturation {
		result.Failures = append(result.Failures, fmt.Sprintf("queue saturation %.2f exceeds %.2f", result.QueueSaturation, slo.MaxQueueSaturation))
	}
	if result.ProjectionLagEvents > slo.MaxProjectionLagEvents {
		result.Failures = append(result.Failures, fmt.Sprintf("projection lag %d events exceeds %d", result.ProjectionLagEvents, slo.MaxProjectionLagEvents))
	}
	result.Met = len(result.Failures) == 0
	return result
}

func maxOfSorted(sorted []float64) float64 {
	if len(sorted) == 0 {
		return 0
	}
	return sorted[len(sorted)-1]
}

func percentile(sorted []float64, p float64) float64 {
	if len(sorted) == 0 {
		return 0
	}
	idx := int(float64(len(sorted)-1)*p + 0.5)
	if idx < 0 {
		idx = 0
	}
	if idx >= len(sorted) {
		idx = len(sorted) - 1
	}
	return sorted[idx]
}

func operations() (map[string]operation, func(), error) {
	kekBytes := bytesOf(32, 0x42)
	wrapper, err := seal.NewLocalKEK(kekBytes)
	secret.Wipe(kekBytes)
	if err != nil {
		return nil, func() {}, err
	}
	signer, err := trstcrypto.GenerateLockedKey(trstcrypto.ECDSAP256)
	if err != nil {
		wrapper.Destroy()
		return nil, func() {}, err
	}
	caDER, err := trstcrypto.SelfSignedCACert(signer, "perf-smoke-ca", time.Hour)
	if err != nil {
		wrapper.Destroy()
		signer.Destroy()
		return nil, func() {}, err
	}
	crlDER, err := trstcrypto.CreateCRL(caDER, signer, []trstcrypto.RevokedSerial{{Serial: "42", RevokedAt: time.Now().UTC(), Reason: 1}}, 1, time.Now().UTC(), time.Now().UTC().Add(time.Hour))
	if err != nil {
		wrapper.Destroy()
		signer.Destroy()
		return nil, func() {}, err
	}
	ocspReq, err := trstcrypto.BuildOCSPRequestForSerial(caDER, "42")
	if err != nil {
		wrapper.Destroy()
		signer.Destroy()
		return nil, func() {}, err
	}
	cleanup := func() {
		wrapper.Destroy()
		signer.Destroy()
	}
	inventoryRows := buildInventoryRows(384)
	return map[string]operation{
		"api.issuance":            issuanceOp,
		"api.inventory":           inventoryOp(inventoryRows),
		"api.graph_risk":          graphRiskOp,
		"api.secrets":             secretOp(wrapper),
		"protocol.enrollment":     protocolEnrollmentOp,
		"revocation.ocsp_crl":     revocationOp(caDER, crlDER, ocspReq),
		"signer.rpc":              signerRPCOp,
		"spine.projection_replay": projectionReplayOp,
	}, cleanup, nil
}

func issuanceOp() error {
	req := struct {
		TenantID       string   `json:"tenant_id"`
		OwnerID        string   `json:"owner_id"`
		IdentityKind   string   `json:"identity_kind"`
		Subject        string   `json:"subject"`
		SANs           []string `json:"sans"`
		IdempotencyKey string   `json:"idempotency_key"`
	}{
		TenantID: "11111111-1111-1111-1111-111111111111", OwnerID: "owner-perf",
		IdentityKind: "x509_certificate", Subject: "api.perf.trstctl.test",
		SANs: []string{"api.perf.trstctl.test", "api-alt.perf.trstctl.test"}, IdempotencyKey: "perf-smoke-issuance",
	}
	b, err := json.Marshal(req)
	if err != nil {
		return err
	}
	var decoded struct {
		TenantID       string   `json:"tenant_id"`
		OwnerID        string   `json:"owner_id"`
		IdentityKind   string   `json:"identity_kind"`
		Subject        string   `json:"subject"`
		SANs           []string `json:"sans"`
		IdempotencyKey string   `json:"idempotency_key"`
	}
	if err := json.Unmarshal(b, &decoded); err != nil {
		return err
	}
	if decoded.IdempotencyKey == "" || len(decoded.SANs) != 2 {
		return fmt.Errorf("perf issuance decode lost mutation contract")
	}
	return nil
}

func buildInventoryRows(count int) []store.Certificate {
	rows := make([]store.Certificate, 0, count)
	for i := count - 1; i >= 0; i-- {
		rows = append(rows, store.Certificate{
			ID:      fmt.Sprintf("cert-%04d", i),
			Subject: fmt.Sprintf("svc-%04d.trstctl.test", i),
			Status:  "active",
		})
	}
	return rows
}

func inventoryOp(source []store.Certificate) operation {
	return func() error {
		rows := append([]store.Certificate(nil), source...)
		sort.Slice(rows, func(i, j int) bool { return rows[i].ID < rows[j].ID })
		page := rows[:128]
		_, err := json.Marshal(page)
		return err
	}
}

func graphRiskOp() error {
	g := graph.New()
	issuerID := "issuer:perf"
	g.AddNode(graph.Node{ID: issuerID, Kind: graph.KindIssuer, Name: "perf issuer"})
	for i := 0; i < 80; i++ {
		workloadID := fmt.Sprintf("workload:%03d", i)
		credID := fmt.Sprintf("cert:%03d", i)
		resourceID := fmt.Sprintf("resource:%03d", i)
		g.AddNode(graph.Node{ID: workloadID, Kind: graph.KindWorkload, Name: workloadID})
		g.AddNode(graph.Node{ID: credID, Kind: graph.KindCredential, Name: credID})
		g.AddNode(graph.Node{ID: resourceID, Kind: graph.KindResource, Name: resourceID})
		g.AddEdge(graph.Edge{From: issuerID, To: credID, Type: graph.EdgeIssued})
		g.AddEdge(graph.Edge{From: workloadID, To: credID, Type: graph.EdgeOwns})
		g.AddEdge(graph.Edge{From: credID, To: resourceID, Type: graph.EdgeDeployedTo})
		if i > 0 {
			g.AddEdge(graph.Edge{From: resourceID, To: fmt.Sprintf("workload:%03d", i-1), Type: graph.EdgeConnectsTo})
		}
	}
	impact := g.BlastRadius("workload:079")
	if len(impact.Affected) == 0 {
		return fmt.Errorf("perf graph impact was empty")
	}
	now := time.Date(2026, 6, 21, 0, 0, 0, 0, time.UTC)
	score := risk.Compute(risk.Signals{
		Now: now, NotBefore: now.Add(-90 * 24 * time.Hour), NotAfter: now.Add(90 * 24 * time.Hour),
		Exposure: len(impact.ByKind[graph.KindResource]), Privilege: risk.PrivilegeHigh,
		LastRotated: now.Add(-30 * 24 * time.Hour), OwnerActive: true, Sensitivity: risk.SensitivityHigh,
	})
	if score.Total <= 0 {
		return fmt.Errorf("perf risk score did not compute")
	}
	return nil
}

func secretOp(wrapper *seal.LocalKEK) operation {
	return func() error {
		plaintext := bytesOf(256, 0x7a)
		defer secret.Wipe(plaintext)
		aad := []byte("tenant/perf/ref/api-key")
		sealed, err := seal.Seal(wrapper, plaintext, aad)
		if err != nil {
			return err
		}
		opened, err := seal.Open(wrapper, sealed, aad)
		if err != nil {
			return err
		}
		defer secret.Wipe(opened)
		if len(opened) != len(plaintext) {
			return fmt.Errorf("perf secret open length = %d, want %d", len(opened), len(plaintext))
		}
		return nil
	}
}

func protocolEnrollmentOp() error {
	order := []byte(`{"identifiers":[{"type":"dns","value":"perf.trstctl.test"},{"type":"dns","value":"alt.perf.trstctl.test"}]}`)
	parsed, err := acme.ParseOrderRequest(order)
	if err != nil {
		return err
	}
	csr := base64.RawURLEncoding.EncodeToString([]byte{0x30, 0x03, 0x02, 0x01, 0x01})
	if _, err := acme.ParseFinalizeRequest([]byte(`{"csr":"` + csr + `"}`)); err != nil {
		return err
	}
	if len(parsed.Domains()) != 2 {
		return fmt.Errorf("perf protocol parser lost domains")
	}
	return nil
}

func revocationOp(caDER, crlDER, ocspReq []byte) operation {
	return func() error {
		serial, err := trstcrypto.ParseOCSPRequestSerial(ocspReq)
		if err != nil {
			return err
		}
		info, err := trstcrypto.ParseCRL(crlDER, caDER)
		if err != nil {
			return err
		}
		if serial != "42" || len(info.RevokedSerials) != 1 {
			return fmt.Errorf("perf revocation parse serial=%s revoked=%d", serial, len(info.RevokedSerials))
		}
		return nil
	}
}

func signerRPCOp() error {
	req := &signerpb.SignRequest{
		Handle:     &signerpb.KeyHandle{Id: "perf-signer-key"},
		Digest:     bytesOf(32, 0x9a),
		Hash:       signerpb.Hash_HASH_SHA256,
		RsaPadding: signerpb.RSAPadding_RSA_PADDING_PSS,
		Purpose:    signerpb.KeyPurpose_KEY_PURPOSE_CA_SIGN,
	}
	encoded, err := proto.Marshal(req)
	if err != nil {
		return err
	}
	var decoded signerpb.SignRequest
	if err := proto.Unmarshal(encoded, &decoded); err != nil {
		return err
	}
	if decoded.GetHandle().GetId() == "" || len(decoded.GetDigest()) != 32 {
		return fmt.Errorf("perf signer RPC payload lost handle or digest")
	}
	return nil
}

func projectionReplayOp() error {
	payload := projections.CRLPublished{
		CAID: "perf-ca", Number: 9, DER: []byte{0x30, 0x03, 0x02, 0x01, 0x09},
		ThisUpdate: time.Date(2026, 6, 21, 0, 0, 0, 0, time.UTC),
		NextUpdate: time.Date(2026, 6, 22, 0, 0, 0, 0, time.UTC),
	}
	data, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	ev := events.Event{Type: projections.EventCRLPublished, TenantID: "11111111-1111-1111-1111-111111111111", Data: data, SchemaVersion: projections.CRLPublishedEventSchemaVersion}
	encoded, err := json.Marshal(ev)
	if err != nil {
		return err
	}
	var decoded events.Event
	if err := json.Unmarshal(encoded, &decoded); err != nil {
		return err
	}
	var out projections.CRLPublished
	if err := json.Unmarshal(decoded.Data, &out); err != nil {
		return err
	}
	if out.Number != payload.Number || out.CAID != payload.CAID {
		return fmt.Errorf("perf projection replay lost CRL payload")
	}
	return nil
}

func bytesOf(n int, b byte) []byte {
	out := make([]byte, n)
	for i := range out {
		out[i] = b
	}
	return out
}
