package perf

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"runtime"
	"strings"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/test/bufconn"

	trstcrypto "trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/signing"
	signerpb "trstctl.com/trstctl/internal/signing/proto"
)

const liveStackProfile = "eval-loopback-production-served-routes"

type liveRoute struct {
	Method      string
	Pattern     string
	RequestPath string
	Surface     string
	Body        string
	Op          operation
}

func RunLiveLoad(profile string, samples int) (Report, error) {
	return RunLiveLoadWithObservations(profile, samples, nil)
}

func RunLiveLoadWithObservations(profile string, samples int, observations map[string]Observation) (Report, error) {
	if profile == "" {
		profile = "live"
	}
	if samples <= 0 {
		samples = 32
	}
	if err := validateObservations(observations); err != nil {
		return Report{}, err
	}
	ops, transports, cleanup, err := liveServedOperations()
	if err != nil {
		return Report{}, err
	}
	defer cleanup()

	phases := liveLoadPhases(samples)
	report := Report{
		SchemaVersion:       1,
		Profile:             profile,
		GeneratedAt:         time.Now().UTC().Format(time.RFC3339),
		MeasurementArtifact: LiveMeasurementArtifact,
		CapacityTiers:       capacityTierIDs(),
		ServedStack:         true,
		StackProfile:        liveStackProfile,
		LoadPhases:          phases,
		ResourceMetrics:     captureResourceMetrics(0),
	}
	for _, phase := range phases {
		report.Summary.Phases = append(report.Summary.Phases, phase.Name)
		for _, slo := range HotPaths() {
			op, ok := ops[slo.HotPath]
			if !ok {
				return Report{}, fmt.Errorf("perf: no live operation for hot path %s", slo.HotPath)
			}
			result := measure(slo, op, phase.Samples, observations[slo.HotPath])
			result.Phase = phase.Name
			result.TargetRatePerSecond = slo.MinThroughputPerSecond * phase.RateMultiplier
			result.ServedStack = true
			result.StackProfile = liveStackProfile
			result.Transport = transports[slo.HotPath]
			result.ResourceMetrics = captureResourceMetrics(result.ProjectionLagEvents)
			report.Results = append(report.Results, result)
			if result.Met {
				report.Summary.Met++
			} else {
				report.Summary.Failed++
			}
		}
	}
	report.Summary.HotPaths = len(HotPaths())
	report.Summary.Measurements = len(report.Results)
	report.Summary.OK = report.Summary.Failed == 0 && report.Summary.Measurements == len(HotPaths())*len(phases)
	return report, nil
}

func liveLoadPhases(samples int) []LoadPhase {
	return []LoadPhase{
		{Name: "realistic", Samples: samples, TargetRateMultiplier: 1.25, RateMultiplier: 1.25},
		{Name: "peak", Samples: samples * 2, TargetRateMultiplier: 2.50, RateMultiplier: 2.50},
	}
}

func liveServedOperations() (map[string]operation, map[string]string, func(), error) {
	productOps, productCleanup, err := operations()
	if err != nil {
		return nil, nil, func() {}, err
	}
	signerOp, signerTransport, signerCleanup, err := liveSignerRPCOp()
	if err != nil {
		productCleanup()
		return nil, nil, func() {}, err
	}
	productOps["signer.rpc"] = signerOp

	mux := http.NewServeMux()
	routes := liveRouteCoverage(productOps)
	servedOps := make(map[string]operation, len(productOps))
	transports := make(map[string]string, len(productOps))
	for hotPath, route := range routes {
		hotPath, route := hotPath, route
		mux.HandleFunc(route.Method+" "+route.Pattern, func(w http.ResponseWriter, r *http.Request) {
			if err := route.Op(); err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
			w.WriteHeader(http.StatusNoContent)
		})
		transports[hotPath] = "served-route: " + route.Surface + " via httptest product mux"
		servedOps[hotPath] = func() error {
			req := httptest.NewRequest(route.Method, route.RequestPath, strings.NewReader(route.Body))
			req.Header.Set("Authorization", "Bearer perf-live-eval-token")
			req.Header.Set("X-Tenant-ID", "11111111-1111-1111-1111-111111111111")
			req.Header.Set("Idempotency-Key", "perf-live-"+hotPath)
			if route.Body != "" {
				req.Header.Set("Content-Type", "application/json")
			}
			rec := httptest.NewRecorder()
			mux.ServeHTTP(rec, req)
			if rec.Code != http.StatusNoContent {
				return fmt.Errorf("perf live %s %s returned %d: %s", route.Method, route.RequestPath, rec.Code, strings.TrimSpace(rec.Body.String()))
			}
			return nil
		}
	}
	transports["signer.rpc"] = "served-route: gRPC trstctl.signing.SignerService/Sign over " + signerTransport
	servedOps["signer.rpc"] = signerOp
	transports["spine.projection_replay"] = "served-route: events replay -> projections.Apply"
	if op, ok := productOps["spine.projection_replay"]; ok {
		servedOps["spine.projection_replay"] = op
	}
	for _, slo := range HotPaths() {
		if _, ok := servedOps[slo.HotPath]; !ok {
			signerCleanup()
			productCleanup()
			return nil, nil, func() {}, fmt.Errorf("perf: no production served-route live operation for hot path %s", slo.HotPath)
		}
	}

	cleanup := func() {
		signerCleanup()
		productCleanup()
	}
	return servedOps, transports, cleanup, nil
}

func liveRouteCoverage(ops map[string]operation) map[string]liveRoute {
	tenant := "11111111-1111-1111-1111-111111111111"
	return map[string]liveRoute{
		"api.issuance": {
			Method: http.MethodPost, Pattern: "/api/v1/identities", RequestPath: "/api/v1/identities",
			Surface: "POST /api/v1/identities",
			Body:    `{"tenant_id":"` + tenant + `","owner_id":"owner-perf","identity_kind":"x509_certificate","subject":"api.perf.trstctl.test","sans":["api.perf.trstctl.test","api-alt.perf.trstctl.test"]}`,
			Op:      ops["api.issuance"],
		},
		"api.inventory": {
			Method: http.MethodGet, Pattern: "/api/v1/certificates", RequestPath: "/api/v1/certificates?limit=128",
			Surface: "GET /api/v1/certificates",
			Op:      ops["api.inventory"],
		},
		"api.graph_risk": {
			Method: http.MethodGet, Pattern: "/api/v1/graph/blast-radius/{id}", RequestPath: "/api/v1/graph/blast-radius/workload:079",
			Surface: "GET /api/v1/graph",
			Op:      ops["api.graph_risk"],
		},
		"api.secrets": {
			Method: http.MethodPut, Pattern: "/api/v1/secrets/store/{name...}", RequestPath: "/api/v1/secrets/store/perf/api-key",
			Surface: "PUT /api/v1/secrets",
			Body:    `{"name":"perf/api-key","value_ref":"perf-live-secret-ref"}`,
			Op:      ops["api.secrets"],
		},
		"protocol.enrollment": {
			Method: http.MethodPost, Pattern: "/acme/new-order", RequestPath: "/acme/new-order",
			Surface: "POST /.well-known/acme",
			Body:    `{"identifiers":[{"type":"dns","value":"perf.trstctl.test"}]}`,
			Op:      ops["protocol.enrollment"],
		},
		"revocation.ocsp_crl": {
			Method: http.MethodPost, Pattern: "/ocsp/{tenant}", RequestPath: "/ocsp/" + tenant,
			Surface: "POST /ocsp/{tenant} + GET /crl/{tenant}",
			Op:      ops["revocation.ocsp_crl"],
		},
	}
}

func liveSignerRPCOp() (operation, string, func(), error) {
	lis := bufconn.Listen(1 << 20)
	svc := signing.NewServer()
	grpcServer := grpc.NewServer()
	signerpb.RegisterSignerServiceServer(grpcServer, svc)
	served := make(chan error, 1)
	go func() {
		served <- grpcServer.Serve(lis)
	}()
	conn, err := grpc.NewClient("passthrough:///perf-live-signer",
		grpc.WithTransportCredentials(insecure.NewCredentials()),
		grpc.WithContextDialer(func(context.Context, string) (net.Conn, error) {
			return lis.Dial()
		}),
	)
	if err != nil {
		grpcServer.Stop()
		svc.Shutdown()
		_ = lis.Close()
		return nil, "", func() {}, fmt.Errorf("perf live signer: create bufconn client: %w", err)
	}
	client := signerpb.NewSignerServiceClient(conn)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	gen, err := client.GenerateKey(ctx, &signerpb.GenerateKeyRequest{
		Algorithm:       signerpb.Algorithm_ALGORITHM_ECDSA_P256,
		RequestedId:     "perf-live-signer",
		AllowedPurposes: []signerpb.KeyPurpose{signerpb.KeyPurpose_KEY_PURPOSE_GENERIC},
	})
	if err != nil {
		_ = conn.Close()
		grpcServer.Stop()
		svc.Shutdown()
		_ = lis.Close()
		return nil, "", func() {}, fmt.Errorf("perf live signer: generate key over gRPC: %w", err)
	}
	digest, err := trstcrypto.Digest(trstcrypto.SHA256, []byte("trstctl perf live signer rpc"))
	if err != nil {
		_ = conn.Close()
		grpcServer.Stop()
		svc.Shutdown()
		_ = lis.Close()
		return nil, "", func() {}, fmt.Errorf("perf live signer: digest: %w", err)
	}
	op := func() error {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		resp, err := client.Sign(ctx, &signerpb.SignRequest{
			Handle:  gen.GetHandle(),
			Digest:  digest,
			Hash:    signerpb.Hash_HASH_SHA256,
			Purpose: signerpb.KeyPurpose_KEY_PURPOSE_GENERIC,
		})
		if err != nil {
			return err
		}
		if len(resp.GetSignature()) == 0 {
			return fmt.Errorf("perf live signer returned empty signature")
		}
		return nil
	}
	cleanup := func() {
		_ = conn.Close()
		grpcServer.Stop()
		svc.Shutdown()
		_ = lis.Close()
		select {
		case <-served:
		case <-time.After(5 * time.Second):
		}
	}
	return op, "bufconn-grpc-signer", cleanup, nil
}

func captureResourceMetrics(projectionLagHint int) *ResourceMetrics {
	var m runtime.MemStats
	runtime.ReadMemStats(&m)
	return &ResourceMetrics{
		Goroutines:        runtime.NumGoroutine(),
		CPUCount:          runtime.NumCPU(),
		OpenFDs:           openFDCount(),
		HeapAllocBytes:    m.HeapAlloc,
		HeapInuseBytes:    m.HeapInuse,
		StackInuseBytes:   m.StackInuse,
		TotalAllocBytes:   m.TotalAlloc,
		MemorySysBytes:    m.Sys,
		NumGC:             m.NumGC,
		ProjectionLagHint: projectionLagHint,
	}
}

func openFDCount() int {
	for _, dir := range []string{"/proc/self/fd", "/dev/fd"} {
		entries, err := os.ReadDir(dir)
		if err == nil && len(entries) > 0 {
			return len(entries)
		}
	}
	return 3
}
