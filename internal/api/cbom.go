// SPDX-License-Identifier: BUSL-1.1

package api

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"trstctl.com/trstctl/internal/api/problem"
	"trstctl.com/trstctl/internal/cbom"
	"trstctl.com/trstctl/internal/crypto/secret"
	"trstctl.com/trstctl/internal/store"
)

// CBOMService is the served CBOM worker behind the API. It scans only public
// cryptographic facts (TLS negotiation, certificate public keys, host config) and
// records observations through the event log before the read model is updated.
type CBOMService interface {
	Preview(ctx context.Context, tenantID string, req CBOMScanRequest) (CBOMScanPreview, error)
	PrepareHost(ctx context.Context, req CBOMScanRequest) (CBOMPreparedHost, error)
	ScanPrepared(ctx context.Context, tenantID string, req CBOMScanRequest, host CBOMPreparedHost) (CBOMScanResponse, error)
	Inventory(ctx context.Context, tenantID string) (CBOMInventoryResponse, error)
}

// CBOMPreparedHost is a bounded, read-only snapshot obtained before the
// idempotency transaction. Only the scanner's selected findings and source
// paths cross into that transaction; the raw file bytes do not.
type CBOMPreparedHost struct {
	Findings      []cbom.Finding
	ResolvedPaths []string
	Failures      int
}

// WithCBOM wires the served CBOM scan + migration-inventory surface. When unset the
// routes fail closed with a clear 503 rather than pretending a scan ran.
func WithCBOM(svc CBOMService) Option {
	return func(c *config) { c.cbom = svc }
}

// CBOMScanRequest names the read-only estate slices to inspect.
type CBOMScanRequest struct {
	TLSEndpoints         []string `json:"tls_endpoints"`
	HostConfigs          []string `json:"host_configs"`
	AllowPrivateEndpoint bool     `json:"allow_private_endpoint,omitempty"`
	PrivateEgressCIDRs   []string `json:"private_egress_cidrs,omitempty"`
}

const (
	// CBOMMaxTLSEndpoints and CBOMMaxHostConfigs keep one operator request
	// reviewable and prevent discovery work from monopolizing the control plane.
	CBOMMaxTLSEndpoints = 64
	CBOMMaxHostConfigs  = 64
	cbomMaxInputLength  = 2048
)

// CBOMScanPreview is the effect-free plan for the exact request Scan will use.
// Limits are numbers (not vague prose) so both people and automation can review
// the blast radius before any network or file read starts.
type CBOMScanPreview struct {
	Capability                string          `json:"capability"`
	Ready                     bool            `json:"ready"`
	EffectFree                bool            `json:"effect_free"`
	NormalizedRequest         CBOMScanRequest `json:"normalized_request"`
	SourceCount               int             `json:"source_count"`
	TLSConnectionLimit        int             `json:"tls_connection_limit"`
	HostReadSelectorCount     int             `json:"host_read_selector_count"`
	HostFileReadLimit         int             `json:"host_file_read_limit"`
	HostFileByteLimit         int64           `json:"host_file_byte_limit"`
	FindingWriteLimit         int             `json:"finding_write_limit"`
	WorkerLimit               int             `json:"worker_limit"`
	QueueDepth                int             `json:"queue_depth"`
	PerEndpointTimeoutSeconds int             `json:"per_endpoint_timeout_seconds"`
	OutsideCalls              []string        `json:"outside_calls"`
	HostReads                 []string        `json:"host_reads"`
	DurableWrites             []string        `json:"durable_writes"`
	SignerCalls               int             `json:"signer_calls"`
	OutboxCalls               int             `json:"outbox_calls"`
	Blockers                  []string        `json:"blockers"`
	RecoverySteps             []string        `json:"recovery_steps"`
	SafetyNotes               []string        `json:"safety_notes"`
}

// NormalizeCBOMScanRequest applies the same acceptance rules to preview and
// execution. It accepts friendly HTTPS URLs or bare hosts, converts them to the
// host:port form the probe uses, and returns a stable deduplicated plan.
func NormalizeCBOMScanRequest(req CBOMScanRequest) (CBOMScanRequest, error) {
	if !req.AllowPrivateEndpoint && len(req.PrivateEgressCIDRs) != 0 {
		return CBOMScanRequest{}, errors.New("CBOM private_egress_cidrs requires allow_private_endpoint")
	}
	if req.AllowPrivateEndpoint {
		if len(req.PrivateEgressCIDRs) > 64 {
			return CBOMScanRequest{}, errors.New("CBOM accepts at most 64 private egress CIDRs")
		}
		if err := validatePrivateEgressCIDRs(req.PrivateEgressCIDRs); err != nil {
			return CBOMScanRequest{}, err
		}
	}
	if len(req.TLSEndpoints) > CBOMMaxTLSEndpoints {
		return CBOMScanRequest{}, fmt.Errorf("CBOM scan accepts at most %d TLS endpoints per run", CBOMMaxTLSEndpoints)
	}
	if len(req.HostConfigs) > CBOMMaxHostConfigs {
		return CBOMScanRequest{}, fmt.Errorf("CBOM scan accepts at most %d host config selectors per run", CBOMMaxHostConfigs)
	}
	tlsEndpoints := make([]string, 0, len(req.TLSEndpoints))
	for _, raw := range req.TLSEndpoints {
		endpoint, err := normalizeCBOMTLSEndpoint(raw)
		if err != nil {
			return CBOMScanRequest{}, err
		}
		if endpoint != "" {
			tlsEndpoints = append(tlsEndpoints, endpoint)
		}
	}
	hostConfigs := make([]string, 0, len(req.HostConfigs))
	for _, raw := range req.HostConfigs {
		value := strings.TrimSpace(raw)
		if value == "" {
			continue
		}
		if len(value) > cbomMaxInputLength || strings.ContainsRune(value, '\x00') {
			return CBOMScanRequest{}, errors.New("CBOM host config selector is too long or contains a null byte")
		}
		cleaned := filepath.Clean(value)
		if !filepath.IsAbs(cleaned) {
			return CBOMScanRequest{}, fmt.Errorf("CBOM host config selector %q must be an absolute path or absolute glob", value)
		}
		hostConfigs = append(hostConfigs, cleaned)
	}
	tlsEndpoints = uniqueSortedStrings(tlsEndpoints)
	hostConfigs = uniqueSortedStrings(hostConfigs)
	privateCIDRs := make([]string, 0, len(req.PrivateEgressCIDRs))
	for _, cidr := range req.PrivateEgressCIDRs {
		privateCIDRs = append(privateCIDRs, strings.TrimSpace(cidr))
	}
	privateCIDRs = uniqueSortedStrings(privateCIDRs)
	if len(tlsEndpoints) == 0 && len(hostConfigs) == 0 {
		return CBOMScanRequest{}, errors.New("CBOM scan requires at least one TLS endpoint or host config")
	}
	return CBOMScanRequest{TLSEndpoints: tlsEndpoints, HostConfigs: hostConfigs,
		AllowPrivateEndpoint: req.AllowPrivateEndpoint, PrivateEgressCIDRs: privateCIDRs}, nil
}

func normalizeCBOMTLSEndpoint(raw string) (string, error) {
	value := strings.TrimSpace(raw)
	if value == "" {
		return "", nil
	}
	if len(value) > cbomMaxInputLength || strings.ContainsRune(value, '\x00') || strings.ContainsAny(value, "\r\n\t ") {
		return "", errors.New("CBOM TLS endpoint is too long or contains whitespace or a null byte")
	}
	if strings.Contains(value, "://") {
		parsed, err := url.Parse(value)
		if err != nil || !strings.EqualFold(parsed.Scheme, "https") || parsed.Hostname() == "" || parsed.User != nil ||
			(parsed.Path != "" && parsed.Path != "/") || parsed.RawQuery != "" || parsed.Fragment != "" {
			return "", fmt.Errorf("CBOM TLS endpoint %q must be an HTTPS origin with no path, query, fragment, or credentials", value)
		}
		value = parsed.Host
	}
	host, port, err := net.SplitHostPort(value)
	if err != nil {
		if ip := net.ParseIP(strings.Trim(value, "[]")); ip != nil {
			host, port = ip.String(), "443"
		} else if !strings.Contains(value, ":") {
			host, port = value, "443"
		} else {
			return "", fmt.Errorf("CBOM TLS endpoint %q must be a host, host:port, IPv6 address, or HTTPS origin", value)
		}
	}
	host = strings.ToLower(strings.TrimSpace(host))
	if host == "" || strings.ContainsAny(host, "/?#@") {
		return "", fmt.Errorf("CBOM TLS endpoint %q has an invalid host", value)
	}
	portNumber, err := strconv.Atoi(port)
	if err != nil || portNumber < 1 || portNumber > 65535 {
		return "", fmt.Errorf("CBOM TLS endpoint %q has an invalid port", value)
	}
	return net.JoinHostPort(host, strconv.Itoa(portNumber)), nil
}

func uniqueSortedStrings(values []string) []string {
	sort.Strings(values)
	out := values[:0]
	for _, value := range values {
		if len(out) == 0 || out[len(out)-1] != value {
			out = append(out, value)
		}
	}
	return out
}

// CBOMReport is the scan summary returned by the served worker.
type CBOMReport struct {
	Sources           int `json:"sources"`
	Findings          int `json:"findings"`
	Weak              int `json:"weak"`
	QuantumVulnerable int `json:"quantum_vulnerable"`
	OutOfPolicy       int `json:"out_of_policy"`
	Failed            int `json:"failed"`
}

// CBOMAsset is one customer-readable crypto inventory row with migration posture.
type CBOMAsset struct {
	CertificateFingerprint string   `json:"certificate_fingerprint,omitempty"`
	ID                     string   `json:"id"`
	Kind                   string   `json:"kind"`
	Location               string   `json:"location"`
	Algorithm              string   `json:"algorithm,omitempty"`
	KeyBits                int      `json:"key_bits,omitempty"`
	Protocol               string   `json:"protocol,omitempty"`
	Cipher                 string   `json:"cipher,omitempty"`
	Library                string   `json:"library,omitempty"`
	Strength               string   `json:"strength"`
	QuantumVulnerable      bool     `json:"quantum_vulnerable"`
	OutOfPolicy            bool     `json:"out_of_policy"`
	Reasons                []string `json:"reasons,omitempty"`
	MigrationTarget        string   `json:"migration_target"`
	MigrationStandard      string   `json:"migration_standard"`
	MigrationGeneration    string   `json:"migration_generation"`
	// ConfigSource is "default" for a host-config fact a product reaches
	// only through its built-in default, and ProductVersion the installed
	// package whose default it is (X2-L7); absent for a stated fact.
	ConfigSource   string `json:"config_source,omitempty"`
	ProductVersion string `json:"product_version,omitempty"`
}

// CBOMInventoryResponse is the read API for the CBOM plus its migration-progress
// rollup.
type CBOMInventoryResponse struct {
	Items             []CBOMAsset            `json:"items"`
	MigrationProgress cbom.MigrationProgress `json:"migration_progress"`
}

// CBOMScanResponse is returned after a served scan completes.
type CBOMScanResponse struct {
	Report            CBOMReport             `json:"report"`
	MigrationProgress cbom.MigrationProgress `json:"migration_progress"`
	ObservedAssetIDs  []string               `json:"observed_asset_ids"`
}

// CBOMInventoryFromAssets adapts store rows to the public inventory shape.
func CBOMInventoryFromAssets(assets []store.CryptoAsset) CBOMInventoryResponse {
	items := make([]CBOMAsset, 0, len(assets))
	findings := make([]cbom.Finding, 0, len(assets))
	for _, a := range assets {
		f := cbom.Finding{
			Kind: cbom.AssetKind(a.Kind), Location: a.Location, Algorithm: a.Algorithm, CertificateFingerprint: a.CertificateFingerprint,
			KeyBits: a.KeyBits, Protocol: a.Protocol, Cipher: a.Cipher, Library: a.Library,
			Class: cbom.Classification{
				Strength: cbom.Strength(a.Strength), QuantumVulnerable: a.QuantumVulnerable,
				OutOfPolicy: a.OutOfPolicy, Reasons: a.Reasons,
			},
		}
		target := cbom.MigrationTargetFor(f)
		items = append(items, CBOMAsset{
			ID: a.ID, Kind: a.Kind, Location: a.Location, Algorithm: a.Algorithm, CertificateFingerprint: a.CertificateFingerprint,
			KeyBits: a.KeyBits, Protocol: a.Protocol, Cipher: a.Cipher, Library: a.Library,
			Strength: a.Strength, QuantumVulnerable: a.QuantumVulnerable,
			OutOfPolicy: a.OutOfPolicy, Reasons: a.Reasons,
			MigrationTarget: target.Algorithm, MigrationStandard: target.Standard,
			MigrationGeneration: target.Generation, ConfigSource: a.ConfigSource, ProductVersion: a.ProductVersion,
		})
		findings = append(findings, f)
	}
	return CBOMInventoryResponse{Items: items, MigrationProgress: cbom.ProgressFor(findings)}
}

func (a *API) previewCBOMScan(w http.ResponseWriter, r *http.Request) {
	tenantID, ok := a.tenant(r)
	if !ok {
		a.writeProblem(w, problemUnauthorized())
		return
	}
	if a.cbom == nil {
		a.writeError(w, errStatus(http.StatusServiceUnavailable, "CBOM scanning is not configured"))
		return
	}
	var req CBOMScanRequest
	if err := decodeJSON(r, &req); err != nil {
		a.writeError(w, errWithStatus(http.StatusBadRequest, err))
		return
	}
	if req.AllowPrivateEndpoint {
		if err := a.requirePrivateEgressPermission(r.Context(), tenantID); err != nil {
			a.writeError(w, err)
			return
		}
	}
	preview, err := a.cbom.Preview(r.Context(), tenantID, req)
	if err != nil {
		a.writeError(w, errWithStatus(http.StatusBadRequest, err))
		return
	}
	a.writeJSON(w, http.StatusOK, preview)
}

//trstctl:mutation
func (a *API) startCBOMScan(w http.ResponseWriter, r *http.Request) {
	idempotencyKey := r.Header.Get("Idempotency-Key")
	tenantID, ok := a.tenant(r)
	if !ok {
		a.writeProblem(w, problem.New(http.StatusUnauthorized, "missing or invalid tenant"))
		return
	}
	if idempotencyKey == "" {
		a.writeProblem(w, problem.New(http.StatusBadRequest, "Idempotency-Key header is required for mutations"))
		return
	}
	if a.cbom == nil {
		a.writeError(w, errStatus(http.StatusServiceUnavailable, "CBOM scanning is not configured"))
		return
	}
	principal, err := requestPrincipalSubject(r.Context())
	if err != nil {
		a.writeError(w, err)
		return
	}
	binding, rawBody, err := mutationRequestBinding(r, principal)
	defer secret.Wipe(rawBody)
	if err != nil {
		a.writeError(w, err)
		return
	}
	if cached, found, lookupErr := a.idem.LookupBound(r.Context(), tenantID, idempotencyKey, binding); lookupErr != nil {
		a.writeError(w, lookupErr)
		return
	} else if found {
		a.writeBoundMutationResponse(w, r.Context(), tenantID, binding, cached, nil)
		return
	}
	r.Body = io.NopCloser(bytes.NewReader(rawBody))
	var req CBOMScanRequest
	if err := decodeJSON(r, &req); err != nil {
		a.writeError(w, errWithStatus(http.StatusBadRequest, err))
		return
	}
	if req.AllowPrivateEndpoint {
		if err := a.requirePrivateEgressPermission(r.Context(), tenantID); err != nil {
			a.writeError(w, err)
			return
		}
	}
	preview, err := a.cbom.Preview(r.Context(), tenantID, req)
	if err != nil {
		a.writeError(w, errWithStatus(http.StatusBadRequest, err))
		return
	}
	if !preview.Ready {
		a.writeError(w, errStatus(http.StatusServiceUnavailable, strings.Join(preview.Blockers, " ")))
		return
	}
	prepareCtx, cancel := context.WithTimeout(r.Context(), 15*time.Second)
	host, err := a.cbom.PrepareHost(prepareCtx, preview.NormalizedRequest)
	cancel()
	if err != nil {
		a.writeError(w, err)
		return
	}
	a.mutateBound(w, r, idempotencyKey, binding, func(ctx context.Context, tenantID string) (int, any, error) {
		if req.AllowPrivateEndpoint {
			if err := a.requirePrivateEgressPermission(ctx, tenantID); err != nil {
				return 0, nil, err
			}
		}
		start := time.Now()
		var opErr error
		defer func() { a.observeFeature("cbom", "scan", start, opErr) }()
		resp, err := a.cbom.ScanPrepared(ctx, tenantID, preview.NormalizedRequest, host)
		if err != nil {
			opErr = err
			return 0, nil, err
		}
		return http.StatusCreated, resp, nil
	})
}

func (a *API) listCBOMAssets(w http.ResponseWriter, r *http.Request) {
	tenantID, ok := a.tenant(r)
	if !ok {
		a.writeProblem(w, problemUnauthorized())
		return
	}
	if a.cbom == nil {
		a.writeError(w, errStatus(http.StatusServiceUnavailable, "CBOM inventory is not configured"))
		return
	}
	resp, err := a.cbom.Inventory(r.Context(), tenantID)
	if err != nil {
		a.writeError(w, err)
		return
	}
	a.writeJSON(w, http.StatusOK, resp)
}
