// Package telemetry implements certctl's opt-in, off-by-default, non-PII usage
// reporting (Section 8 of the PRD).
//
// What it reports — and only this: a random, anonymized instance ID, the
// version, the OS/arch, and credential counts BUCKETED into coarse ranges by
// type. What it never reports: credential content or metadata (subjects, SANs,
// serials, fingerprints), owner identities, hostnames, addresses, or any other
// PII. Exact counts never leave the process — they are bucketed first.
//
// Telemetry is disabled unless an operator explicitly opts in
// (config.Telemetry.Enabled / CERTCTL_TELEMETRY_ENABLED=true). A disabled
// Reporter sends nothing.
package telemetry

import (
	"context"
	"encoding/json"
	"runtime"
	"time"
)

// SchemaVersion identifies the payload shape so the receiver can evolve it.
const SchemaVersion = 1

// Payload is the coarse, anonymized telemetry report. Every field is
// deliberately non-identifying; there is no field for credential content or any
// other PII, by construction.
type Payload struct {
	Schema            int               `json:"schema"`
	InstanceID        string            `json:"instance_id"`
	Version           string            `json:"version"`
	OS                string            `json:"os"`
	Arch              string            `json:"arch"`
	CredentialBuckets map[string]string `json:"credential_buckets"`
}

// Counter reports the instance's credential totals by type. It returns exact
// counts; telemetry buckets them into coarse ranges before anything is sent, so
// an exact figure never leaves the process.
type Counter interface {
	CredentialCounts(ctx context.Context) (map[string]int, error)
}

// Bucket maps an exact count to a coarse range, so a reported figure cannot
// fingerprint a deployment.
func Bucket(n int) string {
	switch {
	case n <= 0:
		return "0"
	case n <= 10:
		return "1-10"
	case n <= 100:
		return "11-100"
	case n <= 1000:
		return "101-1000"
	case n <= 10000:
		return "1001-10000"
	default:
		return "10000+"
	}
}

// BuildPayload assembles a coarse, anonymized payload from the instance metadata
// and the bucketed credential counts.
func BuildPayload(ctx context.Context, instanceID, version string, counter Counter) (Payload, error) {
	counts, err := counter.CredentialCounts(ctx)
	if err != nil {
		return Payload{}, err
	}
	buckets := make(map[string]string, len(counts))
	for typ, n := range counts {
		buckets[typ] = Bucket(n)
	}
	return Payload{
		Schema:            SchemaVersion,
		InstanceID:        instanceID,
		Version:           version,
		OS:                runtime.GOOS,
		Arch:              runtime.GOARCH,
		CredentialBuckets: buckets,
	}, nil
}

// Poster sends a serialized payload to the telemetry endpoint. It is injected so
// the reporter never depends on a concrete HTTP client and tests never touch the
// network.
type Poster func(ctx context.Context, endpoint string, body []byte) error

// Reporter periodically reports telemetry — but only when explicitly enabled.
type Reporter struct {
	Enabled    bool
	Endpoint   string
	Interval   time.Duration
	InstanceID string
	Version    string
	Counter    Counter
	Post       Poster
}

// ReportOnce builds and sends a single payload. It is a no-op — nil error,
// nothing sent — when telemetry is disabled. This is the off-by-default
// guarantee.
func (r *Reporter) ReportOnce(ctx context.Context) error {
	if !r.Enabled {
		return nil
	}
	p, err := BuildPayload(ctx, r.InstanceID, r.Version, r.Counter)
	if err != nil {
		return err
	}
	body, err := json.Marshal(p)
	if err != nil {
		return err
	}
	return r.Post(ctx, r.Endpoint, body)
}

// Run reports once immediately, then on each tick of Interval, until ctx is
// cancelled. It returns immediately, having done nothing, when telemetry is
// disabled. Report errors are swallowed: telemetry must never disrupt the
// control plane.
func (r *Reporter) Run(ctx context.Context) {
	if !r.Enabled {
		return
	}
	_ = r.ReportOnce(ctx)
	if r.Interval <= 0 {
		return
	}
	t := time.NewTicker(r.Interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			_ = r.ReportOnce(ctx)
		}
	}
}
