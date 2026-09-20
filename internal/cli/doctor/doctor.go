// SPDX-License-Identifier: BUSL-1.1

// Package doctor implements `trstctl doctor --prove-isolation`: a fixed set of
// invariant probes an operator runs against their own live deployment, turning
// the isolation guarantees the CI suite proves on our infrastructure into a
// receipt the customer can produce on theirs. Probes reuse the SAME shared
// inventories the CI guards run (store.TenantTableRLSStates,
// store.USINGOnlyTenantPolicies), so the field probe and the test suite cannot
// drift apart.
//
// Safety model: read-only by default. The cross-tenant write probes
// (ISO-3..ISO-5) run only under --write-probe, against two ephemeral probe
// tenants with a reserved, obviously-synthetic id prefix; their rows are
// deleted and the deletion verified, residue under the probe prefix is itself
// a FAIL, and without --write-probe those probes report SKIPPED — a skipped
// proof never looks like a passed one. Probe activity is ordinary database
// activity and may surface in operational monitoring; the runbook says so.
//
// Every probe also states what it does NOT prove: a green ISO-3 proves the
// policy held for that table on that path, not that no bug exists anywhere.
package doctor

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"sort"
	"time"

	"trstctl.com/trstctl/internal/buildinfo"
	"trstctl.com/trstctl/internal/crypto/jose"
	"trstctl.com/trstctl/internal/signing"
	"trstctl.com/trstctl/internal/store"
)

// Status is a probe outcome. SKIPPED is a first-class outcome: a probe that
// could not run reports skip with the reason, never pass.
type Status string

const (
	StatusPass Status = "pass"
	StatusWarn Status = "warn"
	StatusFail Status = "fail"
	StatusSkip Status = "skip"
)

// Probe is one invariant check's outcome.
type Probe struct {
	ID       string         `json:"id"`
	Group    string         `json:"group"`
	Status   Status         `json:"status"`
	Detail   string         `json:"detail"`
	Limits   string         `json:"limits,omitempty"` // what this probe does NOT prove
	Evidence map[string]any `json:"evidence,omitempty"`
}

// Receipt is the machine-readable result. With --sign it carries a compact JWS
// by the deployment's existing audit-export signing key — the same key and the
// same RS256 path the audit bundle export uses; no new key type.
type Receipt struct {
	Schema      string    `json:"schema"`
	GeneratedAt time.Time `json:"generated_at"`
	Deployment  struct {
		Version    string `json:"version"`
		WriteProbe bool   `json:"write_probe"`
	} `json:"deployment"`
	Probes  []Probe `json:"probes"`
	Summary struct {
		Pass int `json:"pass"`
		Fail int `json:"fail"`
		Warn int `json:"warn"`
		Skip int `json:"skip"`
	} `json:"summary"`
	Signature *ReceiptSignature `json:"signature,omitempty"`
}

// ReceiptSignature carries the detached signature over the receipt's canonical
// JSON (the receipt serialized with the signature field absent).
type ReceiptSignature struct {
	Alg   string `json:"alg"`
	KeyID string `json:"key_id"`
	JWS   string `json:"jws"`
}

// ExitError carries doctor's exit code to the binary entrypoint: 1 when at
// least one probe FAILs (or WARNs under --fail-on warn), 2 on configuration or
// connectivity errors.
type ExitError struct{ Code int }

func (e ExitError) Error() string { return fmt.Sprintf("doctor: exit %d", e.Code) }

type options struct {
	proveIsolation bool
	writeProbe     bool
	jsonPath       string
	sign           bool
	failOn         string
	dsn            string
	signerSocket   string
	now            func() time.Time
}

// Run executes `trstctl doctor` with args (everything after the verb). It
// returns nil on success and ExitError{1|2} otherwise, matching the command
// contract: 0 all probes pass, 1 at least one FAIL, 2 config/connectivity.
func Run(ctx context.Context, args []string, getenv func(string) string, stdout, stderr io.Writer) error {
	opts, err := parseFlags(args, getenv, stderr)
	if err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return nil
		}
		_, _ = fmt.Fprintf(stderr, "doctor: %v\n", err)
		return ExitError{2}
	}
	if opts.dsn == "" {
		_, _ = fmt.Fprintln(stderr, "doctor: a PostgreSQL DSN is required (--postgres-dsn or TRSTCTL_POSTGRES_DSN); doctor probes the same datastore the deployment serves from")
		return ExitError{2}
	}

	s, err := store.Open(ctx, opts.dsn)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "doctor: connect: %v\n", err)
		return ExitError{2}
	}
	defer s.Close()

	receipt := Receipt{Schema: "trstctl.doctor.v1", GeneratedAt: opts.now().UTC()}
	receipt.Deployment.Version = buildinfo.String("trstctl")
	receipt.Deployment.WriteProbe = opts.writeProbe

	receipt.Probes = append(receipt.Probes, runIsolationProbes(ctx, s, opts.writeProbe)...)
	receipt.Probes = append(receipt.Probes, runOpsProbes(ctx, s, opts)...)

	for _, p := range receipt.Probes {
		switch p.Status {
		case StatusPass:
			receipt.Summary.Pass++
		case StatusFail:
			receipt.Summary.Fail++
		case StatusWarn:
			receipt.Summary.Warn++
		case StatusSkip:
			receipt.Summary.Skip++
		}
	}

	if opts.sign {
		if err := signReceipt(ctx, &receipt, opts.signerSocket); err != nil {
			_, _ = fmt.Fprintf(stderr, "doctor: sign receipt: %v\n", err)
			return ExitError{2}
		}
	}
	if opts.jsonPath != "" {
		blob, err := json.MarshalIndent(receipt, "", "  ")
		if err != nil {
			_, _ = fmt.Fprintf(stderr, "doctor: encode receipt: %v\n", err)
			return ExitError{2}
		}
		if err := os.WriteFile(opts.jsonPath, append(blob, '\n'), 0o600); err != nil {
			_, _ = fmt.Fprintf(stderr, "doctor: write receipt: %v\n", err)
			return ExitError{2}
		}
	}

	renderReport(stdout, receipt)

	if receipt.Summary.Fail > 0 || (opts.failOn == "warn" && receipt.Summary.Warn > 0) {
		return ExitError{1}
	}
	return nil
}

func parseFlags(args []string, getenv func(string) string, stderr io.Writer) (options, error) {
	opts := options{now: time.Now}
	fs := flag.NewFlagSet("trstctl doctor", flag.ContinueOnError)
	fs.SetOutput(stderr)
	fs.BoolVar(&opts.proveIsolation, "prove-isolation", false, "run the tenant-isolation probe group (default: all read-only groups run; this flag is accepted for the documented surface)")
	fs.BoolVar(&opts.writeProbe, "write-probe", false, "permit the two ephemeral probe tenants and cross-tenant write attempts (required for a full proof; without it the write probes report SKIPPED)")
	fs.StringVar(&opts.jsonPath, "json", "", "write the machine-readable receipt to this path")
	fs.BoolVar(&opts.sign, "sign", false, "sign the receipt with the deployment's audit-export key")
	fs.StringVar(&opts.failOn, "fail-on", "fail", "exit non-zero threshold: fail or warn")
	fs.StringVar(&opts.dsn, "postgres-dsn", getenv("TRSTCTL_POSTGRES_DSN"), "PostgreSQL DSN of the deployment (default $TRSTCTL_POSTGRES_DSN)")
	fs.StringVar(&opts.signerSocket, "signer-socket", getenv("TRSTCTL_SIGNER_SOCKET"), "path to the signer's Unix socket; required by --sign and enables the SIG-2 socket posture probe")
	if err := fs.Parse(args); err != nil {
		return opts, err
	}
	if opts.failOn != "fail" && opts.failOn != "warn" {
		return opts, fmt.Errorf("--fail-on must be fail or warn, got %q", opts.failOn)
	}
	return opts, nil
}

func signReceipt(ctx context.Context, r *Receipt, signerSocket string) error {
	if signerSocket == "" {
		return errors.New("--sign requires --signer-socket or TRSTCTL_SIGNER_SOCKET; private audit keys are never loaded by doctor")
	}
	client, err := signing.DialReady(ctx, signerSocket, 10*time.Second)
	if err != nil {
		return fmt.Errorf("connect signer: %w", err)
	}
	defer func() { _ = client.Close() }()
	remote, err := client.SignerForHandleWithPurpose(ctx, "audit-export", signing.PurposeAuditEvidence)
	if err != nil {
		return fmt.Errorf("bind audit-export signer handle: %w", err)
	}
	key, err := jose.NewDigestSigningKey("audit-export", remote)
	if err != nil {
		return fmt.Errorf("wrap audit-export signer handle: %w", err)
	}
	payload, err := json.Marshal(r) // signature field still nil: this is the canonical signed body
	if err != nil {
		return err
	}
	jws, err := key.SignArtifact(jose.ArtifactDoctorReceipt, payload)
	if err != nil {
		return err
	}
	r.Signature = &ReceiptSignature{Alg: "RS256", KeyID: "audit-export", JWS: jws}
	return nil
}

func renderReport(w io.Writer, r Receipt) {
	_, _ = fmt.Fprintf(w, "trstctl doctor — %s\n", r.GeneratedAt.Format(time.RFC3339))
	groups := map[string][]Probe{}
	var order []string
	for _, p := range r.Probes {
		if _, ok := groups[p.Group]; !ok {
			order = append(order, p.Group)
		}
		groups[p.Group] = append(groups[p.Group], p)
	}
	sort.Strings(order)
	for _, g := range order {
		_, _ = fmt.Fprintf(w, "\n%s\n", g)
		for _, p := range groups[g] {
			_, _ = fmt.Fprintf(w, "  [%-4s] %-6s %s\n", p.Status, p.ID, p.Detail)
		}
	}
	_, _ = fmt.Fprintf(w, "\n%d pass, %d fail, %d warn, %d skipped\n",
		r.Summary.Pass, r.Summary.Fail, r.Summary.Warn, r.Summary.Skip)
	if r.Signature != nil {
		_, _ = fmt.Fprintf(w, "receipt signed (%s, key %s)\n", r.Signature.Alg, r.Signature.KeyID)
	}
}
