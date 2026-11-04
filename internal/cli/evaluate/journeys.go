// SPDX-License-Identifier: BUSL-1.1

package evaluate

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"time"

	"trstctl.com/trstctl/internal/agent/sshkrl"
	"trstctl.com/trstctl/internal/cli"
	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/crypto/sshkeys"
)

// Journeys beside the certificate one (A249). Each runs against the same
// control plane through its own API, records its steps with the same rule —
// a step after a failure is skipped, never passed — and lands in the same
// signed pack. --force-failure <journey> makes one step of that journey
// expect what did not happen, so a reader sees a failure reported as one.

// PackFormatV2 is a pack with journeys beside the certificate journey. A pack
// that ran only the certificate journey keeps PackFormat.
const PackFormatV2 = "trstctl.evaluation-pack/v2"

// The journeys.
const (
	JourneyCertificate = "certificate"
	JourneySecrets     = "secrets"
	JourneySSH         = "ssh"
)

// The secrets and SSH journeys' steps, in order.
const (
	StepSecretCreate = "secret_create"
	StepSecretRead   = "secret_read"
	StepSecretRotate = "secret_rotate"
	StepSecretRun    = "secret_run"
	StepSecretDelete = "secret_delete"
	StepSSHIssue     = "ssh_issue"
	StepSSHVerify    = "ssh_verify"
	StepSSHRevoke    = "ssh_revoke"
	StepSSHKRL       = "ssh_krl"
)

// JourneyResult is one journey beside the certificate one: its steps, its
// verdict, and what it does not show.
type JourneyResult struct {
	Name          string   `json:"name"`
	Verdict       Status   `json:"verdict"`
	Summary       Summary  `json:"summary"`
	Steps         []Step   `json:"steps"`
	Limits        []string `json:"limits"`
	ForcedFailure bool     `json:"forced_failure,omitempty"`
}

// Journeys reads a comma-separated journey list; the certificate journey
// alone when it is empty.
func Journeys(list string) ([]string, error) {
	if strings.TrimSpace(list) == "" {
		return []string{JourneyCertificate}, nil
	}
	var out []string
	for _, name := range strings.Split(list, ",") {
		name = strings.TrimSpace(name)
		switch name {
		case JourneyCertificate, JourneySecrets, JourneySSH:
		default:
			return nil, fmt.Errorf("evaluate: unknown journey %q (certificate, secrets, ssh)", name)
		}
		if !slices.Contains(out, name) {
			out = append(out, name)
		}
	}
	return out, nil
}

// track is one journey's steps beside the certificate journey's.
type track struct {
	j      *journey
	result JourneyResult
	failed string
}

func (j *journey) track(name string) *track {
	return &track{j: j, result: JourneyResult{Name: name, Steps: []Step{}, ForcedFailure: j.opts.ForceFailure == name}}
}

func (t *track) step(ctx context.Context, name string, fn func(context.Context, *Step) error) {
	t.result.Steps = append(t.result.Steps, runStep(ctx, t.j.opts.Now, &t.failed, name, fn))
}

func (t *track) finish(limits ...string) JourneyResult {
	t.result.Summary = summarize(t.result.Steps)
	t.result.Verdict = verdictOf(t.result.Summary)
	t.result.Limits = limits
	if t.result.ForcedFailure {
		t.result.Limits = append(t.result.Limits, "A forced failure was asked for: one step of this journey expected what did not happen, so its failure here is the expected result.")
	}
	return t.result
}

// randomSecret is a synthetic value no one else knows, for the journey to
// write and find again. The pack records its digest, never the value.
func randomSecret() (string, error) {
	raw, err := crypto.RandomBytes(32)
	if err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(raw), nil
}

func digestOf(value string) string { return "sha256:" + crypto.SHA256Hex([]byte(value)) }

// secretsJourney writes a synthetic secret, reads it back, rotates it, has
// trstctl run inject it into a child process, then deletes it and finds it
// gone.
func (j *journey) secretsJourney(ctx context.Context) JourneyResult {
	t := j.track(JourneySecrets)
	name := "trstctl-evaluate/" + strings.TrimSuffix(j.keyPrefix, "-")
	path := "/api/v1/secrets/store/" + url.PathEscape(name)
	first, err := randomSecret()
	second, err2 := randomSecret()
	if err = errors.Join(err, err2); err != nil {
		t.step(ctx, StepSecretCreate, func(context.Context, *Step) error { return err })
		return t.finish()
	}
	read := func(ctx context.Context, s *Step, want string, version int) error {
		var got struct {
			Value   string `json:"value"`
			Version int    `json:"version"`
		}
		if err := j.api.get(ctx, path, &got); err != nil {
			return err
		}
		s.Basis = BasisObserved
		s.Evidence["version"] = strconv.Itoa(got.Version)
		s.Evidence["value_sha256"] = short(digestOf(got.Value))
		if got.Version != version || digestOf(got.Value) != digestOf(want) {
			return fmt.Errorf("read back version %d with digest %s; expected version %d with digest %s", got.Version, short(digestOf(got.Value)), version, short(digestOf(want)))
		}
		return nil
	}
	created := 0
	t.step(ctx, StepSecretCreate, func(ctx context.Context, s *Step) error {
		var meta struct {
			Version int `json:"version"`
		}
		if err := j.api.post(ctx, "/api/v1/secrets/store", map[string]string{"name": name, "value": first}, j.key("secret-create"), &meta); err != nil {
			return err
		}
		created = meta.Version
		s.Basis = BasisRecorded
		s.Evidence["name"], s.Evidence["version"], s.Evidence["value_sha256"] = name, strconv.Itoa(meta.Version), short(digestOf(first))
		s.Detail = fmt.Sprintf("Stored the synthetic secret %s as version %d; the pack keeps its digest, never its value.", name, meta.Version)
		return nil
	})
	t.step(ctx, StepSecretRead, func(ctx context.Context, s *Step) error {
		want := first
		if t.result.ForcedFailure {
			want = second // forced: expect a value that was never written
		}
		if err := read(ctx, s, want, created); err != nil {
			return err
		}
		s.Detail = "Read the secret back: the same version and digest as written."
		return nil
	})
	t.step(ctx, StepSecretRotate, func(ctx context.Context, s *Step) error {
		if _, err := j.api.do(ctx, http.MethodPut, path, map[string]string{"value": second}, j.key("secret-rotate")); err != nil {
			return err
		}
		if err := read(ctx, s, second, created+1); err != nil {
			return err
		}
		s.Detail = fmt.Sprintf("Rotated the secret to version %d and read the new value back.", created+1)
		return nil
	})
	t.step(ctx, StepSecretRun, func(ctx context.Context, s *Step) error {
		if err := j.runWithSecret(ctx, name, second); err != nil {
			return err
		}
		s.Basis = BasisObserved
		s.Detail = "trstctl run gave a child process the rotated value in its environment; the child compared it and exited 0, printing nothing."
		return nil
	})
	t.step(ctx, StepSecretDelete, func(ctx context.Context, s *Step) error {
		if _, err := j.api.do(ctx, http.MethodDelete, path, nil, j.key("secret-delete")); err != nil {
			return err
		}
		var gone *apiError
		_, err := j.api.do(ctx, http.MethodGet, path, nil, "")
		if !errors.As(err, &gone) || gone.Status != http.StatusNotFound {
			return fmt.Errorf("the deleted secret still answers a read: %v", err)
		}
		s.Basis = BasisObserved
		s.Detail = "Deleted the secret; a read now answers 404."
		return nil
	})
	return t.finish(
		"The secrets journey writes, reads, rotates, injects and deletes one synthetic secret in the native store. Syncs to external stores, dynamic secrets and sharing are not part of it.",
		"The run step's child is a POSIX shell that compares the value it was given with the one expected; it shows injection into a process, not into a particular application.",
	)
}

// expectEnv carries the value the run step's child must have been given.
const expectEnv = "TRSTCTL_EVALUATE_EXPECT"

// runWithSecret runs this binary's `trstctl run` in-process, mapping the secret
// into a child that exits 0 only when it was given want. trstctl run passes
// its own environment to the child (all but the token), so the expected value
// reaches the child there, never in an argument list.
func (j *journey) runWithSecret(ctx context.Context, name, want string) error {
	if j.opts.RunCLI != nil {
		return j.opts.RunCLI(ctx, name, want)
	}
	if runtime.GOOS == "windows" {
		return skippedStep{reason: "Skipped: the run step's child is a POSIX shell, which this platform does not provide."}
	}
	if err := os.Setenv(expectEnv, want); err != nil {
		return err
	}
	defer func() { _ = os.Unsetenv(expectEnv) }()
	var stderr strings.Builder
	code := cli.Run(ctx, []string{"run", "--secret", "TRSTCTL_EVALUATE_SECRET=" + name, "--",
		"/bin/sh", "-c", `[ "$TRSTCTL_EVALUATE_SECRET" = "$` + expectEnv + `" ]`},
		cli.Env{Server: j.api.base, Token: j.api.token, HTTPClient: j.api.http}, strings.NewReader(""), io.Discard, &stderr)
	if code != 0 {
		return fmt.Errorf("trstctl run exited %d: %s", code, sentence(strings.TrimSpace(stderr.String())))
	}
	return nil
}

// sshJourney issues a user certificate for a key the evaluator generates,
// checks it offline against the served CA key, revokes it, and finds it in
// the served KRL.
func (j *journey) sshJourney(ctx context.Context) JourneyResult {
	t := j.track(JourneySSH)
	keyID := "trstctl-evaluate-" + strings.TrimSuffix(j.keyPrefix, "-")
	// The eval profile lets a direct user certificate carry this one login
	// name unless protocols.ssh_user_principals lists others.
	principal := firstNonEmpty(j.opts.SSHPrincipal, config.DefaultEvalSSHUserPrincipal)
	// The key is certified, never used to sign: it is destroyed when the
	// journey ends.
	key, err := crypto.GenerateLockedKey(crypto.ECDSAP256)
	if err != nil {
		t.step(ctx, StepSSHIssue, func(context.Context, *Step) error { return err })
		return t.finish()
	}
	defer key.Destroy()
	public, err := crypto.SSHPublicKeyFromSigner(key)
	var subject sshkeys.KeyInfo
	if err == nil {
		subject, err = sshkeys.ParsePublicKey(public)
	}
	if err != nil {
		t.step(ctx, StepSSHIssue, func(context.Context, *Step) error { return err })
		return t.finish()
	}
	var issued struct {
		Certificate string `json:"certificate"`
		Serial      uint64 `json:"serial"`
	}
	var cert sshkeys.CertificateInfo
	t.step(ctx, StepSSHIssue, func(ctx context.Context, s *Step) error {
		if err := j.api.post(ctx, "/api/v1/ssh/certificates", map[string]any{
			"certificate_type": "user", "public_key": strings.TrimSpace(string(public)),
			"key_id": keyID, "principals": []string{principal}, "ttl_seconds": 600,
		}, j.key("ssh-issue"), &issued); err != nil {
			return err
		}
		info, err := sshkeys.ParseCertificate([]byte(issued.Certificate))
		if err != nil {
			return fmt.Errorf("the issued certificate does not parse: %w", err)
		}
		cert = info
		s.Basis = BasisRecorded
		s.Evidence["serial"], s.Evidence["key_id"] = strconv.FormatUint(issued.Serial, 10), keyID
		s.Detail = fmt.Sprintf("Issued user certificate serial %d for principal %s to a key the evaluator generated.", issued.Serial, principal)
		return nil
	})
	t.step(ctx, StepSSHVerify, func(ctx context.Context, s *Step) error {
		raw, err := j.api.do(ctx, http.MethodGet, "/ssh/ca", nil, "")
		if err != nil {
			return err
		}
		authority, err := sshkeys.ParsePublicKey(raw)
		if err != nil {
			return fmt.Errorf("the served CA key does not parse: %w", err)
		}
		now := j.opts.Now()
		switch {
		case cert.Kind != "user" || !cert.SignatureVerified:
			return errors.New("the certificate is not a user certificate whose signature verifies")
		case cert.CAFingerprintSHA256 != authority.FingerprintSHA256:
			return fmt.Errorf("the certificate is signed by %s, not the served CA key %s", cert.CAFingerprintSHA256, authority.FingerprintSHA256)
		case !slices.Contains(cert.Principals, principal):
			return fmt.Errorf("the certificate does not name principal %s", principal)
		case now.Before(cert.ValidAfter) || (!cert.Forever && !now.Before(cert.ValidBefore)):
			return errors.New("the certificate is not valid now")
		case cert.KeyFingerprintSHA256 != subject.FingerprintSHA256 || cert.Serial != issued.Serial || cert.KeyID != keyID:
			return errors.New("the certificate certifies another key, serial or key ID than the one issued")
		}
		s.Basis = BasisObserved
		s.Evidence["authority_sha256"] = authority.FingerprintSHA256
		s.Detail = "Checked offline: signed by the served CA key, for the evaluator's key and principal, inside its validity."
		return nil
	})
	t.step(ctx, StepSSHRevoke, func(ctx context.Context, s *Step) error {
		if err := j.api.post(ctx, "/api/v1/ssh/certificates/revoke", map[string]any{"serial": issued.Serial, "reason": "trstctl evaluate"}, j.key("ssh-revoke"), nil); err != nil {
			return err
		}
		s.Basis = BasisRecorded
		s.Detail = fmt.Sprintf("Revoked serial %d.", issued.Serial)
		return nil
	})
	t.step(ctx, StepSSHKRL, func(ctx context.Context, s *Step) error {
		var version uint64
		err := j.poll(ctx, "the served KRL listing the revoked serial", func(ctx context.Context) (bool, error) {
			raw, err := j.api.do(ctx, http.MethodGet, "/ssh/krl", nil, "")
			if err != nil {
				return false, err
			}
			parsed, err := sshkrl.ParseRevocations(raw)
			if err != nil {
				return false, fmt.Errorf("the served KRL does not parse: %w", err)
			}
			version = parsed.Version
			return revokesSerial(parsed.Carried(), issued.Serial, keyID), nil
		})
		if err != nil {
			return err
		}
		if t.result.ForcedFailure {
			return fmt.Errorf("expected serial %d absent from the served KRL (version %d), and it is listed", issued.Serial, version)
		}
		s.Basis = BasisObserved
		s.Evidence["krl_version"] = strconv.FormatUint(version, 10)
		s.Detail = fmt.Sprintf("The served KRL (version %d) revokes serial %d.", version, issued.Serial)
		return nil
	})
	return t.finish(
		"The SSH journey issues one user certificate and checks the served KRL. It does not install the KRL on a host or log in with the certificate.",
	)
}

// revokesSerial reports whether a KRL's revocations cover serial or key ID.
func revokesSerial(carried sshkrl.Carried, serial uint64, keyID string) bool {
	for _, r := range carried.Serials {
		if serial >= r.Lo && serial <= r.Hi {
			return true
		}
	}
	return slices.Contains(carried.KeyIDs, keyID)
}

// runStep runs one step unless an earlier one of its journey failed: a step
// that finds nothing to work on is skipped, never passed.
func runStep(ctx context.Context, now func() time.Time, failed *string, name string, fn func(context.Context, *Step) error) Step {
	s := Step{Name: name, StartedAt: now().UTC(), Evidence: map[string]string{}}
	var skip skippedStep
	if *failed != "" {
		s.Status, s.Detail = StatusSkipped, "Skipped because the "+strings.ReplaceAll(*failed, "_", " ")+" step failed."
	} else if err := fn(ctx, &s); errors.As(err, &skip) {
		s.Status, s.Detail, s.Basis = StatusSkipped, skip.reason, ""
	} else if err != nil {
		s.Status, s.Detail, s.Basis = StatusFail, sentence(err.Error()), ""
		*failed = name
	} else {
		s.Status = StatusPass
	}
	if len(s.Evidence) == 0 {
		s.Evidence = nil
	}
	s.FinishedAt = now().UTC()
	return s
}

func summarize(steps []Step) Summary {
	var out Summary
	for _, s := range steps {
		switch s.Status {
		case StatusPass:
			out.Passed++
		case StatusFail:
			out.Failed++
		default:
			out.Skipped++
		}
	}
	return out
}

func verdictOf(s Summary) Status {
	if s.Failed > 0 || s.Skipped > 0 {
		return StatusFail
	}
	return StatusPass
}
