// SPDX-License-Identifier: BUSL-1.1

package relay

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"regexp"
	"sync"
	"sync/atomic"
	"time"
	"unicode/utf8"
)

// deployFailureLogLimit bounds the reason the relay writes for one failed
// deploy.
const deployFailureLogLimit = 2048

// DefaultDeployFailureEntries is how many failures the relay's failure log
// keeps; the oldest are dropped first.
const DefaultDeployFailureEntries = 200

// The deploy steps a failure log entry names (A192).
const (
	DeployStepIntent      = "intent"      // the job payload, or a field the deploy needs
	DeployStepExecutor    = "executor"    // whether this agent can run the connector
	DeployStepRedeem      = "redeem"      // redeeming the attempt's credentials
	DeployStepMaterial    = "material"    // taking the redeemed material into locked memory
	DeployStepConnector   = "connector"   // the connector's deploy against the target
	DeployStepSandbox     = "sandbox"     // an operation outside the connector's declared capabilities
	DeployStepPredecessor = "predecessor" // keeping the host predecessor for rollback
	DeployStepVerify      = "verify"      // checking the listener, and the appliance, after the deploy
)

// DeployFailure is one entry in the relay's failure log. Reason is scrubbed:
// every redeemed value, private key and credential-shaped token removed.
type DeployFailure struct {
	At        time.Time `json:"at"`
	JobID     int64     `json:"job_id"`
	Attempt   int       `json:"attempt"`
	Connector string    `json:"connector,omitempty"`
	Target    string    `json:"target,omitempty"`
	Step      string    `json:"step"`
	Reason    string    `json:"reason"`
}

// DeployFailureLog keeps the newest deploy failures in a file on the relay's
// own host (A192). The control plane receives only a closed phrase for a
// failed deploy, because the connector's error can carry whatever the
// appliance echoed back; this log is where an operator with access to the
// relay reads which step failed and why.
type DeployFailureLog struct {
	path  string
	limit int
	mu    sync.Mutex
}

var deployFailureLog atomic.Pointer[DeployFailureLog]

// SetDeployFailureLog installs the relay's failure log; nil leaves failures in
// the process log only.
func SetDeployFailureLog(l *DeployFailureLog) { deployFailureLog.Store(l) }

// OpenDeployFailureLog opens (creating, mode 0600) the failure log at path,
// keeping the newest limit entries (DefaultDeployFailureEntries when limit is
// not positive).
func OpenDeployFailureLog(path string, limit int) (*DeployFailureLog, error) {
	if path == "" {
		return nil, errors.New("relay: the deploy failure log needs a path")
	}
	if limit <= 0 {
		limit = DefaultDeployFailureEntries
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, fmt.Errorf("relay: deploy failure log directory: %w", err)
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_RDONLY, 0o600) // #nosec G304 -- the operator's own flag (CWE-22)
	if err != nil {
		return nil, fmt.Errorf("relay: open deploy failure log: %w", err)
	}
	if err := f.Close(); err != nil {
		return nil, err
	}
	if err := os.Chmod(path, 0o600); err != nil {
		return nil, fmt.Errorf("relay: restrict deploy failure log: %w", err)
	}
	return &DeployFailureLog{path: path, limit: limit}, nil
}

// Path is where the log is kept.
func (l *DeployFailureLog) Path() string { return l.path }

// Record adds e and drops the oldest entries beyond the limit. The file is
// replaced through a temporary file in its directory, so a crash leaves the
// previous log or the new one, never part of either. A damaged log is started
// over rather than refusing the new entry.
func (l *DeployFailureLog) Record(e DeployFailure) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	entries, err := ReadDeployFailures(l.path)
	if err != nil {
		entries = nil
	}
	entries = append(entries, e)
	if len(entries) > l.limit {
		entries = entries[len(entries)-l.limit:]
	}
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	for _, entry := range entries {
		if err := enc.Encode(entry); err != nil {
			return err
		}
	}
	tmp, err := os.CreateTemp(filepath.Dir(l.path), ".deploy-failures-*")
	if err != nil {
		return err
	}
	defer func() { _ = os.Remove(tmp.Name()) }()
	if err := tmp.Chmod(0o600); err != nil {
		_ = tmp.Close()
		return err
	}
	if _, err := tmp.Write(buf.Bytes()); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), l.path)
}

// ReadDeployFailures returns the entries in the failure log at path, oldest
// first. A missing log has none.
func ReadDeployFailures(path string) ([]DeployFailure, error) {
	data, err := os.ReadFile(path) // #nosec G304 -- the operator's own flag (CWE-22)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var out []DeployFailure
	scanner := bufio.NewScanner(bytes.NewReader(data))
	scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for scanner.Scan() {
		line := bytes.TrimSpace(scanner.Bytes())
		if len(line) == 0 {
			continue
		}
		var entry DeployFailure
		if err := json.Unmarshal(line, &entry); err != nil {
			return nil, fmt.Errorf("relay: deploy failure log entry: %w", err)
		}
		out = append(out, entry)
	}
	return out, scanner.Err()
}

// recordDeployFailure writes a failed deploy's step and scrubbed reason to the
// process log and, when one is installed, the failure log.
func recordDeployFailure(job Job, intent DeployIntent, step, reason string) {
	if intent.Connector == "" {
		log.Printf("trstctl-agent: job %d: deploy failed at the %s step: %s", job.JobID, step, reason)
	} else {
		log.Printf("trstctl-agent: job %d: %s deploy to %s failed at the %s step: %s", job.JobID, intent.Connector, intent.Target, step, reason)
	}
	l := deployFailureLog.Load()
	if l == nil {
		return
	}
	if err := l.Record(DeployFailure{
		At: time.Now().UTC(), JobID: job.JobID, Attempt: job.Attempt,
		Connector: intent.Connector, Target: intent.Target, Step: step, Reason: reason,
	}); err != nil {
		log.Printf("trstctl-agent: job %d: the deploy failure log could not be written: %v", job.JobID, err)
	}
}

// failDeploy reports a failed deploy to the control plane as the closed
// phrase, and keeps the step and the scrubbed cause on this host. An AD CS
// inventory shares the path up to redemption but is not a deploy, so it only
// reports.
func failDeploy(ctx context.Context, ch Channel, job Job, intent DeployIntent, step, phrase string, cause error, material Material) {
	if job.Kind != KindADCSInventory {
		reason := phrase
		if cause != nil {
			reason = phrase + ": " + scrubFailure(cause.Error(), material)
		}
		recordDeployFailure(job, intent, step, reason)
	}
	report(ctx, ch, job, OutcomeFailed, phrase)
}

var (
	pemBlockPattern       = regexp.MustCompile(`(?s)-----BEGIN [A-Z0-9 ]+-----.*?-----END [A-Z0-9 ]+-----`)
	pemPrivateTailPattern = regexp.MustCompile(`(?s)-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----.*`)
	authHeaderPattern     = regexp.MustCompile(`(?i)\b((?:proxy-)?authorization)(\s*[:=]\s*)(?:(?:bearer|basic|digest|negotiate|token)\s+)?[^\s,;]+`)
	authSchemePattern     = regexp.MustCompile(`(?i)\b(bearer|basic)\s+[A-Za-z0-9._~+/=-]{8,}`)
	secretValuePattern    = regexp.MustCompile(`(?i)\b(password|passwd|pwd|passphrase|secret|client_secret|token|access_token|refresh_token|api[_-]?key|private[_-]?key)("?\s*[:=]\s*"?)([^\s"&,;}]+)`)
)

// scrubFailure removes what must not be kept from a connector's error: every
// redeemed value (and every line of a multi-line one), every PEM block, the
// value of an authorization header or credential-shaped field, and control
// characters, bounded to deployFailureLogLimit bytes.
func scrubFailure(text string, material Material) string {
	out := redactRedeemed(text, material)
	out = pemBlockPattern.ReplaceAllString(out, "[redacted PEM]")
	out = pemPrivateTailPattern.ReplaceAllString(out, "[redacted private key]")
	out = authHeaderPattern.ReplaceAllString(out, "$1$2[redacted]")
	out = authSchemePattern.ReplaceAllString(out, "$1 [redacted]")
	out = secretValuePattern.ReplaceAllString(out, "$1$2[redacted]")
	out = string(bytes.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f {
			return ' '
		}
		return r
	}, []byte(out)))
	if len(out) > deployFailureLogLimit {
		cut := deployFailureLogLimit
		for cut > 0 && !utf8.RuneStart(out[cut]) {
			cut--
		}
		out = out[:cut] + "…"
	}
	return out
}

// redactRedeemed removes every redeemed value from text, and every line of a
// multi-line value (a PEM key echoed one line at a time), working on the
// material's own bytes so no further copy of a secret is made.
func redactRedeemed(text string, material Material) string {
	out := []byte(text)
	mask := []byte("[redacted]")
	for _, value := range material {
		if v := bytes.TrimSpace(value); len(v) >= 4 {
			out = bytes.ReplaceAll(out, v, mask)
		}
	}
	for _, value := range material {
		for _, line := range bytes.Split(value, []byte("\n")) {
			if line = bytes.TrimSpace(line); len(line) >= 16 {
				out = bytes.ReplaceAll(out, line, mask)
			}
		}
	}
	return string(out)
}
