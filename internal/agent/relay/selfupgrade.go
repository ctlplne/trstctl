// SPDX-License-Identifier: MPL-2.0

package relay

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	fleet "trstctl.com/trstctl/internal/agentupgrade"
	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/netsec"
)

// KindAgentUpgrade is the self-upgrade job kind (epic A5). Each row is
// narrowed to one agent by the control plane's claim SQL; this executor only
// ever replaces ITS OWN binary.
const KindAgentUpgrade = "agent.upgrade"

// maxUpgradeArtifactBytes bounds one download. An agent binary is tens of
// megabytes; a server that streams forever is either misconfigured or hostile,
// and either way the answer is a refusal, not a full disk (AN-7 in miniature).
const maxUpgradeArtifactBytes = 512 << 20

// SelfUpgrade is what the executor needs to replace this agent's binary. nil
// disables the kind entirely — the loop does not even ask for it.
type SelfUpgrade struct {
	// ExecutablePath is this process's own binary, from os.Executable().
	ExecutablePath string
	// CurrentVersion is buildinfo.Version(); a job targeting it is already
	// satisfied and reports executed without downloading anything.
	CurrentVersion string
	// Client fetches artifacts. The agent binary injects one whose egress
	// posture matches the deployment (private mirrors allowed — an air-gapped
	// estate's artifact host is RFC1918 by construction). Nil falls back to
	// the SSRF-safe public-only client, which is the right default for any
	// caller that did not think about egress.
	Client *http.Client
	// Restart hands control to the new binary after a successful stage:
	// exec on Unix, exit-for-the-service-manager on Windows. It runs AFTER
	// the executed report has been delivered, because exec never returns and
	// an unreported success would read as silence — the exact signal that
	// halts the ring. Nil skips the restart (tests, and "stage now, restart
	// in the window" setups).
	Restart func() error
}

func (su *SelfUpgrade) client() *http.Client {
	if su != nil && su.Client != nil {
		return su.Client
	}
	// SEC-005: the guarded client, never an ambient one. Redirects are
	// followed same-origin only and every hop is re-checked; a cross-origin
	// redirect (e.g. a release page bouncing to a CDN) fails the download,
	// which the operator fixes by publishing the direct or mirrored URL.
	return netsec.SafeClient(5 * time.Minute)
}

// runSelfUpgrade executes one agent.upgrade job: pick this platform's
// artifact, download, verify the digest, swap the binary, report, restart.
//
// Report BEFORE restart, always: exec replaces the process image and an
// unsent report is a silent ring. The receipt therefore means "the new binary
// is staged and verified, restart initiated" — the campaign's proof the new
// build actually RUNS is the version the reconnected agent reports, not this
// receipt, and the sweep scores exactly that.
func runSelfUpgrade(ctx context.Context, ch Channel, su *SelfUpgrade, job Job) bool {
	if su == nil {
		// Defensive: the kind is only claimed when su != nil, but a report is
		// still owed if a row arrives — silence would hold the job to lease
		// expiry and then hand it back for the same refusal.
		report(ctx, ch, job, OutcomeFailed, "self-upgrade is not enabled on this agent")
		return false
	}
	var intent fleet.UpgradeIntent
	if err := decodeJobPayload(job.Payload, &intent); err != nil {
		report(ctx, ch, job, OutcomeFailed, "job payload is not an upgrade intent")
		return false
	}
	if strings.TrimSpace(intent.TargetVersion) == "" {
		report(ctx, ch, job, OutcomeFailed, "upgrade intent names no target version")
		return false
	}
	if intent.TargetVersion == su.CurrentVersion {
		// A redelivered job after a completed upgrade, or an operator
		// re-running a ring the agent already crossed. Nothing to do IS the
		// success case, and reporting it keeps the redelivery from cycling.
		report(ctx, ch, job, OutcomeExecuted, "already on the target version")
		return true
	}
	artifact, ok := fleet.ArtifactFor(intent.Artifacts, runtime.GOOS, runtime.GOARCH)
	if !ok {
		// The campaign published builds, none for this platform. The closed
		// phrase names the gap the operator can act on; a generic failure
		// would send them to the artifact host's logs.
		report(ctx, ch, job, OutcomeFailed, "no artifact published for this agent's platform")
		return false
	}

	staged, err := downloadUpgradeArtifact(ctx, su.client(), artifact, su.ExecutablePath)
	if err != nil {
		// The error detail stays local (stderr); the report carries a closed
		// phrase. A download error can echo URLs with embedded tokens, and
		// the queue is the wrong place for those to become durable.
		fmt.Fprintln(os.Stderr, "trstctl-agent: self-upgrade:", err)
		report(ctx, ch, job, OutcomeFailed, upgradeFailurePhrase(err))
		return false
	}

	if err := swapBinary(su.ExecutablePath, staged); err != nil {
		_ = os.Remove(staged)
		fmt.Fprintln(os.Stderr, "trstctl-agent: self-upgrade:", err)
		report(ctx, ch, job, OutcomeFailed, "could not stage the new binary over the running one")
		return false
	}

	report(ctx, ch, job, OutcomeExecuted, "staged "+intent.TargetVersion+"; restarting to load it")
	if su.Restart != nil {
		if err := su.Restart(); err != nil {
			// The report is already gone and cannot be amended — which is the
			// honest shape: the stage DID succeed. If this process never
			// comes back on the new version, the ring's grace expires and the
			// campaign halts on silence, which is the correct verdict for an
			// agent that could not restart itself.
			fmt.Fprintln(os.Stderr, "trstctl-agent: self-upgrade restart failed:", err)
		}
	}
	return true
}

// errUpgradeDigestMismatch marks the one failure that must be phrased apart:
// the bytes arrived and they are not the published build.
var errUpgradeDigestMismatch = errors.New("artifact digest mismatch")

func upgradeFailurePhrase(err error) string {
	if errors.Is(err, errUpgradeDigestMismatch) {
		return "artifact digest did not match the campaign's pinned sha256"
	}
	return "artifact download failed"
}

// downloadUpgradeArtifact fetches the artifact next to the executable (same
// filesystem, so the final rename is atomic) and verifies its digest before
// anything touches the running binary. It returns the staged temp path.
func downloadUpgradeArtifact(ctx context.Context, client *http.Client, artifact fleet.Artifact, exePath string) (string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, artifact.URL, nil)
	if err != nil {
		return "", fmt.Errorf("build artifact request: %w", err)
	}
	resp, err := client.Do(req)
	if err != nil {
		return "", fmt.Errorf("fetch artifact: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("fetch artifact: unexpected status %d", resp.StatusCode)
	}

	dir := filepath.Dir(exePath)
	tmp, err := os.CreateTemp(dir, ".trstctl-agent-upgrade-*")
	if err != nil {
		return "", fmt.Errorf("stage artifact beside the executable: %w", err)
	}
	tmpPath := tmp.Name()
	cleanup := func() {
		_ = tmp.Close()
		_ = os.Remove(tmpPath)
	}
	// +1 so a body exactly at the cap is distinguishable from one that was cut.
	n, err := io.Copy(tmp, io.LimitReader(resp.Body, maxUpgradeArtifactBytes+1))
	if err != nil {
		cleanup()
		return "", fmt.Errorf("download artifact: %w", err)
	}
	if n > maxUpgradeArtifactBytes {
		cleanup()
		return "", fmt.Errorf("artifact exceeds the %d-byte bound", int64(maxUpgradeArtifactBytes))
	}
	if _, err := tmp.Seek(0, io.SeekStart); err != nil {
		cleanup()
		return "", err
	}
	// AN-3: hashing goes through internal/crypto like everything else. The
	// digest decides whether these bytes become this machine's agent — a
	// mismatch is a refusal, whatever the transport said about success.
	digest, _, err := crypto.SHA256ReaderHex(tmp)
	if err != nil {
		cleanup()
		return "", fmt.Errorf("hash artifact: %w", err)
	}
	if !strings.EqualFold(digest, artifact.SHA256) {
		cleanup()
		return "", fmt.Errorf("%w: got %s", errUpgradeDigestMismatch, digest)
	}
	if err := tmp.Close(); err != nil {
		_ = os.Remove(tmpPath)
		return "", err
	}
	if err := os.Chmod(tmpPath, 0o755); err != nil { // #nosec G302 -- the file IS the executable being installed; 0755 is its required mode (CWE-276)
		_ = os.Remove(tmpPath)
		return "", err
	}
	return tmpPath, nil
}

// swapBinary moves the running executable aside and the staged one into place.
//
// Two renames, not a copy: renames are atomic on one filesystem and the temp
// file was created beside the executable for exactly that reason. The old
// binary stays as <exe>.old — deliberately, because a machine whose new build
// cannot start needs something a human can put back without a download.
//
// This works on Windows too: a RUNNING executable's file can be renamed (its
// image is mapped), it just cannot be deleted or overwritten in place — which
// is why the sequence is rename-away then rename-in, never copy-over.
func swapBinary(exePath, staged string) error {
	old := exePath + ".old"
	// A leftover .old from the previous upgrade is expected; on Windows it can
	// linger while unmapped. Best-effort removal — if it cannot be removed the
	// rename below fails and reports honestly.
	_ = os.Remove(old)
	if err := os.Rename(exePath, old); err != nil {
		return fmt.Errorf("move the running binary aside: %w", err)
	}
	if err := os.Rename(staged, exePath); err != nil {
		// Put the world back: the running binary must keep its name, or the
		// next service-manager restart finds nothing to start.
		if restoreErr := os.Rename(old, exePath); restoreErr != nil {
			return fmt.Errorf("install the new binary: %v; AND restoring the old one failed: %w", err, restoreErr)
		}
		return fmt.Errorf("install the new binary: %w", err)
	}
	return nil
}
