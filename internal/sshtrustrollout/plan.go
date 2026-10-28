// SPDX-License-Identifier: BUSL-1.1

package sshtrustrollout

import (
	"bytes"
	"encoding/json"
	"errors"
	"sort"
	"strings"
	"time"

	"github.com/google/uuid"
	"trstctl.com/trstctl/internal/crypto"
)

const MaxHosts = 100
const ReadinessMaxAge = 5 * time.Minute
const MaxExecutionWindow = 30 * time.Minute

// Host is one exact enrolled identity in the reviewed roster. A skipped host
// remains in the plan so its opt-out is visible and cannot be hidden by dispatch.
type Host struct {
	AgentID         string `json:"agent_id"`
	ReadinessDigest string `json:"readiness_digest,omitempty"`
	State           string `json:"state"`
	Reason          string `json:"reason,omitempty"`
}

// Plan contains only an additive public CA change and the exact host roster.
// ExpiresAt is fixed by preview and retained through review, execution and replay.
type Plan struct {
	Name          string    `json:"name"`
	Reason        string    `json:"reason"`
	PublicCAKey   []byte    `json:"public_ca_key"`
	CAFingerprint string    `json:"ca_fingerprint"`
	ExpiresAt     time.Time `json:"expires_at"`
	Hosts         []Host    `json:"hosts"`
}

func (p Plan) Validate() error {
	if strings.TrimSpace(p.Name) != p.Name || len(p.Name) > 128 || strings.ContainsAny(p.Name, "\x00\r\n") {
		return errors.New("name must be one bounded line")
	}
	if len(p.Reason) > 1024 || strings.ContainsRune(p.Reason, 0) {
		return errors.New("provide a bounded reason reviewers can inspect")
	}
	if p.ExpiresAt.IsZero() || p.ExpiresAt.Location() != time.UTC || len(p.Hosts) == 0 || len(p.Hosts) > MaxHosts {
		return errors.New("the plan needs a UTC deadline and between one and 100 hosts")
	}
	previous := ""
	for _, host := range p.Hosts {
		id, err := uuid.Parse(host.AgentID)
		if err != nil || id == uuid.Nil || id.String() != host.AgentID || host.AgentID <= previous {
			return errors.New("reviewed hosts must have distinct sorted canonical identities")
		}
		previous = host.AgentID
		switch host.State {
		case "ready":
			if !digest(host.ReadinessDigest) || host.Reason != "" {
				return errors.New("ready hosts need their exact local policy digest")
			}
		case "skipped":
			if !SkipReason(host.Reason) || host.ReadinessDigest != "" {
				return errors.New("skipped hosts need a closed reason")
			}
		default:
			return errors.New("plan hosts are ready or skipped")
		}
	}
	canonical, _, err := CanonicalPublicCAKey(p.PublicCAKey)
	if err != nil {
		return err
	}
	if !bytes.Equal(canonical, p.PublicCAKey) {
		return errors.New("reviewed SSH CA bytes must use their comment-free canonical line")
	}
	// Reuse the same strict public-key contract as the eventual host command.
	c := Command{RolloutID: p.Hosts[0].AgentID, AgentID: p.Hosts[0].AgentID, PublicCAKey: p.PublicCAKey, CAFingerprint: p.CAFingerprint, PlanDigest: "sha256:" + strings.Repeat("a", 64), ReadinessDigest: "sha256:" + strings.Repeat("b", 64), ExpiresAt: p.ExpiresAt}
	return c.Validate()
}

func SkipReason(reason string) bool {
	switch reason {
	case "disabled", "unconfirmed", "misconfigured", "not_reported", "stale", "not_host_role", "ca_not_staged", "claims_paused":
		return true
	default:
		return false
	}
}

func (p Plan) Digest() (string, error) {
	if err := p.Validate(); err != nil {
		return "", err
	}
	// Name and reason are reviewer metadata. The effect digest binds only public
	// trust material, deadline and the exact roster; the approval also binds the
	// name/reason independently. Erasing personal text cannot change an effect.
	raw, err := json.Marshal(struct {
		PublicCAKey   []byte    `json:"public_ca_key"`
		CAFingerprint string    `json:"ca_fingerprint"`
		ExpiresAt     time.Time `json:"expires_at"`
		Hosts         []Host    `json:"hosts"`
	}{p.PublicCAKey, p.CAFingerprint, p.ExpiresAt, p.Hosts})
	if err != nil {
		return "", err
	}
	return "sha256:" + crypto.SHA256Hex(raw), nil
}

// ValidateReview requires human-readable metadata for a new operator review.
// Structural replay permits cleared metadata after an authorized privacy rewrite.
func (p Plan) ValidateReview() error {
	if strings.TrimSpace(p.Name) == "" || strings.TrimSpace(p.Reason) == "" {
		return errors.New("provide a rollout name and reviewer reason")
	}
	return p.Validate()
}

func (p Plan) ExecutionWindow(now time.Time) error {
	if !now.Before(p.ExpiresAt) || p.ExpiresAt.Sub(now) > MaxExecutionWindow {
		return errors.New("the review window ended or is too long; preview the rollout again")
	}
	return p.ValidateReview()
}

func SortHosts(hosts []Host) {
	sort.Slice(hosts, func(i, j int) bool { return hosts[i].AgentID < hosts[j].AgentID })
}

// ResourceID is the immutable effect reviewers authorize.
func ResourceID(digest string) string { return "ssh-trust-fleet:" + digest }
